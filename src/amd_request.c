/*
 * Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dlfcn.h>
#include <poll.h>

#include <glib.h>
#include <gio/gio.h>
#include <aul.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <rua_internal.h>
#include <rua_stat_internal.h>
#include <tzplatform_config.h>
#include <systemd/sd-login.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_app_com.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_request.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_app_group.h"
#include "amd_cynara.h"
#include "amd_socket.h"
#include "amd_app_com.h"
#include "amd_share.h"
#include "amd_input.h"

#define INHOUSE_UID     tzplatform_getuid(TZ_USER_NAME)
#define REGULAR_UID_MIN     5000

#define MAX_NR_OF_DESCRIPTORS 2
#define PENDING_REQUEST_TIMEOUT 5000 /* msec */

static int amd_fd;
static GIOChannel *amd_io;
static guint amd_wid;
static GHashTable *__dc_socket_pair_hash;
static GHashTable *pending_table;

struct pending_item {
	int clifd;
	int pid;
	int cmd;
	guint timer;
	GList *pending_list;
};

struct request_s {
	int cmd;
	int clifd;
	pid_t pid;
	uid_t uid;
	gid_t gid;
	uid_t t_uid;
	bundle *kb;
	int len;
	int opt;
	unsigned char data[1];
};

typedef struct _rua_stat_pkt_t {
	int uid;
	char *stat_tag;
	char *stat_caller;
	char appid[512];
	gboolean is_group_app;
	char *data;
	int len;
} rua_stat_pkt_t;

typedef int (*app_cmd_dispatch_func)(request_h req);
static gboolean __timeout_pending_item(gpointer user_data);

static int __send_message(int sock, const struct iovec *vec, int vec_size,
		const int *desc, int nr_desc)
{
	struct msghdr msg = {0,};
	int sndret;
	int desclen = 0;
	struct cmsghdr *cmsg = NULL;
	char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)] = {0,};

	if (vec == NULL || vec_size < 1)
		return -EINVAL;
	if (nr_desc < 0 || nr_desc > MAX_NR_OF_DESCRIPTORS)
		return -EINVAL;
	if (desc == NULL)
		nr_desc = 0;

	msg.msg_iov = (struct iovec *)vec;
	msg.msg_iovlen = vec_size;

	/* sending ancillary data */
	if (nr_desc > 0) {
		msg.msg_control = buff;
		msg.msg_controllen = sizeof(buff);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			return -EINVAL;

		/* packing files descriptors */
		if (nr_desc > 0) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			desclen = cmsg->cmsg_len =
				CMSG_LEN(sizeof(int) * nr_desc);
			memcpy((int *)CMSG_DATA(cmsg), desc,
					sizeof(int) * nr_desc);
			cmsg = CMSG_NXTHDR(&msg, cmsg);
			_D("packing file descriptors done");
		}

		/* finished packing updating the corect length */
		msg.msg_controllen = desclen;
	} else {
		msg.msg_control = NULL;
		msg.msg_controllen = 0;
	}

	sndret = sendmsg(sock, &msg, 0);
	_D("sendmsg ret : %d", sndret);
	if (sndret < 0)
		return -errno;

	return sndret;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if (pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

static int __app_process_by_pid(request_h req, const char *pid_str,
		bool *pending)
{
	int pid;
	int ret;
	int dummy;
	const char *appid;
	const char *pkgid;
	const char *type;
	const struct appinfo *ai;
	uid_t target_uid = _request_get_target_uid(req);
	app_status_h app_status;

	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	app_status = _app_status_find(pid);
	if (app_status == NULL) {
		_E("pid %d is not an application", pid);
		_request_send_result(req, -1);
		return -1;
	}

	appid = _app_status_get_appid(app_status);
	ai = _appinfo_find(target_uid, appid);
	if (ai == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	type = _appinfo_get_value(ai, AIT_COMPTYPE);

	if (req->cmd == APP_RESUME_BY_PID || req->cmd == APP_PAUSE_BY_PID)
		aul_send_app_resume_request_signal(pid, appid, pkgid, type);
	else
		aul_send_app_terminate_request_signal(pid, appid, pkgid, type);

	switch (req->cmd) {
	case APP_RESUME_BY_PID:
		ret = _resume_app(pid, req);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
		ret = _term_app(pid, req);
		break;
	case APP_TERM_BGAPP_BY_PID:
		ret = _term_bgapp(pid, req);
		break;
	case APP_KILL_BY_PID:
		ret = _send_to_sigkill(pid);
		if (ret < 0)
			_E("fail to killing - %d\n", pid);
		_app_status_update_status(app_status, STATUS_DYING, false);
		_request_send_result(req, ret);
		break;
	case APP_TERM_REQ_BY_PID:
		ret = _term_req_app(pid, req);
		break;
	case APP_TERM_BY_PID_ASYNC:
		ret = aul_sock_send_raw(pid, target_uid, req->cmd,
				(unsigned char *)&dummy, sizeof(int),
				AUL_SOCK_NOREPLY);
		if (ret < 0)
			_D("terminate req packet send error");

		_request_send_result(req, ret);
		break;
	case APP_PAUSE_BY_PID:
		ret = _pause_app(pid, req);
		break;
	case APP_TERM_BY_PID_SYNC:
		ret = _term_app_v2(pid, req, pending);
		break;
	default:
		_E("unknown command: %d", req->cmd);
		ret = -1;
	}

	return ret;
}

static void __set_effective_appid(uid_t uid, bundle *kb)
{
	const struct appinfo *ai;
	const struct appinfo *effective_ai;
	const char *appid;
	const char *effective_appid;
	const char *pkgid;
	const char *effective_pkgid;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return;

	ai = _appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	effective_appid = _appinfo_get_value(ai, AIT_EFFECTIVE_APPID);
	if (effective_appid == NULL)
		return;

	effective_ai = _appinfo_find(uid, effective_appid);
	if (effective_ai == NULL)
		return;

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	effective_pkgid = _appinfo_get_value(effective_ai, AIT_PKGID);
	if (pkgid && effective_pkgid && strcmp(pkgid, effective_pkgid) == 0) {
		_D("use effective appid instead of the real appid");
		bundle_del(kb, AUL_K_APPID);
		bundle_add(kb, AUL_K_APPID, effective_appid);
	}
}

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec = { 0, };
	int ret;
	struct appinfo *ai;
	rua_stat_pkt_t *pkt = (rua_stat_pkt_t *)user_data;

	if (!pkt)
		return FALSE;

	if (!pkt->is_group_app) {
		ai = _appinfo_find(pkt->uid, pkt->appid);

		rec.pkg_name = pkt->appid;
		rec.app_path = (char *)_appinfo_get_value(ai, AIT_EXEC);

		if (pkt->len > 0)
			rec.arg = pkt->data;

		rec.launch_time = time(NULL);

		SECURE_LOGD("add rua history %s %s",
				rec.pkg_name, rec.app_path);
		ret = rua_db_add_history(&rec);
		if (ret == -1)
			_D("rua add history error");
	}

	if (pkt->stat_caller != NULL && pkt->stat_tag != NULL) {
		SECURE_LOGD("rua_stat_caller: %s, rua_stat_tag: %s",
				pkt->stat_caller, pkt->stat_tag);
		rua_stat_db_update(pkt->stat_caller, pkt->stat_tag);
	}
	if (pkt) {
		if (pkt->data)
			free(pkt->data);
		if (pkt->stat_caller)
			free(pkt->stat_caller);
		if (pkt->stat_tag)
			free(pkt->stat_tag);
		free(pkt);
	}

	return FALSE;
}

static int __add_rua_info(request_h req, bundle *kb, const char *appid)
{
	const char *stat_caller = NULL;
	const char *stat_tag = NULL;
	rua_stat_pkt_t *rua_stat_item = NULL;

	rua_stat_item = calloc(1, sizeof(rua_stat_pkt_t));
	if (rua_stat_item == NULL) {
		_E("out of memory");
		goto error;
	}

	if (req->len > 0) {
		rua_stat_item->data = (char *)calloc(req->len, sizeof(char));
		if (rua_stat_item->data == NULL) {
			_E("out of memory");
			goto error;
		}
		memcpy(rua_stat_item->data, req->data, req->len);
	}
	stat_caller = bundle_get_val(kb, AUL_SVC_K_RUA_STAT_CALLER);
	stat_tag = bundle_get_val(kb, AUL_SVC_K_RUA_STAT_TAG);

	rua_stat_item->len = req->len;
	if (stat_caller != NULL) {
		rua_stat_item->stat_caller = strdup(stat_caller);
		if (rua_stat_item->stat_caller == NULL) {
			_E("Out of memory");
			goto error;
		}
	}

	if (stat_tag != NULL) {
		rua_stat_item->stat_tag = strdup(stat_tag);
		if (rua_stat_item->stat_tag == NULL) {
			_E("Out of memory");
			goto error;
		}

	}
	rua_stat_item->uid = _request_get_target_uid(req);
	rua_stat_item->is_group_app = _app_group_is_group_app(kb);
	strncpy(rua_stat_item->appid, appid, 511);

	g_timeout_add(1500, __add_history_handler, rua_stat_item);

	return 0;
error:
	if (rua_stat_item) {
		if (rua_stat_item->data)
			free(rua_stat_item->data);
		if (rua_stat_item->stat_caller)
			free(rua_stat_item->stat_caller);
		if (rua_stat_item->stat_tag)
			free(rua_stat_item->stat_tag);
		free(rua_stat_item);
	}
	return -1;
}

static int __dispatch_get_mp_socket_pair(request_h req)
{
	int handles[2] = {0, 0};
	struct iovec vec[3];
	int msglen = 0;
	char buffer[1024];
	int ret;
	struct timeval tv;

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, handles) != 0) {
		_E("error create socket pair");
		_request_send_result(req, -1);
		return -1;
	}

	if (handles[0] == -1) {
		_E("error socket open");
		_request_send_result(req, -1);
		return -1;
	}

	tv.tv_sec = 5;
	tv.tv_usec = 0;

	ret = setsockopt(handles[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		_E("Cannot Set SO_RCVTIMEO for socket %d", handles[0]);
		_request_send_result(req, -1);
		goto out;
	}

	ret = setsockopt(handles[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if (ret < 0) {
		_E("Cannot Set SO_RCVTIMEO for socket %d", handles[1]);
		_request_send_result(req, -1);
		goto out;
	}

	_D("amd send mp fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	msglen = __send_message(req->clifd, vec, 1, handles, 2);
	if (msglen < 0) {
		_E("Error[%d]: while sending message\n", -msglen);
		_request_send_result(req, -1);
		ret = -1;
	}
out:
	close(handles[0]);
	close(handles[1]);

	return ret;
}

static int __dispatch_get_dc_socket_pair(request_h req)
{
	const char *caller;
	const char *callee;
	const char *datacontrol_type;
	char *socket_pair_key;
	int socket_pair_key_len;
	int *handles = NULL;
	struct iovec vec[3];
	int msglen = 0;
	char buffer[1024];
	bundle *kb = req->kb;
	struct timeval tv;
	int ret;

	caller = bundle_get_val(kb, AUL_K_CALLER_APPID);
	callee = bundle_get_val(kb, AUL_K_CALLEE_APPID);
	datacontrol_type = bundle_get_val(kb, "DATA_CONTOL_TYPE");

	socket_pair_key_len = strlen(caller) + strlen(callee) + 2;

	socket_pair_key = (char *)calloc(socket_pair_key_len, sizeof(char));
	if (socket_pair_key == NULL) {
		_E("calloc fail");
		goto err_out;
	}

	snprintf(socket_pair_key, socket_pair_key_len, "%s_%s", caller, callee);
	_D("socket pair key : %s", socket_pair_key);

	handles = g_hash_table_lookup(__dc_socket_pair_hash, socket_pair_key);
	if (handles == NULL) {
		handles = (int *)calloc(2, sizeof(int));
		if (handles == NULL) {
			_E("calloc fail");
			goto err_out;
		}

		if (socketpair(AF_UNIX, SOCK_STREAM, 0, handles) != 0) {
			_E("error create socket pair");
			_request_send_result(req, -1);

			free(handles);
			goto err_out;
		}

		if (handles[0] == -1 || handles[1] == -1) {
			_E("error socket open");
			_request_send_result(req, -1);

			free(handles);
			goto err_out;
		}

		tv.tv_sec = 5;
		tv.tv_usec = 0;
		ret = setsockopt(handles[0], SOL_SOCKET, SO_RCVTIMEO, &tv,
				sizeof(tv));
		if (ret < 0) {
			_E("Cannot Set SO_RCVTIMEO for socket %d", handles[0]);
			_request_send_result(req, -1);
			close(handles[0]);
			close(handles[1]);
			free(handles);
			goto err_out;
		}

		ret = setsockopt(handles[1], SOL_SOCKET, SO_RCVTIMEO, &tv,
				sizeof(tv));
		if (ret < 0) {
			_E("Cannot Set SO_RCVTIMEO for socket %d", handles[1]);
			_request_send_result(req, -1);
			close(handles[0]);
			close(handles[1]);
			free(handles);
			goto err_out;
		}

		g_hash_table_insert(__dc_socket_pair_hash,
				strdup(socket_pair_key), handles);
		_D("New socket pair insert done.");
	}

	SECURE_LOGD("amd send fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	if (datacontrol_type != NULL) {
		_D("datacontrol_type : %s", datacontrol_type);
		if (strcmp(datacontrol_type, "consumer") == 0) {
			msglen = __send_message(req->clifd, vec, 1,
					&handles[0], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message", -msglen);
				_request_send_result(req, -1);
				goto err_out;
			}
			close(handles[0]);
			handles[0] = -1;
			if (handles[1] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash,
						socket_pair_key);
			}

		} else {
			msglen = __send_message(req->clifd, vec, 1,
					&handles[1], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message", -msglen);
				_request_send_result(req, -1);
				goto err_out;
			}
			close(handles[1]);
			handles[1] = -1;
			if (handles[0] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash,
						socket_pair_key);
			}
		}
	}
	SECURE_LOGD("send_message msglen : [%d]\n", msglen);
	if (socket_pair_key)
		free(socket_pair_key);

	return 0;

err_out:

	if (handles) {
		if (handles[0] > 0)
			close(handles[0]);
		if (handles[1] > 0)
			close(handles[1]);
	}
	if (socket_pair_key) {
		g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
		free(socket_pair_key);
	}

	return -1;
}

static int __dispatch_update_rua_stat(request_h req)
{
	int result;
	char *caller = NULL;
	char *tag = NULL;

	bundle_get_str(req->kb, AUL_SVC_K_RUA_STAT_CALLER, &caller);
	bundle_get_str(req->kb, AUL_SVC_K_RUA_STAT_TAG, &tag);
	result = rua_stat_db_update(caller, tag);

	_D("rua_stat_db_update result : %d", result);
	_request_send_result(req, result);

	return 0;
}

static int __dispatch_add_history(request_h req)
{
	int result;
	struct rua_rec rec;
	char *time_str;

	memset((void *)&rec, 0, sizeof(rec));

	bundle_get_str(req->kb, AUL_K_RUA_PKGNAME, &rec.pkg_name);
	bundle_get_str(req->kb, AUL_K_RUA_APPPATH, &rec.app_path);
	bundle_get_str(req->kb, AUL_K_RUA_ARG, &rec.arg);
	bundle_get_str(req->kb, AUL_K_RUA_TIME, &time_str);
	if (time_str != NULL)
		rec.launch_time = atoi(time_str);
	else
		rec.launch_time = (int)time(NULL);
	result = rua_db_add_history(&rec);

	_D("rua_db_add_history result : %d", result);
	_request_send_result(req, result);

	return 0;
}

static int __dispatch_remove_history(request_h req)
{
	int result;
	bundle *b;

	/* b can be NULL */
	b = bundle_decode(req->data, req->len);
	result = rua_db_delete_history(b);

	if (b)
		bundle_free(b);

	_D("rua_db_delete_history result : %d", result);
	_request_send_result(req, result);

	return 0;
}

static int __dispatch_app_group_get_window(request_h req)
{
	char *buf;
	int pid;
	int wid;

	bundle_get_str(req->kb, AUL_K_PID, &buf);
	pid = atoi(buf);
	wid = _app_group_get_window(pid);
	_request_send_result(req, wid);

	return 0;
}

static int __dispatch_app_group_set_window(request_h req)
{
	char *buf;
	int wid;
	int ret;

	bundle_get_str(req->kb, AUL_K_WID, &buf);
	wid = atoi(buf);
	ret = _app_group_set_window(req->pid, wid);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_app_group_get_fg_flag(request_h req)
{
	char *buf;
	int pid;
	int fg;

	bundle_get_str(req->kb, AUL_K_PID, &buf);
	pid = atoi(buf);
	fg = _app_group_get_fg_flag(pid);
	_request_send_result(req, fg);

	return 0;
}

static int __dispatch_app_group_clear_top(request_h req)
{
	_app_group_clear_top(req->pid);
	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_group_get_leader_pid(request_h req)
{
	char *buf;
	int pid;
	int lpid;

	bundle_get_str(req->kb, AUL_K_PID, &buf);
	pid = atoi(buf);
	lpid = _app_group_get_leader_pid(pid);
	_request_send_result(req, lpid);

	return 0;
}

static int __dispatch_app_group_get_leader_pids(request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = {0,};

	_app_group_get_leader_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0) {
		_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS, empty, 0);
	} else {
		_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	return 0;
}

static int __dispatch_app_group_get_idle_pids(request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = {0,};

	_app_group_get_idle_pids(&cnt, &pids);
	if (pids == NULL || cnt == 0) {
		_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS, empty, 0);
	} else {
		_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	return 0;
}

static int __dispatch_app_group_get_group_pids(request_h req)
{
	char *buf;
	int leader_pid;
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	bundle_get_str(req->kb, AUL_K_LEADER_PID, &buf);
	leader_pid = atoi(buf);

	_app_group_get_group_pids(leader_pid, &cnt, &pids);
	if (pids == NULL || cnt == 0) {
		_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, empty, 0);
	} else {
		_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));
	}

	if (pids != NULL)
		free(pids);

	return 0;
}

static int __dispatch_app_group_lower(request_h req)
{
	int ret = 0;

	_app_group_lower(req->pid, &ret);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_app_group_activate_below(request_h req)
{
	char *buf = NULL;
	int ret;

	if (req->pid != _get_focused_pid()) {
		_E("Caller pid was not focused");
		_request_send_result(req, -EREJECTED);
		return -EREJECTED;
	}

	bundle_get_str(req->kb, AUL_K_APPID, &buf);
	ret = _app_group_activate_below(req->pid, buf);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_start(request_h req)
{
	const char *appid;
	int ret;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	__set_effective_appid(_request_get_target_uid(req), kb);

	appid = bundle_get_val(kb, AUL_K_APPID);
	ret = _launch_start_app(appid, req);
	if (ret <= 0)
		_input_unlock();

	if (ret > 0 && __add_rua_info(req, kb, appid) < 0)
		return -1;

	return 0;
}

static int __dispatch_app_result(request_h req)
{
	bundle *kb;
	int pid;
	int pgid;
	char tmp_pid[MAX_PID_STR_BUFSZ];
	int res;
	shared_info_h si = NULL;
	const char *appid;
	int ret;
	uid_t target_uid = _request_get_target_uid(req);
	app_status_h app_status;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	pid = __get_caller_pid(kb);
	if (pid < 0)
		return AUL_R_ERROR;

	pgid = getpgid(_request_get_pid(req));
	if (pgid > 0) {
		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pgid);
		bundle_del(kb, AUL_K_CALLEE_PID);
		bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);
	}

	app_status = _app_status_find(getpgid(pid));
	appid = _app_status_get_appid(app_status);
	if (appid) {
		si = _temporary_permission_create(pgid, appid, kb, target_uid);
		if (si == NULL)
			_D("No sharable path : %d %s", pgid, appid);
	}

	res = aul_sock_send_bundle(pid, target_uid, req->cmd, kb,
			AUL_SOCK_NOREPLY);
	if (res < 0)
		res = AUL_R_ERROR;

	if (si) {
		if (res >= 0) {
			ret = _temporary_permission_apply(pid, target_uid, si);
			if (ret != 0) {
				_D("Couldn't apply temporary permission: %d",
						ret);
			}
		}
		_temporary_permission_destroy(si);
	}

	return 0;
}

static int __dispatch_app_pause(request_h req)
{
	const char *appid;
	bundle *kb;
	int ret;
	app_status_h app_status;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	app_status = _app_status_find_by_appid(appid,
			_request_get_target_uid(req));
	ret = _app_status_get_pid(app_status);
	if (ret > 0)
		ret = _pause_app(ret, req);
	else
		_E("%s is not running", appid);

	return 0;
}

static int __dispatch_app_process_by_pid(request_h req)
{
	const char *appid;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid, NULL);

	return 0;
}

static int __dispatch_app_term_async(request_h req)
{
	const char *appid;
	bundle *kb;
	const char *term_pid;
	struct appinfo *ai;
	app_status_h app_status;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	term_pid = bundle_get_val(kb, AUL_K_APPID);
	app_status = _app_status_find(atoi(term_pid));
	appid = _app_status_get_appid(app_status);
	ai = _appinfo_find(_request_get_target_uid(req), appid);
	if (ai) {
		_appinfo_set_value(ai, AIT_STATUS, "norestart");
		__app_process_by_pid(req, term_pid, NULL);
	}

	return 0;
}

static int __dispatch_app_term(request_h req)
{
	const char *appid;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid, NULL);

	return 0;
}

static int __dispatch_app_running_info(request_h req)
{
	int ret;

	ret = _app_status_send_running_appinfo(_request_remove_fd(req),
			req->cmd, _request_get_target_uid(req));
	return ret;
}

static int __dispatch_app_all_running_info(request_h req)
{
	int ret;

	ret = _app_status_send_running_appinfo(_request_remove_fd(req),
			req->cmd, _request_get_target_uid(req));
	return ret;
}

static int __dispatch_app_is_running(request_h req)
{
	char appid[MAX_PACKAGE_STR_SIZE];
	int ret;
	app_status_h app_status;

	snprintf(appid, sizeof(appid), "%s", (const char *)req->data);
	app_status = _app_status_find_by_appid(appid,
			_request_get_target_uid(req));
	ret = _app_status_is_running(app_status);
	SECURE_LOGD("APP_IS_RUNNING : %s : %d", appid, ret);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_get_appid_by_pid(request_h req)
{
	int pid;
	int ret;

	memcpy(&pid, req->data, req->len);
	ret = _app_status_get_appid_bypid(_request_remove_fd(req), pid);
	_D("app_status_get_appid_bypid : %d : %d", pid, ret);

	return 0;
}

static int __dispatch_app_get_pkgid_by_pid(request_h req)
{
	int pid;
	int ret;

	memcpy(&pid, req->data, sizeof(int));
	ret = _app_status_get_pkgid_bypid(_request_remove_fd(req), pid);
	_D("APP_GET_PKGID_BYPID : %d : %d", pid, ret);

	return 0;
}

static int __dispatch_legacy_command(request_h req)
{
	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_status_update(request_h req)
{
	int *status;
	const char *appid;
	struct appinfo *ai;
	app_status_h app_status;

	app_status = _app_status_find(req->pid);
	if (app_status == NULL)
		return -1;

	status = (int *)req->data;
	switch (*status) {
	case STATUS_NORESTART:
		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(_request_get_target_uid(req), appid);
		_appinfo_set_value((struct appinfo *)ai, AIT_STATUS,
				"norestart");
		break;
	case STATUS_VISIBLE:
	case STATUS_BG:
		break;
	default:
		_app_status_update_status(app_status, *status, false);
		break;
	}

	return 0;
}

static int __dispatch_app_get_status(request_h req)
{
	int pid;
	int status;
	app_status_h app_status;

	memcpy(&pid, req->data, sizeof(int));
	app_status = _app_status_find(pid);
	status = _app_status_get_status(app_status);
	_request_send_result(req, status);

	return 0;
}

static int __dispatch_app_add_loader(request_h req)
{
	bundle *kb;
	int ret;
	char tmpbuf[MAX_PID_STR_BUFSZ];
	int pgid;
	uid_t target_uid = _request_get_target_uid(req);

	kb = req->kb;
	if (kb == NULL)
		return -1;

	pgid = getpgid(_request_get_pid(req));
	snprintf(tmpbuf, sizeof(tmpbuf), "%d", pgid);
	bundle_add(kb, AUL_K_CALLER_PID, tmpbuf);
	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, target_uid,
			PAD_CMD_ADD_LOADER, kb);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_app_remove_loader(request_h req)
{
	bundle *kb;
	int ret;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			_request_get_target_uid(req), PAD_CMD_REMOVE_LOADER,
			kb);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_agent_dead_signal(request_h req)
{
	uid_t target_uid = _request_get_target_uid(req);

	_D("AMD_AGENT_DEAD_SIGNAL: %d", target_uid);
	_app_status_remove_all_app_info_with_uid(target_uid);

	return 0;
}

static int __dispatch_amd_reload_appinfo(request_h req)
{
	_D("AMD_RELOAD_APPINFO");
	_appinfo_reload();
	_request_send_result(req, 0);

	return 0;
}

static int __dispatch_app_com_create(request_h req)
{
	bundle *kb;
	int ret;
	size_t propagate_size;
	unsigned int propagate = 0;
	const char *privilege;
	const char *endpoint;
	unsigned int *prop;
	int pgid;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	privilege = bundle_get_val(kb, AUL_K_COM_PRIVILEGE);
	if (!privilege) {
		/* privilege is not mandatory so far */
		_D("non-privileged endpoint: %s", endpoint);
	}

	ret = bundle_get_byte(kb, AUL_K_COM_PROPAGATE, (void **)&prop,
			&propagate_size);
	if (ret == 0)
		propagate = *prop;

	_D("endpoint: %s propagate: %x privilege: %s",
			endpoint, propagate, privilege);

	ret = _app_com_add_endpoint(endpoint, propagate, privilege);
	if (ret == AUL_APP_COM_R_ERROR_OK ||
			ret == AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS) {
		pgid = getpgid(_request_get_pid(req));
		ret = _app_com_join(endpoint, pgid, NULL);
		if (ret == AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS) {
			_E("illegal access: remove endpoint");
			_app_com_remove_endpoint(endpoint);
		}
	}

	_request_send_result(req, ret);
	return 0;
}

static int __dispatch_app_com_join(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;
	const char *filter;
	int pgid;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		bundle_free(kb);
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	filter = bundle_get_val(kb, AUL_K_COM_FILTER);

	pgid = getpgid(_request_get_pid(req));
	ret = _app_com_join(endpoint, pgid, filter);

	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_send(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;
	int pgid;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	pgid = getpgid(_request_get_pid(req));
	ret = _app_com_send(endpoint, pgid, kb);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_leave(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;
	int pgid;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	pgid = getpgid(_request_get_pid(req));
	ret = _app_com_leave(endpoint, pgid);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_register_pid(request_h req)
{
	bundle *kb;
	const struct appinfo *ai;
	const char *appid;
	const char *component_type;
	const char *pid_str;
	int pid;
	int ret;
	uid_t target_uid = _request_get_target_uid(req);
	int caller_pid = _request_get_pid(req);
	app_status_h app_status;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL)
		return -1;

	pid_str = bundle_get_val(kb, AUL_K_PID);
	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	app_status = _app_status_find_by_appid(appid, target_uid);
	ret = _app_status_is_running(app_status);
	if (ret > 0) {
		if (ret != pid)
			kill(pid, SIGKILL);
		_D("status info is already exist: %s", appid);
		return 0;
	}
	_D("appid: %s, pid: %d", appid, pid);

	ai = _appinfo_find(target_uid, appid);
	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strcmp(component_type, APP_TYPE_UI) == 0) {
		_app_group_start_app(pid, kb, pid, FALSE,
				APP_GROUP_LAUNCH_MODE_SINGLE);
	}

	_app_status_add_app_info(ai, pid, false, target_uid, caller_pid);

	return 0;
}

static int __dispatch_app_set_app_control_default_app(request_h req)
{
	bundle *kb = NULL;
	const char *op;
	const char *mime_type;
	const char *uri;
	const char *appid;
	int ret;

	kb = req->kb;
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	op = aul_svc_get_operation(kb);
	appid = aul_svc_get_appid(kb);
	if (op == NULL || appid == NULL) {
		_E("Invalid operation, appid");
		_request_send_result(req, -1);
		return -1;
	}

	mime_type = aul_svc_get_mime(kb);
	uri = aul_svc_get_uri(kb);

	ret = aul_svc_set_defapp_for_uid(op, mime_type, uri,
			appid, _request_get_target_uid(req));
	if (ret < 0) {
		_E("Error[%d], aul_svc_set_defapp", ret);
		_request_send_result(req, -1);
		return -1;
	}

	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_unset_app_control_default_app(request_h req)
{
	char appid[MAX_PACKAGE_STR_SIZE];
	int ret;

	snprintf(appid, MAX_PACKAGE_STR_SIZE - 1, "%s",
			(const char *)req->data);

	ret = aul_svc_unset_defapp_for_uid(appid, _request_get_target_uid(req));
	if (ret < 0) {
		_E("Error[%d], aul_svc_unset_defapp", ret);
		_request_send_result(req, -1);
		return -1;
	}

	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_set_process_group(request_h req)
{
	int owner_pid;
	int child_pid;
	bundle *kb = NULL;
	const char *child_appid;
	const char *child_pkgid;
	const struct appinfo *ai;
	const char *str_pid;
	app_status_h app_status;
	int ret;

	kb = req->kb;
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	str_pid = bundle_get_val(kb, AUL_K_OWNER_PID);
	if (str_pid == NULL) {
		_E("No owner pid");
		_request_send_result(req, -1);
		return -1;
	}

	owner_pid = atoi(str_pid);
	str_pid = bundle_get_val(kb, AUL_K_CHILD_PID);
	if (str_pid == NULL) {
		_E("No child pid");
		_request_send_result(req, -1);
		return -1;
	}

	child_pid = atoi(str_pid);
	app_status = _app_status_find(child_pid);
	child_appid = _app_status_get_appid(app_status);
	if (child_appid == NULL) {
		_E("No child appid");
		_request_send_result(req, -1);
		return -1;
	}

	ai = _appinfo_find(_request_get_target_uid(req), child_appid);
	child_pkgid = _appinfo_get_value(ai, AIT_PKGID);
	ret = aul_send_app_group_signal(owner_pid, child_pid, child_pkgid);

	_request_send_result(req, ret);
	return 0;
}

static int __dispatch_app_prepare_candidate_process(request_h req)
{
	bundle *b = NULL;
	int ret;

	b = bundle_create();
	if (b == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			_request_get_target_uid(req), PAD_CMD_DEMAND, b);
	bundle_free(b);

	_request_send_result(req, ret);
	return 0;
}

static int __dispatch_app_term_sync(request_h req)
{
	int ret;
	int pid;
	const char *appid;
	bundle *kb;
	struct pending_item *pending_item;
	bool pending = false;

	kb = req->kb;
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	appid = bundle_get_val(kb, AUL_K_APPID);
	ret = __app_process_by_pid(req, appid, &pending);
	if (ret < 0)
		return -1;

	/* add pending list to wait app terminated successfully */
	if (pending) {
		pid = atoi(appid);
		pending_item = calloc(1, sizeof(struct pending_item));
		if (pending_item == NULL) {
			_E("Out of memory");
			_request_send_result(req, ret);
			return -1;
		}
		pending_item->clifd = _request_remove_fd(req);
		pending_item->pid = pid;
		pending_item->cmd = _request_get_cmd(req);
		pending_item->timer = g_timeout_add(PENDING_REQUEST_TIMEOUT,
				__timeout_pending_item, (gpointer)pending_item);
		g_hash_table_insert(pending_table, GINT_TO_POINTER(pid),
				pending_item);
	}

	return 0;
}

static int __dispatch_app_get_status_by_appid(request_h req)
{
	int status;
	int pid;
	uid_t uid;
	const char *appid;
	bundle *kb;
	app_status_h app_status;

	kb = _request_get_bundle(req);
	if (kb == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	uid = _request_get_target_uid(req);
	appid = bundle_get_val(kb, AUL_K_APPID);
	if (appid == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	app_status = _app_status_find_by_appid(appid, uid);
	pid = _app_status_is_running(app_status);
	if (pid <= 0) {
		_request_send_result(req, -1);
		return -1;
	}

	status = _app_status_get_status(app_status);
	if (status == STATUS_VISIBLE) {
		if (_get_focused_pid() == pid)
			status = STATUS_FOCUS;
	}

	_request_send_result(req, status);
	_D("appid: %s, pid: %d, status: %d", appid, pid, status);

	return 0;
}

static app_cmd_dispatch_func dispatch_table[APP_CMD_MAX] = {
	[APP_GET_DC_SOCKET_PAIR] = __dispatch_get_dc_socket_pair,
	[APP_GET_MP_SOCKET_PAIR] = __dispatch_get_mp_socket_pair,
	[APP_START] =  __dispatch_app_start,
	[APP_OPEN] = __dispatch_app_start,
	[APP_RESUME] = __dispatch_app_start,
	[APP_RESUME_BY_PID] = __dispatch_app_process_by_pid,
	[APP_TERM_BY_PID] = __dispatch_app_term,
	[APP_TERM_BY_PID_WITHOUT_RESTART] = __dispatch_app_term_async,
	[APP_RESULT] = __dispatch_app_result,
	[APP_START_RES] = __dispatch_app_start,
	[APP_CANCEL] = __dispatch_app_result,
	[APP_KILL_BY_PID] = __dispatch_app_term,
	[APP_UPDATE_RUA_STAT] = __dispatch_update_rua_stat,
	[APP_ADD_HISTORY] = __dispatch_add_history,
	[APP_REMOVE_HISTORY] = __dispatch_remove_history,
	[APP_RUNNING_INFO] = __dispatch_app_running_info,
	[APP_RUNNING_INFO_RESULT] = NULL,
	[APP_IS_RUNNING] = __dispatch_app_is_running,
	[APP_GET_APPID_BYPID] = __dispatch_app_get_appid_by_pid,
	[APP_GET_PKGID_BYPID] = __dispatch_app_get_pkgid_by_pid,
	[APP_GET_INFO_OK] = NULL,
	[APP_GET_INFO_ERROR] = NULL,
	[APP_KEY_EVENT] = NULL,
	[APP_KEY_RESERVE] = __dispatch_legacy_command,
	[APP_KEY_RELEASE] = __dispatch_legacy_command,
	[APP_STATUS_UPDATE] = __dispatch_app_status_update,
	[APP_RUNNING_LIST_UPDATE] = __dispatch_legacy_command,
	[APP_TERM_REQ_BY_PID] = __dispatch_app_process_by_pid,
	[APP_TERM_BY_PID_ASYNC] = __dispatch_app_term_async,
	[APP_TERM_BGAPP_BY_PID] = __dispatch_app_term,
	[APP_PAUSE] = __dispatch_app_pause,
	[APP_PAUSE_BY_PID] = __dispatch_app_process_by_pid,
	[APP_GROUP_GET_WINDOW] = __dispatch_app_group_get_window,
	[APP_GROUP_SET_WINDOW] = __dispatch_app_group_set_window,
	[APP_GROUP_GET_FG] = __dispatch_app_group_get_fg_flag,
	[APP_GROUP_GET_LEADER_PID] = __dispatch_app_group_get_leader_pid,
	[APP_GROUP_GET_LEADER_PIDS] = __dispatch_app_group_get_leader_pids,
	[APP_GROUP_GET_GROUP_PIDS] = __dispatch_app_group_get_group_pids,
	[APP_GROUP_GET_IDLE_PIDS] = __dispatch_app_group_get_idle_pids,
	[APP_GROUP_LOWER] = __dispatch_app_group_lower,
	[APP_GROUP_CLEAR_TOP] = __dispatch_app_group_clear_top,
	[APP_GROUP_ACTIVATE_BELOW] = __dispatch_app_group_activate_below,
	[APP_GET_STATUS] = __dispatch_app_get_status,
	[APP_ADD_LOADER] = __dispatch_app_add_loader,
	[APP_REMOVE_LOADER] = __dispatch_app_remove_loader,
	[APP_GET_PID] = __dispatch_app_is_running,
	[AMD_RELOAD_APPINFO] = __dispatch_amd_reload_appinfo,
	[AGENT_DEAD_SIGNAL] = __dispatch_agent_dead_signal,
	[APP_COM_CREATE] = __dispatch_app_com_create,
	[APP_COM_JOIN] = __dispatch_app_com_join,
	[APP_COM_SEND] = __dispatch_app_com_send,
	[APP_COM_LEAVE] = __dispatch_app_com_leave,
	[APP_REGISTER_PID] = __dispatch_app_register_pid,
	[APP_ALL_RUNNING_INFO] = __dispatch_app_all_running_info,
	[APP_SET_APP_CONTROL_DEFAULT_APP] =
		__dispatch_app_set_app_control_default_app,
	[APP_UNSET_APP_CONTROL_DEFAULT_APP] =
		__dispatch_app_unset_app_control_default_app,
	[APP_START_ASYNC] = __dispatch_app_start,
	[APP_SET_PROCESS_GROUP] = __dispatch_app_set_process_group,
	[APP_PREPARE_CANDIDATE_PROCESS] =
		__dispatch_app_prepare_candidate_process,
	[APP_TERM_BY_PID_SYNC] = __dispatch_app_term_sync,
	[APP_GET_STATUS_BY_APPID] = __dispatch_app_get_status_by_appid,
};

static void __free_request(gpointer data)
{
	request_h req = (request_h)data;

	if (req->kb)
		bundle_free(req->kb);

	free(req);
}

static void __free_pending_item(struct pending_item *item)
{
	g_list_free_full(item->pending_list, __free_request);
	if (g_main_context_find_source_by_user_data(NULL, item))
		g_source_remove(item->timer);
	free(item);
}

static void __process_pending_request(gpointer data, gpointer user_data)
{
	request_h req = (request_h)data;

	dispatch_table[req->cmd](req);

	if (req->clifd)
		close(_request_remove_fd(req));
}

static void __timeout_pending_request(gpointer data, gpointer user_data)
{
	request_h req = (request_h)data;

	_request_send_result(req, -1);
}

static gboolean __timeout_pending_item(gpointer user_data)
{
	struct pending_item *item = (struct pending_item *)user_data;

	if (item->clifd) {
		if (item->cmd == APP_TERM_BY_PID_SYNC)
			_send_result_to_client(item->clifd, -1);
		else
			_send_result_to_client(item->clifd, item->pid);
	}

	g_list_foreach(item->pending_list, __timeout_pending_request, NULL);

	g_hash_table_remove(pending_table, GINT_TO_POINTER(item->pid));
	__free_pending_item(item);

	return FALSE;
}

int _request_flush_pending_request(int pid)
{
	struct pending_item *item;

	item = (struct pending_item *)g_hash_table_lookup(
			pending_table, GINT_TO_POINTER(pid));
	if (item == NULL)
		return -1;

	if (item->cmd == APP_TERM_BY_PID_SYNC) {
		_send_result_to_client(item->clifd, 0);
		item->clifd = 0;
	}

	__timeout_pending_item((gpointer)item);

	return 0;
}

int _request_reply_for_pending_request(int pid)
{
	struct pending_item *item;

	item = (struct pending_item *)g_hash_table_lookup(
			pending_table, GINT_TO_POINTER(pid));
	if (item == NULL)
		return -1;

	if (item->clifd)
		_send_result_to_client(item->clifd, pid);

	g_hash_table_remove(pending_table, GINT_TO_POINTER(pid));
	g_list_foreach(item->pending_list, __process_pending_request, NULL);

	__free_pending_item(item);

	return 0;
}

static request_h __get_request(int clifd, app_pkt_t *pkt,
		struct ucred cr)
{
	request_h req;

	req = (request_h)malloc(sizeof(struct request_s) + pkt->len);
	if (req == NULL)
		return NULL;

	req->clifd = clifd;
	req->pid = cr.pid;
	req->uid = cr.uid;
	req->gid = cr.gid;
	req->t_uid = getuid();
	req->cmd = pkt->cmd;
	req->len = pkt->len;
	req->opt = pkt->opt;
	memcpy(req->data, pkt->data, pkt->len + 1);

	if (pkt->opt & AUL_SOCK_BUNDLE) {
		req->kb = bundle_decode(pkt->data, pkt->len);
		if (req->kb == NULL) {
			free(req);
			return NULL;
		}
	} else {
		req->kb = NULL;
	}

	return req;
}

static gboolean __request_handler(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	int fd = g_io_channel_unix_get_fd(io);
	app_pkt_t *pkt;
	int ret;
	int clifd;
	struct ucred cr;
	request_h req;

	pkt = aul_sock_recv_pkt(fd, &clifd, &cr);
	if (pkt == NULL) {
		_E("recv error");
		return TRUE;
	}

	req = __get_request(clifd, pkt, cr);
	if (req == NULL) {
		close(clifd);
		free(pkt);
		return TRUE;
	}

	if (cr.uid >= REGULAR_UID_MIN) {
		ret = _cynara_check_privilege(req);
		if (ret < 0) {
			_E("request has been denied by cynara");
			ret = -EILLEGALACCESS;
			_request_send_result(req, ret);
			__free_request(req);
			free(pkt);
			return TRUE;
		}
	}

	if (req->opt & AUL_SOCK_NOREPLY) {
		close(req->clifd);
		req->clifd = 0;
	}

	if (pkt->cmd >= 0 && pkt->cmd < APP_CMD_MAX &&
			dispatch_table[pkt->cmd]) {
		if (dispatch_table[pkt->cmd](req) != 0)
			_E("callback returns FALSE : %d", pkt->cmd);
	} else {
		_E("Invalid packet or not supported command");
	}

	if (req->clifd)
		close(_request_remove_fd(req));

	__free_request(req);
	free(pkt);

	return TRUE;
}

int _request_get_fd(request_h req)
{
	return req->clifd;
}

int _request_get_pid(request_h req)
{
	return req->pid;
}

bundle *_request_get_bundle(request_h req)
{
	return req->kb;
}

request_h _request_create_local(int cmd, uid_t uid, int pid, bundle *kb)
{
	request_h req;

	req = (request_h)malloc(sizeof(struct request_s));
	if (req == NULL) {
		_E("out of memory");
		return NULL;
	}

	req->clifd = -1;
	req->pid = pid;
	req->uid = uid;
	req->gid = getgid();
	req->t_uid = getuid();
	req->cmd = cmd;
	req->len = 0;
	req->opt = AUL_SOCK_NONE;
	req->kb = bundle_dup(kb);

	return req;
}

void _request_free_local(request_h req)
{
	if (req == NULL)
		return;

	if (req->kb)
		bundle_free(req->kb);

	free(req);
}

int _request_get_cmd(request_h req)
{
	return req->cmd;
}

int _request_remove_fd(request_h req)
{
	int r = req->clifd;

	req->clifd = 0;

	return r;
}

uid_t _request_get_target_uid(request_h req)
{
	return req->t_uid;
}

uid_t _request_get_uid(request_h req)
{
	return req->uid;
}

int _request_send_raw(request_h req, int cmd, unsigned char *data, int len)
{
	return aul_sock_send_raw_with_fd(_request_remove_fd(req), cmd, data,
			len, AUL_SOCK_NOREPLY);
}

int _request_send_result(request_h req, int res)
{
	if (req->clifd && (req->opt & AUL_SOCK_NOREPLY))
		close(_request_remove_fd(req));
	else if (req->clifd)
		_send_result_to_client(_request_remove_fd(req), res);

	return 0;
}

int _request_init(void)
{
	__dc_socket_pair_hash = g_hash_table_new_full(g_str_hash,  g_str_equal,
			free, free);
	pending_table = g_hash_table_new(g_direct_hash, g_direct_equal);

	amd_fd = _create_sock_activation();
	if (amd_fd == -1) {
		_D("Create server socket without socket activation");
		amd_fd = _create_server_sock();
		if (amd_fd == -1) {
			g_hash_table_destroy(pending_table);
			g_hash_table_destroy(__dc_socket_pair_hash);
			_E("Create server socket failed.");
			return -1;
		}
	}

	amd_io = g_io_channel_unix_new(amd_fd);
	if (amd_io == NULL) {
		close(amd_fd);
		g_hash_table_destroy(pending_table);
		g_hash_table_destroy(__dc_socket_pair_hash);
		return -1;
	}

	amd_wid = g_io_add_watch(amd_io, G_IO_IN, __request_handler, NULL);

	return 0;
}

