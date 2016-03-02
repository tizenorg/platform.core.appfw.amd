/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <rua.h>
#include <rua_stat.h>
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
#include "amd_status.h"
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
static GHashTable *__dc_socket_pair_hash = NULL;
static GHashTable *pending_table;

struct pending_item {
	int clifd;
	int pid;
	guint timer;
	GList *pending_list;
};

struct request_s {
	int cmd;
	int clifd;
	pid_t pid;
	uid_t uid;
	gid_t gid;
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

static int __send_message(int sock, const struct iovec *vec, int vec_size, const int *desc, int nr_desc)
{
	struct msghdr msg = {0};
	int sndret;

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
		int desclen = 0;
		struct cmsghdr *cmsg = NULL;
		char buff[CMSG_SPACE(sizeof(int) * MAX_NR_OF_DESCRIPTORS)] = {0};

		msg.msg_control = buff;
		msg.msg_controllen = sizeof(buff);
		cmsg = CMSG_FIRSTHDR(&msg);
		if (cmsg == NULL)
			return -EINVAL;

		/* packing files descriptors */
		if (nr_desc > 0) {
			cmsg->cmsg_level = SOL_SOCKET;
			cmsg->cmsg_type = SCM_RIGHTS;
			desclen = cmsg->cmsg_len = CMSG_LEN(sizeof(int) * nr_desc);
			memcpy((int *)CMSG_DATA(cmsg), desc, sizeof(int) * nr_desc);
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
	else
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

static int __app_process_by_pid(request_h req, const char *pid_str)
{
	int pid;
	int ret;
	int dummy;
	char *appid;
	const char *pkgid = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;

	if (pid_str == NULL)
		return -1;

	pid = atoi(pid_str);
	if (pid <= 1) {
		_E("invalid pid");
		return -1;
	}

	appid = _status_app_get_appid_bypid(pid);
	if (appid == NULL) {
		_E("pid %d is not an app", pid);
		_request_send_result(req, -1);
		return -1;
	}

	ai = appinfo_find(req->uid, appid);
	if (ai) {
		pkgid = appinfo_get_value(ai, AIT_PKGID);
		type = appinfo_get_value(ai, AIT_COMPTYPE);
	}

	if (ai && (req->cmd == APP_RESUME_BY_PID || req->cmd == APP_PAUSE_BY_PID))
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
		if ((ret = _send_to_sigkill(pid)) < 0)
			_E("fail to killing - %d\n", pid);
		_status_update_app_info_list(pid, STATUS_DYING, FALSE, req->uid);
		_request_send_result(req, ret);
		break;
	case APP_TERM_REQ_BY_PID:
		ret = _term_req_app(pid, req);
		break;
	case APP_TERM_BY_PID_ASYNC:
		ret = aul_sock_send_raw_async(pid, getuid(), req->cmd,
				(unsigned char *)&dummy, sizeof(int), AUL_SOCK_CLOSE | AUL_SOCK_NOREPLY);
		if (ret < 0)
			_D("terminate req packet send error");

		_request_send_result(req, ret);
		break;
	case APP_PAUSE_BY_PID:
		ret = _pause_app(pid, req);
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

	ai = appinfo_find(uid, appid);
	if (ai == NULL)
		return;

	effective_appid = appinfo_get_value(ai, AIT_EFFECTIVE_APPID);
	if (effective_appid == NULL)
		return;

	effective_ai = appinfo_find(uid, effective_appid);
	if (effective_ai == NULL)
		return;

	pkgid = appinfo_get_value(ai, AIT_PKGID);
	effective_pkgid = appinfo_get_value(effective_ai, AIT_PKGID);
	if (pkgid && effective_pkgid && strcmp(pkgid, effective_pkgid) == 0) {
		_D("use effective appid instead of the real appid");
		bundle_del(kb, AUL_K_APPID);
		bundle_add(kb, AUL_K_APPID, effective_appid);
	}
}

static gboolean __add_history_handler(gpointer user_data)
{
	struct rua_rec rec;
	int ret;
	char *app_path = NULL;
	struct appinfo *ai;

	rua_stat_pkt_t *pkt = (rua_stat_pkt_t *)user_data;

	if (!pkt)
		return FALSE;

	if (!pkt->is_group_app) {
		ai = (struct appinfo *)appinfo_find(pkt->uid, pkt->appid);;
		app_path = (char *)appinfo_get_value(ai, AIT_EXEC);

		memset((void *)&rec, 0, sizeof(rec));

		rec.pkg_name = pkt->appid;
		rec.app_path = app_path;

		if (pkt->len > 0)
			rec.arg = pkt->data;

		SECURE_LOGD("add rua history %s %s", rec.pkg_name, rec.app_path);

		ret = rua_add_history(&rec);
		if (ret == -1)
			_D("rua add history error");
	}

	if (pkt->stat_caller != NULL && pkt->stat_tag != NULL) {
		SECURE_LOGD("rua_stat_caller: %s, rua_stat_tag: %s", pkt->stat_caller, pkt->stat_tag);
		rua_stat_update(pkt->stat_caller, pkt->stat_tag);
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
	rua_stat_item->uid = req->uid;
	rua_stat_item->is_group_app = app_group_is_group_app(kb);
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
	struct sockaddr_un saddr;
	int ret = 0;


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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;

	_D("amd send mp fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	msglen = __send_message(req->clifd, vec, 1, handles, 2);
	if (msglen < 0) {
		_E("Error[%d]: while sending message\n", -msglen);
		_request_send_result(req, -1);
		ret = -1;
	}

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
	struct sockaddr_un saddr;
	bundle *kb = req->kb;

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

			if (handles)
				free(handles);
			goto err_out;
		}

		if (handles[0] == -1) {
			_E("error socket open");
			_request_send_result(req, -1);

			if (handles)
				free(handles);
			goto err_out;
		}
		g_hash_table_insert(__dc_socket_pair_hash, strdup(socket_pair_key),
				handles);

		_D("New socket pair insert done.");
	}


	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;

	SECURE_LOGD("amd send fd : [%d, %d]", handles[0], handles[1]);
	vec[0].iov_base = buffer;
	vec[0].iov_len = strlen(buffer) + 1;

	if (datacontrol_type != NULL) {
		_D("datacontrol_type : %s", datacontrol_type);
		if (strcmp(datacontrol_type, "consumer") == 0) {
			msglen = __send_message(req->clifd, vec, 1, &handles[0], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message\n", -msglen);
				_request_send_result(req, -1);
				g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
				goto err_out;
			}
			close(handles[0]);
			handles[0] = -1;
			if (handles[1] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
			}

		} else {
			msglen = __send_message(req->clifd, vec, 1, &handles[1], 1);
			if (msglen < 0) {
				_E("Error[%d]: while sending message\n", -msglen);
				_request_send_result(req, -1);
				g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
				goto err_out;
			}
			close(handles[1]);
			handles[1] = -1;
			if (handles[0] == -1) {
				_E("remove from hash : %s", socket_pair_key);
				g_hash_table_remove(__dc_socket_pair_hash, socket_pair_key);
			}
		}
	}
	SECURE_LOGD("send_message msglen : [%d]\n", msglen);
	if (socket_pair_key)
		free(socket_pair_key);

	return 0;

err_out:
	if (socket_pair_key)
		free(socket_pair_key);

	return -1;
}

static int __dispatch_remove_history(request_h req)
{
	int result = 0;
	bundle *b = NULL;
	/* b can be NULL */
	b = bundle_decode(req->data, req->len);
	result = rua_delete_history_from_db(b);
	bundle_free(b);
	_D("rua_delete_history_from_db result : %d", result);

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
	wid = app_group_get_window(pid);
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
	ret = app_group_set_window(req->pid, wid);
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
	fg = app_group_get_fg_flag(pid);
	_request_send_result(req, fg);

	return 0;
}

static int __dispatch_app_group_clear_top(request_h req)
{
	app_group_clear_top(req->pid);
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
	lpid = app_group_get_leader_pid(pid);
	_request_send_result(req, lpid);

	return 0;
}

static int __dispatch_app_group_get_leader_pids(request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	app_group_get_leader_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0)
		_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS, empty, 0);
	else
		_request_send_raw(req, APP_GROUP_GET_LEADER_PIDS, (unsigned char *)pids,
				 cnt * sizeof(int));

	if (pids != NULL)
		free(pids);

	return 0;
}

static int __dispatch_app_group_get_idle_pids(request_h req)
{
	int cnt;
	int *pids;
	unsigned char empty[1] = { 0 };

	app_group_get_idle_pids(&cnt, &pids);

	if (pids == NULL || cnt == 0)
		_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS, empty, 0);
	else
		_request_send_raw(req, APP_GROUP_GET_IDLE_PIDS,
				(unsigned char *)pids, cnt * sizeof(int));

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

	app_group_get_group_pids(leader_pid, &cnt, &pids);
	if (pids == NULL || cnt == 0)
		_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, empty, 0);
	else
		_request_send_raw(req, APP_GROUP_GET_GROUP_PIDS, (unsigned char *)pids,
					cnt * sizeof(int));

	if (pids != NULL)
		free(pids);

	return 0;
}

static int __dispatch_app_group_lower(request_h req)
{
	int ret = 0;

	app_group_lower(req->pid, &ret);
	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_app_start(request_h req)
{
	const char *appid;
	const char *target_uid;
	int ret = -1;
	int t_uid;
	char *state;
	bool pending = false;
	struct pending_item *pending_item;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	__set_effective_appid(req->uid, kb);

	appid = bundle_get_val(kb, AUL_K_APPID);
	if (req->uid < REGULAR_UID_MIN) {
		target_uid = bundle_get_val(kb, AUL_K_TARGET_UID);
		if (target_uid != NULL) {
			t_uid = atoi(target_uid);
			sd_uid_get_state(t_uid, &state);
			if (strcmp(state, "offline") &&
			    strcmp(state, "closing")) {
				ret = _start_app(appid, kb, t_uid, req, &pending);
			} else {
				_E("uid:%d session is %s", t_uid, state);
				_request_send_result(req, AUL_R_ERROR);
				goto error;
			}
		} else {
			_E("request from root, treat as global user");
			ret = _start_app(appid, kb, GLOBAL_USER, req, &pending);
		}
	} else {
		ret = _start_app(appid, kb, req->uid, req, &pending);
	}

	if (ret <= 0)
		_input_unlock();

	/* add pending list to wait app launched successfully */
	if (pending) {
		pending_item = calloc(1, sizeof(struct pending_item));
		pending_item->clifd = _request_remove_fd(req);
		pending_item->pid = ret;
		pending_item->timer = g_timeout_add(PENDING_REQUEST_TIMEOUT,
				__timeout_pending_item, (gpointer)pending_item);
		g_hash_table_insert(pending_table, GINT_TO_POINTER(ret),
				pending_item);
	}

	if (ret > 0 && __add_rua_info(req, kb, appid) < 0)
		goto error;
	return 0;

error:
	return -1;
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

	kb = req->kb;
	if (kb == NULL)
		return -1;

	if ((pid = __get_caller_pid(kb)) < 0)
			return AUL_R_ERROR;

	pgid = getpgid(req->pid);
	if (pgid > 0) {
		snprintf(tmp_pid, MAX_PID_STR_BUFSZ, "%d", pgid);
		bundle_del(kb, AUL_K_CALLEE_PID);
		bundle_add(kb, AUL_K_CALLEE_PID, tmp_pid);
	}

	appid = _status_app_get_appid_bypid(getpgid(pid));

	if (appid != NULL) {
		si = _temporary_permission_create(pgid, appid, kb, req->uid);
		if (si == NULL)
			_D("No sharable path : %d %s", pgid, appid);
	}

	if ((res = aul_sock_send_bundle_async(pid, getuid(), req->cmd, kb, AUL_SOCK_CLOSE | AUL_SOCK_NOREPLY)) < 0)
		res = AUL_R_ERROR;

	if (si) {
		if (res >= 0 && (ret = _temporary_permission_apply(pid, req->uid, si)) != 0)
			_D("Couldn't apply temporary permission: %d", ret);
		_temporary_permission_destroy(si);
	}

	return 0;
}

static int __dispatch_app_pause(request_h req)
{
	char *appid;
	bundle *kb;
	int ret;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = (char *)bundle_get_val(kb, AUL_K_APPID);
	ret = _status_app_is_running_v2(appid, req->uid);
	if (ret > 0)
		ret = _pause_app(ret, req);
	else
		_E("%s is not running", appid);

	return 0;
}

static int __dispatch_app_process_by_pid(request_h req)
{
	char *appid;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = (char *)bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid);

	return 0;
}

static int __dispatch_app_term_async(request_h req)
{
	char *appid;
	bundle *kb;
	char *term_pid;
	struct appinfo *ai;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	term_pid = (char *)bundle_get_val(kb, AUL_K_APPID);
	appid = _status_app_get_appid_bypid(atoi(term_pid));
	ai = appinfo_find(req->uid, appid);
	if (ai) {
		appinfo_set_value(ai, AIT_STATUS, "norestart");
		__app_process_by_pid(req, term_pid);
	}

	return 0;
}

static int __dispatch_app_term(request_h req)
{
	char *appid;
	bundle *kb;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	appid = (char *)bundle_get_val(kb, AUL_K_APPID);
	__app_process_by_pid(req, appid);

	return 0;
}

static int __dispatch_app_running_info(request_h req)
{
	_status_send_running_appinfo(_request_remove_fd(req), req->cmd, req->uid);
	return 0;
}

static int __dispatch_app_all_running_info(request_h req)
{
	_status_send_running_appinfo(_request_remove_fd(req), req->cmd, req->uid);
	return 0;
}

static int __dispatch_app_is_running(request_h req)
{
	char *appid = NULL;
	int ret;

	appid = malloc(MAX_PACKAGE_STR_SIZE);
	if (appid == NULL) {
		_E("out of memory");
		_request_send_result(req, -1);
		return -1;
	}
	strncpy(appid, (const char*)req->data, MAX_PACKAGE_STR_SIZE-1);
	ret = _status_app_is_running(appid, req->uid);
	SECURE_LOGD("APP_IS_RUNNING : %s : %d", appid, ret);
	_request_send_result(req, ret);
	free(appid);

	return 0;
}

static int __dispatch_app_get_appid_by_pid(request_h req)
{
	int pid;
	int ret;

	memcpy(&pid, req->data, req->len);
	ret = _status_get_appid_bypid(_request_remove_fd(req), pid);
	_D("app_get_appid_bypid : %d : %d", pid, ret);

	return 0;
}

static int __dispatch_app_get_pkgid_by_pid(request_h req)
{
	int pid;
	int ret;

	memcpy(&pid, req->data, sizeof(int));
	ret = _status_get_pkgid_bypid(_request_remove_fd(req), pid);
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
	char *appid;
	struct appinfo *ai;

	status = (int *)req->data;
	if (*status == STATUS_NORESTART) {
		appid = _status_app_get_appid_bypid(req->pid);
		ai = appinfo_find(req->uid, appid);
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "norestart");
	} else if (*status != STATUS_VISIBLE && *status != STATUS_BG) {
		_status_update_app_info_list(req->pid, *status, FALSE, req->uid);
	}

	return 0;
}

static int __dispatch_app_get_status(request_h req)
{
	int pid;
	int ret;

	memcpy(&pid, req->data, sizeof(int));
	ret = _status_get_app_info_status(pid, 0);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_add_loader(request_h req)
{
	bundle *kb;
	int ret;
	char tmpbuf[MAX_PID_STR_BUFSZ];

	kb = req->kb;
	if (kb == NULL)
		return -1;

	snprintf(tmpbuf, sizeof(tmpbuf), "%d", getpgid(req->pid));
	bundle_add(kb, AUL_K_CALLER_PID, tmpbuf);
	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, req->uid,
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

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, req->uid,
			PAD_CMD_REMOVE_LOADER, kb);

	_request_send_result(req, ret);

	return ret;
}

static int __dispatch_agent_dead_signal(request_h req)
{
	_D("AMD_AGENT_DEAD_SIGNAL: %d", req->uid);
	_status_remove_app_info_list_with_uid(req->uid);

	return 0;
}

static int __dispatch_amd_reload_appinfo(request_h req)
{
	_D("AMD_RELOAD_APPINFO");
	appinfo_reload();
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

	ret = bundle_get_byte(kb, AUL_K_COM_PROPAGATE, (void **)&prop, &propagate_size);
	if (ret == 0)
		propagate = *prop;

	_D("endpoint: %s propagate: %x privilege: %s", endpoint, propagate, privilege);

	ret = app_com_add_endpoint(endpoint, propagate, privilege);
	if (ret == AUL_APP_COM_R_ERROR_OK || ret == AUL_APP_COM_R_ERROR_ENDPOINT_ALREADY_EXISTS) {
		ret = app_com_join(endpoint, getpgid(req->pid), NULL);
		if (ret == AUL_APP_COM_R_ERROR_ILLEGAL_ACCESS) {
			_E("illegal access: remove endpoint");
			app_com_remove_endpoint(endpoint);
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

	ret = app_com_join(endpoint, getpgid(req->pid), filter);

	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_send(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	ret = app_com_send(endpoint, getpgid(req->pid), kb);
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_com_leave(request_h req)
{
	bundle *kb;
	int ret;
	const char *endpoint;

	kb = req->kb;
	if (kb == NULL)
		return -1;

	endpoint = bundle_get_val(kb, AUL_K_COM_ENDPOINT);
	if (endpoint == NULL) {
		_request_send_result(req, AUL_APP_COM_R_ERROR_FATAL_ERROR);
		return 0;
	}

	ret = app_com_leave(endpoint, getpgid(req->pid));
	_request_send_result(req, ret);

	return 0;
}

static int __dispatch_app_register_pid(request_h req)
{
	bundle *kb;
	const struct appinfo *ai;
	const char *appid;
	const char *app_path;
	const char *component_type;
	const char *pid_str;
	int pid;
	int ret;

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
	ret = _status_app_is_running(appid, req->uid);
	if (ret > 0) {
		if (ret != pid)
			kill(pid, SIGKILL);
		_D("status info is already exist: %s", appid);
		return 0;
	}

	_D("appid: %s, pid: %d", appid, pid);

	ai = appinfo_find(req->uid, appid);
	app_path = appinfo_get_value(ai, AIT_EXEC);
	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strcmp(component_type, APP_TYPE_UI) == 0)
		app_group_start_app(pid, kb, pid,
				FALSE, APP_GROUP_LAUNCH_MODE_SINGLE);

	_status_add_app_info_list(appid, app_path, pid, false, req->uid);

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

	kb= req->kb;
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

	ret = aul_svc_set_defapp_for_uid(op, mime_type, uri, appid, req->uid);
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

	snprintf(appid, MAX_PACKAGE_STR_SIZE - 1, "%s", (const char*)req->data);

	ret = aul_svc_unset_defapp_for_uid(appid, req->uid);
	if (ret < 0) {
		_E("Error[%d], aul_svc_unset_defapp", ret);
		_request_send_result(req, -1);
		return -1;
	}

	_request_send_result(req, 0);
	return 0;
}

static int __dispatch_app_input_lock(request_h req)
{
	_input_lock();
	_request_send_result(req, 0);
	return 0;
}

static app_cmd_dispatch_func dispatch_table[APP_CMD_MAX] = {
	[APP_GET_DC_SOCKET_PAIR] =  __dispatch_get_dc_socket_pair,
	[APP_GET_MP_SOCKET_PAIR] =  __dispatch_get_mp_socket_pair,
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
	[APP_ADD_HISTORY] = NULL,
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
	[APP_SET_APP_CONTROL_DEFAULT_APP] = __dispatch_app_set_app_control_default_app,
	[APP_UNSET_APP_CONTROL_DEFAULT_APP] = __dispatch_app_unset_app_control_default_app,
	[APP_START_ASYNC] = __dispatch_app_start,
	[APP_INPUT_LOCK] = __dispatch_app_input_lock,
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

	if (item->clifd)
		_send_result_to_client(item->clifd, item->pid);
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
	req->cmd = pkt->cmd;
	req->len = pkt->len;
	req->opt = pkt->opt;
	memcpy(req->data, pkt->data, pkt->len + 1);

	if (pkt->opt & AUL_SOCK_BUNDLE)
		req->kb = bundle_decode(pkt->data, pkt->len);
	else
		req->kb = NULL;

	return req;
}

static int __check_app_is_running(request_h req)
{
	bundle *b = req->kb;
	char *str;
	int pid;
	int ret = 0;

	if (b == NULL)
		return -1;

	if (bundle_get_str(b, AUL_K_APPID, &str)) {
		_E("cannot get target pid");
		return -1;
	}

	switch (req->cmd) {
	case APP_RESUME_BY_PID:
	case APP_TERM_BY_PID:
	case APP_TERM_BY_PID_WITHOUT_RESTART:
	case APP_KILL_BY_PID:
	case APP_TERM_REQ_BY_PID:
	case APP_TERM_BY_PID_ASYNC:
	case APP_TERM_BGAPP_BY_PID:
	case APP_PAUSE_BY_PID:
		/* get pid */
		pid = atoi(str);
		if (_status_app_get_appid_bypid(pid))
			ret = pid;
		break;
	default:
		pid = _status_app_is_running(str, req->uid);
		if (pid > 0)
			ret = pid;
	}

	return ret;
}

static int __check_request(request_h req)
{
	int pid;
	struct pending_item *item;

	if (req->opt & AUL_SOCK_NOREPLY)
		close(_request_remove_fd(req));

	if ((req->opt & AUL_SOCK_QUEUE) == 0)
		return 0;

	pid = __check_app_is_running(req);
	if (pid < 0)
		return -1;
	else if (pid == 0)
		return 0;

	if (_status_get_app_info_status(pid, req->uid) == STATUS_DYING)
		return 0;

	item = g_hash_table_lookup(pending_table, GINT_TO_POINTER(pid));
	if (item == NULL)
		return 0;

	item->pending_list = g_list_append(item->pending_list, req);

	return 1;
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

	if ((pkt = aul_sock_recv_pkt(fd, &clifd, &cr)) == NULL) {
		_E("recv error");
		return FALSE;
	}

	req = __get_request(clifd, pkt, cr);
	if (req == NULL) {
		close(clifd);
		free(pkt);
		return TRUE;
	}

	if (cr.uid >= REGULAR_UID_MIN) {
		ret = check_privilege_by_cynara(req);
		if (ret < 0) {
			_E("request has been denied by smack");
			ret = -EILLEGALACCESS;
			_request_send_result(req, ret);
			__free_request(req);
			free(pkt);
			return TRUE;
		}
	}

	ret = __check_request(req);
	if (ret < 0) {
		_request_send_result(req, ret);
		__free_request(req);
		free(pkt);
		return TRUE;
	} else if (ret > 0) {
		free(pkt);
		return TRUE;
	}

	if (pkt->cmd >= 0 && pkt->cmd < APP_CMD_MAX && dispatch_table[pkt->cmd]) {
		if (dispatch_table[pkt->cmd](req) != 0)
			_E("callback returns FALSE : %d", pkt->cmd);
	} else {
		_E("Invalid packet or not supported command");
		if (req->clifd)
			close(req->clifd);
		req->clifd = 0;
	}

	if (req->clifd)
		close(req->clifd);

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

request_h _request_create_local(int cmd, int uid, int pid)
{
	request_h req;

	req = (request_h)malloc(sizeof(struct request_s));
	if (req == NULL)
		return NULL;

	req->clifd = -1;
	req->pid = pid;
	req->uid = uid;
	req->gid = getpgid(uid);
	req->cmd = cmd;
	req->len = 0;
	req->opt = AUL_SOCK_NONE;
	req->kb = NULL;

	return req;
}

void _request_free_local(request_h req)
{
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

int _request_send_raw(request_h req, int cmd, unsigned char *data, int len)
{
	return aul_sock_send_raw_async_with_fd(_request_remove_fd(req), cmd, data, len, AUL_SOCK_CLOSE);
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
	__dc_socket_pair_hash = g_hash_table_new_full(g_str_hash,  g_str_equal, free, free);
	pending_table = g_hash_table_new(g_direct_hash, g_direct_equal);

	amd_fd = _create_sock_activation();
	if (amd_fd == -1) {
		_D("Create server socket without socket activation");
		amd_fd = aul_sock_create_server(AUL_UTIL_PID, getuid());
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
