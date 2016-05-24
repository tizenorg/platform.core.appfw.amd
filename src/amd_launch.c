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
#include <stdbool.h>
#include <signal.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <aul.h>
#include <glib.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <pkgmgr-info.h>
#include <poll.h>
#include <tzplatform_config.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <ttrace.h>

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_app_group.h"
#include "amd_util.h"
#include "app_signal.h"
#include "amd_socket.h"
#include "amd_share.h"
#include "amd_app_com.h"
#include "amd_splash_screen.h"
#include "amd_input.h"
#include "amd_suspend.h"
#include "amd_signal.h"
#include "amd_extractor.h"

#define DAC_ACTIVATE

#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME 16
#define OSP_K_LAUNCH_TYPE "__OSP_LAUNCH_TYPE__"
#define OSP_V_LAUNCH_TYPE_DATACONTROL "datacontrol"

#define PROC_STATUS_LAUNCH 0
#define PROC_STATUS_FG 3
#define PROC_STATUS_BG 4
#define PROC_STATUS_FOCUS 5

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

struct launch_s {
	const char *appid;
	const struct appinfo *ai;
	int pid;
	int leader_pid;
	bool can_attach;
	bool new_process;
	bool is_subapp;
	app_group_launch_mode launch_mode;
	int prelaunch_attr;
	int bg_category;
	int bg_allowed;
	shared_info_h share_info;
};

struct fgmgr {
	guint tid;
	int pid;
};

static GList *_fgmgr_list;
static int __pid_of_last_launched_ui_app;
static int __focused_pid;

static void __set_reply_handler(int fd, int pid, request_h req, int cmd);
static int __nofork_processing(int cmd, int pid, bundle *kb, request_h req);
extern void _cleanup_dead_info(int pid);

static void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

int _launch_start_app_local_with_bundle(uid_t uid, const char *appid,
		bundle *kb)
{
	bool dummy;
	request_h req;
	int r = 0;

	__set_stime(kb);
	bundle_add(kb, AUL_K_APPID, appid);
	req = _request_create_local(APP_START, uid, getpid(), kb);
	if (req == NULL) {
		_E("out of memory");
		return -1;
	}

	r = _launch_start_app(appid, req, &dummy);
	_request_free_local(req);

	return r;
}

int _launch_start_app_local(uid_t uid, const char *appid)
{
	int pid;
	bundle *kb;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return -1;
	}

	pid = _launch_start_app_local_with_bundle(uid, appid, kb);
	bundle_free(kb);

	return pid;
}

int _send_to_sigkill(int pid)
{
	int pgid;

	pgid = getpgid(pid);
	if (pgid <= 1)
		return -1;

	if (killpg(pgid, SIGKILL) < 0)
		return -1;

	return 0;
}

int _resume_app(int pid, request_h req)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, getuid(), APP_RESUME_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_ASYNC);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			_E("resume packet timeout error");
		} else {
			_E("raise failed - %d resume fail\n", pid);
			_E("we will term the app - %d\n", pid);
			_send_to_sigkill(pid);
			ret = -1;
		}
		_request_send_result(req, ret);
	}
	_D("resume done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_RESUME_BY_PID);

	return ret;
}

int _pause_app(int pid, request_h req)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, getuid(), APP_PAUSE_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_ASYNC);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			_E("pause packet timeout error");
		} else {
			_E("iconify failed - %d pause fail", pid);
			_E("we will term the app - %d", pid);
			_send_to_sigkill(pid);
			ret = -1;
		}
		_request_send_result(req, ret);
	}
	_D("pause done");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_PAUSE_BY_PID);

	return ret;
}

int _term_sub_app(int pid)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, getuid(), APP_TERM_BY_PID_ASYNC,
			(unsigned char *)&dummy, 0, AUL_SOCK_NOREPLY);
	if (ret < 0) {
		_E("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			return -1;
		}
	}

	return 0;
}

int _term_app(int pid, request_h req)
{
	int dummy;
	int ret;
	int cnt;
	int *pids = NULL;
	int i;

	if (_app_group_is_leader_pid(pid)) {
		_app_group_get_group_pids(pid, &cnt, &pids);
		for (i = cnt - 1; i >= 0; i--) {
			if (i != 0)
				_term_sub_app(pids[i]);
			_app_group_remove(pids[i]);
		}
		free(pids);
	}

	ret = aul_sock_send_raw(pid, getuid(), APP_TERM_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_ASYNC);
	if (ret < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d\n", pid);
			_request_send_result(req, -1);
			return -1;
		}
		_request_send_result(req, 0);
	}
	_D("term done\n");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_BY_PID);

	return 0;
}

int _term_req_app(int pid, request_h req)
{
	int dummy;
	int ret;

	ret = aul_sock_send_raw(pid, getuid(), APP_TERM_REQ_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_ASYNC);
	if (ret < 0) {
		_D("terminate req send error");
		_request_send_result(req, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_REQ_BY_PID);

	return 0;
}

int _term_bgapp(int pid, request_h req)
{
	int dummy;
	int ret;
	int cnt;
	int *pids = NULL;
	int i;
	int status = -1;

	if (_app_group_is_leader_pid(pid)) {
		_app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			status = _status_get_app_info_status(pids[cnt - 1],
					getuid());
			if (status == STATUS_BG) {
				for (i = cnt - 1 ; i >= 0; i--) {
					if (i != 0)
						_term_sub_app(pids[i]);
					_app_group_remove(pids[i]);
				}
			}
		}
		free(pids);
	}

	ret = aul_sock_send_raw(pid, getuid(), APP_TERM_BGAPP_BY_PID,
			(unsigned char *)&dummy, sizeof(int), AUL_SOCK_ASYNC);
	if (ret < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d", pid);
			_request_send_result(req, -1);
			return -1;
		}
		_request_send_result(req, 0);
	}
	_D("term_bgapp done");

	if (ret > 0)
		__set_reply_handler(ret, pid, req, APP_TERM_BGAPP_BY_PID);

	return 0;
}

int _term_app_v2(int pid, request_h req, bool *pend)
{
	int dummy;
	int ret;
	int cnt;
	int *pids = NULL;
	int i;

	if (_app_group_is_leader_pid(pid)) {
		_app_group_get_group_pids(pid, &cnt, &pids);
		for (i = cnt - 1; i >= 0; i--) {
			if (i != 0)
				_term_sub_app(pids[i]);
			_app_group_remove(pids[i]);
		}
		free(pids);
	}

	ret = aul_sock_send_raw(pid, getuid(), APP_TERM_BY_PID_SYNC,
			(unsigned char *)&dummy, 0,
			AUL_SOCK_ASYNC | AUL_SOCK_NOREPLY);
	if (ret < 0) {
		_D("Failed to send the terminate packet - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("Failed to kill - %d\n", pid);
			_request_send_result(req, -1);
			return -1;
		}
	}
	_D("term v2 done");

	if (pend)
		*pend = true;
	if (ret > 0)
		close(ret);

	return 0;
}

int _fake_launch_app(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	ret = aul_sock_send_bundle(pid, getuid(), cmd, kb, AUL_SOCK_ASYNC);
	if (ret < 0) {
		_E("error request fake launch - error code = %d", ret);
		_request_send_result(req, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, req, cmd);

	return ret;
}

static gboolean __au_glib_check(GSource *src)
{
	GSList *fd_list;
	GPollFD *tmp;

	fd_list = src->poll_fds;
	do {
		tmp = (GPollFD *) fd_list->data;
		if ((tmp->revents & (POLLIN | POLLPRI)))
			return TRUE;
		fd_list = fd_list->next;
	} while (fd_list);

	return FALSE;
}

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback,
		gpointer data)
{
	callback(data);
	return TRUE;
}

static gboolean __au_glib_prepare(GSource *src, gint *timeout)
{
	return FALSE;
}

static GSourceFuncs funcs = {
	.prepare = __au_glib_prepare,
	.check = __au_glib_check,
	.dispatch = __au_glib_dispatch,
	.finalize = NULL
};

struct reply_info {
	GSource *src;
	GPollFD *gpollfd;
	guint timer_id;
	int clifd;
	int pid;
	int cmd;
};

static gboolean __reply_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *)data;
	int fd = r_info->gpollfd->fd;
	int len;
	int res = 0;
	int clifd = r_info->clifd;
	int pid = r_info->pid;
	int cmd = r_info->cmd;

	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}
	close(fd);

	switch (cmd) {
	case APP_TERM_BY_PID:
	case APP_TERM_BGAPP_BY_PID:
		if (res >= 0)
			res = 0;
		_send_result_to_client(clifd, res);
		break;
	case APP_START_ASYNC:
	case APP_PAUSE_BY_PID:
		close(clifd);
		break;
	default:
		if (res >= 0)
			res = pid;
		_send_result_to_client(clifd, res);
		break;
	}

	_D("listen fd : %d , send fd : %d, pid : %d", fd, clifd, pid);

	g_source_remove(r_info->timer_id);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return TRUE;
}

static gboolean __recv_timeout_handler(gpointer data)
{
	struct reply_info *r_info = (struct reply_info *)data;
	int fd = r_info->gpollfd->fd;
	int clifd = r_info->clifd;
	const char *appid;
	const struct appinfo *ai;
	const char *taskmanage;
	int ret = -EAGAIN;

	_E("application is not responding: pid(%d) cmd(%d)",
			r_info->pid, r_info->cmd);
	close(fd);

	switch (r_info->cmd) {
	case APP_OPEN:
	case APP_RESUME:
	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
		appid = _status_app_get_appid_bypid(r_info->pid);
		if (appid == NULL)
			break;
		ai = _appinfo_find(getuid(), appid);
		if (ai == NULL)
			break;
		taskmanage = _appinfo_get_value(ai, AIT_TASKMANAGE);
		if (taskmanage && strcmp(taskmanage, "true") == 0)
			_signal_send_watchdog(r_info->pid, SIGKILL);
		break;
	case APP_TERM_BY_PID:
	case APP_TERM_BGAPP_BY_PID:
		if (_send_to_sigkill(r_info->pid) == 0)
			ret = 0;
		break;
	}

	_send_result_to_client(clifd, ret);
	g_source_remove_poll(r_info->src, r_info->gpollfd);
	g_source_destroy(r_info->src);
	g_free(r_info->gpollfd);
	free(r_info);

	return FALSE;
}

static void __set_reply_handler(int fd, int pid, request_h req, int cmd)
{
	GPollFD *gpollfd;
	GSource *src;
	struct reply_info *r_info;

	src = g_source_new(&funcs, sizeof(GSource));

	gpollfd = (GPollFD *) g_malloc(sizeof(GPollFD));
	gpollfd->events = POLLIN;
	gpollfd->fd = fd;

	r_info = malloc(sizeof(*r_info));
	if (r_info == NULL) {
		_E("out of memory");
		g_free(gpollfd);
		g_source_unref(src);
		return;
	}

	r_info->clifd = _request_remove_fd(req);
	r_info->pid = pid;
	r_info->src = src;
	r_info->gpollfd = gpollfd;
	r_info->cmd = cmd;

	r_info->timer_id = g_timeout_add(5000, __recv_timeout_handler,
			(gpointer)r_info);
	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc)__reply_handler,
			(gpointer)r_info, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);
	g_source_attach(src, NULL);

	_D("listen fd : %d, send fd : %d", fd, r_info->clifd);
}

static int __nofork_processing(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		ret = _resume_app(pid, req);
		if (ret < 0)
			_E("__resume_app failed. error code = %d", ret);
		_D("resume app done");
		break;

	case APP_START:
	case APP_START_RES:
	case APP_START_ASYNC:
		_D("fake launch pid : %d\n", pid);
		ret = _fake_launch_app(cmd, pid, kb, req);
		if (ret < 0)
			_E("fake_launch failed. error code = %d", ret);
		_D("fake launch done");
		break;
	default:
		_E("unknown command: %d", cmd);
		ret = -1;
	}

	return ret;
}

static int __compare_signature(const struct appinfo *ai, int cmd,
		uid_t caller_uid, const char *appid, const char *caller_appid)
{
	const char *permission;
	const struct appinfo *caller_ai;
	const char *preload;
	pkgmgrinfo_cert_compare_result_type_e compare_result;

	permission = _appinfo_get_value(ai, AIT_PERM);
	if (permission && strcmp(permission, "signature") == 0) {
		if (caller_uid != 0 && (cmd == APP_START ||
					cmd == APP_START_RES ||
					cmd == APP_START_ASYNC)) {
			caller_ai = _appinfo_find(caller_uid, caller_appid);
			preload = _appinfo_get_value(caller_ai, AIT_PRELOAD);
			if (!preload || strcmp(preload, "true") == 0)
				return 0;

			/* is admin is global */
			if (caller_uid != GLOBAL_USER) {
				pkgmgrinfo_pkginfo_compare_usr_app_cert_info(
						caller_appid, appid,
						caller_uid, &compare_result);
			} else {
				pkgmgrinfo_pkginfo_compare_app_cert_info(
						caller_appid, appid,
						&compare_result);
			}

			if (compare_result != PMINFO_CERT_COMPARE_MATCH)
				return -EILLEGALACCESS;
		}
	}

	return 0;
}

static int __get_pid_for_app_group(const char *appid, uid_t uid, bundle *kb,
		struct launch_s *handle)
{
	int status = -1;
	int found_pid = -1;
	int found_lpid = -1;
	int ret;

	if (_app_group_is_group_app(kb)) {
		handle->pid = -1;
		handle->is_subapp = true;
	} else {
		handle->is_subapp = false;
	}

	if (handle->pid > 0)
		status = _status_get_app_info_status(handle->pid, uid);

	if (handle->pid == -1 || status == STATUS_DYING) {
		ret = _app_group_find_singleton(appid, &found_pid, &found_lpid);
		if (ret == 0) {
			handle->pid = found_pid;
			handle->new_process = false;
		} else {
			handle->new_process = true;
		}

		ret = _app_group_can_start_app(appid, kb,
				&handle->can_attach,
				&handle->leader_pid,
				&handle->launch_mode);
		if (ret != 0) {
			_E("can't make group info");
			return -EILLEGALACCESS;
		}

		if (handle->can_attach &&
				handle->leader_pid == found_lpid) {
			_E("can't launch singleton app in the same group");
			return -EILLEGALACCESS;
		}

		if (found_pid != -1) {
			_W("_app_group_clear_top, pid: %d", found_pid);
			_app_group_clear_top(found_pid);
		}
	}

	if (handle->pid == -1 && handle->can_attach)
		handle->pid = _app_group_find_pid_from_recycle_bin(appid);

	return 0;
}

static void __prepare_to_suspend_services(int pid)
{
	int dummy;

	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	aul_sock_send_raw(pid, getuid(), APP_SUSPEND, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
}

static void __prepare_to_wake_services(int pid)
{
	int dummy;

	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	aul_sock_send_raw(pid, getuid(), APP_WAKE, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
}

static gboolean __check_service_only(gpointer user_data)
{
	int pid = GPOINTER_TO_INT(user_data);

	SECURE_LOGD("[__SUSPEND__] pid :%d", pid);
	_status_check_service_only(pid, getuid(),
			__prepare_to_suspend_services);

	return FALSE;
}

static char *__get_cert_value_from_pkginfo(const char *pkgid, uid_t uid)
{
	int ret;
	const char *cert_value;
	pkgmgrinfo_certinfo_h certinfo;

	ret = pkgmgrinfo_pkginfo_create_certinfo(&certinfo);
	if (ret != PMINFO_R_OK) {
		_E("Failed to create certinfo");
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_load_certinfo(pkgid, certinfo, uid);
	if (ret != PMINFO_R_OK) {
		_E("Failed to load certinfo");
		pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);
		return NULL;
	}

	ret = pkgmgrinfo_pkginfo_get_cert_value(certinfo,
			PMINFO_DISTRIBUTOR_ROOT_CERT, &cert_value);
	if (ret != PMINFO_R_OK || cert_value == NULL) {
		_E("Failed to get cert value");
		pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);
		return NULL;
	}

	pkgmgrinfo_pkginfo_destroy_certinfo(certinfo);

	return strdup(cert_value);
}

static int __get_visibility_from_certsvc(const char *cert_value)
{
	int ret;
	CertSvcInstance instance;
	CertSvcCertificate certificate;
	CertSvcVisibility visibility = CERTSVC_VISIBILITY_PUBLIC;

	if (cert_value == NULL)
		return (int)visibility;

	ret = certsvc_instance_new(&instance);
	if (ret != CERTSVC_SUCCESS) {
		_E("certsvc_instance_new() is failed.");
		return (int)visibility;
	}

	ret = certsvc_certificate_new_from_memory(instance,
			(const unsigned char *)cert_value,
			strlen(cert_value),
			CERTSVC_FORM_DER_BASE64,
			&certificate);
	if (ret != CERTSVC_SUCCESS) {
		_E("certsvc_certificate_new_from_memory() is failed.");
		certsvc_instance_free(instance);
		return (int)visibility;
	}

	ret = certsvc_certificate_get_visibility(certificate, &visibility);
	if (ret != CERTSVC_SUCCESS)
		_E("certsvc_certificate_get_visibility() is failed.");

	certsvc_instance_free(instance);

	return (int)visibility;
}

static int __check_execute_permission(const char *callee_pkgid,
		const char *caller_appid, uid_t caller_uid, bundle *kb)
{
	struct appinfo *ai;
	const char *caller_pkgid;
	const char *launch_type;
	const char *v;
	char num[256];
	int vi_num;
	int visibility;
	char *cert_value;

	if (callee_pkgid == NULL)
		return -1;

	ai = _appinfo_find(caller_uid, caller_appid);
	if (ai == NULL)
		return 0;

	caller_pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (caller_pkgid == NULL)
		return 0;

	if (strcmp(caller_pkgid, callee_pkgid) == 0)
		return 0;

	launch_type = bundle_get_val(kb, OSP_K_LAUNCH_TYPE);
	if (launch_type == NULL
		|| strcmp(launch_type, OSP_V_LAUNCH_TYPE_DATACONTROL) != 0) {
		v = _appinfo_get_value(ai, AIT_VISIBILITY);
		if (v == NULL) {
			cert_value = __get_cert_value_from_pkginfo(caller_pkgid,
					caller_uid);
			vi_num = __get_visibility_from_certsvc(cert_value);
			if (cert_value)
				free(cert_value);

			snprintf(num, sizeof(num), "%d", vi_num);
			_appinfo_set_value(ai, AIT_VISIBILITY, num);
			v = num;
		}

		visibility = atoi(v);
		if (!(visibility & CERTSVC_VISIBILITY_PLATFORM)) {
			_E("Couldn't launch service app in other packages");
			return -EREJECTED;
		}
	}

	return 0;
}

static gboolean __fg_timeout_handler(gpointer data)
{
	struct fgmgr *fg = data;

	if (!fg)
		return FALSE;

	_status_update_app_info_list(fg->pid, STATUS_BG, TRUE, getuid());

	_fgmgr_list = g_list_remove(_fgmgr_list, fg);
	free(fg);

	return FALSE;
}

static void __add_fgmgr_list(int pid)
{
	struct fgmgr *fg;

	fg = calloc(1, sizeof(struct fgmgr));
	if (!fg)
		return;

	fg->pid = pid;
	fg->tid = g_timeout_add(5000, __fg_timeout_handler, fg);

	_fgmgr_list = g_list_append(_fgmgr_list, fg);
}

static void __del_fgmgr_list(int pid)
{
	GList *iter = NULL;
	struct fgmgr *fg;

	if (pid < 0)
		return;

	for (iter = _fgmgr_list; iter != NULL; iter = g_list_next(iter)) {
		fg = (struct fgmgr *)iter->data;
		if (fg->pid == pid) {
			g_source_remove(fg->tid);
			_fgmgr_list = g_list_remove(_fgmgr_list, fg);
			free(fg);
			return;
		}
	}
}

static int __send_hint_for_visibility(uid_t uid)
{
	bundle *b = NULL;
	int ret;

	b = bundle_create();

	ret = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK, uid,
			PAD_CMD_VISIBILITY, b);

	if (b)
		bundle_free(b);
	__pid_of_last_launched_ui_app = 0;

	return ret;
}

static int __app_status_handler(int pid, int status, void *data)
{
	char *appid = NULL;
	int bg_category = 0x00;
	int app_status = -1;
	const struct appinfo *ai = NULL;

	_W("pid(%d) status(%d)", pid, status);

	app_status  = _status_get_app_info_status(pid, getuid());
	if (app_status == STATUS_DYING && status != PROC_STATUS_LAUNCH)
		return 0;

	switch (status) {
	case PROC_STATUS_FG:
		__del_fgmgr_list(pid);
		_status_update_app_info_list(pid, STATUS_VISIBLE, FALSE,
				getuid());
		_suspend_remove_timer(pid);

		if (pid == __pid_of_last_launched_ui_app)
			__send_hint_for_visibility(getuid());
		break;

	case PROC_STATUS_BG:
		_status_update_app_info_list(pid, STATUS_BG, FALSE, getuid());
		appid = _status_app_get_appid_bypid(pid);
		if (appid) {
			ai = _appinfo_find(getuid(), appid);
			bg_category = (bool)_appinfo_get_value(ai,
					AIT_BG_CATEGORY);
			if (!bg_category)
				_suspend_add_timer(pid, ai);
		}
		break;

	case PROC_STATUS_FOCUS:
		__focused_pid = pid;
		break;
	}

	return 0;
}

int _get_focused_pid(void)
{
	return __focused_pid;
}

int _launch_init(void)
{
	int ret;

	_D("_launch_init");
	_signal_init();

	ret = aul_listen_app_status_signal(__app_status_handler, NULL);
	_D("ret : %d", ret);

	return 0;
}

static int __check_ver(const char *required, const char *actual)
{
	int ret;

	if (required && actual) {
		ret = strverscmp(required, actual);
		if (ret < 1)
			return 1;
	}

	return 0;
}

static int __get_prelaunch_attribute(const struct appinfo *ai)
{
	int attribute_val = RESOURCED_BACKGROUND_MANAGEMENT_ATTRIBUTE;
	const char *api_version;

	api_version = _appinfo_get_value(ai, AIT_API_VERSION);
	if (api_version && __check_ver("2.4", api_version))
		attribute_val |= RESOURCED_API_VER_2_4_ATTRIBUTE;

	_D("api-version: %s", api_version);
	_D("prelaunch attribute %d%d%d%d(2)",
			(attribute_val & 0x8) >> 3,
			(attribute_val & 0x4) >> 2,
			(attribute_val & 0x2) >> 1,
			(attribute_val & 0x1));

	return attribute_val;
}

static int __get_background_category(const struct appinfo *ai)
{
	int category = 0x0;

	category = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);

	_D("background category: %#x", category);

	return category;
}

static bool __is_allowed_background(const char *component_type, int bg_category)
{
	bool bg_allowed = false;

	/*
	 * 2.4 bg-categorized (uiapp || svcapp) || watch || widget -> bg allowed
	 * 2.3 uiapp -> not allowed, 2.3 svcapp -> bg allowed
	 */
	if (!strcmp(component_type, APP_TYPE_UI) ||
			!strcmp(component_type, APP_TYPE_SERVICE)) {
		if (bg_category)
			bg_allowed = true;
	} else {
		bg_allowed = true;
	}

	return bg_allowed;
}

static void __set_caller_appinfo(const char *caller_appid, int caller_pid,
		uid_t caller_uid, bundle *kb)
{
	char buf[MAX_PID_STR_BUFSZ];

	snprintf(buf, sizeof(buf), "%d", caller_pid);
	bundle_del(kb, AUL_K_CALLER_PID);
	bundle_add(kb, AUL_K_CALLER_PID, buf);

	snprintf(buf, sizeof(buf), "%d", caller_uid);
	bundle_del(kb, AUL_K_CALLER_UID);
	bundle_add(kb, AUL_K_CALLER_UID, buf);

	if (caller_appid) {
		bundle_del(kb, AUL_K_CALLER_APPID);
		bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
	}
}

static const char *__get_caller_appid(int caller_pid)
{
	char *caller_appid;

	caller_appid = _status_app_get_appid_bypid(caller_pid);
	if (caller_appid == NULL)
		caller_appid = _status_app_get_appid_bypid(getpgid(caller_pid));

	return caller_appid;
}

static int __check_executable(const struct appinfo *ai)
{
	const char *status;
	int enable;
	int ret;

	status = _appinfo_get_value(ai, AIT_STATUS);
	if (status == NULL)
		return -1;

	if (strcmp(status, "blocking") == 0) {
		_D("Blocking");
		return -EREJECTED;
	}

	ret = _appinfo_get_int_value(ai, AIT_ENABLEMENT, &enable);
	if (ret == 0 && !(enable & APP_ENABLEMENT_MASK_ACTIVE)) {
		_D("Disabled");
		return -EREJECTED;
	}

	return 0;
}

static void __set_appinfo_for_launchpad(const struct appinfo *ai, bundle *kb)
{
	const char *str;

	str = _appinfo_get_value(ai, AIT_HWACC);
	if (str) {
		bundle_del(kb, AUL_K_HWACC);
		bundle_add(kb, AUL_K_HWACC, str);
	}

	str = _appinfo_get_value(ai, AIT_ROOT_PATH);
	if (str) {
		bundle_del(kb, AUL_K_ROOT_PATH);
		bundle_add(kb, AUL_K_ROOT_PATH, str);
	}

	str = _appinfo_get_value(ai, AIT_EXEC);
	if (str) {
		bundle_del(kb, AUL_K_EXEC);
		bundle_add(kb, AUL_K_EXEC, str);
	}

	str = _appinfo_get_value(ai, AIT_PKGTYPE);
	if (str) {
		bundle_del(kb, AUL_K_PACKAGETYPE);
		bundle_add(kb, AUL_K_PACKAGETYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_PKGID);
	if (str) {
		bundle_del(kb, AUL_K_PKGID);
		bundle_add(kb, AUL_K_PKGID, str);
	}

	str = _appinfo_get_value(ai, AIT_POOL);
	if (str) {
		bundle_del(kb, AUL_K_INTERNAL_POOL);
		bundle_add(kb, AUL_K_INTERNAL_POOL, str);
	}

	str = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (str) {
		bundle_del(kb, AUL_K_COMP_TYPE);
		bundle_add(kb, AUL_K_COMP_TYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_APPTYPE);
	if (str) {
		bundle_del(kb, AUL_K_APP_TYPE);
		bundle_add(kb, AUL_K_APP_TYPE, str);
	}

	str = _appinfo_get_value(ai, AIT_API_VERSION);
	if (str) {
		bundle_del(kb, AUL_K_API_VERSION);
		bundle_add(kb, AUL_K_API_VERSION, str);
	}
}

static int __prepare_starting_app(struct launch_s *handle, request_h req,
		const char *appid)
{
	int ret;
	const char *pkgid;
	const char *comp_type;
	const char *multiple;
	const char *caller_appid;
	const char *widget_viewer;
	int cmd = _request_get_cmd(req);
	int caller_pid = _request_get_pid(req);
	uid_t caller_uid = _request_get_uid(req);
	uid_t target_uid = _request_get_target_uid(req);
	bundle *kb = _request_get_bundle(req);

	handle->appid = appid;
	handle->ai = _appinfo_find(target_uid, appid);
	if (handle->ai == NULL) {
		_D("Failed to find appinfo of %s", appid);
		return -ENOENT;
	}

	ret = __check_executable(handle->ai);
	if (ret < 0)
		return -1;

	caller_appid = __get_caller_appid(caller_pid);
	__set_caller_appinfo(caller_appid, caller_pid, caller_uid, kb);

	ret = __compare_signature(handle->ai, cmd, target_uid, appid,
			caller_appid);
	if (ret < 0)
		return ret;

	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return -1;

	if (caller_appid && (strcmp(comp_type, APP_TYPE_WIDGET) == 0 ||
				strcmp(comp_type, APP_TYPE_WATCH) == 0)) {
		widget_viewer = bundle_get_val(kb, AUL_K_WIDGET_VIEWER);
		if (widget_viewer && strcmp(widget_viewer, caller_appid) == 0) {
			handle->pid = _status_app_is_running_with_org_caller(
					appid, caller_pid);
		} else {
			handle->pid = _status_app_is_running(appid, target_uid);
		}
	} else {
		multiple = _appinfo_get_value(handle->ai, AIT_MULTI);
		if (multiple == NULL || strcmp(multiple, "false") == 0) {
			handle->pid = _status_app_is_running(appid, target_uid);
		}
	}

	if (strcmp(comp_type, APP_TYPE_UI) == 0) {
		ret = __get_pid_for_app_group(appid, target_uid, kb, handle);
		if (ret < 0)
			return -1;

		_input_lock();
	} else if (caller_appid && strcmp(comp_type, APP_TYPE_SERVICE) == 0) {
		pkgid = _appinfo_get_value(handle->ai, AIT_PKGID);
		ret = __check_execute_permission(pkgid, caller_appid,
				target_uid, kb);
		if (ret < 0)
			return -1;
	}

	if (cmd == APP_START_RES) {
		bundle_del(kb, AUL_K_WAIT_RESULT);
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");
	}

	handle->share_info = _temporary_permission_create(caller_pid,
			appid, kb, target_uid);
	if (handle->share_info == NULL)
		_E("No sharable path: %d %s", caller_pid, appid);

	_extractor_mount(handle->ai, kb, _extractor_mountable_get_tep_paths);
	_extractor_mount(handle->ai, kb, _extractor_mountable_get_tpk_paths);

	handle->prelaunch_attr = __get_prelaunch_attribute(
			handle->ai);
	handle->bg_category = __get_background_category(handle->ai);
	handle->bg_allowed = __is_allowed_background(comp_type,
			handle->bg_category);
	if (handle->bg_allowed) {
		_D("[__SUSPEND__] allowed background, appid: %s, app-type: %s",
				appid, comp_type);
		bundle_del(kb, AUL_K_ALLOWED_BG);
		bundle_add(kb, AUL_K_ALLOWED_BG, "ALLOWED_BG");
	}

	return 0;
}

static int __do_starting_app(struct launch_s *handle, request_h req,
		bool *pending)
{
	int status = -1;
	int cmd = _request_get_cmd(req);
	int caller_pid = _request_get_pid(req);
	uid_t target_uid = _request_get_target_uid(req);
	bundle *kb = _request_get_bundle(req);
	const char *pkgid;
	const char *comp_type;
	const char *pad_type = LAUNCHPAD_PROCESS_POOL_SOCK;
	splash_image_h splash_image;
	int ret;

	pkgid = _appinfo_get_value(handle->ai, AIT_PKGID);
	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);

	if (handle->pid > 0) {
		status = _status_get_app_info_status(handle->pid,
				target_uid);
	}

	if (handle->pid > 0 && status != STATUS_DYING) {
		if (handle->pid == caller_pid) {
			SECURE_LOGD("caller & callee process are same. %s:%d,",
					handle->appid, handle->pid);
			return -ELOCALLAUNCH_ID;
		}

		aul_send_app_resume_request_signal(handle->pid,
				handle->appid, pkgid, comp_type);
		_suspend_remove_timer(handle->pid);
		if (comp_type && !strcmp(comp_type, APP_TYPE_SERVICE)) {
			if (handle->bg_allowed == false)
				__prepare_to_wake_services(handle->pid);
		}

		ret = __nofork_processing(cmd, handle->pid, kb, req);
		if (ret < 0)
			_temporary_permission_destroy(handle->share_info);

		return ret;
	}

	if (handle->pid > 0 && status == STATUS_DYING) {
		ret = kill(handle->pid, SIGKILL);
		if (ret == -1) {
			_W("Failed to send SIGKILL: %d:%s,", handle->pid,
					strerror(errno));
		}
		_cleanup_dead_info(handle->pid);
	}

	__set_appinfo_for_launchpad(handle->ai, kb);
	if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE)
		pad_type = DEBUG_LAUNCHPAD_SOCK;

	splash_image = _splash_screen_create_image(handle->ai, kb, cmd);
	_splash_screen_send_image(splash_image);

	_signal_send_proc_prelaunch(handle->appid, pkgid,
			handle->prelaunch_attr, handle->bg_category);

	ret = _send_cmd_to_launchpad(pad_type, target_uid, PAD_CMD_LAUNCH, kb);
	if (ret < 0) {
		_temporary_permission_destroy(handle->share_info);
		_splash_screen_destroy_image(splash_image);
		return ret;
	}

	handle->pid = ret;
	*pending = true;
	_splash_screen_send_pid(splash_image, handle->pid);
	_suspend_add_proc(handle->pid);
	aul_send_app_launch_request_signal(handle->pid, handle->appid,
			pkgid, comp_type);
	if (comp_type && !strcmp(comp_type, APP_TYPE_SERVICE)) {
		if (handle->bg_allowed)
			g_idle_add(__check_service_only, GINT_TO_POINTER(ret));
	}

	return ret;
}

static int __complete_starting_app(struct launch_s *handle, request_h req)
{
	bundle *kb = _request_get_bundle(req);
	uid_t target_uid = _request_get_target_uid(req);
	int caller_pid = _request_get_pid(req);
	const char *comp_type;
	int ret;

	comp_type = _appinfo_get_value(handle->ai, AIT_COMPTYPE);
	if (comp_type && !strcmp(comp_type, APP_TYPE_SERVICE)) {
		if (handle->new_process) {
			_D("Add app group info %d", handle->pid);
			__pid_of_last_launched_ui_app = handle->pid;
			_app_group_start_app(handle->pid, kb,
					handle->leader_pid,
					handle->can_attach,
					handle->launch_mode);
			__add_fgmgr_list(handle->pid);
		} else {
			_app_group_restart_app(handle->pid, kb);
		}
	}

	_status_add_app_info_list(handle->ai, handle->pid, handle->is_subapp,
			target_uid, caller_pid);

	if (handle->share_info) {
		ret = _temporary_permission_apply(handle->pid, target_uid,
				handle->share_info);
		if (ret < 0)
			_D("Couldn't apply temporary permission: %d", ret);

		_temporary_permission_destroy(handle->share_info);
	}

	return handle->pid;
}

int _launch_start_app(const char *appid, request_h req, bool *pending)
{
	int ret;
	struct launch_s launch_data = {0,};
	int caller_pid = _request_get_pid(req);
	uid_t caller_uid = _request_get_uid(req);

	traceBegin(TTRACE_TAG_APPLICATION_MANAGER, "AMD:START_APP");
	_D("_launch_start_app: appid=%s caller pid=%d uid=%d",
			appid, caller_pid, caller_uid);

	ret = __prepare_starting_app(&launch_data, req, appid);
	if (ret < 0) {
		_request_send_result(req, ret);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		return -1;
	}

	ret = __do_starting_app(&launch_data, req, pending);
	if (ret < 0) {
		_request_send_result(req, ret);
		traceEnd(TTRACE_TAG_APPLICATION_MANAGER);
		return -1;
	}

	ret = __complete_starting_app(&launch_data, req);
	traceEnd(TTRACE_TAG_APPLICATION_MANAGER);

	return ret;
}

