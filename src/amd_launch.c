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
#include <sys/stat.h>
#include <unistd.h>
#include <pkgmgr-info.h>
#include <poll.h>
#include <tzplatform_config.h>
#include <cert-svc/ccert.h>
#include <cert-svc/cinstance.h>
#include <gio/gio.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>
#include <vconf.h>

#include "amd_config.h"
#include "amd_launch.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_app_group.h"
#include "amd_util.h"
#include "app_signal.h"
#include "amd_cynara.h"
#include "amd_socket.h"
#include "amd_share.h"
#include "amd_app_com.h"

#define DAC_ACTIVATE

#define TERM_WAIT_SEC 3
#define INIT_PID 1

#define AUL_PR_NAME         16
#define OSP_K_LAUNCH_TYPE "__OSP_LAUNCH_TYPE__"
#define OSP_V_LAUNCH_TYPE_DATACONTROL "datacontrol"

#define PROC_STATUS_LAUNCH  0
#define PROC_STATUS_FG	3
#define PROC_STATUS_BG	4

/* SDK related defines */
#define PATH_APP_ROOT tzplatform_getenv(TZ_USER_APP)
#define PATH_GLOBAL_APP_RO_ROOT tzplatform_getenv(TZ_SYS_RO_APP)
#define PATH_GLOBAL_APP_RW_ROOT tzplatform_getenv(TZ_SYS_RW_APP)
#define PATH_DATA "/data"
#define SDK_CODE_COVERAGE "CODE_COVERAGE"
#define SDK_DYNAMIC_ANALYSIS "DYNAMIC_ANALYSIS"
#define PATH_DA_SO "/home/developer/sdk_tools/da/da_probe.so"
#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define PREFIX_EXTERNAL_STORAGE_PATH "/opt/storage/sdcard/"

#if 0
struct fgmgr {
	guint tid;
	int pid;
};

static GList *_fgmgr_list;
#endif

struct wl_splash_screen {
	struct wl_display *display;
	struct wl_registry *registry;
	struct tizen_launchscreen *launch_screen;
};

struct wl_splash_image {
	struct tizen_launch_image *image;
	guint tid;
};

static int __pid_of_last_launched_ui_app;
static GDBusConnection *conn;
static struct wl_splash_screen *wl_ss;

static void __set_reply_handler(int fd, int pid, request_h req, int cmd);
static int __nofork_processing(int cmd, int pid, bundle * kb, request_h req);
extern void _cleanup_dead_info(int pid);
extern int _wl_is_initialized(void);
static struct wl_splash_screen *__init_splash_screen(void);

static void __set_stime(bundle *kb)
{
	struct timeval tv;
	char tmp[MAX_LOCAL_BUFSZ];

	gettimeofday(&tv, NULL);
	snprintf(tmp, MAX_LOCAL_BUFSZ, "%ld/%ld", tv.tv_sec, tv.tv_usec);
	bundle_add(kb, AUL_K_STARTTIME, tmp);
}

int _start_app_local_with_bundle(uid_t uid, const char *appid, bundle *kb)
{
	bool dummy;
	request_h req;
	int r = 0;

	__set_stime(kb);
	bundle_add(kb, AUL_K_APPID, appid);
	req = _request_create_local(APP_START, uid, getpid());
	if (req == NULL) {
		_E("out of memory");
		return -1;
	}

	r = _start_app(appid, kb, uid, req, &dummy);
	_request_free_local(req);

	return r;
}

int _start_app_local(uid_t uid, const char *appid)
{
	int pid;
	bundle *kb;

	kb = bundle_create();
	if (kb == NULL) {
		_E("out of memory");
		return -1;
	}

	pid = _start_app_local_with_bundle(uid, appid, kb);

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

	if ((ret = aul_sock_send_raw_async(pid, getuid(), APP_RESUME_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_NONE)) < 0) {
		if (ret == -EAGAIN)
			_E("resume packet timeout error");
		else {
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

	if ((ret = aul_sock_send_raw_async(pid, getuid(), APP_PAUSE_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_NONE)) < 0) {
		if (ret == -EAGAIN)
			_E("pause packet timeout error");
		else {
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

	if ((ret = aul_sock_send_raw_async(pid, getuid(), APP_TERM_BY_PID_ASYNC,
			(unsigned char *)&dummy, 0, AUL_SOCK_CLOSE | AUL_SOCK_NOREPLY)) < 0) {
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

	if (app_group_is_leader_pid(pid)) {
		int cnt;
		int *pids = NULL;
		int i;

		app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			for (i = cnt - 1 ; i >= 0; i--) {
				if (i != 0)
					_term_sub_app(pids[i]);
				app_group_remove(pids[i]);

			}
			free(pids);
		}
	}

	if ((ret = aul_sock_send_raw_async(pid, getuid(), APP_TERM_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_NONE)) < 0) {
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

	if ((ret = aul_sock_send_raw_async(pid, getuid(), APP_TERM_REQ_BY_PID,
			(unsigned char *)&dummy, 0, AUL_SOCK_NONE)) < 0) {
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
	int fd;
	int cnt;
	int *pids = NULL;
	int i;
	int status = -1;

	if (app_group_is_leader_pid(pid)) {
		app_group_get_group_pids(pid, &cnt, &pids);
		if (cnt > 0) {
			status = _status_get_app_info_status(pids[cnt - 1], getuid());
			if (status == STATUS_BG) {
				for (i = cnt - 1 ; i >= 0; i--) {
					if (i != 0)
						_term_sub_app(pids[i]);
					app_group_remove(pids[i]);
				}
			}
		}
		free(pids);
	}

	if ((fd = aul_sock_send_raw_async(pid, getuid(), APP_TERM_BGAPP_BY_PID,
		(unsigned char *)&dummy, sizeof(int), AUL_SOCK_NONE)) < 0) {
		_D("terminate packet send error - use SIGKILL");
		if (_send_to_sigkill(pid) < 0) {
			_E("fail to killing - %d", pid);
			_request_send_result(req, -1);
			return -1;
		}
		_request_send_result(req, 0);
	}
	_D("term_bgapp done");
	if (fd > 0)
		__set_reply_handler(fd, pid, req, APP_TERM_BGAPP_BY_PID);

	return 0;
}

int _fake_launch_app(int cmd, int pid, bundle *kb, request_h req)
{
	int ret;

	if ((ret = aul_sock_send_bundle_async(pid, getuid(), cmd, kb,
			 AUL_SOCK_NONE)) < 0) {
		_E("error request fake launch - error code = %d", ret);
		_request_send_result(req, ret);
	}

	if (ret > 0)
		__set_reply_handler(ret, pid, req, cmd);

	return ret;
}

static int __send_watchdog_signal(int pid, int signal_num)
{
	GError *err = NULL;

	if (conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	if (g_dbus_connection_emit_signal(conn,
					NULL,
					RESOURCED_PROC_OBJECT,
					RESOURCED_PROC_INTERFACE,
					RESOURCED_PROC_WATCHDOG_SIGNAL,
					g_variant_new("(ii)", pid, signal_num),
					&err) == FALSE) {
		_E("g_dbus_connection_emit_signal() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	if (g_dbus_connection_flush_sync(conn, NULL, &err) == FALSE) {
		_E("g_dbus_connection_flush_sync() is failed: %s",
					err->message);
		g_error_free(err);
		return -1;
	}

	_W("send a watchdog signal done: %d", pid);

	return 0;
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

static gboolean __au_glib_dispatch(GSource *src, GSourceFunc callback, gpointer data)
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
	struct reply_info *r_info = (struct reply_info *) data;;
	int fd = r_info->gpollfd->fd;
	int len;
	int res = 0;
	int clifd = r_info->clifd;
	int pid = r_info->pid;

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

	if (res < 0)
		_send_result_to_client(clifd, res);
	else
		_send_result_to_client(clifd, pid);

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
		appid = _status_app_get_appid_bypid(r_info->pid);
		if (appid == NULL)
			break;
		ai = appinfo_find(getuid(), appid);
		if (ai == NULL)
			break;
		taskmanage = appinfo_get_value(ai, AIT_TASKMANAGE);
		if (taskmanage && strcmp(taskmanage, "true") == 0)
			__send_watchdog_signal(r_info->pid, SIGKILL);
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

	r_info->timer_id = g_timeout_add(5000, __recv_timeout_handler, (gpointer) r_info);
	g_source_add_poll(src, gpollfd);
	g_source_set_callback(src, (GSourceFunc) __reply_handler, (gpointer) r_info, NULL);
	g_source_set_priority(src, G_PRIORITY_DEFAULT);
	g_source_attach(src, NULL);

	_D("listen fd : %d, send fd : %d", fd, r_info->clifd);
}

static int __nofork_processing(int cmd, int pid, bundle * kb, request_h req)
{
	int ret;

	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
		_D("resume app's pid : %d\n", pid);
		if ((ret = _resume_app(pid, req)) < 0)
			_E("__resume_app failed. error code = %d", ret);
		_D("resume app done");
		break;

	case APP_START:
	case APP_START_RES:
		_D("fake launch pid : %d\n", pid);
		if ((ret = _fake_launch_app(cmd, pid, kb, req)) < 0)
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
				uid_t caller_uid, const char* appid, char *caller_appid, int fd)
{
	const char *permission;
	int ret;
	const struct appinfo *caller_ai;
	const char *preload;
	pkgmgrinfo_cert_compare_result_type_e compare_result;

	permission = appinfo_get_value(ai, AIT_PERM);
	if (permission && strncmp(permission, "signature", 9) == 0) {
		if (caller_uid != 0 && (cmd == APP_START || cmd == APP_START_RES)) {
			caller_ai = appinfo_find(caller_uid, caller_appid);
			preload = appinfo_get_value(caller_ai, AIT_PRELOAD);
			if (preload && strncmp(preload, "true", 4) != 0) {
				/* is admin is global */
				if (caller_uid != GLOBAL_USER)
					pkgmgrinfo_pkginfo_compare_usr_app_cert_info(caller_appid,
						appid, caller_uid, &compare_result);
				else
					pkgmgrinfo_pkginfo_compare_app_cert_info(caller_appid,
						appid, &compare_result);
				if (compare_result != PMINFO_CERT_COMPARE_MATCH) {
					ret = -EILLEGALACCESS;
					_send_result_to_client(fd, ret);
					return ret;
				}
			}
		}
	}

	return 0;
}

static int __get_pid_for_app_group(const char *appid, int pid, int caller_uid, bundle* kb,
		int *lpid, gboolean *can_attach, gboolean *new_process,
		app_group_launch_mode* launch_mode, bool *is_subapp)
{
	int st = -1;
	int found_pid = -1;
	int found_lpid = -1;

	if (app_group_is_group_app(kb)) {
		pid = -1;
		*is_subapp = true;
	} else {
		*is_subapp = false;
	}

	if (pid > 0)
		st = _status_get_app_info_status(pid, caller_uid);

	if (pid == -1 || st == STATUS_DYING) {
		if (app_group_find_singleton(appid, &found_pid, &found_lpid) == 0) {
			pid = found_pid;
			*new_process = FALSE;
		} else {
			*new_process = TRUE;
		}

		if (app_group_can_start_app(appid, kb, can_attach, lpid, launch_mode) != 0) {
			_E("can't make group info");
			return -EILLEGALACCESS;
		}

		if (*can_attach && *lpid == found_lpid) {
			_E("can't launch singleton app in the same group");
			return -EILLEGALACCESS;
		}

		if (found_pid != -1) {
			_W("app_group_clear_top, pid: %d", found_pid);
			app_group_clear_top(found_pid);
		}
	}

	if (pid == -1 && *can_attach)
		pid = app_group_find_pid_from_recycle_bin(appid);

	return pid;
}

static int __tep_mount(char *mnt_path[])
{
	GError *err = NULL;
	GDBusMessage *msg = NULL;
	int ret = 0;
	int rv = 0;
	struct stat link_buf = {0,};

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	rv = lstat(mnt_path[0], &link_buf);
	if (rv == 0) {
		rv = unlink(mnt_path[0]);
		if (rv)
			_E("Unable tp remove link file %s", mnt_path[0]);
	}

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_MOUNT_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		ret = -1;
		goto func_out;
	}
	g_dbus_message_set_body(msg,
			g_variant_new("(ss)", mnt_path[0], mnt_path[1]));

	if (g_dbus_connection_send_message(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					NULL,
					&err) == FALSE) {
		_E("g_dbus_connection_send_message() is failed: %s",
					err->message);
		ret = -1;
	}

func_out:
	if (msg)
		g_object_unref(msg);

	g_clear_error(&err);

	return ret;
}

static void __send_mount_request(const struct appinfo *ai, const char *tep_name,
		bundle *kb)
{
	SECURE_LOGD("tep name is: %s", tep_name);
	char *mnt_path[2] = {NULL, };
	const char *installed_storage = NULL;
	char tep_path[PATH_MAX] = {0, };
	const char *path_app_root = NULL;

	const char *global = appinfo_get_value(ai, AIT_GLOBAL);
	const char *pkgid = appinfo_get_value(ai, AIT_PKGID);
	const char *preload = appinfo_get_value(ai, AIT_PRELOAD);
	installed_storage = appinfo_get_value(ai, AIT_STORAGE_TYPE);

	if (global && strcmp("true", global) == 0) {
		if (preload && strcmp(preload, "true") == 0)
			path_app_root = PATH_GLOBAL_APP_RO_ROOT;
		else
			path_app_root = PATH_GLOBAL_APP_RW_ROOT;
	} else {
		path_app_root = PATH_APP_ROOT;
	}

	if (installed_storage != NULL) {
		SECURE_LOGD("storage: %s", installed_storage);
		if (strncmp(installed_storage, "internal", 8) == 0) {
			snprintf(tep_path, PATH_MAX, "%s/%s/res/%s",
					path_app_root, pkgid, tep_name);
			mnt_path[1] = strdup(tep_path);
			snprintf(tep_path, PATH_MAX, "%s/%s/res/tep",
					path_app_root, pkgid);
			mnt_path[0] = strdup(tep_path);
		} else if (strncmp(installed_storage, "external", 8) == 0) {
			snprintf(tep_path, PATH_MAX, "%step/%s",
					PREFIX_EXTERNAL_STORAGE_PATH, tep_name);
			mnt_path[1] = strdup(tep_path);
			snprintf(tep_path, PATH_MAX, "%step/tep-access",
					PREFIX_EXTERNAL_STORAGE_PATH); /* TODO : keeping tep/tep-access for now for external storage */
			mnt_path[0] = strdup(tep_path);
		}

		if (mnt_path[0] && mnt_path[1]) {
			bundle_add(kb, AUL_TEP_PATH, mnt_path[0]);
			int ret = -1;
			ret = aul_is_tep_mount_dbus_done(mnt_path[0]);
			if (ret != 1) {
				ret = __tep_mount(mnt_path);
				if (ret < 0)
					_E("dbus error %d", ret);
			}
		}
		if (mnt_path[0])
			free(mnt_path[0]);
		if (mnt_path[1])
			free(mnt_path[1]);
	}
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

	ai = appinfo_find(caller_uid, caller_appid);
	if (ai == NULL)
		return 0;

	caller_pkgid = appinfo_get_value(ai, AIT_PKGID);
	if (caller_pkgid == NULL)
		return 0;

	if (strcmp(caller_pkgid, callee_pkgid) == 0)
		return 0;

	launch_type = bundle_get_val(kb, OSP_K_LAUNCH_TYPE);
	if (launch_type == NULL
		|| strcmp(launch_type, OSP_V_LAUNCH_TYPE_DATACONTROL) != 0) {
		v = appinfo_get_value(ai, AIT_VISIBILITY);
		if (v == NULL) {
			cert_value = __get_cert_value_from_pkginfo(caller_pkgid,
					caller_uid);
			vi_num = __get_visibility_from_certsvc(cert_value);
			if (cert_value)
				free(cert_value);

			snprintf(num, sizeof(num), "%d", vi_num);
			appinfo_set_value(ai, AIT_VISIBILITY, num);
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

#if 0
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

static int __app_status_handler(int pid, int status, void *data)
{
	/* char *appid = NULL; */
	/* int bg_category = 0x00; */
	int app_status = -1;
	/* const struct appinfo *ai = NULL; */

	_W("pid(%d) status(%d)", pid, status);

	app_status  = _status_get_app_info_status(pid, getuid());

	if (app_status == STATUS_DYING && status != PROC_STATUS_LAUNCH)
		return 0;

	if (status == PROC_STATUS_FG) {
		__del_fgmgr_list(pid);
		_status_update_app_info_list(pid, STATUS_VISIBLE, FALSE, getuid());
		/* _amd_suspend_remove_timer(pid); */
	} else if (status == PROC_STATUS_BG) {
		_status_update_app_info_list(pid, STATUS_BG, FALSE, getuid());
		/*
		appid = _status_app_get_appid_bypid(pid);
		if (appid) {
			ai = appinfo_find(getuid(), appid);
			bg_category = (bool)appinfo_get_value(ai, AIT_BG_CATEGORY);
			if (!bg_category)
				_amd_suspend_add_timer(pid, ai);
		}*/
	} else if (status == PROC_STATUS_LAUNCH) {
		_D("pid(%d) status(%d)", pid, status);
	}

	return 0;
}
#endif

static int __invoke_dbus_method_call(const char *dest,
		const char *path,
		const char *interface,
		const char *method,
		GVariant *param)
{
	int ret = -1;
	GError *err = NULL;
	GDBusMessage *msg = NULL;
	GDBusMessage *reply = NULL;
	GVariant *body;

	if (param == NULL)
		return -1;

	if (conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed. %s", err->message);
			g_clear_error(&err);
			return -1;
		}
	}

	msg = g_dbus_message_new_method_call(dest,
			path,
			interface,
			method);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	g_dbus_message_set_body(msg, param);

	reply = g_dbus_connection_send_message_with_reply_sync(conn,
			msg,
			G_DBUS_SEND_MESSAGE_FLAGS_NONE,
			500,
			NULL,
			NULL,
			&err);
	if (reply == NULL) {
		_E("g_dbus_connection_send_mesage_with_reply_sync() "
				"is falied. %s", err->message);
		goto out;
	}

	body = g_dbus_message_get_body(reply);
	if (body == NULL) {
		_E("g_dbus_message_get_body() is failed.");
		goto out;
	}

	ret = (int)g_variant_get_int32(body);

out:
	if (msg)
		g_object_unref(msg);
	if (reply)
		g_object_unref(reply);

	g_clear_error(&err);

	return ret;
}

static void __destroy_splash_image(struct wl_splash_image *wl_si)
{
	if (wl_si == NULL)
		return;

	if (wl_si->tid > 0)
		g_source_remove(wl_si->tid);
	if (wl_si->image)
		tizen_launch_image_destroy(wl_si->image);
	free(wl_si);
}

static gboolean __splash_image_timeout_handler(gpointer data)
{
	struct wl_splash_image *wl_si = (struct wl_splash_image *)data;

	if (wl_si == NULL)
		return FALSE;

	__destroy_splash_image(wl_si);

	return FALSE;
}

static int __app_can_launch_splash_image(const struct appinfo *ai, bundle *kb, int cmd)
{
	const char *fake_effect;
	const char *component_type;
	const char *operation;

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strncmp(component_type, APP_TYPE_SERVICE,
				strlen(APP_TYPE_SERVICE)) == 0) {
		_D("component_type: %s", component_type);
		return -1;
	}

	if (cmd == APP_OPEN)
		return 0;

	fake_effect = bundle_get_val(kb, "__FAKE_EFFECT__");
	if (fake_effect == NULL) {
		_D("fake_effect is NULL");
		return -1;
	}

	if (strncmp(fake_effect, "OFF", strlen("OFF")) == 0) {
		_D("fake effect off");
		return -1;
	}

	operation = bundle_get_val(kb, AUL_SVC_OPERATION_MAIN);
	if (operation == NULL) {
		_D("operation is NULL");
		return -1;
	}

	if (strncmp(operation, AUL_SVC_OPERATION_MAIN,
				strlen(AUL_SVC_OPERATION_MAIN)) != 0) {
		_D("operation is not %s", AUL_SVC_OPERATION_MAIN);
		return -1;
	}

	return 0;
}

static struct appinfo_splash_screen *__get_splash_screen_info(
		const struct appinfo *ai, int screen_mode)
{
	if (screen_mode == 0 || screen_mode == 2)
		return (struct appinfo_splash_screen *)appinfo_get_value(ai,
				AIT_PORTRAIT_SPLASH_SCREEN);
	else if (screen_mode == 1 || screen_mode == 3)
		return (struct appinfo_splash_screen *)appinfo_get_value(ai,
				AIT_LANDSCAPE_SPLASH_SCREEN);

	return NULL;
}

static struct wl_splash_image *__send_image_to_wm(const struct appinfo *ai,
		bundle *kb, int cmd)
{
	struct wl_splash_image *wl_si;
	struct wl_splash_screen *wl_ss;
	struct appinfo_splash_screen *ai_ss;
	int rots[] = {0, 90, 180, 270};
	int screen_mode;
	int rotate_allowed = 0;
	int file_type = 1;
	int indicator = 0;

	wl_ss = __init_splash_screen();
	if (wl_ss == NULL)
		return NULL;

	if (__app_can_launch_splash_image(ai, kb, cmd) < 0)
		return NULL;

	screen_mode = __invoke_dbus_method_call(ROTATION_BUS_NAME,
						ROTATION_OBJECT_PATH,
						ROTATION_INTERFACE_NAME,
						ROTATION_METHOD_NAME,
						g_variant_new("(i)", 0));
	_D("screen_mode: %d", screen_mode);
	if (screen_mode == -1)
		screen_mode = 0;

	vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
						&rotate_allowed);
	_D("rotate_allowed: %d", rotate_allowed);
	if (rotate_allowed == 0)
		screen_mode = 0;

	ai_ss = __get_splash_screen_info(ai, screen_mode);
	if (ai_ss == NULL)
		return NULL;

	if (strncmp(ai_ss->type, "img", strlen("img")) == 0)
		file_type = 0;
	if (strncmp(ai_ss->indicatordisplay, "on", strlen("on")) == 0)
		indicator = 1;

	wl_si = (struct wl_splash_image *)calloc(1,
			sizeof(struct wl_splash_image));
	if (wl_si == NULL) {
		_E("out of memory");
		return NULL;
	}

	wl_si->image = tizen_launchscreen_create_img(wl_ss->launch_screen);
	if (wl_si->image == NULL) {
		_E("Failed to get launch image");
		free(wl_si);
		return NULL;
	}
	wl_display_flush(wl_ss->display);

	_D("src: %s, type: %s, indicator:%s, rotation: %d",
		ai_ss->src, ai_ss->type,
		ai_ss->indicatordisplay, rots[screen_mode]);
	tizen_launch_image_launch(wl_si->image, ai_ss->src, file_type,
			rots[screen_mode], indicator);
	wl_display_flush(wl_ss->display);

	wl_si->tid = g_timeout_add(3000, __splash_image_timeout_handler, wl_si);

	return wl_si;
}

static void __send_pid_to_wm(struct wl_splash_image *wl_si, int pid)
{
	if (wl_si == NULL)
		return;

	tizen_launch_image_owner(wl_si->image, pid);
}

static void __wl_listener_cb(void *data, struct wl_registry *registry,
		unsigned int id, const char *interface, unsigned int version)
{
	struct wl_splash_screen *wl_ss = (struct wl_splash_screen *)data;

	if (wl_ss == NULL)
		return;

	if (interface && strncmp(interface, "tizen_launchscreen",
				strlen("tizen_launchscreen")) == 0) {
		_D("interface: %s", interface);
		wl_ss->launch_screen = wl_registry_bind(registry, id,
				&tizen_launchscreen_interface, 1);
	}
}

static void __wl_listener_remove_cb(void *data,
		struct wl_registry *registry, unsigned int id)
{
	(void)data;
	(void)registry;
	(void)id;
}

static const struct wl_registry_listener registry_listener = {
	__wl_listener_cb,
	__wl_listener_remove_cb,
};

static struct wl_splash_screen *__init_splash_screen(void)
{
	if (wl_ss)
		return wl_ss;

	if (_wl_is_initialized() == 0)
		return NULL;

	wl_ss = (struct wl_splash_screen *)calloc(1,
			sizeof(struct wl_splash_screen));
	if (wl_ss == NULL) {
		_E("out of memory");
		return NULL;
	}

	wl_ss->display = wl_display_connect(NULL);
	if (wl_ss->display == NULL) {
		_E("Failed to get display");
		free(wl_ss);
		return NULL;
	}

	wl_ss->registry = wl_display_get_registry(wl_ss->display);
	if (wl_ss->registry == NULL) {
		_E("Failed to get registry");
		wl_display_disconnect(wl_ss->display);
		free(wl_ss);
		return NULL;
	}

	wl_registry_add_listener(wl_ss->registry, &registry_listener, NULL);
	wl_display_dispatch(wl_ss->display);
	wl_display_roundtrip(wl_ss->display);

	return wl_ss;
}

int _launch_init()
{
#if 0
	int ret;
#endif
	GError *err = NULL;

	_D("_launch_init");

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

#if 0
	/*
	 * TODO: After applying emit app status signal in enlightenment,
	 *	remove this comment
	 */
	ret = aul_listen_app_status_signal(__app_status_handler, NULL);
	_D("ret : %d", ret);
#endif

	if (__init_splash_screen() == NULL)
		_E("Failed to initialize splash screen");

	return 0;
}

int _send_hint_for_visibility(uid_t uid)
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

int _get_pid_of_last_launched_ui_app()
{
	return __pid_of_last_launched_ui_app;
}

int _start_app(const char* appid, bundle* kb, uid_t caller_uid,
				request_h req, bool *pending)
{
	int ret;
	const struct appinfo *ai;
	const char *status;
	const char *multiple = NULL;
	const char *app_path = NULL;
	const char *pkg_type = NULL;
	const char *pkg_id = NULL;
	const char *component_type = NULL;
	const char *process_pool = NULL;
	const char *tep_name = NULL;
	const char *app_type = NULL;
	int pid = -1;
	char tmpbuf[MAX_PID_STR_BUFSZ];
	const char *hwacc;
	const char *root_path;
	char *caller_appid;
	int lpid = -1;
	int callee_status = -1;
	gboolean can_attach = FALSE;
	gboolean new_process = FALSE;
	app_group_launch_mode launch_mode;
	const char *pad_type = LAUNCHPAD_PROCESS_POOL_SOCK;
	bool is_subapp = false;
	shared_info_h share_handle;
	int cmd = _request_get_cmd(req);
	int caller_pid = _request_get_pid(req);
	struct wl_splash_image *wl_si;

	snprintf(tmpbuf, MAX_PID_STR_BUFSZ, "%d", caller_pid);
	bundle_add(kb, AUL_K_CALLER_PID, tmpbuf);

	snprintf(tmpbuf, MAX_PID_STR_BUFSZ, "%d", caller_uid);
	bundle_add(kb, AUL_K_CALLER_UID, tmpbuf);

	_D("_start_app: caller pid=%d uid=%d", caller_pid, caller_uid);

	if (cmd == APP_START_RES)
		bundle_add(kb, AUL_K_WAIT_RESULT, "1");

	caller_appid = _status_app_get_appid_bypid(caller_pid);
	if (caller_appid != NULL) {
		bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
	} else {
		caller_appid = _status_app_get_appid_bypid(getpgid(caller_pid));
		if (caller_appid != NULL)
			bundle_add(kb, AUL_K_CALLER_APPID, caller_appid);
	}

	ai = appinfo_find(caller_uid, appid);
	if (ai == NULL) {
		_D("cannot find appinfo of %s", appid);
		_request_send_result(req, -ENOENT);
		return -1;
	}

	status = appinfo_get_value(ai, AIT_STATUS);
	if (status == NULL) {
		_request_send_result(req, -1);
		return -1;
	}

	if (!strcmp(status, "blocking")) {
		_D("blocking");
		_request_send_result(req, -EREJECTED);
		return -EREJECTED;
	}

	app_path = appinfo_get_value(ai, AIT_EXEC);
	pkg_type = appinfo_get_value(ai, AIT_PKGTYPE);
	pkg_id = appinfo_get_value(ai, AIT_PKGID);
	process_pool = appinfo_get_value(ai, AIT_POOL);
	app_type = appinfo_get_value(ai, AIT_APPTYPE);

	if ((ret = __compare_signature(ai, cmd, caller_uid, appid, caller_appid, _request_get_fd(req))) != 0)
		return ret;

	multiple = appinfo_get_value(ai, AIT_MULTI);
	if (!multiple || strncmp(multiple, "false", 5) == 0)
		pid = _status_app_is_running(appid, caller_uid);

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type
			&& strncmp(component_type, APP_TYPE_UI, strlen(APP_TYPE_UI)) == 0) {
		pid = __get_pid_for_app_group(appid, pid, caller_uid, kb,
				&lpid, &can_attach, &new_process, &launch_mode, &is_subapp);
		if (pid == -EILLEGALACCESS) {
			_request_send_result(req, pid);
			return pid;
		}
	} else if (component_type
			&& strncmp(component_type, APP_TYPE_SERVICE, strlen(APP_TYPE_SERVICE)) == 0) {
		if (caller_appid) {
			ret = __check_execute_permission(pkg_id,
					caller_appid, caller_uid, kb);
			if (ret != 0) {
				_request_send_result(req, ret);
				return ret;
			}
		}
	}

	share_handle = _temporary_permission_create(caller_pid, appid, kb, caller_uid);
	if (share_handle == NULL)
		_D("No sharable path : %d %s", caller_pid, appid);

	tep_name = appinfo_get_value(ai, AIT_TEP);
	if (tep_name != NULL)
		__send_mount_request(ai, tep_name, kb);

	if (pid > 0)
		callee_status = _status_get_app_info_status(pid, caller_uid);

	if (pid > 0 && callee_status != STATUS_DYING) {
		if (caller_pid == pid) {
			SECURE_LOGD("caller process & callee process is same.[%s:%d]", appid, pid);
			pid = -ELOCALLAUNCH_ID;
			_request_send_result(req, pid);
		} else {
			aul_send_app_resume_request_signal(pid, appid, pkg_id, component_type);
			if ((ret = __nofork_processing(cmd, pid, kb, req)) < 0) {
				pid = ret;
				_request_send_result(req, pid);
			}
		}
	} else {
		if (callee_status == STATUS_DYING && pid > 0) {
			ret = kill(pid, SIGKILL);
			if (ret == -1)
				_W("send SIGKILL: %s", strerror(errno));
			_cleanup_dead_info(pid);
		}

		hwacc = appinfo_get_value(ai, AIT_HWACC);
		root_path = appinfo_get_value(ai, AIT_ROOT_PATH);
		bundle_add(kb, AUL_K_HWACC, hwacc);
		bundle_add(kb, AUL_K_ROOT_PATH, root_path);
		bundle_add(kb, AUL_K_EXEC, app_path);
		bundle_add(kb, AUL_K_PACKAGETYPE, pkg_type);
		bundle_add(kb, AUL_K_PKGID, pkg_id);
		bundle_add(kb, AUL_K_INTERNAL_POOL, process_pool);
		bundle_add(kb, AUL_K_COMP_TYPE, component_type);
		bundle_add(kb, AUL_K_APP_TYPE, app_type);

		if (bundle_get_type(kb, AUL_K_SDK) != BUNDLE_TYPE_NONE)
			pad_type = DEBUG_LAUNCHPAD_SOCK;

		wl_si = __send_image_to_wm(ai, kb, cmd);

		pid = _send_cmd_to_launchpad(pad_type, caller_uid, PAD_CMD_LAUNCH, kb);
		if (pid > 0) {
			*pending = true;
			__send_pid_to_wm(wl_si, pid);
			aul_send_app_launch_request_signal(pid, appid, pkg_id, component_type);
		} else {
			__destroy_splash_image(wl_si);
		}
	}

	if (pid > 0) {
		if (component_type &&
			strncmp(component_type, APP_TYPE_UI, strlen(APP_TYPE_UI)) == 0) {
			if (new_process) {
				_D("add app group info");
				__pid_of_last_launched_ui_app = pid;
				app_group_start_app(pid, kb, lpid, can_attach, launch_mode);
				/* __add_fgmgr_list(pid); */
			} else {
				app_group_restart_app(pid, kb);
			}
		}
		_status_add_app_info_list(appid, app_path, pid, is_subapp, caller_uid);
	}

	if (share_handle) {
		if (pid > 0 && (ret = _temporary_permission_apply(pid, caller_uid, share_handle)) != 0)
			_D("Couldn't apply temporary permission: %d", ret);
		_temporary_permission_destroy(share_handle);
	}

	return pid;
}
