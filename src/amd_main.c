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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <aul.h>
#include <rua_internal.h>
#include <pkgmgr-info.h>
#include <glib.h>
#include <tzplatform_config.h>
#include <bundle.h>
#include <systemd/sd-daemon.h>
#include <gio/gio.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_app_group.h"
#include "amd_cynara.h"
#include "amd_app_com.h"
#include "amd_share.h"
#include "amd_socket.h"
#include "amd_splash_screen.h"
#include "amd_input.h"
#include "amd_signal.h"
#include "amd_wayland.h"
#include "amd_extractor.h"
#include "amd_suspend.h"
#include "amd_app_data.h"

#define AUL_SP_DBUS_PATH "/Org/Tizen/Aul/Syspopup"
#define AUL_SP_DBUS_SIGNAL_INTERFACE "org.tizen.aul.syspopup"
#define AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL "syspopup_launch_request"

struct restart_info {
	char *appid;
	int count;
	guint timer;
};

static GHashTable *restart_tbl;

static gboolean __restart_timeout_handler(void *data)
{
	struct restart_info *ri = (struct restart_info *)data;

	_D("ri (%x)", ri);
	_D("appid (%s)", ri->appid);

	g_hash_table_remove(restart_tbl, ri->appid);
	free(ri->appid);
	free(ri);

	return FALSE;
}

static bool __check_restart(const char *appid)
{
	struct restart_info *ri = NULL;
	char err_buf[1024];

	ri = g_hash_table_lookup(restart_tbl, appid);
	if (!ri) {
		ri = malloc(sizeof(struct restart_info));
		if (!ri) {
			_E("create restart info: %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			return false;
		}
		memset(ri, 0, sizeof(struct restart_info));
		ri->appid = strdup(appid);
		ri->count = 1;
		g_hash_table_insert(restart_tbl, ri->appid, ri);

		_D("ri (%x)", ri);
		_D("appid (%s)", appid);

		ri->timer = g_timeout_add(10 * 1000, __restart_timeout_handler,
				ri);
	} else {
		ri->count++;
		_D("count (%d)", ri->count);
		if (ri->count > 5) {
			g_source_remove(ri->timer);
			g_hash_table_remove(restart_tbl, ri->appid);
			free(ri->appid);
			free(ri);
			return false;
		}
	}
	return true;
}

static bool __can_restart_app(const char *appid, uid_t uid)
{
	const char *pkg_status;
	const char *component_type;
	struct appinfo *ai;
	int r;
	int val = 0;

	_D("appid: %s", appid);
	ai = _appinfo_find(uid, appid);
	if (!ai)
		return false;

	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (!component_type)
		return false;

	if (strncmp(component_type, APP_TYPE_SERVICE,
				strlen(APP_TYPE_SERVICE)) != 0)
		return false;

	pkg_status = _appinfo_get_value(ai, AIT_STATUS);
	if (pkg_status && strcmp(pkg_status, "blocking") == 0) {
		_appinfo_set_value(ai, AIT_STATUS, "restart");
	} else if (pkg_status && strcmp(pkg_status, "norestart") == 0) {
		_appinfo_set_value(ai, AIT_STATUS, "installed");
	} else {
		r = _appinfo_get_int_value(ai, AIT_RESTART, &val);
		if (r == 0 && val && __check_restart(appid))
			return true;
	}

	return false;
}

void _cleanup_dead_info(app_status_h app_status)
{
	int pid;
	int caller_pid;
	uid_t uid;

	if (app_status == NULL)
		return;

	pid = _app_status_get_pid(app_status);
	uid = _app_status_get_uid(app_status);

	_D("pid: %d, uid: %d", pid, uid);
	_extractor_unmount(pid, _extractor_mountable_get_tep_paths);
	_extractor_unmount(pid, _extractor_mountable_get_tpk_paths);
	_app_com_client_remove(pid);
	if (_app_group_is_leader_pid(pid)) {
		_W("app_group_leader_app, pid: %d", pid);
		if (_app_group_find_second_leader(pid) == -1) {
			_app_group_clear_top(pid);
			_app_group_set_dead_pid(pid);
			_app_group_remove(pid);
		} else {
			_app_group_remove_leader_pid(pid);
		}
	} else if (_app_group_is_sub_app(pid)) {
		_W("app_group_sub_app, pid: %d", pid);
		caller_pid = _app_group_get_next_caller_pid(pid);
		if (_app_group_can_reroute(pid)
				|| (caller_pid > 0 && caller_pid != pid)) {
			_W("app_group reroute");
			_app_group_reroute(pid);
		} else {
			_W("app_group clear top");
			_app_group_clear_top(pid);
		}
		_app_group_set_dead_pid(pid);
		_app_group_remove(pid);
	}

	_temporary_permission_drop(pid, uid);
	_app_data_cleanup(pid, uid);
	_app_status_remove(app_status);
	aul_send_app_terminated_signal(pid);
}

static int __app_dead_handler(int pid, void *data)
{
	bool restart = false;
	char *appid = NULL;
	const char *tmp_appid;
	app_status_h app_status;
	uid_t uid;

	if (pid <= 0)
		return 0;

	_D("APP_DEAD_SIGNAL : %d", pid);

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return 0;

	tmp_appid = _app_status_get_appid(app_status);
	if (tmp_appid == NULL)
		return 0;

	uid = _app_status_get_uid(app_status);
	restart = __can_restart_app(tmp_appid, uid);
	if (restart)
		appid = strdup(tmp_appid);

	_cleanup_dead_info(app_status);
	_request_flush_pending_request(pid);

	if (restart)
		_launch_start_app_local(uid, appid);
	if (appid)
		free(appid);

	return 0;
}

static void __syspopup_signal_handler(GDBusConnection *conn,
				const gchar *sender_name,
				const gchar *object_path,
				const gchar *interface_name,
				const gchar *signal_name,
				GVariant *parameters,
				gpointer data)
{
	gchar *appid = NULL;
	gchar *b_raw = NULL;
	bundle *kb;
	int ret;

	if (g_strcmp0(signal_name, AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL) != 0)
		return;

	g_variant_get(parameters, "(ss)", &appid, &b_raw);
	_D("syspopup launch request: %s", appid);

	kb = bundle_decode((bundle_raw *)b_raw, strlen(b_raw));
	if (kb) {
		ret = _launch_start_app_local_with_bundle(getuid(), appid, kb);
		if (ret < 0)
			_E("syspopup launch request failed: %s", appid);

		bundle_free(kb);
	}

	g_free(appid);
	g_free(b_raw);
}

static int __syspopup_dbus_signal_handler_init(void)
{
	GError *error = NULL;
	GDBusConnection *conn;
	guint subscription_id;

	conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (conn == NULL) {
		_E("Failed to connect to the D-BUS Daemon: %s", error->message);
		g_error_free(error);
		return -1;
	}

	subscription_id = g_dbus_connection_signal_subscribe(conn,
					NULL,
					AUL_SP_DBUS_SIGNAL_INTERFACE,
					AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL,
					AUL_SP_DBUS_PATH,
					NULL,
					G_DBUS_SIGNAL_FLAGS_NONE,
					__syspopup_signal_handler,
					NULL,
					NULL);
	if (subscription_id == 0) {
		_E("g_dbus_connection_signal_subscribe() is failed.");
		g_object_unref(conn);
		return -1;
	}

	_D("syspopup dbus signal initialized");

	return 0;
}

static int __init(void)
{
	int r;
	bundle *b;

	if (_appinfo_init()) {
		_E("_appinfo_init failed");
		return -1;
	}

	if (aul_listen_app_dead_signal(__app_dead_handler, NULL)) {
		_E("aul_listen_app_dead_signal failed");
		return -1;
	}

	restart_tbl = g_hash_table_new(g_str_hash, g_str_equal);

	r = _cynara_init();
	if (r != 0) {
		_E("cynara initialize failed.");
		return -1;
	}

	_request_init();
	_app_status_init();
	_app_group_init();
	r = rua_db_delete_history(NULL);
	_D("rua_delete_history : %d", r);

	_app_com_broker_init();
	_launch_init();
	_splash_screen_init();
	_input_init();
	_wayland_init();
	_suspend_init();
	_app_data_init();

	if (__syspopup_dbus_signal_handler_init() < 0)
		_E("__syspopup_dbus_signal_handler_init failed");

	b = bundle_create();
	if (b == NULL) {
		_E("failed to make a bundle");
		return -1;
	}

	r = _send_cmd_to_launchpad(LAUNCHPAD_PROCESS_POOL_SOCK,
			getuid(), PAD_CMD_MAKE_DEFAULT_SLOTS, b);
	if (r != 0)
		_E("failed to make default slots");

	bundle_free(b);
	return 0;
}

static void __ready(void)
{
	int fd;
	char path[PATH_MAX];

	_D("AMD is ready");

	snprintf(path, sizeof(path), "/run/user/%d/.amd_ready", getuid());

	fd = creat(path,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if (fd != -1)
		close(fd);

	sd_notify(0, "READY=1");
}

static void __finish(void)
{
	_app_data_fini();
	_suspend_fini();
	_wayland_finish();
	_input_fini();
	_app_com_broker_fini();
	_cynara_finish();
	_app_status_finish();
}

int main(int argc, char *argv[])
{
	GMainLoop *mainloop = NULL;

	if (__init() != 0) {
		_E("AMD Initialization failed!\n");
		return -1;
	}

	__ready();

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("failed to create glib main loop");
		return -1;
	}
	g_main_loop_run(mainloop);

	__finish();

	return 0;
}

