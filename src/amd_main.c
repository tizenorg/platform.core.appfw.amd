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
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <aul.h>
#include <pkgmgr-info.h>
#include <glib.h>
#include <stdlib.h>
#include <tzplatform_config.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <bundle.h>
#include <stdbool.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_app_group.h"

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define AUL_SP_DBUS_PATH "/Org/Tizen/Aul/Syspopup"
#define AUL_SP_DBUS_SIGNAL_INTERFACE "org.tizen.aul.syspopup"
#define AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL "syspopup_launch_request"

struct restart_info {
	char *appid;
	int count;
	guint timer;
};

static GHashTable *restart_tbl;

static int __init(void);

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

	ri = g_hash_table_lookup(restart_tbl, appid);
	if (!ri) {
		ri = malloc(sizeof(struct restart_info));
		if (!ri) {
			_E("create restart info: %s", strerror(errno));
			return false;
		}
		memset(ri, 0, sizeof(struct restart_info));
		ri->appid = strdup(appid);
		ri->count = 1;
		g_hash_table_insert(restart_tbl, ri->appid, ri);

		_D("ri (%x)", ri);
		_D("appid (%s)", appid);

		ri->timer = g_timeout_add(10 * 1000, __restart_timeout_handler, ri);
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

static bool __can_restart_app(int pid)
{
	const char *pkg_status;
	const char *appid = NULL;
	const struct appinfo *ai = NULL;

	appid = _status_app_get_appid_bypid(pid);

	if (!appid)
		return false;

	ai = appinfo_find(getuid(), appid);
	pkg_status = appinfo_get_value(ai, AIT_STATUS);
	_D("appid: %s", appid);

	if (ai && pkg_status && strncmp(pkg_status, "blocking", 8) == 0) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "restart");
	} else if (ai && pkg_status && strncmp(pkg_status, "norestart", 9) == 0) {
		appinfo_set_value((struct appinfo *)ai, AIT_STATUS, "installed");
	} else {
		int r = appinfo_get_boolean(ai, AIT_RESTART);

		if (r && __check_restart(appid))
			return true;
	}

	return false;
}

static int __app_dead_handler(int pid, void *data)
{
	if (pid <= 0)
		return 0;

	 _D("APP_DEAD_SIGNAL : %d", pid);

	bool restart;
	char *appid = NULL;
	const char *tmp_appid;

	restart =  __can_restart_app(pid);
	if (restart) {
		tmp_appid = _status_app_get_appid_bypid(pid);

		if (tmp_appid)
			appid = strdup(tmp_appid);
	}

	if (app_group_is_leader_pid(pid)) {
		_W("app_group_leader_app, pid: %d", pid);
		if (app_group_find_second_leader(pid) == -1) {
			app_group_clear_top(pid);
			app_group_set_dead_pid(pid);
			app_group_remove(pid);
		} else
			app_group_remove_leader_pid(pid);
	} else if (app_group_is_sub_app(pid)) {
		_W("app_group_sub_app, pid: %d", pid);
		int caller_pid = app_group_get_next_caller_pid(pid);

		if (app_group_can_reroute(pid) || (caller_pid > 0 && caller_pid != pid)) {
			_W("app_group reroute");
			app_group_reroute(pid);
		} else {
			_W("app_group clear top");
			app_group_clear_top(pid);
		}
		app_group_set_dead_pid(pid);
		app_group_remove(pid);
	}

	_status_remove_app_info_list(pid, getuid());
	_request_flush_pending_request(pid);
	aul_send_app_terminated_signal(pid);

	if (restart)
		_start_app_local(getuid(), appid);
	if (appid)
		free(appid);

	return 0;
}

int __agent_dead_handler(uid_t user)
{
	_status_remove_app_info_list_with_uid(user);
	return 0;
}

static DBusHandlerResult __syspopup_signal_filter(DBusConnection *conn,
				DBusMessage *message, void *data)
{
	DBusError error;
	const char *interface;
	const char *appid;
	const char *b_raw;
	bundle *kb;

	dbus_error_init(&error);

	interface = dbus_message_get_interface(message);
	if (interface == NULL) {
		_E("reject by security issue - no interface");
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	}

	if (dbus_message_is_signal(message, interface,
				AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL)) {
		if (dbus_message_get_args(message, &error, DBUS_TYPE_STRING, &appid,
				DBUS_TYPE_STRING, &b_raw, DBUS_TYPE_INVALID) == FALSE) {
			_E("Failed to get data: %s", error.message);
			dbus_error_free(&error);
			return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
		}

		_D("syspopup launch request: %s", appid);
		kb = bundle_decode((const bundle_raw *)b_raw, strlen(b_raw));
		if (kb) {
			if (_start_app_local_with_bundle(getuid(), appid, kb) < 0)
				_E("syspopup launch request failed: %s", appid);

			bundle_free(kb);
		}
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static int __syspopup_dbus_signal_handler_init(void)
{
	DBusError error;
	DBusConnection *conn;
	char rule[MAX_LOCAL_BUFSZ];

	dbus_error_init(&error);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (conn == NULL) {
		_E("Failed to connect to the D-BUS Daemon: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	dbus_connection_setup_with_g_main(conn, NULL);

	snprintf(rule, sizeof(rule), "path='%s',type='signal',interface='%s'",
			AUL_SP_DBUS_PATH, AUL_SP_DBUS_SIGNAL_INTERFACE);
	dbus_bus_add_match(conn, rule, &error);
	if (dbus_error_is_set(&error)) {
		_E("Failed to rule set: %s", error.message);
		dbus_error_free(&error);
		return -1;
	}

	if (dbus_connection_add_filter(conn,
				__syspopup_signal_filter, NULL, NULL) == FALSE) {
		_E("Failed to add filter");
		return -1;
	}

	_D("syspopup dbus signal initialized");

	return 0;
}

static int __init(void)
{
	if (appinfo_init()) {
		_E("appinfo_init failed\n");
		return -1;
	}

	if (aul_listen_app_dead_signal(__app_dead_handler, NULL)) {
		_E("aul_listen_app_dead_signal failed");
		return -1;
	}

	restart_tbl = g_hash_table_new(g_str_hash, g_str_equal);
	_request_init();
	_status_init();
	app_group_init();

	if (__syspopup_dbus_signal_handler_init() < 0)
		 _E("__syspopup_dbus_signal_handler_init failed");

	return 0;
}

int main(int argc, char *argv[])
{
	GMainLoop *mainloop = NULL;

	if (__init() != 0) {
		_E("AMD Initialization failed!\n");
		return -1;
	}

	mainloop = g_main_loop_new(NULL, FALSE);
	if (!mainloop) {
		_E("failed to create glib main loop");
		return -1;
	}
	g_main_loop_run(mainloop);

	return 0;
}
