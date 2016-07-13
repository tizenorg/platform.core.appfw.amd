/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <stdio.h>
#include <sys/stat.h>

#include <gio/gio.h>

#include "app_signal.h"
#include "amd_config.h"
#include "amd_util.h"
#include "amd_signal.h"

#define MAX_LABEL_BUFSZ 1024

static GDBusConnection *conn;

int _signal_init(void)
{
	GError *err = NULL;

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	return 0;
}

int _signal_send_watchdog(int pid, int signal_num)
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

int _signal_send_proc_prelaunch(const char *appid, const char *pkgid,
		int attribute, int category)
{
	GError *err = NULL;
	GVariant *param;

	if (conn == NULL) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (conn == NULL) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	param = g_variant_new("(ssii)", appid, pkgid, attribute, category);
	if (g_dbus_connection_emit_signal(conn,
					NULL,
					RESOURCED_PROC_OBJECT,
					RESOURCED_PROC_INTERFACE,
					RESOURCED_PROC_PRELAUNCH_SIGNAL,
					param,
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

	_W("send a prelaunch signal done: " \
			"appid(%s) pkgid(%s) attribute(%x) category(%x)",
			appid, pkgid, attribute, category);

	return 0;
}

int _signal_send_tep_mount(char *mnt_path[], const char *pkgid)
{
	GError *err = NULL;
	GDBusMessage *msg = NULL;
	int ret = 0;
	int rv = 0;
	struct stat link_buf = {0,};
	GVariant *param;
	char buf[MAX_LABEL_BUFSZ];

	if (pkgid == NULL) {
		_E("Invalid parameter");
		return -1;
	}

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

	snprintf(buf, sizeof(buf), "User::Pkg::%s::RO", pkgid);
	param = g_variant_new("(sss)", mnt_path[0], mnt_path[1], buf);
	g_dbus_message_set_body(msg, param);

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

int _signal_send_tep_unmount(const char *mnt_path)
{
	GError *err = NULL;
	GDBusMessage *msg = NULL;

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	msg = g_dbus_message_new_method_call(TEP_BUS_NAME,
					TEP_OBJECT_PATH,
					TEP_INTERFACE_NAME,
					TEP_UNMOUNT_METHOD);
	if (msg == NULL) {
		_E("g_dbus_message_new_method_call() is failed.");
		return -1;
	}

	g_dbus_message_set_body(msg, g_variant_new("(s)", mnt_path));
	if (g_dbus_connection_send_message(conn,
					msg,
					G_DBUS_SEND_MESSAGE_FLAGS_NONE,
					NULL,
					&err) == FALSE) {
		_E("g_dbus_connection_send_message() is failed: %s",
					err->message);
		g_object_unref(msg);
		g_clear_error(&err);
		return -1;
	}

	if (msg)
		g_object_unref(msg);
	g_clear_error(&err);

	return 0;
}

int _signal_send_proc_suspend(int pid)
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
					APPFW_SUSPEND_HINT_PATH,
					APPFW_SUSPEND_HINT_INTERFACE,
					APPFW_SUSPEND_HINT_SIGNAL,
					g_variant_new("(i)", pid),
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

	_D("[__SUSPEND__] Send suspend hint, pid: %d", pid);

	return 0;
}

