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
#include <string.h>
#include <aul.h>
#include <rua.h>
#include <pkgmgr-info.h>
#include <glib.h>
#include <stdlib.h>
#include <tzplatform_config.h>
#include <bundle.h>
#include <stdbool.h>
#include <systemd/sd-daemon.h>
#include <gio/gio.h>
#include <sys/inotify.h>
#include <Ecore_Wayland.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_app_group.h"
#include "amd_cynara.h"
#include "amd_app_com.h"
#include "amd_share.h"
#include "amd_socket.h"
#include "amd_splash_screen.h"
#include "amd_input.h"

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)
#define AUL_SP_DBUS_PATH "/Org/Tizen/Aul/Syspopup"
#define AUL_SP_DBUS_SIGNAL_INTERFACE "org.tizen.aul.syspopup"
#define AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL "syspopup_launch_request"
#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

struct restart_info {
	char *appid;
	int count;
	guint timer;
};

struct wl_watch {
	int fd;
	int wd_wl;
	int wd_wm;
	GIOChannel *io;
	guint wid;
};

static GHashTable *restart_tbl;
static int wm_ready = 0;
static int wl_0_ready = 0;
static int wl_initialized = 0;

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

static bool __can_restart_app(const char *appid)
{
	const char *pkg_status;
	const char *component_type;
	struct appinfo *ai;
	int r;

	_D("appid: %s", appid);
	ai = appinfo_find(getuid(), appid);
	if (!ai)
		return false;

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (!component_type)
		return false;

	if (strncmp(component_type, APP_TYPE_SERVICE,
				strlen(APP_TYPE_SERVICE)) != 0)
		return false;

	pkg_status = appinfo_get_value(ai, AIT_STATUS);
	if (pkg_status && strncmp(pkg_status, "blocking", 8) == 0) {
		appinfo_set_value(ai, AIT_STATUS, "restart");
	} else if (pkg_status && strncmp(pkg_status, "norestart", 9) == 0) {
		appinfo_set_value(ai, AIT_STATUS, "installed");
	} else {
		r = appinfo_get_boolean(ai, AIT_RESTART);
		if (r && __check_restart(appid))
			return true;
	}

	return false;
}

void _cleanup_dead_info(int pid)
{
	int caller_pid;

	_D("pid: %d", pid);
	app_com_client_remove(pid);
	if (app_group_is_leader_pid(pid)) {
		_W("app_group_leader_app, pid: %d", pid);
		if (app_group_find_second_leader(pid) == -1) {
			app_group_clear_top(pid);
			app_group_set_dead_pid(pid);
			app_group_remove(pid);
		} else {
			app_group_remove_leader_pid(pid);
		}
	} else if (app_group_is_sub_app(pid)) {
		_W("app_group_sub_app, pid: %d", pid);
		caller_pid = app_group_get_next_caller_pid(pid);
		if (app_group_can_reroute(pid)
				|| (caller_pid > 0 && caller_pid != pid)) {
			_W("app_group reroute");
			app_group_reroute(pid);
		} else {
			_W("app_group clear top");
			app_group_clear_top(pid);
		}
		app_group_set_dead_pid(pid);
		app_group_remove(pid);
	}

	_temporary_permission_drop(pid, getuid());
	_status_remove_app_info_list(pid, getuid());
	aul_send_app_terminated_signal(pid);
}

static int __app_dead_handler(int pid, void *data)
{
	bool restart = false;
	char *appid = NULL;
	const char *tmp_appid;

	if (pid <= 0)
		return 0;

	_D("APP_DEAD_SIGNAL : %d", pid);

	tmp_appid = _status_app_get_appid_bypid(pid);
	if (tmp_appid == NULL)
		return 0;

	restart = __can_restart_app(tmp_appid);
	if (restart)
		appid = strdup(tmp_appid);

	_cleanup_dead_info(pid);
	_request_flush_pending_request(pid);

	if (restart)
		_start_app_local(getuid(), appid);
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

	if (g_strcmp0(signal_name, AUL_SP_DBUS_LAUNCH_REQUEST_SIGNAL) != 0)
		return;

	g_variant_get(parameters, "(ss)", &appid, &b_raw);
	_D("syspopup launch request: %s", appid);

	kb = bundle_decode((const bundle_raw *)b_raw, strlen(b_raw));
	if (kb) {
		if (_start_app_local_with_bundle(getuid(), appid, kb) < 0)
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

int _wl_is_initialized(void)
{
	return wl_initialized;
}

static gboolean __wl_monitor_cb(GIOChannel *io, GIOCondition cond, gpointer data)
{
	char buf[INOTIFY_BUF];
	ssize_t len = 0;
	int i = 0;
	struct inotify_event *event;
	char *p;
	int fd = g_io_channel_unix_get_fd(io);

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		_E("Failed to read");
		return TRUE;
	}

	while (i < len) {
		event = (struct inotify_event *)&buf[i];
		if (event->len) {
			p = event->name;
			if (p &&
				!strncmp(p, "wayland-0", strlen("wayland-0"))) {
				_D("%s is created", p);
				wl_0_ready = 1;
			} else if (p &&
				!strncmp(p, ".wm_ready", strlen(".wm_ready"))) {
				_D("%s is created", p);
				wm_ready = 1;
			}

			if (wm_ready && wl_0_ready) {
				wl_initialized = 1;
				return FALSE;
			}
		}
		i += offsetof(struct inotify_event, name) + event->len;
	}

	return TRUE;
}

static void __wl_watch_destroy_cb(gpointer data)
{
	struct wl_watch *watch = (struct wl_watch *)data;

	if (watch == NULL)
		return;

	g_io_channel_unref(watch->io);

	if (watch->wd_wm)
		inotify_rm_watch(watch->fd, watch->wd_wm);
	if (watch->wd_wl)
		inotify_rm_watch(watch->fd, watch->wd_wl);
	close(watch->fd);
	free(watch);
}

static void __init_wl(void)
{
	char buf[PATH_MAX];
	struct wl_watch *watch;

	snprintf(buf, sizeof(buf), "/run/user/%d/wayland-0", getuid());
	if (access(buf, F_OK) == 0) {
		_D("%s exists", buf);
		wl_0_ready = 1;
	}

	if (access("/run/.wm_ready", F_OK) == 0) {
		_D("/run/.wm_ready exists");
		wm_ready = 1;
	}

	if (wm_ready && wl_0_ready) {
		wl_initialized = 1;
		return;
	}

	watch = (struct wl_watch *)calloc(1, sizeof(struct wl_watch));
	if (watch == NULL) {
		_E("out of memory");
		return;
	}

	watch->fd = inotify_init();
	if (watch->fd < 0) {
		_E("Failed to initialize inotify");
		free(watch);
		return;
	}

	if (!wl_0_ready) {
		snprintf(buf, sizeof(buf), "/run/user/%d", getuid());
		watch->wd_wl = inotify_add_watch(watch->fd, buf, IN_CREATE);
		if (watch->wd_wl < 0) {
			_E("Failed to add inotify watch");
			close(watch->fd);
			free(watch);
			return;
		}
	}

	if (!wm_ready) {
		watch->wd_wm = inotify_add_watch(watch->fd, "/run", IN_CREATE);
		if (watch->wd_wm < 0) {
			_E("Failed to add inotify watch");
			if (watch->wd_wl)
				inotify_rm_watch(watch->fd, watch->wd_wl);
			close(watch->fd);
			free(watch);
			return;
		}
	}

	watch->io = g_io_channel_unix_new(watch->fd);
	if (watch->io == NULL) {
		_E("Failed to create GIOChannel");
		if (watch->wd_wm)
			inotify_rm_watch(watch->fd, watch->wd_wm);
		if (watch->wd_wl)
			inotify_rm_watch(watch->fd, watch->wd_wl);
		close(watch->fd);
		free(watch);
		return;
	}

	watch->wid = g_io_add_watch_full(watch->io, G_PRIORITY_DEFAULT,
			G_IO_IN, __wl_monitor_cb, watch, __wl_watch_destroy_cb);
}

static int __init(void)
{
	int r;
	bundle *b;

	if (appinfo_init()) {
		_E("appinfo_init failed");
		return -1;
	}

	if (aul_listen_app_dead_signal(__app_dead_handler, NULL)) {
		_E("aul_listen_app_dead_signal failed");
		return -1;
	}

	restart_tbl = g_hash_table_new(g_str_hash, g_str_equal);

	r = init_cynara();
	if (r != 0) {
		_E("cynara initialize failed.");
		return -1;
	}

	__init_wl();
	_request_init();
	_status_init();
	app_group_init();
	r = rua_delete_history_from_db(NULL);
	_D("rua_delete_history : %d", r);

	app_com_broker_init();
	_launch_init();
	_splash_screen_init();
	_input_init();

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

	app_com_broker_fini();
	_input_fini();
	return 0;
}
