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

#define _GNU_SOURCE
#include <bundle.h>
#include <bundle_internal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <glib.h>
#include <gio/gio.h>
#include <aul_cmd.h>
#include <aul_svc_priv_key.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>
#include <vconf.h>

#include "app_signal.h"
#include "amd_config.h"
#include "amd_appinfo.h"
#include "amd_util.h"
#include "amd_wayland.h"

#define K_FAKE_EFFECT "__FAKE_EFFECT__"
#define APP_CONTROL_OPERATION_MAIN "http://tizen.org/appcontrol/operation/main"
#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

struct wl_watch {
	int fd;
	int wd;
	GIOChannel *io;
	guint wid;
};

struct wl_splash_screen {
	struct wl_display *display;
	struct wl_registry *registry;
	struct tizen_launchscreen *screen;
};

static GDBusConnection *conn;
static int wl_initialized = 0;
static struct wl_splash_screen *wl_ss = NULL;
static int rotate_allowed = 0;

static struct wl_splash_screen *__init_splash_screen(void);

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

void _destroy_splash_image(struct wl_splash_image *wl_si)
{
	if (wl_si == NULL)
		return;

	if (wl_si->tid > 0)
		g_source_remove(wl_si->tid);
	if (wl_si->image) {
		tizen_launch_image_destroy(wl_si->image);
		wl_display_flush(wl_ss->display);
	}
	free(wl_si);
}

static gboolean __splash_image_timeout_handler(gpointer data)
{
	struct wl_splash_image *wl_si = (struct wl_splash_image *)data;

	_destroy_splash_image(wl_si);

	return FALSE;
}

static int __app_can_launch_splash_image(const struct appinfo *ai, bundle *kb, int cmd)
{
	const char *fake_effect;
	const char *component_type;
	const char *operation;

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strncmp(component_type, APP_TYPE_UI,
				strlen(APP_TYPE_UI)) != 0) {
		_D("component_type: %s", component_type);
		return -1;
	}

	if (cmd == APP_OPEN)
		return 0;

	fake_effect = bundle_get_val(kb, K_FAKE_EFFECT);
	if (fake_effect == NULL) {
		_D("fake_effect is NULL");
		return -1;
	}

	if (strncmp(fake_effect, "OFF", strlen("OFF")) == 0) {
		_D("fake effect off");
		return -1;
	}

	operation = bundle_get_val(kb, AUL_SVC_K_OPERATION);
	if (operation == NULL) {
		_D("operation is NULL");
		return -1;
	}

	if (strncmp(operation, APP_CONTROL_OPERATION_MAIN,
				strlen(APP_CONTROL_OPERATION_MAIN)) != 0) {
		_D("operation is not %s", APP_CONTROL_OPERATION_MAIN);
		return -1;
	}

	return 0;
}

static struct appinfo_splash_screen *__get_splash_screen_info(
		const struct appinfo *ai, int screen_mode)
{
	if (screen_mode == 1 || screen_mode == 3)
		return (struct appinfo_splash_screen *)appinfo_get_value(ai,
						AIT_PORTRAIT_SPLASH_SCREEN);
	else if (screen_mode == 2 || screen_mode == 4)
		return (struct appinfo_splash_screen *)appinfo_get_value(ai,
						AIT_LANDSCAPE_SPLASH_SCREEN);

	return NULL;
}

struct wl_splash_image *_send_image_to_wm(const struct appinfo *ai,
		bundle *kb, int cmd)
{
	struct wl_splash_image *wl_si;
	struct wl_splash_screen *wl_ss;
	struct appinfo_splash_screen *ai_ss;
	int rots[] = {0, 90, 180, 270};
	int screen_mode;
	int file_type = 0;
	int indicator = 1;

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
	if (screen_mode == -1)
		screen_mode = 1;
	if (rotate_allowed == 0)
		screen_mode = 1;

	ai_ss = __get_splash_screen_info(ai, screen_mode);
	if (ai_ss == NULL)
		return NULL;

	if (access(ai_ss->src, F_OK) != 0)
		return NULL;

	if (strncmp(ai_ss->type, "edj", strlen("edj")) == 0)
		file_type = 1;
	if (strncmp(ai_ss->indicatordisplay, "false", strlen("false")) == 0)
		indicator = 0;

	wl_si = (struct wl_splash_image *)calloc(1,
			sizeof(struct wl_splash_image));
	if (wl_si == NULL) {
		_E("out of memory");
		return NULL;
	}

	wl_si->image = tizen_launchscreen_create_img(wl_ss->screen);
	if (wl_si->image == NULL) {
		_E("Failed to get launch image");
		free(wl_si);
		return NULL;
	}
	wl_display_flush(wl_ss->display);

	tizen_launch_image_launch(wl_si->image, ai_ss->src, file_type,
			rots[screen_mode - 1], indicator);
	wl_display_flush(wl_ss->display);

	wl_si->tid = g_timeout_add(3000, __splash_image_timeout_handler, wl_si);

	return wl_si;
}

void _send_pid_to_wm(struct wl_splash_image *wl_si, int pid)
{
	if (wl_si == NULL || wl_si->image == NULL)
		return;

	tizen_launch_image_owner(wl_si->image, pid);
	wl_display_flush(wl_ss->display);
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
		wl_ss->screen = wl_registry_bind(registry, id,
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

	wl_registry_add_listener(wl_ss->registry, &registry_listener, wl_ss);
	wl_display_dispatch(wl_ss->display);
	wl_display_roundtrip(wl_ss->display);

	return wl_ss;
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
			if (p && !strncmp(p, "wayland-0", strlen("wayland-0"))) {
				_D("%s exists", p);
				wl_initialized = 1;
				return FALSE;
			}
		}
		i += sizeof(struct inotify_event) + event->len;
	}

	return TRUE;
}

static void __wl_watch_destroy_cb(gpointer data)
{
	struct wl_watch *watch = (struct wl_watch *)data;

	if (watch == NULL)
		return;

	g_io_channel_unref(watch->io);
	inotify_rm_watch(watch->fd, watch->wd);
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
		wl_initialized = 1;
		return;
	}

	snprintf(buf, sizeof(buf), "/run/user/%d", getuid());

	watch = (struct wl_watch *)calloc(1, sizeof(struct wl_watch));
	if (watch == NULL) {
		_E("out of memory");
		return;
	}

	watch->fd = inotify_init();
	watch->wd = inotify_add_watch(watch->fd, buf, IN_CREATE);
	watch->io = g_io_channel_unix_new(watch->fd);
	watch->wid = g_io_add_watch_full(watch->io, G_PRIORITY_DEFAULT,
			G_IO_IN, __wl_monitor_cb, watch, __wl_watch_destroy_cb);
}

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name == NULL)
		return;
	else if (strcmp(name, VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL) == 0)
		rotate_allowed = vconf_keynode_get_bool(key);
}

int _wayland_init(void)
{
	GError *err = NULL;

	_D("init wayland");

	if (!conn) {
		conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
		if (!conn) {
			_E("g_bus_get_sync() is failed: %s", err->message);
			g_error_free(err);
			return -1;
		}
	}

	__init_wl();

	if (__init_splash_screen() == NULL)
		_E("Failed to initialize splash screen");

	vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
						&rotate_allowed);
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
				__vconf_cb, NULL) != 0)
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL);

	return 0;
}
