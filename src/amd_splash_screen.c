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
#include <stdbool.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "amd_splash_screen.h"

#define K_FAKE_EFFECT "__FAKE_EFFECT__"
#define APP_CONTROL_OPERATION_MAIN "http://tizen.org/appcontrol/operation/main"

struct splash_screen {
	struct wl_display *display;
	struct wl_registry *registry;
	struct tizen_launchscreen *screen;
};

struct splash_image {
	struct tizen_launch_image *image;
	char *src;
	int type;
	int rotation;
	int indicator;
	guint tid;
};

static GDBusConnection *conn;
static struct splash_screen *splash_s = NULL;
static int rotate_allowed = 0;

extern int _wl_is_initialized(void);
static struct splash_screen *__init_splash_screen(void);
static struct splash_screen *__get_splash_screen(void);

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

void _splash_screen_destroy_image(splash_image_h si)
{
	struct splash_screen *ss;

	if (si == NULL)
		return;

	if (si->src)
		free(si->src);
	if (si->tid > 0)
		g_source_remove(si->tid);
	if (si->image) {
		ss = __get_splash_screen();
		tizen_launch_image_destroy(si->image);
		wl_display_flush(ss->display);
	}
	free(si);
}

static gboolean __splash_image_timeout_handler(gpointer data)
{
	splash_image_h si = (splash_image_h)data;

	_splash_screen_destroy_image(si);

	return FALSE;
}

static int __app_can_launch_splash_image(const struct appinfo *ai,
		bundle *kb, int cmd)
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
	if ((screen_mode == 2 || screen_mode == 4) && rotate_allowed == true)
		return (struct appinfo_splash_screen *)appinfo_get_value(ai,
						AIT_LANDSCAPE_SPLASH_SCREEN);

	return (struct appinfo_splash_screen *)appinfo_get_value(ai,
			AIT_PORTRAIT_SPLASH_SCREEN);
}

splash_image_h _splash_screen_create_image(const struct appinfo *ai,
		bundle *kb, int cmd)
{
	struct splash_image *si;
	struct splash_screen *ss;
	struct appinfo_splash_screen *ai_ss;
	int rots[] = {0, 90, 180, 270};
	int screen_mode;
	int file_type = 0;
	int indicator = 1;

	ss = __get_splash_screen();
	if (ss == NULL || ss->screen == NULL)
		return NULL;

	if (__app_can_launch_splash_image(ai, kb, cmd) < 0)
		return NULL;

	screen_mode = __invoke_dbus_method_call(ROTATION_BUS_NAME,
						ROTATION_OBJECT_PATH,
						ROTATION_INTERFACE_NAME,
						ROTATION_METHOD_NAME,
						g_variant_new("(i)", 0));
	_D("screen_mode: %d", screen_mode);
	if (screen_mode < 1)
		screen_mode = 1;
	if (rotate_allowed == false)
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

	si = (struct splash_image *)calloc(1,
			sizeof(struct splash_image));
	if (si == NULL) {
		_E("out of memory");
		return NULL;
	}

	si->image = tizen_launchscreen_create_img(ss->screen);
	if (si->image == NULL) {
		_E("Failed to get launch image");
		free(si);
		return NULL;
	}
	wl_display_flush(ss->display);

	si->src = strdup(ai_ss->src);
	if (si->src == NULL) {
		_E("out of memory");
		_splash_screen_destroy_image(si);
		return NULL;
	}

	si->type = file_type;
	si->rotation = rots[screen_mode - 1];
	si->indicator = indicator;
	si->tid = g_timeout_add(3000, __splash_image_timeout_handler, si);

	return si;
}

void _splash_screen_send_image(splash_image_h si)
{
	struct splash_screen *ss;

	if (si == NULL)
		return;

	ss = __get_splash_screen();
	tizen_launch_image_launch(si->image, si->src, si->type,
			si->rotation, si->indicator);
	wl_display_flush(ss->display);
}

void _splash_screen_send_pid(splash_image_h si, int pid)
{
	struct splash_screen *ss;

	if (si == NULL)
		return;

	ss = __get_splash_screen();
	tizen_launch_image_owner(si->image, pid);
	wl_display_flush(ss->display);
}

static struct splash_screen *__get_splash_screen(void)
{
	if (splash_s)
		return splash_s;

	return __init_splash_screen();
}

static void __wl_listener_cb(void *data, struct wl_registry *registry,
		unsigned int id, const char *interface, unsigned int version)
{
	struct splash_screen *ss = (struct splash_screen *)data;

	if (ss == NULL)
		return;

	if (interface && strncmp(interface, "tizen_launchscreen",
				strlen("tizen_launchscreen")) == 0) {
		_D("interface: %s", interface);
		ss->screen = wl_registry_bind(registry, id,
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

static struct splash_screen *__init_splash_screen(void)
{
	if (!_wl_is_initialized())
		return NULL;

	splash_s = (struct splash_screen *)calloc(1,
			sizeof(struct splash_screen));
	if (splash_s == NULL) {
		_E("out of memory");
		return NULL;
	}

	splash_s->display = wl_display_connect(NULL);
	if (splash_s->display == NULL) {
		_E("Failed to get display");
		free(splash_s);
		return NULL;
	}

	splash_s->registry = wl_display_get_registry(splash_s->display);
	if (splash_s->registry == NULL) {
		_E("Failed to get registry");
		wl_display_disconnect(splash_s->display);
		free(splash_s);
		return NULL;
	}

	wl_registry_add_listener(splash_s->registry,
				&registry_listener, splash_s);
	wl_display_dispatch(splash_s->display);
	wl_display_roundtrip(splash_s->display);

	return splash_s;
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

int _splash_screen_init(void)
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

	if (!__init_splash_screen())
		_E("Failed to initialize splash screen");

	vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
						&rotate_allowed);
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
				__vconf_cb, NULL) != 0)
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL);

	return 0;
}
