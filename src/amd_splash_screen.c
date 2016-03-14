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
#include <unistd.h>
#include <aul_cmd.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>
#include <vconf.h>
#include <sensor_internal.h>

#include "amd_config.h"
#include "amd_appinfo.h"
#include "amd_util.h"
#include "amd_splash_screen.h"

#define K_FAKE_EFFECT "__FAKE_EFFECT__"
#define APP_CONTROL_OPERATION_MAIN "http://tizen.org/appcontrol/operation/main"

struct splash_screen_s {
	struct wl_display *display;
	struct wl_registry *registry;
	struct tizen_launchscreen *screen;
};

struct splash_image_s {
	struct tizen_launch_image *image;
	char *src;
	int type;
	int rotation;
	int indicator;
	guint tid;
};

struct rotation_s {
	int handle;
	int angle;
	int auto_rotate;
};

static struct splash_screen_s splash_screen;
static int splash_screen_initialized = 0;
static struct rotation_s rotation;
static int rotation_initialized = 0;

extern int _wl_is_initialized(void);
static int __init_splash_screen(void);
static int __init_rotation(void);

void _splash_screen_destroy_image(splash_image_h si)
{
	if (si == NULL)
		return;

	if (si->src)
		free(si->src);
	if (si->tid > 0)
		g_source_remove(si->tid);
	if (si->image) {
		tizen_launch_image_destroy(si->image);
		wl_display_flush(splash_screen.display);
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
					bundle *kb)
{
	const char *component_type;
	const char *fake_effect;
	const struct appinfo_splash_screen *ai_ss;

	component_type = appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strncmp(component_type, APP_TYPE_SERVICE,
				strlen(APP_TYPE_SERVICE)) == 0) {
		_D("component_type: %s", component_type);
		return -1;
	}

	fake_effect = bundle_get_val(kb, K_FAKE_EFFECT);
	if (fake_effect && strncmp(fake_effect, "OFF", strlen("OFF")) == 0)
		return -1;

	ai_ss = appinfo_get_ptr_value(ai, AIT_SPLASH_SCREEN);
	if (ai_ss == NULL || ai_ss->display == false)
		return -1;

	return 0;
}

static struct appinfo_splash_image *__get_splash_image_info(
		const struct appinfo *ai, bundle *kb, int cmd)
{
	const struct appinfo_splash_screen *ai_ss;
	const char *operation;
	GHashTable *tbl;

	ai_ss = appinfo_get_ptr_value(ai, AIT_SPLASH_SCREEN);
	if (ai_ss == NULL)
		return NULL;

	if ((rotation.angle == 90 || rotation.angle == 270)
				&& rotation.auto_rotate == true)
		tbl = ai_ss->landscape;
	else
		tbl = ai_ss->portrait;

	if (tbl == NULL)
		return NULL;

	if (cmd == APP_OPEN)
		return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, "launch-effect");

	operation = bundle_get_val(kb, AUL_SVC_K_OPERATION);
	if (operation == NULL)
		return NULL;

	if ((strcmp(operation, APP_CONTROL_OPERATION_MAIN) == 0)
		|| (strcmp(operation, AUL_SVC_OPERATION_DEFAULT) == 0))
		return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, "launch-effect");

	return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, operation);
}

splash_image_h _splash_screen_create_image(const struct appinfo *ai,
		bundle *kb, int cmd)
{
	struct splash_image_s *si;
	struct appinfo_splash_image *ai_si;
	int file_type = 0;
	int indicator = 1;

	if (!splash_screen_initialized) {
		if (__init_splash_screen() < 0)
			return NULL;
	}

	if (__app_can_launch_splash_image(ai, kb) < 0)
		return NULL;

	if (!rotation_initialized) {
		if (__init_rotation() < 0)
			_E("Failed to initialize rotation");
	}
	_D("angle: %d", rotation.angle);

	ai_si = __get_splash_image_info(ai, kb, cmd);
	if (ai_si == NULL)
		return NULL;
	if (access(ai_si->src, F_OK) != 0)
		return NULL;
	if (strncasecmp(ai_si->type, "edj", strlen("edj")) == 0)
		file_type = 1;
	if (strncmp(ai_si->indicatordisplay, "false", strlen("false")) == 0)
		indicator = 0;

	si = (struct splash_image_s *)calloc(1, sizeof(struct splash_image_s));
	if (si == NULL) {
		_E("out of memory");
		return NULL;
	}

	si->image = tizen_launchscreen_create_img(splash_screen.screen);
	if (si->image == NULL) {
		_E("Failed to get launch image");
		free(si);
		return NULL;
	}
	wl_display_flush(splash_screen.display);

	si->src = strdup(ai_si->src);
	if (si->src == NULL) {
		_E("out of memory");
		_splash_screen_destroy_image(si);
		return NULL;
	}

	si->type = file_type;
	si->rotation = rotation.angle;
	si->indicator = indicator;
	si->tid = g_timeout_add(3000, __splash_image_timeout_handler, si);

	return si;
}

void _splash_screen_send_image(splash_image_h si)
{
	if (si == NULL)
		return;

	tizen_launch_image_launch(si->image, si->src, si->type,
			si->rotation, si->indicator);
	wl_display_flush(splash_screen.display);
}

void _splash_screen_send_pid(splash_image_h si, int pid)
{
	if (si == NULL)
		return;

	tizen_launch_image_owner(si->image, pid);
	wl_display_flush(splash_screen.display);
}

static void __wl_listener_cb(void *data, struct wl_registry *registry,
		unsigned int id, const char *interface, unsigned int version)
{
	if (interface && strncmp(interface, "tizen_launchscreen",
				strlen("tizen_launchscreen")) == 0) {
		_D("interface: %s", interface);
		splash_screen.screen = wl_registry_bind(registry, id,
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

static int __init_splash_screen(void)
{
	if (!_wl_is_initialized())
		return -1;

	splash_screen.display = wl_display_connect(NULL);
	if (splash_screen.display == NULL) {
		_E("Failed to get display");
		return -1;
	}

	splash_screen.registry = wl_display_get_registry(splash_screen.display);
	if (splash_screen.registry == NULL) {
		_E("Failed to get registry");
		wl_display_disconnect(splash_screen.display);
		return -1;
	}

	wl_registry_add_listener(splash_screen.registry,
			&registry_listener, NULL);
	wl_display_flush(splash_screen.display);
	wl_display_roundtrip(splash_screen.display);

	if (splash_screen.screen == NULL) {
		_E("Failed to bind screen");
		wl_display_disconnect(splash_screen.display);
		return -1;
	}

	splash_screen_initialized = 1;

	return 0;
}

static void __rotation_changed_cb(sensor_t sensor, unsigned int event_type,
		sensor_data_t *data, void *user_data)
{
	int event;

	if (event_type != AUTO_ROTATION_CHANGE_STATE_EVENT)
		return;

	event = (int)data->values[0];
	switch (event) {
	case AUTO_ROTATION_DEGREE_0:
		rotation.angle = 0;
		break;
	case AUTO_ROTATION_DEGREE_90:
		rotation.angle = 90;
		break;
	case AUTO_ROTATION_DEGREE_180:
		rotation.angle = 180;
		break;
	case AUTO_ROTATION_DEGREE_270:
		rotation.angle = 270;
		break;
	default:
		break;
	}

	_D("angle: %d", rotation.angle);
}

static void __auto_rotate_screen_cb(keynode_t *key, void *data)
{
	rotation.auto_rotate = vconf_keynode_get_bool(key);
	if (!rotation.auto_rotate)
		_D("auto_rotate: %d, angle: %d",
				rotation.auto_rotate, rotation.angle);
}

static int __init_rotation(void)
{
	bool r;
	sensor_t sensor = sensord_get_sensor(AUTO_ROTATION_SENSOR);

	rotation.angle = 0;
	rotation.handle = sensord_connect(sensor);
	if (rotation.handle < 0) {
		_E("Failed to connect sensord");
		return -1;
	}

	r = sensord_register_event(rotation.handle,
			AUTO_ROTATION_CHANGE_STATE_EVENT,
			SENSOR_INTERVAL_NORMAL,
			0,
			__rotation_changed_cb,
			NULL);
	if (!r) {
		_E("Failed to register event");
		sensord_disconnect(rotation.handle);
		return -1;
	}

	r = sensord_start(rotation.handle, 0);
	if (!r) {
		_E("Failed to start sensord");
		sensord_unregister_event(rotation.handle,
				AUTO_ROTATION_CHANGE_STATE_EVENT);
		sensord_disconnect(rotation.handle);
		return -1;
	}

	if (vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
				&rotation.auto_rotate))
		rotation.auto_rotate = false;
	if (vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
				__auto_rotate_screen_cb, NULL) != 0)
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL);

	rotation_initialized = 1;

	return 0;
}

int _splash_screen_init(void)
{
	_D("init splash screen");

	if (__init_splash_screen() < 0)
		_E("Failed to initialize splash screen");

	if (__init_rotation() < 0)
		_E("Failed to initialize rotation");

	return 0;
}
