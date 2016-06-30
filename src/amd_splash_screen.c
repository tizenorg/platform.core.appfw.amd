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
#include <glib.h>
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
#include "amd_wayland.h"

#define K_FAKE_EFFECT "__FAKE_EFFECT__"
#define APP_CONTROL_OPERATION_MAIN "http://tizen.org/appcontrol/operation/main"
#define SPLASH_SCREEN_INFO_PATH "/usr/share/aul"
#define TAG_SPLASH_IMAGE "[Splash image]"
#define TAG_NAME "Name"
#define TAG_FILE "File"
#define TAG_TYPE "Type"
#define TAG_ORIENTATION "Orientation"
#define TAG_INDICATOR_DISPLAY "Indicator-display"
#define TAG_COLOR_DEPTH "Color-depth"

struct splash_image_s {
	struct tizen_launch_image *image;
	char *appid;
	char *src;
	int type;
	int rotation;
	int indicator;
	int color_depth;
	guint tid;
};

struct rotation_s {
	int handle;
	int angle;
	int auto_rotate;
};

struct image_info_s {
	char *name;
	char *file;
	char *type;
	char *orientation;
	char *indicator_display;
	char *color_depth;
};

static struct wl_display *display;
static struct tizen_launchscreen *tz_launchscreen;
static int splash_screen_initialized;
static struct rotation_s rotation;
static int rotation_initialized;
static GList *default_image_list;

static int __init_splash_screen(void);
static int __init_rotation(void);

void _splash_screen_destroy_image(splash_image_h si)
{
	if (si == NULL)
		return;

	if (si->appid)
		free(si->appid);
	if (si->src)
		free(si->src);
	if (si->tid > 0)
		g_source_remove(si->tid);
	if (si->image) {
		tizen_launch_image_destroy(si->image);
		wl_display_flush(display);
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
	int display;

	component_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (component_type && strncmp(component_type, APP_TYPE_SERVICE,
				strlen(APP_TYPE_SERVICE)) == 0) {
		_D("component_type: %s", component_type);
		return -1;
	}

	fake_effect = bundle_get_val(kb, K_FAKE_EFFECT);
	if (fake_effect && strncmp(fake_effect, "OFF", strlen("OFF")) == 0)
		return -1;

	_appinfo_get_int_value(ai, AIT_SPLASH_SCREEN_DISPLAY, &display);
	if (!(display & APP_ENABLEMENT_MASK_ACTIVE))
		return -1;

	return 0;
}

static struct appinfo_splash_image *__get_splash_image_info(
		const struct appinfo *ai, bundle *kb, int cmd)
{
	const struct appinfo_splash_screen *ai_ss;
	const char *operation;
	GHashTable *tbl;

	ai_ss = _appinfo_get_ptr_value(ai, AIT_SPLASH_SCREEN);
	if (ai_ss == NULL)
		return NULL;

	if ((rotation.angle == 90 || rotation.angle == 270)
				&& rotation.auto_rotate == true)
		tbl = ai_ss->landscape;
	else
		tbl = ai_ss->portrait;

	if (tbl == NULL)
		return NULL;

	if (cmd == APP_OPEN) {
		return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, "launch-effect");
	}

	operation = bundle_get_val(kb, AUL_SVC_K_OPERATION);
	if (operation == NULL)
		return NULL;

	if ((strcmp(operation, APP_CONTROL_OPERATION_MAIN) == 0)
		|| (strcmp(operation, AUL_SVC_OPERATION_DEFAULT) == 0)) {
		return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, "launch-effect");
	}

	return (struct appinfo_splash_image *)g_hash_table_lookup(
				tbl, operation);
}

static struct image_info_s *__get_default_image_info(bundle *kb)
{
	struct image_info_s *info = NULL;
	const char *orientation = "portrait";
	const char *str;
	GList *list;

	if (default_image_list == NULL)
		return NULL;

	if ((rotation.angle == 90 || rotation.angle == 270) &&
			rotation.auto_rotate == true)
		orientation = "landscape";

	str = bundle_get_val(kb, AUL_SVC_K_SPLASH_SCREEN);
	if (str == NULL)
		str = "default";

	list = default_image_list;
	while (list) {
		info = (struct image_info_s *)list->data;
		if (info && strcmp(str, info->name) == 0) {
			if (!strcasecmp(info->orientation, orientation))
				return info;
		}

		list = g_list_next(list);
	}

	return NULL;
}

splash_image_h _splash_screen_create_image(const struct appinfo *ai,
		bundle *kb, int cmd)
{
	struct splash_image_s *si;
	struct appinfo_splash_image *ai_si;
	struct image_info_s *info;
	const char *appid;
	const char *src;
	int file_type = 0;
	int indicator = 1;
	int color_depth = 24; /* default */

	if (!splash_screen_initialized) {
		if (__init_splash_screen() < 0)
			return NULL;
	}

	if (__app_can_launch_splash_image(ai, kb) < 0)
		return NULL;

	if (!rotation_initialized) {
		if (__init_rotation() < 0)
			_W("Failed to initialize rotation");
	}
	_D("angle: %d", rotation.angle);

	ai_si = __get_splash_image_info(ai, kb, cmd);
	if (ai_si) {
		src = ai_si->src;
		if (access(src, F_OK) != 0)
			return NULL;
		if (strcasecmp(ai_si->type, "edj") == 0)
			file_type = 1;
		if (strcmp(ai_si->indicatordisplay, "false") == 0)
			indicator = 0;
		if (strcmp(ai_si->color_depth, "32") == 0)
			color_depth = 32;
	} else {
		info = __get_default_image_info(kb);
		if (info == NULL)
			return NULL;

		src = info->file;
		if (access(src, F_OK != 0))
			return NULL;
		if (strcasecmp(info->type, "edj") == 0)
			file_type = 1;
		if (strcmp(info->indicator_display, "false") == 0)
			indicator = 0;
		if (strcmp(info->color_depth, "32") == 0)
			color_depth = 32;
	}

	si = (struct splash_image_s *)calloc(1, sizeof(struct splash_image_s));
	if (si == NULL) {
		_E("out of memory");
		return NULL;
	}

	si->image = tizen_launchscreen_create_img(tz_launchscreen);
	if (si->image == NULL) {
		_E("Failed to get launch image");
		free(si);
		return NULL;
	}
	wl_display_flush(display);

	appid = _appinfo_get_value(ai, AIT_NAME);
	si->appid = strdup(appid);
	if (si->appid == NULL) {
		_E("out of memory");
		_splash_screen_destroy_image(si);
		return NULL;
	}

	si->src = strdup(src);
	if (si->src == NULL) {
		_E("out of memory");
		_splash_screen_destroy_image(si);
		return NULL;
	}

	si->type = file_type;
	si->rotation = rotation.angle;
	si->indicator = indicator;
	si->color_depth = color_depth;
	si->tid = g_timeout_add(3000, __splash_image_timeout_handler, si);

	return si;
}

void _splash_screen_send_image(splash_image_h si)
{
	struct wl_array options;

	if (si == NULL)
		return;

	wl_array_init(&options);
	/* TODO: Set appid */
	tizen_launch_image_launch(si->image, si->src, si->type, si->color_depth,
			si->rotation, si->indicator, &options);
	wl_display_flush(display);
	wl_array_release(&options);
}

void _splash_screen_send_pid(splash_image_h si, int pid)
{
	if (si == NULL)
		return;

	tizen_launch_image_owner(si->image, pid);
	wl_display_flush(display);
}

static void __wl_listener_cb(void *data, struct wl_registry *registry,
		unsigned int id, const char *interface, unsigned int version)
{
	if (interface && strncmp(interface, "tizen_launchscreen",
				strlen("tizen_launchscreen")) == 0) {
		_D("interface: %s", interface);
		if (!tz_launchscreen) {
			tz_launchscreen = wl_registry_bind(registry, id,
					&tizen_launchscreen_interface, 1);
		}
	}
}

static void __wl_listener_remove_cb(void *data, struct wl_registry *registry,
		unsigned int id)
{
	if (tz_launchscreen) {
		tizen_launchscreen_destroy(tz_launchscreen);
		tz_launchscreen = NULL;
	}
}

static struct wl_registry_listener registry_listener = {
	__wl_listener_cb,
	__wl_listener_remove_cb
};

static int __init_splash_screen(void)
{
	if (!display) {
		display = _wayland_get_display();
		if (!display) {
			_E("Failed to get display");
			return -1;
		}
	}

	if (!tz_launchscreen) {
		_E("Failed to bind tizen launch screen");
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
	if (!rotation.auto_rotate) {
		_D("auto_rotate: %d, angle: %d",
				rotation.auto_rotate, rotation.angle);
	}
}

static int __init_rotation(void)
{
	int ret;
	bool r;
	sensor_t sensor = sensord_get_sensor(AUTO_ROTATION_SENSOR);

	rotation.angle = 0;
	rotation.handle = sensord_connect(sensor);
	if (rotation.handle < 0) {
		_W("Failed to connect sensord");
		return -1;
	}

	r = sensord_register_event(rotation.handle,
			AUTO_ROTATION_CHANGE_STATE_EVENT,
			SENSOR_INTERVAL_NORMAL,
			0,
			__rotation_changed_cb,
			NULL);
	if (!r) {
		_W("Failed to register event");
		sensord_disconnect(rotation.handle);
		return -1;
	}

	r = sensord_start(rotation.handle, 0);
	if (!r) {
		_W("Failed to start sensord");
		sensord_unregister_event(rotation.handle,
				AUTO_ROTATION_CHANGE_STATE_EVENT);
		sensord_disconnect(rotation.handle);
		return -1;
	}

	ret = vconf_get_bool(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
			&rotation.auto_rotate);
	if (ret != VCONF_OK)
		rotation.auto_rotate = false;

	ret = vconf_notify_key_changed(VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL,
			__auto_rotate_screen_cb, NULL);
	if (ret != 0) {
		_W("Failed to register callback for %s",
				VCONFKEY_SETAPPL_AUTO_ROTATE_SCREEN_BOOL);
	}

	rotation_initialized = 1;

	return 0;
}

static void __destroy_image_info(struct image_info_s *info)
{
	if (info == NULL)
		return;

	if (info->color_depth)
		free(info->color_depth);
	if (info->indicator_display)
		free(info->indicator_display);
	if (info->type)
		free(info->type);
	if (info->orientation)
		free(info->orientation);
	if (info->file)
		free(info->file);
	if (info->name)
		free(info->name);
	free(info);
}

struct image_info_s *__create_image_info(void)
{
	struct image_info_s *info;

	info = (struct image_info_s *)calloc(1, sizeof(struct image_info_s));
	if (info == NULL) {
		_E("out of memory");
		return NULL;
	}

	return info;
}

static int __validate_image_info(struct image_info_s *info)
{
	if (info == NULL)
		return -1;

	if (info->name == NULL ||
			info->file == NULL ||
			info->orientation == NULL)
		return -1;

	if (info->type == NULL) {
		if (strstr(info->file, "edj"))
			info->type = strdup("edj");
		else
			info->type = strdup("img");
	}

	if (info->indicator_display == NULL)
		info->indicator_display = strdup("true");

	if (info->color_depth == NULL)
		info->color_depth = strdup("24");

	return 0;
}

static void __parse_file(const char *file)
{
	FILE *fp;
	char buf[LINE_MAX];
	char tok1[LINE_MAX];
	char tok2[LINE_MAX];
	struct image_info_s *info = NULL;

	fp = fopen(file, "rt");
	if (fp == NULL)
		return;

	while (fgets(buf, sizeof(buf), fp) != NULL) {
		tok1[0] = '\0';
		tok2[0] = '\0';
		sscanf(buf, "%s %s", tok1, tok2);

		if (strncasecmp(TAG_SPLASH_IMAGE, tok1,
					strlen(TAG_SPLASH_IMAGE)) == 0) {
			if (info) {
				if (__validate_image_info(info) < 0) {
					__destroy_image_info(info);
				} else {
					default_image_list = g_list_append(
							default_image_list,
							info);
				}
			}
			info = __create_image_info();
			continue;
		}

		if (tok1[0] == '\0' || tok2[0] == '\0' || info == NULL)
			continue;

		if (strncasecmp(TAG_NAME, tok1, strlen(TAG_NAME)) == 0)
			info->name = strdup(tok2);
		else if (strncasecmp(TAG_FILE, tok1, strlen(TAG_FILE)) == 0)
			info->file = strdup(tok2);
		else if (strncasecmp(TAG_TYPE, tok1, strlen(TAG_TYPE)) == 0)
			info->type = strdup(tok2);
		else if (strncasecmp(TAG_ORIENTATION, tok1,
					strlen(TAG_ORIENTATION)) == 0)
			info->orientation = strdup(tok2);
		else if (strncasecmp(TAG_INDICATOR_DISPLAY, tok1,
					strlen(TAG_INDICATOR_DISPLAY)) == 0)
			info->indicator_display = strdup(tok2);
		else if (strncasecmp(TAG_COLOR_DEPTH, tok1,
					strlen(TAG_COLOR_DEPTH)) == 0)
			info->color_depth = strdup(tok2);
	}

	if (info) {
		if (__validate_image_info(info) < 0) {
			__destroy_image_info(info);
		} else {
			default_image_list = g_list_append(default_image_list,
					info);
		}
	}

	fclose(fp);
}

static int __load_splash_screen_info(const char *path)
{
	DIR *dp;
	struct dirent entry;
	struct dirent *result = NULL;
	char *ext;
	char buf[PATH_MAX];

	dp = opendir(path);
	if (dp == NULL)
		return -1;

	while (readdir_r(dp, &entry, &result) == 0 && result != NULL) {
		if (entry.d_name[0] == '.')
			continue;

		ext = strrchr(entry.d_name, '.');
		if (ext && !strcmp(ext, ".conf")) {
			snprintf(buf, sizeof(buf), "%s/%s", path, entry.d_name);
			__parse_file(buf);
		}
	}

	closedir(dp);

	return 0;
}

int _splash_screen_init(void)
{
	_D("init splash screen");

	__load_splash_screen_info(SPLASH_SCREEN_INFO_PATH);
	_wayland_add_registry_listener(&registry_listener, NULL);

	if (__init_rotation() < 0)
		_W("Failed to initialize rotation");

	return 0;
}

