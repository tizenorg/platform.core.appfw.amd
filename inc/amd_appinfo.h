/*
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#pragma once

#include <sys/types.h>
#include <stdbool.h>

#include <glib.h>

#define AIT_START 0
enum appinfo_type {
	AIT_NAME = AIT_START,
	AIT_EXEC,
	AIT_PKGTYPE,
	AIT_ONBOOT, /* start on boot: boolean */
	AIT_RESTART, /* auto restart: boolean */
	AIT_MULTI,
	AIT_HWACC,
	AIT_PERM,
	AIT_PKGID,
	AIT_PRELOAD,
	AIT_STATUS,
	AIT_POOL,
	AIT_COMPTYPE,
	AIT_TEP,
	AIT_MOUNTABLE_PKG,
	AIT_STORAGE_TYPE,
	AIT_BG_CATEGORY,
	AIT_LAUNCH_MODE,
	AIT_GLOBAL,
	AIT_EFFECTIVE_APPID,
	AIT_TASKMANAGE,
	AIT_VISIBILITY,
	AIT_APPTYPE,
	AIT_ROOT_PATH,
	AIT_SPLASH_SCREEN,
	AIT_SPLASH_SCREEN_DISPLAY,
	AIT_API_VERSION,
	AIT_ENABLEMENT,
	AIT_MAX
};

struct appinfo {
	char *val[AIT_MAX];
};

struct appinfo_splash_screen {
	GHashTable *portrait;
	GHashTable *landscape;
};

struct appinfo_splash_image {
	char *src;
	char *type;
	char *indicatordisplay;
	char *color_depth;
};

#define APP_TYPE_SERVICE	"svcapp"
#define APP_TYPE_UI		"uiapp"
#define APP_TYPE_WIDGET		"widgetapp"
#define APP_TYPE_WATCH		"watchapp"

#define APP_ENABLEMENT_MASK_ACTIVE	0x1
#define APP_ENABLEMENT_MASK_REQUEST	0x2

typedef void (*appinfo_iter_callback)(void *user_data,
		const char *filename, struct appinfo *c);
int appinfo_init(void);
void appinfo_fini(void);
int appinfo_insert(uid_t uid, const char *pkgid);
struct appinfo *appinfo_find(uid_t caller_uid, const char *appid);
const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type);
const void *appinfo_get_ptr_value(const struct appinfo *c,
		enum appinfo_type type);
int appinfo_get_int_value(const struct appinfo *c, enum appinfo_type type,
		int *val);
int appinfo_set_value(struct appinfo *c, enum appinfo_type, const char *val);
int appinfo_set_ptr_value(struct appinfo *c, enum appinfo_type, void *val);
int appinfo_set_int_value(struct appinfo *c, enum appinfo_type type, int val);
void appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data);
void appinfo_reload(void);

