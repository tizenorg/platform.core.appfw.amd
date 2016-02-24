/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <glib.h>
#include <dirent.h>
#include <package-manager.h>
#include <pkgmgr-info.h>
#include <vconf.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_launch.h"
#include "amd_status.h"

static pkgmgr_client *pc;
static GHashTable *user_tbl;
static GHashTable *pkg_pending;
struct user_appinfo {
	uid_t uid;
	GHashTable *tbl; /* key is appid, value is struct appinfo */
	void *extra_data;
};

typedef int (*appinfo_handler_cb)(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data);

enum _background_category {
	_BACKGROUND_CATEGORY_MEDIA = 0x01,
	_BACKGROUND_CATEGORY_DOWNLOAD = 0x02,
	_BACKGROUND_CATEGORY_BACKGROUND_NETWORK = 0x04,
	_BACKGROUND_CATEGORY_LOCATION = 0x08,
	_BACKGROUND_CATEGORY_SENSOR = 0x10,
	_BACKGROUND_CATEGORY_IOT_COMMUNICATION = 0x20,
	_BACKGROUND_CATEGORY_SYSTEM = 0x40
};

static int gles = 1;

static void __free_appinfo_splash_screen(
		struct appinfo_splash_screen *splashscreen)
{
	if (splashscreen == NULL)
		return;

	if (splashscreen->indicatordisplay)
		free(splashscreen->indicatordisplay);
	if (splashscreen->type)
		free(splashscreen->type);
	if (splashscreen->src)
		free(splashscreen->src);
	free(splashscreen);
}

static void __free_appinfo(gpointer data)
{
	struct appinfo *c = data;
	int i;

	if (!c)
		return;

	for (i = AIT_START; i < AIT_MAX; i++) {
		if (i == AIT_PORTRAIT_SPLASH_SCREEN
				|| i == AIT_LANDSCAPE_SPLASH_SCREEN)
			__free_appinfo_splash_screen((struct appinfo_splash_screen *)c->val[i]);
		else if (i != AIT_BG_CATEGORY && c->val[i] != NULL)
			free(c->val[i]);
	}

	free(c);
}

static void __free_user_appinfo(gpointer data)
{
	struct user_appinfo *info = (struct user_appinfo *)data;

	g_hash_table_destroy(info->tbl);
	free(info);
}

static int __read_background_category(const char *category_name, void *user_data)
{
	struct appinfo *c = user_data;
	int category = (intptr_t)(c->val[AIT_BG_CATEGORY]);

	if (!category_name)
		return 0;

	if (strncmp(category_name, "disable", strlen("disable")) == 0) {
		c->val[AIT_BG_CATEGORY] = 0x00;
		return -1;
	}

	if (strncmp(category_name, "media", strlen("media")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_MEDIA));
	else if (strncmp(category_name, "download", strlen("download")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_DOWNLOAD));
	else if (strncmp(category_name, "background-network", strlen("background-network")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_BACKGROUND_NETWORK));
	else if (strncmp(category_name, "location", strlen("location")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_LOCATION));
	else if (strncmp(category_name, "sensor", strlen("sensor")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_SENSOR));
	else if (strncmp(category_name, "iot-communication", strlen("iot-communication")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_IOT_COMMUNICATION));
	else if (strncmp(category_name, "system", strlen("system")) == 0)
		c->val[AIT_BG_CATEGORY] = (char *)((intptr_t)(category | _BACKGROUND_CATEGORY_SYSTEM));

	return 0;
}

static int __appinfo_add_exec(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *exec = NULL;

	if (pkgmgrinfo_appinfo_get_exec(handle, &exec) != PMINFO_R_OK) {
		_E("failed to get exec");
		return -1;
	}

	info->val[AIT_EXEC] = strdup(exec);

	return 0;
}

static int __appinfo_add_pkgtype(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *pkgtype = NULL;

	if (pkgmgrinfo_appinfo_get_pkgtype(handle, &pkgtype) != PMINFO_R_OK) {
		_E("failed to get pkgtype");
		return -1;
	}

	info->val[AIT_PKGTYPE] = strdup(pkgtype);

	return 0;
}

static int __appinfo_add_onboot(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool onboot = false;

	if (pkgmgrinfo_appinfo_is_onboot(handle, &onboot) != PMINFO_R_OK) {
		_E("failed to get onboot");
		return -1;
	}

	info->val[AIT_ONBOOT] = strdup(onboot ? "true" : "false");

	return 0;
}

static int __appinfo_add_restart(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool restart = false;

	if (pkgmgrinfo_appinfo_is_autorestart(handle, &restart) != PMINFO_R_OK) {
		_E("failed to get restart");
		return -1;
	}

	info->val[AIT_RESTART] = strdup(restart ? "true" : "false");

	return 0;
}

static int __appinfo_add_multi(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool multiple = false;

	if (pkgmgrinfo_appinfo_is_multiple(handle, &multiple) != PMINFO_R_OK) {
		_E("failed to get multiple");
		return -1;
	}

	info->val[AIT_MULTI] = strdup(multiple ? "true" : "false");

	return 0;
}

static int __appinfo_add_hwacc(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	pkgmgrinfo_app_hwacceleration hwacc;

	if (pkgmgrinfo_appinfo_get_hwacceleration(handle, &hwacc)) {
		_E("failed to get hwacc");
		return -1;
	}

	info->val[AIT_HWACC] = strdup(
				(gles == 0 ||
				 hwacc == PMINFO_HWACCELERATION_NOT_USE_GL) ?
				"NOT_USE" :
				(hwacc == PMINFO_HWACCELERATION_USE_GL) ?
				"USE" :
				"SYS");

	return 0;
}

static int __appinfo_add_perm(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	pkgmgrinfo_permission_type permission;

	if (pkgmgrinfo_appinfo_get_permission_type(handle,
		&permission) != PMINFO_R_OK) {
		_E("failed to get permission type");
		return -1;
	}

	info->val[AIT_PERM] = strdup(
				(permission == PMINFO_PERMISSION_SIGNATURE) ?
				"signature" :
				(permission == PMINFO_PERMISSION_PRIVILEGE) ?
				"privilege" :
				"normal");

	return 0;
}

static int __appinfo_add_pkgid(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *pkgid = NULL;

	if (pkgmgrinfo_appinfo_get_pkgid(handle, &pkgid) != PMINFO_R_OK) {
		_E("failed to get pkgid");
		return -1;
	}

	info->val[AIT_PKGID] = strdup(pkgid);

	return 0;
}

static int __appinfo_add_preload(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool preload = false;

	if (pkgmgrinfo_appinfo_is_preload(handle, &preload) != PMINFO_R_OK) {
		_E("failed to get preload");
		return -1;
	}

	info->val[AIT_PRELOAD] = strdup(preload ? "true" : "false");

	return 0;
}

static int __appinfo_add_status(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	info->val[AIT_STATUS] = strdup("installed");

	return 0;
}

static int __appinfo_add_pool(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool process_pool = false;

	if (pkgmgrinfo_appinfo_is_process_pool(handle, &process_pool) != PMINFO_R_OK) {
		_E("failed to get process_pool");
		return -1;
	}

	info->val[AIT_POOL] = strdup(process_pool ? "true" : "false");

	return 0;
}

static int __appinfo_add_comptype(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *component_type = NULL;

	if (pkgmgrinfo_appinfo_get_component_type(handle,
		&component_type) != PMINFO_R_OK) {
		_E("failed to get component type");
		return -1;
	}

	info->val[AIT_COMPTYPE] = strdup(component_type);

	return 0;
}

static int __appinfo_add_tep(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *tep_name = NULL;
	struct user_appinfo *user_data = (struct user_appinfo *)data;

	if (pkgmgrinfo_pkginfo_get_tep_name((pkgmgrinfo_pkginfo_h)user_data->extra_data,
						&tep_name) != PMINFO_R_OK) {
		_D("failed to get tep_name");
		info->val[AIT_TEP] = NULL;
	} else {
		info->val[AIT_TEP] = strdup(tep_name);
	}

	return 0;
}

static int __appinfo_add_storage_type(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	pkgmgrinfo_installed_storage installed_storage;

	if (pkgmgrinfo_appinfo_get_installed_storage_location(handle,
		&installed_storage) == PMINFO_R_OK) {
		if (installed_storage == PMINFO_INTERNAL_STORAGE)
			info->val[AIT_STORAGE_TYPE] = strdup("internal");
		else if (installed_storage == PMINFO_EXTERNAL_STORAGE)
			info->val[AIT_STORAGE_TYPE] = strdup("external");
	} else {
		info->val[AIT_STORAGE_TYPE] = strdup("internal");
	}

	return 0;
}

static int __appinfo_add_bg_category(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	info->val[AIT_BG_CATEGORY] = 0x0;
	if (pkgmgrinfo_appinfo_foreach_background_category(handle,
		__read_background_category, info) != PMINFO_R_OK) {
		_E("Failed to get background category");
		return -1;
	}

	return 0;
}

static int __appinfo_add_launch_mode(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *mode = NULL;

	if (pkgmgrinfo_appinfo_get_launch_mode(handle, &mode) != PMINFO_R_OK) {
		_E("failed to get launch_mode");
		return -1;
	}

	info->val[AIT_LAUNCH_MODE] = strdup(mode ? mode : "single");

	return 0;
}

static int __appinfo_add_global(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool is_global = false;
	struct user_appinfo *user_data = (struct user_appinfo *)data;

	if (pkgmgrinfo_pkginfo_is_for_all_users((pkgmgrinfo_pkginfo_h)user_data->extra_data,
						&is_global) != PMINFO_R_OK) {
		_E("get pkginfo failed");
		return -1;
	}

	info->val[AIT_GLOBAL] = strdup(is_global ? "true" : "false");

	return 0;
}

static int __appinfo_add_effective_appid(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *effective_appid = NULL;

	if (pkgmgrinfo_appinfo_get_effective_appid(handle, &effective_appid) != PMINFO_R_OK) {
		_D("Failed to get effective appid");
		info->val[AIT_EFFECTIVE_APPID] = NULL;
	} else {
		if (effective_appid && strlen(effective_appid) > 0)
			info->val[AIT_EFFECTIVE_APPID] = strdup(effective_appid);
	}

	return 0;
}

static int __appinfo_add_taskmanage(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	bool taskmanage = false;

	if (pkgmgrinfo_appinfo_is_taskmanage(handle, &taskmanage) != PMINFO_R_OK)
		_D("Failed to get taskmanage info");

	info->val[AIT_TASKMANAGE] = strdup(taskmanage ? "true" : "false");

	return 0;
}

static int __appinfo_add_apptype(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *apptype = NULL;

	if (pkgmgrinfo_appinfo_get_apptype(handle, &apptype) != PMINFO_R_OK) {
		_E("failed to get apptype");
		return -1;
	}

	info->val[AIT_APPTYPE] = strdup(apptype);

	return 0;
}

static int __appinfo_add_root_path(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{
	char *path = NULL;
	struct user_appinfo *user_data = (struct user_appinfo *)data;

	if (pkgmgrinfo_pkginfo_get_root_path((pkgmgrinfo_pkginfo_h)user_data->extra_data,
						&path) != PMINFO_R_OK) {
		_E("get pkginfo failed");
		return -1;
	}

	info->val[AIT_ROOT_PATH] = path ? strdup(path) : NULL;

	return 0;
}

static int __add_splash_screen_list_cb(const char *src, const char *type,
		const char *orientation, const char *indicatordisplay,
		void *user_data)
{
	struct appinfo *info = (struct appinfo *)user_data;
	struct appinfo_splash_screen *splashscreen;

	splashscreen = (struct appinfo_splash_screen *)calloc(1,
			sizeof(struct appinfo_splash_screen));
	if (splashscreen == NULL) {
		_E("out of memory");
		return -1;
	}

	splashscreen->src = strdup(src);
	splashscreen->type = strdup(type);
	splashscreen->indicatordisplay = strdup(indicatordisplay);

	if (strncmp(orientation, "portrait", strlen("portrait")) == 0)
		info->val[AIT_PORTRAIT_SPLASH_SCREEN] = (char *)splashscreen;
	else if (strncmp(orientation, "landscape", strlen("landscape")) == 0)
		info->val[AIT_LANDSCAPE_SPLASH_SCREEN] = (char *)splashscreen;
	else
		__free_appinfo_splash_screen(splashscreen);

	return 0;
}

static int __appinfo_add_splash_screens(const pkgmgrinfo_appinfo_h handle, struct appinfo *info, void *data)
{

	if (pkgmgrinfo_appinfo_foreach_splash_screen(handle,
				__add_splash_screen_list_cb, info) < 0) {
		_E("Failed to get splash screen");
		return -1;
	}

	return 0;
}

static appinfo_handler_cb appinfo_add_table[AIT_MAX] = {
	[AIT_NAME] = NULL,
	[AIT_EXEC] = __appinfo_add_exec,
	[AIT_PKGTYPE] = __appinfo_add_pkgtype,
	[AIT_ONBOOT] = __appinfo_add_onboot,
	[AIT_RESTART] = __appinfo_add_restart,
	[AIT_MULTI] = __appinfo_add_multi,
	[AIT_HWACC] = __appinfo_add_hwacc,
	[AIT_PERM] = __appinfo_add_perm,
	[AIT_PKGID] = __appinfo_add_pkgid,
	[AIT_PRELOAD] = __appinfo_add_preload,
	[AIT_STATUS] = __appinfo_add_status,
	[AIT_POOL] = __appinfo_add_pool,
	[AIT_COMPTYPE] = __appinfo_add_comptype,
	[AIT_TEP] = __appinfo_add_tep,
	[AIT_STORAGE_TYPE] = __appinfo_add_storage_type,
	[AIT_BG_CATEGORY] = __appinfo_add_bg_category,
	[AIT_LAUNCH_MODE] = __appinfo_add_launch_mode,
	[AIT_GLOBAL] = __appinfo_add_global,
	[AIT_EFFECTIVE_APPID] = __appinfo_add_effective_appid,
	[AIT_TASKMANAGE] = __appinfo_add_taskmanage,
	[AIT_VISIBILITY] = NULL,
	[AIT_APPTYPE] = __appinfo_add_apptype,
	[AIT_ROOT_PATH] = __appinfo_add_root_path,
	[AIT_PORTRAIT_SPLASH_SCREEN] = __appinfo_add_splash_screens,
	[AIT_LANDSCAPE_SPLASH_SCREEN] = NULL,
	[AIT_API_VERSION] = NULL,
};

static int __appinfo_insert_handler (const pkgmgrinfo_appinfo_h handle,
					void *data)
{
	int i;
	struct appinfo *c;
	struct user_appinfo *info = (struct user_appinfo *)data;
	char *appid;

	if (!handle || !info) {
		_E("null app handle");
		return -1;
	}

	if (pkgmgrinfo_appinfo_get_appid(handle, &appid) != PMINFO_R_OK) {
		_E("fail to get appinfo");
		return -1;
	}

	g_hash_table_remove(info->tbl, appid);

	c = calloc(1, sizeof(struct appinfo));
	if (!c) {
		_E("create appinfo: %s", strerror(errno));
		return -1;
	}

	c->val[AIT_NAME] = strdup(appid);

	for (i = AIT_START; i < AIT_MAX; i++) {
		if (appinfo_add_table[i] && appinfo_add_table[i](handle, c, info) < 0) {
			__free_appinfo(c);
			return -1;
		}
	}

	SECURE_LOGD("%s : %s : %s : %s", c->val[AIT_NAME], c->val[AIT_COMPTYPE],
		c->val[AIT_PKGTYPE], c->val[AIT_APPTYPE]);

	g_hash_table_insert(info->tbl, c->val[AIT_NAME], c);

	return 0;
}

static int __pkg_list_cb(pkgmgrinfo_pkginfo_h handle, void *user_data)
{
	bool is_global;
	struct user_appinfo *info = (struct user_appinfo *)user_data;

	if (pkgmgrinfo_pkginfo_is_for_all_users(handle, &is_global)) {
		_E("get pkginfo failed");
		return -1;
	}

	/* do not load appinfo for attached global apps */
	if (info->uid != GLOBAL_USER && is_global)
		return 0;

	info->extra_data = handle;
	if (pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
			__appinfo_insert_handler, user_data,
			info->uid)) {
		_E("get appinfo failed");
		return -1;
	}

	return 0;
}

static void __remove_user_appinfo(uid_t uid)
{
	g_hash_table_remove(user_tbl, GINT_TO_POINTER(uid));
}

static void __handle_onboot(void *user_data, const char *appid,
		struct appinfo *info)
{
	uid_t uid = (uid_t)(intptr_t)user_data;

	if (strcmp(info->val[AIT_COMPTYPE], APP_TYPE_SERVICE) != 0)
		return;

	if (!strcmp(info->val[AIT_ONBOOT], "true")) {
		if (_status_app_is_running(appid, uid) > 0)
			return;
		_D("start app %s from user %d by onboot", appid, uid);
		_start_app_local(uid, info->val[AIT_NAME]);
	}
}

static struct user_appinfo *__add_user_appinfo(uid_t uid)
{
	int r;
	struct user_appinfo *info;

	info = calloc(1, sizeof(struct user_appinfo));
	if (info == NULL) {
		_E("out of memory");
		return NULL;
	}

	info->uid = uid;
	info->tbl = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			__free_appinfo);
	if (info->tbl == NULL) {
		_E("out of memory");
		free(info);
		return NULL;
	}

	g_hash_table_insert(user_tbl, GINT_TO_POINTER(uid), info);

	r = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, info, info->uid);
	if (r != PMINFO_R_OK) {
		__remove_user_appinfo(uid);
		return NULL;
	}

	if (uid != GLOBAL_USER) {
		appinfo_foreach(uid, __handle_onboot, (void *)(intptr_t)uid);
		appinfo_foreach(GLOBAL_USER, __handle_onboot,
				(void *)(intptr_t)uid);
	}

	_D("loaded appinfo table for uid %d", uid);

	return info;
}

static struct user_appinfo *__find_user_appinfo(uid_t uid)
{
	return g_hash_table_lookup(user_tbl, GINT_TO_POINTER(uid));
}

static void __appinfo_set_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	char *pkgid = (char *)user_data;

	if (strcmp(info->val[AIT_PKGID], pkgid))
		return;

	free(info->val[AIT_STATUS]);
	info->val[AIT_STATUS] = strdup("blocking");
	_D("%s status changed: blocking", appid);
}

static void __appinfo_unset_blocking_cb(void *user_data,
		const char *appid, struct appinfo *info)
{
	char *pkgid = (char *)user_data;

	if (strcmp(info->val[AIT_PKGID], pkgid))
		return;

	free(info->val[AIT_STATUS]);
	info->val[AIT_STATUS] = strdup("installed");
	_D("%s status changed: installed", appid);
}

static gboolean __appinfo_remove_cb(gpointer key, gpointer value, gpointer data)
{
	char *pkgid = (char *)data;
	struct appinfo *info = (struct appinfo *)value;

	if (!strcmp(info->val[AIT_PKGID], pkgid)) {
		_D("appinfo removed: %s", info->val[AIT_NAME]);
		return TRUE;
	}

	return FALSE;
}

static void __appinfo_delete_on_event(uid_t uid, const char *pkgid)
{
	struct user_appinfo *info;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		_E("cannot find appinfo for uid %d", uid);
		return;
	}

	g_hash_table_foreach_remove(info->tbl, __appinfo_remove_cb,
			(gpointer)pkgid);
}

static void __appinfo_insert_on_event(uid_t uid, const char *pkgid)
{
	appinfo_insert(uid, pkgid);
	appinfo_foreach(uid, __handle_onboot, (void *)(intptr_t)uid);
}

static int __package_event_cb(uid_t target_uid, int req_id,
		const char *pkg_type, const char *pkgid,
		const char *key, const char *val, const void *pmsg, void *data)
{
	char *op;

	if (!strcasecmp(key, "start")) {
		if (!strcasecmp(val, "uninstall") ||
				!strcasecmp(val, "update"))
			appinfo_foreach(target_uid, __appinfo_set_blocking_cb,
					(void *)pkgid);
		g_hash_table_insert(pkg_pending, strdup(pkgid), strdup(val));
	}

	if (!strcasecmp(key, "error")) {
		op = g_hash_table_lookup(pkg_pending, pkgid);
		if (op == NULL)
			return 0;

		if (!strcasecmp(op, "uninstall") || !strcasecmp(op, "update"))
			appinfo_foreach(target_uid, __appinfo_unset_blocking_cb,
					(void *)pkgid);
		g_hash_table_remove(pkg_pending, pkgid);
	}

	if (!strcasecmp(key, "end")) {
		op = g_hash_table_lookup(pkg_pending, pkgid);
		if (op == NULL)
			return 0;

		if (!strcasecmp(op, "uninstall")) {
			__appinfo_delete_on_event(target_uid, pkgid);
		} else if (!strcasecmp(op, "install")) {
			__appinfo_insert_on_event(target_uid, pkgid);
		} else if (!strcasecmp(op, "update")) {
			__appinfo_delete_on_event(target_uid, pkgid);
			__appinfo_insert_on_event(target_uid, pkgid);
		}

		g_hash_table_remove(pkg_pending, pkgid);
	}

	return 0;
}

static int __init_package_event_handler(void)
{
	pc = pkgmgr_client_new(PC_LISTENING);
	if (pc == NULL)
		return -1;

	if (pkgmgr_client_listen_status(pc, __package_event_cb, NULL) < 0)
		return -1;

	return 0;
}

static void __fini_package_event_handler(void)
{
	pkgmgr_client_free(pc);
}

int appinfo_init(void)
{
	FILE *fp;
	char buf[4096] = {0,};
	char *tmp;
	struct user_appinfo *global_appinfo;

	fp = fopen("/proc/cmdline", "r");
	if (fp == NULL) {
		_E("appinfo init failed: %s", strerror(errno));
		return -1;
	}

	if (fgets(buf, sizeof(buf), fp) != NULL) {
		tmp = strstr(buf, "gles");
		if (tmp != NULL)
			sscanf(tmp, "gles=%d", &gles);
	}
	fclose(fp);

	user_tbl = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			__free_user_appinfo);
	if (user_tbl == NULL)
		return -1;

	pkg_pending = g_hash_table_new_full(g_str_hash, g_str_equal,
			free, free);
	if (pkg_pending == NULL)
		return -1;

	global_appinfo = __add_user_appinfo(GLOBAL_USER);
	if (global_appinfo == NULL) {
		appinfo_fini();
		return -1;
	}

	if (__init_package_event_handler()) {
		appinfo_fini();
		return -1;
	}

	return 0;
}

void appinfo_fini(void)
{
	g_hash_table_destroy(user_tbl);
	g_hash_table_destroy(pkg_pending);
	__fini_package_event_handler();
}

struct appinfo *appinfo_find(uid_t caller_uid, const char *appid)
{
	struct user_appinfo *info;
	struct appinfo *ai;

	/* search from user table */
	info = __find_user_appinfo(caller_uid);
	if (info == NULL) {
		info = __add_user_appinfo(caller_uid);
		if (info == NULL)
			return NULL;
	}

	ai = g_hash_table_lookup(info->tbl, appid);
	if (ai)
		return ai;

	if (caller_uid == GLOBAL_USER)
		return NULL;

	/* search again from global table */
	info = __find_user_appinfo(GLOBAL_USER);
	if (info == NULL) {
		_E("cannot find global appinfo table!");
		return NULL;
	}

	return g_hash_table_lookup(info->tbl, appid);
}

int appinfo_insert(uid_t uid, const char *pkgid)
{
	struct user_appinfo *info;
	pkgmgrinfo_pkginfo_h handle;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		info = __add_user_appinfo(uid);
		if (info == NULL)
			_E("load appinfo for uid %d failed", uid);
		return 0;
	}

	if (pkgmgrinfo_pkginfo_get_usr_pkginfo(pkgid, uid, &handle)) {
		_E("get pkginfo failed: %s", pkgid);
		return -1;
	}

	info->extra_data = handle;
	if (pkgmgrinfo_appinfo_get_usr_list(handle, PMINFO_ALL_APP,
				__appinfo_insert_handler,
				info, info->uid)) {
		_E("add appinfo of pkg %s failed", pkgid);
		pkgmgrinfo_pkginfo_destroy_pkginfo(handle);
		return -1;
	}

	pkgmgrinfo_pkginfo_destroy_pkginfo(handle);

	return 0;
}

static void __reload_appinfo(gpointer key, gpointer value, gpointer user_data)
{
	int r;
	struct user_appinfo *info = (struct user_appinfo *)value;

	g_hash_table_remove_all(info->tbl);

	r = pkgmgrinfo_pkginfo_get_usr_list(__pkg_list_cb, info, info->uid);
	if (r != PMINFO_R_OK) {
		__remove_user_appinfo(info->uid);
		return;
	}

	_D("reloaded appinfo table for uid %d", info->uid);
}

void appinfo_reload(void)
{
	g_hash_table_foreach(user_tbl, __reload_appinfo, NULL);
}

const char *appinfo_get_value(const struct appinfo *c, enum appinfo_type type)
{
	if (!c) {
		errno = EINVAL;
		_E("appinfo get value: %s", strerror(errno));
		return NULL;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return NULL;

	return c->val[type];
}

int appinfo_set_value(struct appinfo *c, enum appinfo_type type, const char *val)
{
	int category;

	if (!c || !val) {
		errno = EINVAL;
		_E("appinfo is NULL, type: %d, val %s", type, val);
		return -1;
	}

	if (type < AIT_START || type >= AIT_MAX)
		return -1;

	_D("%s : %s : %s", c->val[AIT_NAME], c->val[type], val);
	if (type == AIT_BG_CATEGORY) {
		category = (intptr_t)c->val[type];
		c->val[type] = (char *)((intptr_t)(category | (int)((intptr_t)val)));
	} else {
		if (c->val[type])
			free(c->val[type]);
		c->val[type] = strdup(val);
	}

	return 0;
}

struct _cbinfo {
	appinfo_iter_callback cb;
	void *cb_data;
};

static void __iter_cb(gpointer key, gpointer value, gpointer user_data)
{
	struct _cbinfo *cbi = user_data;

	if (cbi == NULL)
		return;

	cbi->cb(cbi->cb_data, key, value);
}

void appinfo_foreach(uid_t uid, appinfo_iter_callback cb, void *user_data)
{
	struct user_appinfo *info;
	struct _cbinfo cbi;

	info = __find_user_appinfo(uid);
	if (info == NULL) {
		info = __add_user_appinfo(uid);
		if (info == NULL)
			return;
	}

	if (!cb) {
		errno = EINVAL;
		_E("appinfo foreach: %s", strerror(errno));
		return;
	}

	cbi.cb = cb;
	cbi.cb_data = user_data;

	g_hash_table_foreach(info->tbl, __iter_cb, &cbi);
}

int appinfo_get_boolean(const struct appinfo *c, enum appinfo_type type)
{
	const char *v;

	v = appinfo_get_value(c, type);
	if (!v)
		return -1;

	if (!strcmp(v, "1") || !strcasecmp(v, "true"))
		return 1;

	if (!strcmp(v, "0") || !strcasecmp(v, "false"))
		return 0;

	errno = EFAULT;

	return -1;
}
