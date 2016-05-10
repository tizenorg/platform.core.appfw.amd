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
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <aul.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_signal.h"
#include "amd_status.h"
#include "amd_extractor.h"

#define PATH_APP_ROOT tzplatform_getenv(TZ_USER_APP)
#define PATH_GLOBAL_APP_RO_ROOT tzplatform_getenv(TZ_SYS_RO_APP)
#define PATH_GLOBAL_APP_RW_ROOT tzplatform_getenv(TZ_SYS_RW_APP)
#define PREFIX_EXTERNAL_STORAGE_PATH tzplatform_mkpath(TZ_SYS_STORAGE, "sdcard")

static GHashTable *mount_point_hash;

static const char *__get_app_root_path(const struct appinfo *ai)
{
	const char *path_app_root;
	const char *global;
	const char *preload;

	preload = appinfo_get_value(ai, AIT_PRELOAD);
	global = appinfo_get_value(ai, AIT_GLOBAL);
	if (global && strncmp(global, "true", strlen("true")) == 0) {
		if (preload && strncmp(preload, "true", strlen("true")) == 0)
			path_app_root = PATH_GLOBAL_APP_RO_ROOT;
		else
			path_app_root = PATH_GLOBAL_APP_RW_ROOT;
	} else {
		path_app_root = PATH_APP_ROOT;
	}

	return path_app_root;
}

char **_amd_extractor_mountable_tep(const struct appinfo *ai)
{
	char tep_path[PATH_MAX] = {0, };
	char **mnt_path = NULL;
	const char *pkgid = appinfo_get_value(ai, AIT_PKGID);
	const char *installed_storage = appinfo_get_value(ai, AIT_STORAGE_TYPE);
	const char *tep_name = appinfo_get_value(ai, AIT_TEP);

	if (tep_name == NULL || installed_storage == NULL || pkgid == NULL)
		return NULL;

	mnt_path = (char **)malloc(sizeof(char *) * 2);
	if (mnt_path == NULL)
		return NULL;

	SECURE_LOGD("storage: %s", installed_storage);
	if (strncmp(installed_storage, "internal", 8) == 0) {
		mnt_path[1] = strdup(tep_name);
		snprintf(tep_path, PATH_MAX, "%s/%s/tep/mount",
				__get_app_root_path(ai), pkgid);
		mnt_path[0] = strdup(tep_path);
	} else if (strncmp(installed_storage, "external", 8) == 0) {
		snprintf(tep_path, PATH_MAX, "%s/tep/%s",
				PREFIX_EXTERNAL_STORAGE_PATH, tep_name);
		mnt_path[1] = strdup(tep_path);
		/* TODO : keeping tep/tep-access for now for external storage */
		snprintf(tep_path, PATH_MAX, "%s/tep/tep-access",
				PREFIX_EXTERNAL_STORAGE_PATH);
		mnt_path[0] = strdup(tep_path);
	}

	return mnt_path;
}

char **_amd_extractor_mountable_tpk(const struct appinfo *ai)
{
	char mount_point[PATH_MAX] = {0, };
	char **mnt_path = NULL;
	const char *pkgid = appinfo_get_value(ai, AIT_PKGID);
	const char *tpk = appinfo_get_value(ai, AIT_MOUNTABLE_PKG);

	if (tpk == NULL || pkgid == NULL)
		return NULL;

	mnt_path = (char **)malloc(sizeof(char *) * 2);
	if (mnt_path == NULL)
		return NULL;

	mnt_path[1] = strdup(tpk);
	snprintf(mount_point, PATH_MAX, "%s/%s/.pkg",
				__get_app_root_path(ai), pkgid);
	mnt_path[0] = strdup(mount_point);

	return mnt_path;
}

static void __free_path(char **path, int cnt)
{
	int i;

	if (path == NULL)
		return;

	for (i = 0; i < cnt; i++) {
		if (path[i])
			free(path[i]);
	}
	free(path);
}

static void __free_set(gpointer data)
{
	g_hash_table_destroy((GHashTable *)data);
}

static void __prepare_map()
{
	if (mount_point_hash == NULL)
		mount_point_hash = g_hash_table_new_full(g_str_hash, g_str_equal, free, __free_set);
}

static void __put_mount_path(const struct appinfo *ai, const char *str)
{
	const char *appid;
	GHashTable *set;

	__prepare_map();
	set = g_hash_table_lookup(mount_point_hash, str);

	if (set == NULL) {
		set = g_hash_table_new_full(g_str_hash, g_str_equal, free, NULL);
		if (set == NULL)
			return;
		g_hash_table_insert(mount_point_hash, strdup(str), set);
	}

	appid = appinfo_get_value(ai, AIT_NAME);
	g_hash_table_insert(set, strdup(appid), NULL);
}

static bool __is_unmountable(const char *appid, const char *key)
{
	GHashTable *set;

	if (_status_get_process_cnt(appid) > 1)
		return false;

	__prepare_map();
	set  = g_hash_table_lookup(mount_point_hash, key);

	if (set == NULL)
		return false;

	g_hash_table_remove(set, appid);
	if (g_hash_table_size(set) > 0)
		return false;

	return true;
}

void _amd_extractor_mount(const struct appinfo *ai, bundle *kb, _amd_extractor_mountable mountable)
{
	char **mnt_path = NULL;
	int ret;
	const char **array = NULL;
	int len = 0;
	const char *default_array[1] = { NULL };
	char **new_array = NULL;
	int i;
	bool dup = false;
	const char *pkgid = NULL;

	if ((mnt_path = mountable(ai)) == NULL)
		return;

	if (mnt_path[0] && mnt_path[1]) {
		array = bundle_get_str_array(kb, AUL_TEP_PATH, &len);
		if (array == NULL) {
			default_array[0] = mnt_path[0];
			bundle_add_str_array(kb, AUL_TEP_PATH, default_array, 1);
		} else {
			for (i = 0; i < len; i++) {
				if (strcmp(mnt_path[0], array[i]) == 0) {
					dup = true;
					break;
				}
			}

			if (!dup) {
				new_array = malloc(sizeof(char*) * (len + 1));
				for (i = 0; i < len; i++)
					new_array[i] = strdup(array[i]);
				new_array[len] = strdup(mnt_path[0]);
				bundle_del(kb, AUL_TEP_PATH);
				bundle_add_str_array(kb, AUL_TEP_PATH,
						(const char **)new_array, len + 1);
				__free_path(new_array, len + 1);
			}
		}

		__put_mount_path(ai, mnt_path[0]);
		ret = aul_is_tep_mount_dbus_done(mnt_path[0]);
		if (ret != 1) {
			pkgid = appinfo_get_value(ai, AIT_PKGID);
			ret = _signal_send_tep_mount(mnt_path, pkgid);
			if (ret < 0)
				_E("dbus error %d", ret);
			else
				_D("Mount request was sent %s %s", mnt_path[0], mnt_path[1]);
		}
	}

	__free_path(mnt_path, 2);
}

void _amd_extractor_unmount(int pid, _amd_extractor_mountable mountable)
{
	const char *appid;
	const struct appinfo *ai;
	struct stat link_buf;
	int ret;
	char **mnt_path = NULL;

	appid = _status_app_get_appid_bypid(pid);
	if (appid == NULL)
		return;

	ai = appinfo_find(getuid(), appid);
	if (ai == NULL)
		return;

	if ((mnt_path = mountable(ai)) == NULL)
		return;

	if (!__is_unmountable(appid, mnt_path[0]))
		return;

	g_hash_table_remove(mount_point_hash, mnt_path[0]);
	ret = _signal_send_tep_unmount(mnt_path[0]);
	if (ret < 0)
		_E("Failed to send unmount: %s", mnt_path[0]);
	else
		_D("Unmount request was sent %s", mnt_path[0]);

	ret = lstat(mnt_path[0], &link_buf);
	if (ret == 0) {
		ret = unlink(mnt_path[0]);
		if (ret == 0)
			_D("Symbolic link removed");
		else
			_E("Failed to remove the link: %s", mnt_path[0]);
	}

	__free_path(mnt_path, 2);
}

