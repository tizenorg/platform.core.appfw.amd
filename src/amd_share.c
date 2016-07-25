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
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <linux/limits.h>

#include <glib.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>
#include <security-manager.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_app_status.h"
#include "amd_share.h"
#include "aul_svc_priv_key.h"

#define LEGACY_APP_ROOT_PATH "/opt/usr/apps"
#define LEGACY_PATH_OFFSET	14

struct shared_info_main_s {
	char *appid;
	uid_t uid;
	shared_info_t *shared_info;
};

static char **__array_dup(const char **strs, int len)
{
	int i;
	char **array;

	if (len <= 0 || strs == NULL)
		return NULL;

	array = malloc(sizeof(char *) * len);
	if (array == NULL)
		return NULL;

	for (i = 0; i < len; i++)
		array[i] = strdup(strs[i]);

	return array;
}

static void __array_free(char **array, int len)
{
	int i;

	if (len <= 0 || array == NULL)
		return;

	for (i = 0; i < len; i++)
		free(array[i]);

	free(array);
}

static int __can_share(const char *path, const char *pkgid, uid_t uid)
{
	struct stat path_stat;
	char buf[PATH_MAX];
	char new_path[PATH_MAX];

	if (strncmp(LEGACY_APP_ROOT_PATH, path, strlen(LEGACY_APP_ROOT_PATH)) == 0) {
		tzplatform_set_user(uid);
		snprintf(new_path, sizeof(new_path), "%s/%s",
			tzplatform_getenv(TZ_USER_APP), &path[LEGACY_PATH_OFFSET]);
		tzplatform_reset_user();
		path = new_path;
	}

	if (access(path, F_OK) != 0)
		return -1;

	if (stat(path, &path_stat) != 0)
		return -1;

	if (!S_ISREG(path_stat.st_mode))
		return -1;

	tzplatform_set_user(uid);
	snprintf(buf, sizeof(buf), "%s/%s/data/",
			tzplatform_getenv(TZ_USER_APP), pkgid);
	tzplatform_reset_user();

	if (strncmp(path, buf, strlen(buf)) != 0)
		return -1;

	return 0;
}

static char *__convert_path(const char *path, uid_t uid, bool *converted)
{
	char new_path[PATH_MAX];

	*converted = false;
	if (strncmp(LEGACY_APP_ROOT_PATH, path, strlen(LEGACY_APP_ROOT_PATH)) == 0) {
		tzplatform_set_user(uid);
		snprintf(new_path, sizeof(new_path), "%s/%s",
			tzplatform_getenv(TZ_USER_APP), &path[LEGACY_PATH_OFFSET]);
		tzplatform_reset_user();
		path = new_path;
		*converted = true;
	}

	return strdup(path);
}

static int __get_owner_pid(int caller_pid, bundle *kb)
{
	char *org_caller = NULL;
	const char *appid;
	int org_caller_pid;
	app_status_h app_status;
	int ret;

	ret = bundle_get_str(kb, AUL_K_ORG_CALLER_PID, &org_caller);
	if (ret != BUNDLE_ERROR_NONE)
		return caller_pid;

	org_caller_pid = atoi(org_caller);
	app_status = _app_status_find(caller_pid);
	appid = _app_status_get_appid(app_status);
	if (appid && (strcmp(APP_SELECTOR, appid) == 0 ||
			strcmp(SHARE_PANEL, appid) == 0))
		caller_pid = org_caller_pid;

	return caller_pid;
}

static const char *__get_owner_appid(int caller_pid, bundle *kb)
{
	const char *owner_appid;
	int owner_pid = -1;
	app_status_h app_status;

	owner_pid = __get_owner_pid(caller_pid, kb);
	owner_pid = getpgid(owner_pid); /* for webapp */
	app_status = _app_status_find(owner_pid);
	owner_appid = _app_status_get_appid(app_status);

	return owner_appid;
}

static shared_info_h __new_shared_info_handle(const char *appid, uid_t uid,
		const char *owner_appid)
{
	shared_info_h h;
	int ret;

	h = malloc(sizeof(struct shared_info_main_s));
	if (h == NULL)
		return NULL;

	h->shared_info = malloc(sizeof(shared_info_t));
	if (h->shared_info == NULL) {
		free(h);
		return NULL;
	}

	ret = security_manager_private_sharing_req_new(&h->shared_info->handle);
	if (ret != SECURITY_MANAGER_SUCCESS) {
		free(h->shared_info);
		free(h);
		return NULL;
	}

	h->shared_info->owner_appid = strdup(owner_appid);
	h->appid = strdup(appid);
	h->uid = uid;

	return h;
}

static GList *__add_valid_uri(GList *paths, int caller_pid, const char *appid,
		const char *owner_appid, bundle *kb, uid_t uid)
{
	char *path = NULL;
	const char *pkgid;
	const struct appinfo *ai;
	int ret;
	bool converted = false;
	char buf[PATH_MAX] = { 0, };

	ret = bundle_get_str(kb, AUL_SVC_K_URI, &path);
	if (ret != BUNDLE_ERROR_NONE)
		return paths;

	if (!path) {
		_D("path was null");
		return paths;
	}

	if (strncmp(path, "file://", 7) == 0) {
		path = &path[7];
	} else {
		_E("file wasn't started with file://");
		return paths;
	}

	ai = _appinfo_find(uid, owner_appid);
	pkgid = _appinfo_get_value(ai, AIT_PKGID);

	if (__can_share(path, pkgid, uid) != 0) {
		_E("__can_share() returned an error");
		return paths;
	}

	path = __convert_path(path, uid, &converted);
	paths = g_list_append(paths, path);

	if (converted) {
		snprintf(buf, sizeof(buf), "file://%s", path);
		bundle_del(kb, AUL_SVC_K_URI);
		bundle_add(kb, AUL_SVC_K_URI, buf);
	}

	return paths;
}

static GList *__add_valid_key_for_data_selected(GList *paths, int caller_pid,
		const char *appid, const char *owner_appid, bundle *kb,
		uid_t uid)
{
	int i;
	int len = 0;
	const char **path_array = NULL;
	char **new_array = NULL;
	int type = bundle_get_type(kb, AUL_SVC_DATA_SELECTED);
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;
	char *path;
	bool converted = false;
	bool found = false;

	if (type != BUNDLE_TYPE_STR_ARRAY)
		return paths;

	path_array = bundle_get_str_array(kb, AUL_SVC_DATA_SELECTED, &len);
	if (!path_array || len <= 0) {
		_E("path_array was null");
		return paths;
	}

	ai = _appinfo_find(uid, owner_appid);
	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL) {
		_E("pkgid was null");
		return paths;
	}

	new_array = __array_dup(path_array, len);
	for (i = 0; i < len; i++) {
		if (__can_share(path_array[i], pkgid, uid) == 0) {
			path = __convert_path(path_array[i], uid, &converted);
			paths = g_list_append(paths, path);

			if (converted) {
				free(new_array[i]);
				new_array[i] = strdup(path);
				found = true;
			}
		}
	}

	if (found) {
		bundle_del(kb, AUL_SVC_DATA_SELECTED);
		bundle_add_str_array(kb, AUL_SVC_DATA_SELECTED, (const char **)new_array, len);
	}
	__array_free(new_array, len);

	return paths;
}

static GList *__add_valid_key_for_data_path(GList *paths, int caller_pid,
		const char *appid, const char *owner_appid, bundle *kb,
		uid_t uid)
{
	int type = bundle_get_type(kb, AUL_SVC_DATA_PATH);
	char *path = NULL;
	const char **path_array = NULL;
	char **new_array = NULL;
	int len;
	int i;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;
	bool converted = false;
	bool found = false;

	switch (type) {
	case BUNDLE_TYPE_STR:
		bundle_get_str(kb, AUL_SVC_DATA_PATH, &path);
		if (!path) {
			_E("path was null");
			break;
		}

		ai = _appinfo_find(uid, owner_appid);
		pkgid = _appinfo_get_value(ai, AIT_PKGID);
		if (pkgid == NULL) {
			_E("pkgid was null");
			break;
		}

		if (__can_share(path, pkgid, uid) != 0) {
			_E("__can_share() returned an error");
			break;
		}
		path = __convert_path(path, uid, &converted);
		paths = g_list_append(paths, path);
		if (converted) {
			bundle_del(kb, AUL_SVC_DATA_PATH);
			bundle_add(kb, AUL_SVC_DATA_PATH, path);
		}
		break;
	case BUNDLE_TYPE_STR_ARRAY:
		path_array = bundle_get_str_array(kb, AUL_SVC_DATA_PATH, &len);
		if (!path_array || len <= 0) {
			_E("path_array was null");
			break;
		}

		ai = _appinfo_find(uid, owner_appid);
		pkgid = _appinfo_get_value(ai, AIT_PKGID);
		if (pkgid == NULL) {
			_E("pkgid was null");
			break;
		}

		new_array = __array_dup(path_array, len);
		for (i = 0; i < len; i++) {
			if (__can_share(path_array[i], pkgid, uid) == 0) {
				path = __convert_path(path_array[i], uid, &converted);
				paths = g_list_append(paths, path);
				if (converted) {
					free(new_array[i]);
					new_array[i] = strdup(path);
					found = true;
				}
			}
		}

		if (found) {
			bundle_del(kb, AUL_SVC_DATA_PATH);
			bundle_add_str_array(kb, AUL_SVC_DATA_PATH, (const char **)new_array, len);
		}
		__array_free(new_array, len);
		break;
	}

	return paths;
}

static char **__convert_list_to_array(GList *list)
{
	int len;
	int i = 0;
	char **array;

	if (list == NULL)
		return NULL;

	len = g_list_length(list);
	if (len == 0)
		return NULL;

	array = (char **)g_malloc(sizeof(char *) * (len + 1));
	if (array == NULL) {
		_E("out of memory");
		return NULL;
	}

	while (list) {
		array[i] = g_strdup(list->data);
		list = g_list_next(list);
		i++;
	}
	array[len] = NULL;

	return array;
}

shared_info_h _temporary_permission_create(int caller_pid, const char *appid,
		bundle *kb, uid_t uid)
{
	char **path_array = NULL;
	int len;
	const char *owner_appid = NULL;
	GList *paths = NULL;
	shared_info_h h = NULL;
	int r;

	owner_appid = __get_owner_appid(caller_pid, kb);
	paths = __add_valid_key_for_data_path(paths, caller_pid, appid,
			owner_appid, kb, uid);
	paths = __add_valid_key_for_data_selected(paths, caller_pid, appid,
			owner_appid, kb, uid);
	paths = __add_valid_uri(paths, caller_pid, appid, owner_appid, kb, uid);
	if (!paths || !owner_appid)
		goto clear;

	_D("grant permission %s : %s", owner_appid, appid);

	h = __new_shared_info_handle(appid, uid, owner_appid);
	if (h == NULL)
		goto clear;

	len = g_list_length(paths);
	path_array = __convert_list_to_array(paths);
	if (path_array == NULL)
		goto clear;

	r = security_manager_private_sharing_req_set_owner_appid(
			h->shared_info->handle, owner_appid);
	if (r != SECURITY_MANAGER_SUCCESS)
		_E("Failed to set owner appid(%s) %d", owner_appid, r);

	r = security_manager_private_sharing_req_set_target_appid(
			h->shared_info->handle, appid);
	if (r != SECURITY_MANAGER_SUCCESS)
		_E("Failed to set target appid(%s) %d", appid, r);

	r = security_manager_private_sharing_req_add_paths(
			h->shared_info->handle, (const char **)path_array, len);
	if (r != SECURITY_MANAGER_SUCCESS)
		_E("Failed to add paths %d", r);

	_D("security_manager_private_sharing_apply ++");
	r = security_manager_private_sharing_apply(h->shared_info->handle);
	_D("security_manager_private_sharing_apply --");
	if (r != SECURITY_MANAGER_SUCCESS) {
		_E("Failed to apply private sharing %d", r);
		_temporary_permission_destroy(h);
		h = NULL;
	}

clear:
	if (paths)
		g_list_free_full(paths, free);

	if (path_array)
		g_strfreev(path_array);

	return h;
}

int _temporary_permission_apply(int pid, uid_t uid, shared_info_h handle)
{
	int ret;
	app_status_h app_status;

	if (handle == NULL)
		return -1;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return -1;

	ret = _app_status_add_shared_info(app_status, handle->shared_info);
	if (ret != 0)
		return ret;

	handle->shared_info = NULL;

	return 0;
}

int _temporary_permission_destroy(shared_info_h handle)
{
	int r;

	if (handle == NULL)
		return -1;

	if (handle->shared_info) { /* back out */
		_D("revoke permission %s : %s",
				handle->shared_info->owner_appid,
				handle->appid);
		r = security_manager_private_sharing_drop(
				handle->shared_info->handle);
		if (r != SECURITY_MANAGER_SUCCESS)
			_E("revoke error %d", r);

		security_manager_private_sharing_req_free(
				handle->shared_info->handle);
		free(handle->shared_info->owner_appid);
	}

	free(handle->appid);
	free(handle);

	return 0;
}

int _temporary_permission_drop(int pid, uid_t uid)
{
	int r;
	shared_info_t *sit;
	app_status_h app_status;
	GList *list;

	app_status = _app_status_find(pid);
	if (app_status == NULL)
		return -1;

	list = _app_status_get_shared_info_list(app_status);
	if (!list) {
		_D("list was null");
		return -1;
	}

	while (list) {
		sit = (shared_info_t *)list->data;
		_D("revoke permission %s : %d", sit->owner_appid, pid);
		r = security_manager_private_sharing_drop(sit->handle);
		if (r != SECURITY_MANAGER_SUCCESS)
			_E("revoke error %d", r);
		security_manager_private_sharing_req_free(sit->handle);
		list = g_list_next(list);
	}

	return _app_status_clear_shared_info_list(app_status);
}

