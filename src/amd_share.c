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
#include <glib.h>
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

#include <aul.h>
#include <aul_svc.h>
#include <bundle.h>
#include <bundle_internal.h>
#include <tzplatform_config.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_share.h"
#include "aul_svc_priv_key.h"

static int __can_share(const char *path, const char *pkgid, uid_t uid)
{
	struct stat path_stat;
	char buf[PATH_MAX];

	if (access(path, F_OK) != 0)
		return -1;

	if (stat(path, &path_stat) != 0)
		return -1;

	if (!S_ISREG(path_stat.st_mode))
		return -1;

	tzplatform_set_user(uid);
	snprintf(buf, sizeof(buf), "%s/%s/data/", tzplatform_getenv(TZ_USER_APP), pkgid);
	tzplatform_reset_user();

	if (strncmp(path, buf, strlen(buf)) != 0)
		return -1;

	return 0;
}

static int __get_owner_pid(int caller_pid, bundle *kb)
{
	char *org_caller = NULL;
	const char *appid;
	int org_caller_pid;

	if (bundle_get_str(kb, AUL_K_ORG_CALLER_PID, &org_caller) == BUNDLE_ERROR_NONE) {
		org_caller_pid = atoi(org_caller);
		appid = _status_app_get_appid_bypid(caller_pid);

		if (appid && (strcmp(APP_SELECTOR, appid) == 0 ||
			strcmp(SHARE_PANEL, appid) == 0))
				caller_pid = org_caller_pid;
	}

	return caller_pid;
}

static shared_info_h __new_shared_info(const char *owner_appid, char **paths)
{
	shared_info_h h;

	h = malloc(sizeof(shared_info_t));

	if (h == NULL)
		return NULL;

	h->owner_appid = strdup(owner_appid);
	h->paths = paths;

	return h;
}

static void __delete_paths(char **paths)
{
	int i = 0;

	if (paths) {
		while (1) {
			if (paths[i] == NULL) {
				free(paths);
				break;
			}
			free(paths[i]);
			i++;
		}
	}
}

static bool __has_valid_uri(int caller_pid, const char *appid, bundle *kb, char **paths,
		int *owner_pid, uid_t uid)
{
	char *path = NULL;
	const char *owner_appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;

	if (bundle_get_str(kb, AUL_SVC_K_URI, &path) == BUNDLE_ERROR_NONE) {
		if (!path) {
			_E("path was null");
			return false;
		}

		if (strncmp(path, "file://", 7) == 0) {
			path = &path[7];
		} else {
			_E("file wasn't started with file://");
			return false;
		}

		if (*owner_pid == -1) {
			*owner_pid = __get_owner_pid(caller_pid, kb);
			*owner_pid = getpgid(*owner_pid); /* for webapp */
		}

		owner_appid = _status_app_get_appid_bypid(*owner_pid);
		ai = appinfo_find(uid, owner_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__can_share(path, pkgid, uid) != 0) {
			_E("__can_share() returned an error");
			return false;
		}

		if (!paths) {
			paths = (char**)malloc(sizeof(char*) * 2);
			if (!paths) {
				_E("Out of memory");
				return false;
			}

			paths[0] = strdup(path);
			paths[1] = NULL;
		} else {
			int i = 0;
			while (1) {
				if (paths[i] == NULL) {
					paths[i] = strdup(path);
					break;
				}
				i++;
			}
		}
		return true;
	}

	return false;
}

shared_info_h _temporary_permission_create(int caller_pid, const char *appid, bundle *kb, uid_t uid)
{
	int type = bundle_get_type(kb, AUL_SVC_DATA_PATH);
	char *path = NULL;
	const char **path_array = NULL;
	int len;
	const char *owner_appid;
	const char *owner_pkgid;
	int i;
	char **paths = NULL;
	int owner_pid = -1;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;
	bool valid = false;
	int cnt = 0;
	shared_info_h h;

	switch (type) {
	case BUNDLE_TYPE_STR:
		bundle_get_str(kb, AUL_SVC_DATA_PATH, &path);
		if (!path) {
			_E("path was null");
			valid = __has_valid_uri(caller_pid, appid, kb, paths, &owner_pid, uid);
			owner_appid = _status_app_get_appid_bypid(owner_pid);
			goto finally;
		}

		owner_pid = __get_owner_pid(caller_pid, kb);
		owner_pid = getpgid(owner_pid); /* for webapp */
		owner_appid = _status_app_get_appid_bypid(owner_pid);

		ai = appinfo_find(uid, owner_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__can_share(path, pkgid, uid) != 0) {
			_E("__can_share() returned an error");
			valid = __has_valid_uri(caller_pid, appid, kb, paths, &owner_pid, uid);
			goto finally;

		}

		paths = (char**)malloc(sizeof(char*) * 3);
		if (!paths) {
			_E("Out of memory");
			goto finally;
		}

		paths[0] = strdup(path);
		paths[1] = NULL;
		paths[2] = NULL;
		valid = true;
		break;

	case BUNDLE_TYPE_STR_ARRAY:
		path_array = bundle_get_str_array(kb, AUL_SVC_DATA_PATH, &len);
		if (!path_array || len <= 0) {
			_E("path_array was null");
			valid = __has_valid_uri(caller_pid, appid, kb, paths, &owner_pid, uid);
			owner_appid = _status_app_get_appid_bypid(owner_pid);
			goto finally;

		}

		owner_pid = __get_owner_pid(caller_pid, kb);
		owner_pid = getpgid(owner_pid); /* for webapp */
		owner_appid = _status_app_get_appid_bypid(owner_pid);
		ai = appinfo_find(uid, owner_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		paths = (char**)malloc(sizeof(char*) * (len + 2));
		if (!paths) {
			_E("Out of memory");
			goto finally;
		}

		for (i = 0; i < len; i++) {
			if (__can_share(path_array[i], pkgid, uid) == 0)
				paths[cnt++] = strdup(path_array[i]);
		}

		if (cnt > 0){
			paths[cnt] = NULL;
			paths[cnt + 1] = NULL;
			valid = true;
		} else {
			free(paths);
			paths = NULL;
		}
		break;
	}

	if (__has_valid_uri(caller_pid, appid, kb, paths, &owner_pid, uid))
		valid = true;
finally:
	if (valid && owner_appid && paths) {
		ai = appinfo_find(uid, owner_appid);
		owner_pkgid = appinfo_get_value(ai, AIT_PKGID);
		ai = appinfo_find(uid, appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		_D("grant permission %s : %s : %s", paths[0], owner_pkgid, pkgid);

		h = __new_shared_info(owner_appid, paths);

		if (h == NULL) {
			__delete_paths(paths);
			return NULL;
		}

		/*
		_D("call security_server_perm_apply_sharing ++");
		int r = security_server_perm_apply_sharing(NULL, (const char**)paths,
				owner_pkgid, pkgid);
		_D("call security_server_perm_apply_sharing --");

		if (r != SECURITY_SERVER_API_SUCCESS) {
			_E("security_server_perm_apply_sharing() returned an error %d",r);
			_temporary_permission_destroy(h);
			return NULL;
		} else {*/
			return h;
		//}
	}

	__delete_paths(paths);
	return NULL;
}

int _temporary_permission_apply(int pid, uid_t uid, shared_info_h handle)
{
	if (handle) {
		shared_info_h si = __new_shared_info(handle->owner_appid, handle->paths);

		_status_add_shared_info(pid, uid, si);
		free(handle->owner_appid);
		handle->owner_appid = NULL;
		handle->paths = NULL;
		return 0;
	}

	return -1;
}

int _temporary_permission_destroy(shared_info_h handle)
{
	if (handle) {
		if (handle->owner_appid)
			free(handle->owner_appid);
		if (handle->paths)
			__delete_paths(handle->paths);
		free(handle);
		return 0;
	}

	return -1;
}

int _temporary_permission_drop(int pid, uid_t uid)
{
	const char *owner_pkgid;
	const char *appid;
	const char *pkgid;
	const struct appinfo *ai;
	shared_info_t *sit;
	GList *list = _status_get_shared_info_list(pid, uid);

	if (!list) {
		_E("list was null");
		return -1;
	}

	while (list) {
		sit = (shared_info_t*)list->data;
		ai = appinfo_find(uid, sit->owner_appid);
		owner_pkgid = appinfo_get_value(ai, AIT_PKGID);
		appid = _status_app_get_appid_bypid(pid);
		ai = appinfo_find(uid, appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		_D("revoke permission %s : %s", owner_pkgid, pkgid);
		//int r = security_server_perm_drop_sharing(NULL, (const char**)sit->paths,
		//		owner_pkgid, pkgid);

		//if (r != SECURITY_SERVER_API_SUCCESS)
		//	_E("revoke error %d",r);

		list = g_list_next(list);
	}
	return _status_clear_shared_info_list(pid, uid);
}


