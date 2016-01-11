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
#include <sys/smack.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_appinfo.h"
#include "amd_status.h"
#include "amd_share.h"

/** AUL SVC internal private key */
#define AUL_SVC_K_URI       "__APP_SVC_URI__"
#define APP_SELECTOR_LABEL "User::App::org.tizen.app-selector"
#define SHARE_PANEL_LABEL "User::App::org.tizen.share-panel"
#define APP_LABEL_PREFIX "User::App::"

struct share_file_info_s {
	char *caller_exec_label;
	char *callee_exec_label;
	char **paths;
};

static int __can_share(const char *path, const char *pkgid)
{
	struct stat path_stat;

	if (access(path, F_OK) != 0)
		return -1;

	if (stat(path, &path_stat) != 0)
		return -1;

	if (!S_ISREG(path_stat.st_mode))
		return -1;

	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "/opt/usr/apps/%s/data/", pkgid);
	if (strncmp(path, buf, strlen(buf)) != 0)
		return -1;

	return 0;
}

static int __get_current_security_attribute(int pid, char *buf, int size)
{
	int fd;
	int ret;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "/proc/%d/attr/current", pid);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, buf, size - 1);
	if (ret <= 0) {
		close(fd);
		return -1;
	} else
		buf[ret] = 0;

	close(fd);

	return 0;
}

static int __get_exec_label_by_pid(int pid, char** exec_label)
{
	const char *appid = NULL;
	const char *exec = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;
	char attr[PATH_MAX];

	if (__get_current_security_attribute(pid, attr, sizeof(attr)) == 0) {
		*exec_label = strdup(attr);
		return 0;
	}

	appid = _status_app_get_appid_bypid(pid);
	if (appid) {
		ai = appinfo_find(getuid(), appid);
		exec = appinfo_get_value(ai, AIT_EXEC);
		type = appinfo_get_value(ai, AIT_TYPE);

		if (exec && type) {
			if (strcmp("wgt", type) == 0) {
				if (smack_lgetlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			} else {
				if (smack_getlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			}
		}
	}

	return -1;
}

static int __get_exec_label_by_appid(const char *appid, char** exec_label)
{
	const char *exec = NULL;
	const char *type = NULL;
	const struct appinfo *ai = NULL;

	if (appid) {
		ai = appinfo_find(getuid(), appid);
		exec = appinfo_get_value(ai, AIT_EXEC);
		type = appinfo_get_value(ai, AIT_TYPE);

		if (exec && type) {
			if (strcmp("wgt", type) == 0) {
				if (smack_lgetlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			} else {
				if (smack_getlabel(exec, exec_label, SMACK_LABEL_EXEC) == 0)
					return 0;
			}
		}
	}

	return -1;
}

static int __get_owner_pid(int caller_pid, bundle *kb)
{
	char *org_caller = NULL;

	if (bundle_get_str(kb, AUL_K_ORG_CALLER_PID, &org_caller) == BUNDLE_ERROR_NONE) {
		int org_caller_pid = atoi(org_caller);
		char *c_exec_label = NULL;

		if (__get_exec_label_by_pid(caller_pid, &c_exec_label) == 0) {

			if (c_exec_label &&
				(strcmp(APP_SELECTOR_LABEL, c_exec_label) == 0 ||
				strcmp(SHARE_PANEL_LABEL, c_exec_label) == 0))
					caller_pid = org_caller_pid;
		}

		if (c_exec_label)
			free(c_exec_label);
	}

	return caller_pid;
}

static int __get_exec_label(char **caller_exec_label, char **callee_exec_label,
				int caller_pid, const char *appid)
{
	char *label_caller = NULL;
	char *label = NULL;

	if (__get_exec_label_by_pid(caller_pid, &label_caller) != 0) {
		return -1;
	}

	if (__get_exec_label_by_appid(appid, &label) != 0) {
		free(label_caller);
		return -1;
	}

	*caller_exec_label = label_caller;
	*callee_exec_label = label;

	if (label_caller && label && strcmp(label_caller, label) == 0) {
		_E("caller_exec_label == callee_exec_label");
		return -1;
	}

	return 0;
}

static void __add_shared_info(int pid, const char *caller_exec_label, const char *callee_exec_label, char **paths)
{
	_status_set_exec_label(pid, getuid(), callee_exec_label);
	_status_add_shared_info(pid, getuid(), caller_exec_label, paths);
}

static share_file_info_h __new_share_file_info(char *caller_exec_label, char *callee_exec_label, char **paths)
{
	struct share_file_info_s *h;
	share_file_info_h sfi = malloc(sizeof(struct share_file_info_s));

	if (sfi == NULL)
		return NULL;

	h = (struct share_file_info_s *)sfi;
	h->caller_exec_label = caller_exec_label;
	h->callee_exec_label = callee_exec_label;
	h->paths = paths;

	return sfi;
}

static void __delete_share_file_info(char *caller_exec_label, char *callee_exec_label, char **paths)
{
	if (caller_exec_label)
		free(caller_exec_label);
	if (callee_exec_label)
		free(callee_exec_label);
	if (paths) {
		int i = 0;
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
		int *owner_pid, char *caller_exec_label, char *callee_exec_label)
{
	char *path = NULL;
	const char *tmp_appid = NULL;
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

		tmp_appid = _status_app_get_appid_bypid(*owner_pid);
		ai = appinfo_find(getuid(), tmp_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__can_share(path, pkgid) != 0) {
			_E("__can_share() returned an error");
			return false;
		}

		if (!caller_exec_label && !callee_exec_label) {
			if (__get_exec_label(&caller_exec_label, &callee_exec_label, *owner_pid,
				appid) != 0) {
				_E("__get_exec_label() returned an error");
				return false;
			}
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
/*
static const char* __get_pkgid_from_exec_label(const char *exec_label)
{
	const char *appid;
	const char *pkgid;
	const struct appinfo *ai;
	int len = strlen(APP_LABEL_PREFIX);

	if (exec_label == NULL)
		return NULL;

	if (strlen(exec_label) <= len)
		return NULL;

	appid =  exec_label + len;
	ai = appinfo_find(getuid(), appid);
	pkgid = appinfo_get_value(ai, AIT_PKGID);

	return pkgid;
}*/

share_file_info_h _temporary_permission_create(int caller_pid, const char *appid, bundle *kb)
{
	int type = bundle_get_type(kb, AUL_SVC_DATA_PATH);
	char *path = NULL;
	const char **path_array = NULL;
	int len;
	char *caller_exec_label = NULL;
	char *callee_exec_label = NULL;
	int i;
	char **paths = NULL;
	int owner_pid = -1;
	const char *tmp_appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;
	bool valid = false;

	switch (type) {
	case BUNDLE_TYPE_STR:
		bundle_get_str(kb, AUL_SVC_DATA_PATH, &path);
		if (!path) {
			_E("path was null");
			valid = __has_valid_uri(caller_pid, appid, kb, paths,
					&owner_pid, caller_exec_label, callee_exec_label);
			goto finally;
		}

		owner_pid = __get_owner_pid(caller_pid, kb);
		owner_pid = getpgid(owner_pid); /* for webapp */
		tmp_appid = _status_app_get_appid_bypid(owner_pid);

		ai = appinfo_find(getuid(), tmp_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__can_share(path, pkgid) != 0) {
			_E("__can_share() returned an error");
			valid = __has_valid_uri(caller_pid, appid, kb, paths,
					&owner_pid, caller_exec_label, callee_exec_label);
			goto finally;

		}

		if (__get_exec_label(&caller_exec_label, &callee_exec_label, owner_pid,
			appid) != 0) {
			_E("__get_exec_label() returned an error");
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
			valid = __has_valid_uri(caller_pid, appid, kb, paths,
					&owner_pid, caller_exec_label, callee_exec_label);
			goto finally;

		}

		owner_pid = __get_owner_pid(caller_pid, kb);
		owner_pid = getpgid(owner_pid); /* for webapp */
		tmp_appid = _status_app_get_appid_bypid(owner_pid);
		ai = appinfo_find(getuid(), tmp_appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		if (__get_exec_label(&caller_exec_label, &callee_exec_label, owner_pid,
			appid) != 0) {
			_E("__get_exec_label() returned an error");
			goto finally;
		}

		paths = (char**)malloc(sizeof(char*) * (len + 2));
		if (!paths) {
			_E("Out of memory");
			goto finally;
		}

		int cnt = 0;
		for (i = 0; i < len; i++) {
			if (__can_share(path_array[i], pkgid) == 0)
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

finally:
	if (valid && caller_exec_label && paths) {
		share_file_info_h h;

		_D("grant permission %s : %s : %s", paths[0], caller_exec_label,
			callee_exec_label);

		h = __new_share_file_info(caller_exec_label, callee_exec_label, paths);

		if (h == NULL) {
			__delete_share_file_info(caller_exec_label, callee_exec_label, paths);
			return NULL;
		}

		/*
		_D("call security_server_perm_apply_sharing ++");
		int r = security_server_perm_apply_sharing(NULL, (const char**)paths,
				__get_pkgid_from_exec_label(caller_exec_label),
				__get_pkgid_from_exec_label(callee_exec_label));
		_D("call security_server_perm_apply_sharing --");

		if (r != SECURITY_SERVER_API_SUCCESS)
			_E("security_server_perm_apply_sharing() returned an error %d",r);
		else */
			return h;
	}

	__delete_share_file_info(caller_exec_label, callee_exec_label, paths);
	return NULL;
}

int _temporary_permission_apply(int pid, share_file_info_h handle)
{
	if (handle) {
		struct share_file_info_s *h = (struct share_file_info_s *)handle;

		__add_shared_info(pid, h->caller_exec_label, h->callee_exec_label, h->paths);
		h->paths = NULL;
		return 0;
	}

	return -1;
}

int _temporary_permission_destroy(share_file_info_h handle)
{
	if (handle) {
		struct share_file_info_s *h = (struct share_file_info_s *)handle;

		__delete_share_file_info(h->caller_exec_label, h->callee_exec_label, h->paths);
		free(h);
		return 0;
	}

	return -1;
}

int _temporary_permission_drop(int pid)
{
	GList *list = _status_get_shared_info_list(pid, getuid());
	const char *callee_label = _status_get_exec_label(pid, getuid());

	if (!list || !callee_label) {
		_E("list or callee_label was null");
		return -1;
	}

	while (list) {
		shared_info_t *sit = (shared_info_t*)list->data;

		_D("revoke permission %s : %s", sit->owner_exec_label, callee_label);
		//int r = security_server_perm_drop_sharing(NULL, (const char**)sit->paths,
		//		__get_pkgid_from_exec_label(sit->owner_exec_label),
		//		__get_pkgid_from_exec_label(callee_label));

		//if (r != SECURITY_SERVER_API_SUCCESS)
		//	_E("revoke error %d",r);

		list = g_list_next(list);
	}
	return _status_clear_shared_info_list(pid, getuid());
}


