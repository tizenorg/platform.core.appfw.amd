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

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include <glib.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle_internal.h>
#include <aul_sock.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_app_group.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_app_status.h"
#include "app_signal.h"
#include "amd_appinfo.h"
#include "amd_share.h"
#include "amd_suspend.h"
#include "amd_wayland.h"

#define APP_SVC_K_LAUNCH_MODE   "__APP_SVC_LAUNCH_MODE__"

static struct wl_display *display;
static struct tizen_policy *tz_policy;
static int tz_policy_initialized;

static void __wl_listener_cb(void *data, struct wl_registry *reg,
		uint32_t id, const char *interface, uint32_t ver)
{
	if (!strcmp(interface, "tizen_policy")) {
		if (!tz_policy) {
			tz_policy = wl_registry_bind(reg, id,
					&tizen_policy_interface, 1);
		}
	}
}

static void __wl_listener_remove_cb(void *data, struct wl_registry *reg,
		uint32_t id)
{
	if (tz_policy) {
		tizen_policy_destroy(tz_policy);
		tz_policy = NULL;
	}
}

static struct wl_registry_listener registry_listener = {
	__wl_listener_cb,
	__wl_listener_remove_cb
};

static GHashTable *app_group_hash;
static int dead_pid = -1;
static int focused_leader_pid = -1;
static GList *recycle_bin;

extern char *home_appid;

typedef struct _app_group_context_t {
	int pid;
	int wid;
	int status;
	int fg;
	int group_sig;
	int can_be_leader;
	int reroute;
	int caller_pid;
	int can_shift;
	int recycle;
	app_group_launch_mode launch_mode;
} app_group_context_t;

static int __wl_init(void)
{
	if (!display) {
		display = _wayland_get_display();
		if (!display) {
			_E("Failed to get display");
			return -1;
		}
	}

	if (!tz_policy)
		return -1;

	tz_policy_initialized = 1;

	return 0;
}

static void __lower_window(int wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			_E("__wl_init() failed");
			return;
		}
	}

	tizen_policy_lower_by_res_id(tz_policy, wid);
	wl_display_roundtrip(display);
}

static void __attach_window(int parent_wid, int child_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			_E("__wl_init() failed");
			return;
		}
	}

	tizen_policy_set_transient_for(tz_policy, child_wid, parent_wid);
	wl_display_roundtrip(display);
}

static void __detach_window(int child_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			_E("__wl_init() failed");
			return;
		}
	}

	tizen_policy_unset_transient_for(tz_policy, child_wid);
	wl_display_roundtrip(display);
}

static void __activate_below(int wid, int below_wid)
{
	if (!tz_policy_initialized) {
		if (__wl_init() < 0) {
			_E("__wl_init() failed");
			return;
		}
	}

	tizen_policy_activate_below_by_res_id(tz_policy, below_wid, wid);
	wl_display_roundtrip(display);
}

static gint __comp_pid(gconstpointer a, gconstpointer b)
{
	app_group_context_t *ac1 = (app_group_context_t *)a;

	return ac1->pid - GPOINTER_TO_INT(b);
}

static void __list_destroy_cb(gpointer data)
{
	free(data);
}

static gboolean __hash_table_cb(gpointer key, gpointer value,
		gpointer user_data)
{
	int pid = GPOINTER_TO_INT(user_data);
	GList *list = (GList *)value;
	GList *itr = g_list_first(list);
	app_group_context_t *ac;

	while (itr != NULL) {
		ac = (app_group_context_t *)itr->data;
		if (ac && ac->pid == pid) {
			free(ac);
			list = g_list_delete_link(list, itr);
			if (g_list_length(list) == 0) {
				g_list_free_full(list, __list_destroy_cb);
				return TRUE;
			} else {
				return FALSE;
			}
		}
		itr = g_list_next(itr);
	}

	return FALSE;
}

static GList *__find_removable_apps(int from)
{
	int cnt;
	int *pids = NULL;
	GList *list = NULL;
	bool found = false;
	int i;
	int j;
	int *gpids = NULL;
	int gcnt;

	_app_group_get_leader_pids(&cnt, &pids);

	for (i = 0; i < cnt; i++) {
		_app_group_get_group_pids(pids[i], &gcnt, &gpids);
		for (j = 0; j < gcnt; j++) {
			if (gpids[j] == from) {
				found = true;
				continue;
			}

			if (found) {
				list = g_list_append(list,
						GINT_TO_POINTER(gpids[j]));
			}
		}

		if (gpids != NULL)
			free(gpids);

		if (found)
			break;
	}

	if (pids != NULL)
		free(pids);

	return list;
}

static void __prepare_to_suspend_services(int pid, uid_t uid)
{
	int ret;
	int dummy;

	_D("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_raw(pid, uid, APP_SUSPEND, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
	if (ret < 0)
		_E("error on suspend service for pid: %d", pid);
}

static void __prepare_to_wake_services(int pid, uid_t uid)
{
	int ret;
	int dummy;

	_D("[__SUSPEND__] pid: %d, uid: %d", pid, uid);
	ret = aul_sock_send_raw(pid, uid, APP_WAKE, (unsigned char *)&dummy,
			sizeof(int), AUL_SOCK_NOREPLY);
	if (ret < 0)
		_E("error on wake service for pid: %d", pid);
}

static void __set_flag(GList *list, int cpid, int flag, bool force)
{
	app_group_context_t *ac;
	app_status_h app_status;
	const struct appinfo *ai;
	const char *appid;
	const char *pkgid;
	int bg_category;
	uid_t uid;

	while (list) {
		ac = (app_group_context_t *)list->data;
		if (ac && (ac->fg != flag || force == true)) {
			app_status = _app_status_find(ac->pid);
			appid = _app_status_get_appid(app_status);
			uid = _app_status_get_uid(app_status);
			ai = _appinfo_find(getuid(), appid);
			pkgid = _appinfo_get_value(ai, AIT_PKGID);
			bg_category = (intptr_t)_appinfo_get_value(ai,
					AIT_BG_CATEGORY);
			if (flag) {
				_D("Send FG signal %s", appid);
				aul_send_app_status_change_signal(ac->pid,
						appid, pkgid, STATUS_FOREGROUND,
						APP_TYPE_UI);
				if (!bg_category) {
					_app_status_find_service_apps(
						app_status,
						STATUS_VISIBLE,
						__prepare_to_wake_services,
						false);
				}
			} else {
				_D("send BG signal %s", appid);
				aul_send_app_status_change_signal(ac->pid,
						appid, pkgid, STATUS_BACKGROUND,
						APP_TYPE_UI);
				if (!bg_category) {
					_app_status_find_service_apps(
						app_status,
						STATUS_BG,
						__prepare_to_suspend_services,
						true);
					if (force && cpid == ac->pid) {
						__prepare_to_suspend_services(
								ac->pid, uid);
						_suspend_add_timer(ac->pid, ai);
					}
				}
			}
			ac->fg = flag;
		}
		list = g_list_next(list);
	}
}

static void __set_fg_flag(int cpid, int flag, bool force)
{
	int lpid = _app_group_get_leader_pid(cpid);
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		ac = (app_group_context_t *)i->data;
		if (ac && ac->pid == lpid) {
			__set_flag(i, cpid, flag, force);
			break;
		}
	}
}

static bool __is_visible(int cpid)
{
	int lpid = _app_group_get_leader_pid(cpid);
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		ac = (app_group_context_t *)i->data;
		if (ac && ac->pid == lpid) {
			while (i != NULL) {
				ac = (app_group_context_t *)i->data;
				if (ac && ac->status == STATUS_VISIBLE)
					return true;

				i = g_list_next(i);
			}
			break;
		}
	}

	return false;
}

static bool __can_attach_window(bundle *b, const char *appid,
		app_group_launch_mode *launch_mode)
{
	char *str = NULL;
	const char *mode = NULL;
	const struct appinfo *ai = NULL;

	ai = _appinfo_find(getuid(), appid);
	mode = _appinfo_get_value(ai, AIT_LAUNCH_MODE);

	if (mode == NULL)
		*launch_mode = APP_GROUP_LAUNCH_MODE_SINGLE;
	else if (strcmp(mode, "caller") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_CALLER;
	else if (strcmp(mode, "single") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_SINGLE;
	else if (strcmp(mode, "group") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_GROUP;
	else if (strcmp(mode, "singleton") == 0)
		*launch_mode = APP_GROUP_LAUNCH_MODE_SINGLETON;

	switch (*launch_mode) {
	case APP_GROUP_LAUNCH_MODE_CALLER:
	case APP_GROUP_LAUNCH_MODE_SINGLETON:
		_D("launch mode from db is caller or singleton");

		bundle_get_str(b, APP_SVC_K_LAUNCH_MODE, &str);
		if (str != NULL && strncmp(str, "group", 5) == 0)
			return true;
		break;
	case APP_GROUP_LAUNCH_MODE_GROUP:
		return true;
	case APP_GROUP_LAUNCH_MODE_SINGLE:
		return false;
	}

	return false;
}

static bool __can_be_leader(bundle *b)
{
	char *str = NULL;

	bundle_get_str(b, AUL_SVC_K_CAN_BE_LEADER, &str);
	if (str != NULL && strcmp(str, "true") == 0)
		return true;

	return false;
}

static int __get_previous_pid(int pid)
{
	int previous_pid = -1;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac == NULL) {
				i = g_list_next(i);
				continue;
			}

			if (ac && ac->pid == pid)
				return previous_pid;

			previous_pid = ac->pid;
			i = g_list_next(i);
		}
	}

	return -1;
}

static int __get_caller_pid(bundle *kb)
{
	const char *pid_str;
	int pid;

	pid_str = bundle_get_val(kb, AUL_K_ORG_CALLER_PID);
	if (pid_str)
		goto end;

	pid_str = bundle_get_val(kb, AUL_K_CALLER_PID);
	if (pid_str == NULL)
		return -1;

end:
	pid = atoi(pid_str);
	if (pid <= 1)
		return -1;

	return pid;
}

static app_group_context_t *__detach_context_from_recycle_bin(int pid)
{
	GList *iter = recycle_bin;
	app_group_context_t *ac;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		if (ac && ac->pid == pid) {
			recycle_bin = g_list_delete_link(recycle_bin, iter);
			return ac;
		}

		iter = g_list_next(iter);
	}

	return NULL;

}

static void __group_add(int leader_pid, int pid, int wid,
		app_group_launch_mode mode, int caller_pid, int can_shift,
		int recycle)
{
	app_group_context_t *ac = NULL;
	GList *list;
	GList *tmp_list;

	ac = __detach_context_from_recycle_bin(pid);
	if (ac == NULL) {
		ac = malloc(sizeof(app_group_context_t));
		if (ac == NULL) {
			_E("out of memory");
			return;
		}
		ac->pid = pid;
		ac->wid = wid;
		ac->fg = 0;
		ac->can_be_leader = 0;
		ac->reroute = 0;
		ac->launch_mode = mode;
		ac->caller_pid = caller_pid;
		ac->can_shift = can_shift;
		ac->recycle = recycle;
	}

	if (leader_pid == pid || ac->recycle)
		ac->group_sig = 1;
	else
		ac->group_sig = 0;

	dead_pid = -1;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(leader_pid));
	if (list != NULL) {
		tmp_list = g_list_find_custom(list, GINT_TO_POINTER(pid),
				__comp_pid);
		if (tmp_list != NULL) {
			_E("pid exist");
			free(ac);
			return;
		}
	}

	list = g_list_append(list, ac);
	g_hash_table_insert(app_group_hash, GINT_TO_POINTER(leader_pid), list);

	if (ac->wid != 0)
		_app_group_set_window(pid, ac->wid);
}

static void __group_remove(int pid)
{
	int ppid = __get_previous_pid(pid);

	g_hash_table_foreach_remove(app_group_hash, __hash_table_cb,
			GINT_TO_POINTER(pid));

	if (ppid != -1)
		_app_group_set_status(ppid, -1, false);
}

static app_group_context_t *__get_context(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid)
				return ac;

			i = g_list_next(i);
		}
	}

	return NULL;
}

static int __can_recycle(int pid)
{
	app_group_context_t *context = __get_context(pid);

	if (context)
		return context->recycle;

	return 0;
}

static int __can_reroute(int pid)
{
	app_group_context_t *context = __get_context(pid);

	if (context)
		return context->reroute;

	return 0;
}

static app_group_context_t *__context_dup(const app_group_context_t *context)
{
	app_group_context_t *dup;

	if (!context) {
		_E("context is NULL.");
		return NULL;
	}

	dup = malloc(sizeof(app_group_context_t));
	if (!dup) {
		_E("out of memory");
		return NULL;
	}

	memcpy(dup, context, sizeof(app_group_context_t));
	return dup;
}

static void __do_recycle(app_group_context_t *context)
{
	const char *appid;
	const char *pkgid;
	const struct appinfo *ai;
	app_status_h app_status;
	uid_t uid;

	app_status = _app_status_find(context->pid);
	uid = _app_status_get_uid(app_status);

	if (context->fg) {
		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(uid, appid);
		pkgid = _appinfo_get_value(ai, AIT_PKGID);

		_D("send_signal BG %s", appid);
		aul_send_app_status_change_signal(context->pid, appid, pkgid,
				STATUS_BACKGROUND, APP_TYPE_UI);
		_app_status_find_service_apps(app_status, STATUS_BG,
				__prepare_to_suspend_services, true);
		context->fg = 0;
	}
	recycle_bin = g_list_append(recycle_bin, context);
	_temporary_permission_drop(context->pid, uid);
}

void _app_group_init(void)
{
	_wayland_add_registry_listener(&registry_listener, NULL);
	app_group_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal,
			NULL, NULL);
}

void _app_group_remove(int pid)
{
	app_group_context_t *context;

	__group_remove(pid);
	context = __detach_context_from_recycle_bin(pid);
	if (context)
		free(context);
}

void _app_group_remove_from_recycle_bin(int pid)
{
	app_group_context_t *context = __detach_context_from_recycle_bin(pid);

	if (context)
		free(context);
}

int _app_group_get_window(int pid)
{
	app_group_context_t *context = __get_context(pid);

	if (context)
		return context->wid;

	return -1;
}

int _app_group_set_window(int pid, int wid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	int previous_wid;
	int caller_wid;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		previous_wid = 0;
		while (i != NULL) {
			ac = (app_group_context_t *) i->data;
			if (ac == NULL) {
				i = g_list_next(i);
				continue;
			}

			if (ac && ac->pid == pid) {
				ac->wid = wid;
				if (previous_wid != 0)
					__attach_window(previous_wid, wid);

				if (ac->can_shift && ac->caller_pid > 0) {
					caller_wid = _app_group_get_window(
							ac->caller_pid);
					if (caller_wid != 0) {
						__attach_window(caller_wid,
								wid);
					}
				}

				i = g_list_next(i);
				if (i) {
					ac = (app_group_context_t *)i->data;
					if (ac->wid != 0)
						__attach_window(wid, ac->wid);
				}

				return 0;
			}
			previous_wid = ac->wid;
			i = g_list_next(i);
		}
	}

	return -1;
}

void _app_group_clear_top(int pid)
{
	int p;
	GList *list;
	GList *itr;

	list = __find_removable_apps(pid);
	if (list != NULL) {
		itr = g_list_last(list);
		while (itr != NULL) {
			p = GPOINTER_TO_INT(itr->data);
			__detach_window(p);
			_term_sub_app(p);
			_app_group_remove(p);
			itr = g_list_previous(itr);
		}
		g_list_free(list);
	}
}

bool _app_group_is_group_app(bundle *kb)
{
	char *str = NULL;
	const char *mode;
	char *appid = NULL;
	const struct appinfo *ai;

	if (kb == NULL)
		return false;

	bundle_get_str(kb, AUL_K_APPID, &appid);
	if (appid == NULL)
		return false;

	ai = _appinfo_find(getuid(), appid);
	mode = _appinfo_get_value(ai, AIT_LAUNCH_MODE);

	if (mode != NULL && (strcmp(mode, "caller") == 0 ||
				strcmp(mode, "singleton") == 0)) {
		bundle_get_str(kb, APP_SVC_K_LAUNCH_MODE, &str);
		if (str != NULL && strcmp(str, "group") == 0)
			return true;
	} else if (mode != NULL && strcmp(mode, "group") == 0) {
		return true;
	}

	return false;
}

void _app_group_get_leader_pids(int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	int size = g_hash_table_size(app_group_hash);
	int *leader_pids;
	int i;

	if (size > 0) {
		leader_pids = (int *)malloc(sizeof(int) * size);
		if (leader_pids == NULL) {
			_E("out of memory");
			*cnt = 0;
			*pids = NULL;
			return;
		}

		g_hash_table_iter_init(&iter, app_group_hash);
		i = 0;
		while (g_hash_table_iter_next(&iter, &key, &value)) {
			leader_pids[i] = GPOINTER_TO_INT(key);
			i++;
		}

		*cnt = size;
		*pids = leader_pids;
	} else {
		*cnt = 0;
		*pids = NULL;
	}
}

bool _app_group_is_leader_pid(int pid)
{
	int cnt;
	int *pids = NULL;
	int i;

	_app_group_get_leader_pids(&cnt, &pids);
	for (i = 0; i < cnt; i++) {
		if (pid == pids[i]) {
			free(pids);
			return true;
		}
	}

	if (pids != NULL)
		free(pids);

	return false;
}

void _app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	int size;
	int *pid_array;
	int j;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		if (GPOINTER_TO_INT(key) == leader_pid) {
			list = (GList *)value;
			i = g_list_first(list);
			size = g_list_length(list);

			if (size > 0) {
				j = 0;
				pid_array = (int *)malloc(sizeof(int) * size);
				if (pid_array == NULL) {
					_E("out of memory");
					*cnt = 0;
					*pids = NULL;
					return;
				}

				while (i != NULL) {
					ac = (app_group_context_t *)i->data;
					pid_array[j] = ac->pid;
					i = g_list_next(i);
					j++;
				}

				*cnt = size;
				*pids = pid_array;
			} else {
				*cnt = 0;
				*pids = NULL;
			}
			return;
		}
	}

	*cnt = 0;
	*pids = NULL;
}

bool _app_group_is_sub_app(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *found;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		if (list != NULL) {
			found = g_list_find_custom(list, GINT_TO_POINTER(pid),
					__comp_pid);
			if (found) {
				if (g_list_first(list) == found)
					return false;
				return true;
			}
		}
	}

	return false;
}

void _app_group_reroute(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *found;
	GList *before;
	GList *after;
	app_group_context_t *ac1;
	app_group_context_t *ac2;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		if (list != NULL) {
			found = g_list_find_custom(list, GINT_TO_POINTER(pid),
					__comp_pid);
			if (found) {
				before = g_list_previous(found);
				after = g_list_next(found);
				if (before == NULL || after == NULL)
					return;

				_D("reroute");
				ac1 = (app_group_context_t *)before->data;
				ac2 = (app_group_context_t *)after->data;

				__detach_window(ac2->wid);
				__attach_window(ac1->wid, ac2->wid);
				break;
			}
		}
	}
}

int _app_group_get_leader_pid(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *found;
	int lpid = -1;
	int again = 0;

repeat:
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		if (list != NULL) {
			found = g_list_find_custom(list, GINT_TO_POINTER(pid),
					__comp_pid);
			if (found) {
				lpid = GPOINTER_TO_INT(key);
				break;
			}
		}
	}

	if (lpid == -1 && dead_pid == pid)
		lpid = focused_leader_pid;

	if (lpid == -1 && again == 0) {
		pid = getpgid(pid);
		again = 1;
		goto repeat;
	}

	return lpid;
}

void _app_group_set_dead_pid(int pid)
{
	focused_leader_pid = _app_group_get_leader_pid(pid);
	dead_pid = pid;
	if (dead_pid == focused_leader_pid) {
		focused_leader_pid = -1;
		dead_pid = -1;
	}
}

int _app_group_get_status(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid)
				return  ac->status;

			i = g_list_next(i);
		}
	}
	return -1;
}

static void __set_status(app_group_context_t *ac, app_group_context_t *last_ac,
		int lpid, int pid, int status, bool force)
{
	const char *pkgid;
	app_status_h app_status;

	if (status > 0)
		ac->status = status;

	if (last_ac->wid != 0 || status == STATUS_VISIBLE || force == TRUE) {
		if (__is_visible(pid)) {
			__set_fg_flag(pid, 1, force);
			if (!ac->group_sig && lpid != pid) {
				app_status = _app_status_find(pid);
				pkgid = _app_status_get_pkgid(app_status);
				_D("send group signal %d", pid);
				aul_send_app_group_signal(lpid, pid, pkgid);
				ac->group_sig = 1;
			}
		} else {
			__set_fg_flag(pid, 0, force);
		}
	}
}

int _app_group_set_status(int pid, int status, bool force)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;
	GList *last;
	app_group_context_t *last_ac;
	int lpid;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		last = g_list_last(list);
		last_ac = (app_group_context_t *)last->data;
		lpid = GPOINTER_TO_INT(key);
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid) {
				__set_status(ac, last_ac, lpid, pid, status,
						force);
				return 0;
			}
			i = g_list_next(i);
		}
	}
	return -1;
}

int _app_group_get_fg_flag(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid)
				return ac->fg;

			i = g_list_next(i);
		}
	}

	return 0;
}

int _app_group_set_hint(int pid, bundle *kb)
{
	char *str_leader = NULL;
	char *str_reroute = NULL;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	if (kb == NULL)
		return -1;

	bundle_get_str(kb, AUL_SVC_K_CAN_BE_LEADER, &str_leader);
	bundle_get_str(kb, AUL_SVC_K_REROUTE, &str_reroute);

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid) {
				if (str_leader && !strcmp(str_leader, "true"))
					ac->can_be_leader = 1;
				if (str_reroute && !strcmp(str_reroute, "true"))
					ac->reroute = 1;
				return 0;
			}
			i = g_list_next(i);
		}
	}

	return -1;
}

int _app_group_find_second_leader(int lpid)
{
	app_group_context_t *ac;
	GList *list;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));
	if (list != NULL) {
		list = g_list_next(list);
		if (list != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac && ac->can_be_leader) {
				_W("found the second leader, lpid: %d, pid: %d",
						lpid, ac->pid);
				return ac->pid;
			}
		}
	}

	return -1;
}

void _app_group_remove_leader_pid(int lpid)
{
	app_group_context_t *ac;
	GList *next;
	GList *list;

	list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));
	if (list != NULL) {
		next = g_list_next(list);
		if (next != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac)
				free(ac);
			list = g_list_delete_link(list, list);
			ac = (app_group_context_t *)next->data;
			g_hash_table_insert(app_group_hash,
					GINT_TO_POINTER(ac->pid), next);
			g_hash_table_remove(app_group_hash,
					GINT_TO_POINTER(lpid));
		}
	}
}

int _app_group_can_start_app(const char *appid, bundle *b, bool *can_attach,
				int *lpid, app_group_launch_mode *mode)
{
	const char *val;
	int caller_pid;
	int caller_wid;

	*can_attach = false;
	if (__can_attach_window(b, appid, mode)) {
		*can_attach = true;
		val = bundle_get_val(b, AUL_K_ORG_CALLER_PID);
		if (val == NULL)
			val = bundle_get_val(b, AUL_K_CALLER_PID);

		if (val == NULL) {
			_E("no caller pid");
			return -1;
		}

		caller_pid = atoi(val);
		*lpid = _app_group_get_leader_pid(caller_pid);
		if (*lpid != -1) {
			caller_wid = _app_group_get_window(caller_pid);
			if (caller_wid == 0) {
				_D("caller window wasn't ready");
				if (__can_be_leader(b))
					*can_attach = false;
				else
					*can_attach = true;
			}
		} else {
			_E("no lpid");
			if (__can_be_leader(b))
				*can_attach = false;
			else
				return -1;
		}
	}

	return 0;
}

void _app_group_start_app(int pid, bundle *b, int lpid, bool can_attach,
		app_group_launch_mode mode)
{
	int caller_pid = __get_caller_pid(b);
	int can_shift = 0;
	int recycle = 0;
	const char *str;

	_D("app_group_start_app");

	str = bundle_get_val(b, AUL_SVC_K_SHIFT_WINDOW);
	if (str != NULL && strcmp(str, "true") == 0)
		can_shift = 1;

	str = bundle_get_val(b, AUL_SVC_K_RECYCLE);
	if (str != NULL && strcmp(str, "true") == 0)
		recycle = 1;

	if (can_attach)
		__group_add(lpid, pid, 0, mode, caller_pid, 0, recycle);
	else
		__group_add(pid, pid, 0, mode, caller_pid, can_shift, 0);
	_app_group_set_hint(pid, b);
}

int _app_group_find_singleton(const char *appid, int *found_pid,
		int *found_lpid)
{
	GHashTableIter iter;
	gpointer key = NULL;
	gpointer value = NULL;
	app_status_h app_status;
	const char *target;
	GList *list;
	app_group_context_t *ac;
	int singleton = APP_GROUP_LAUNCH_MODE_SINGLETON;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		while (list != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac && ac->launch_mode == singleton) {
				app_status = _app_status_find(ac->pid);
				target = _app_status_get_appid(app_status);
				if (appid && target && !strcmp(appid, target)) {
					*found_pid = ac->pid;
					*found_lpid = GPOINTER_TO_INT(key);
					return 0;
				}
			}
			list = g_list_next(list);
		}
	}

	return -1;
}

int _app_group_can_reroute(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid)
				return ac->reroute;

			i = g_list_next(i);
		}
	}

	return 0;
}

void _app_group_lower(int pid, int *exit)
{
	app_group_context_t *ac;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;

	if (_app_group_is_sub_app(pid)) {
		if (__can_recycle(pid) && __can_reroute(pid)) {
			ac = __get_context(pid);
			if (ac) {
				if (ac->wid != 0)
					__detach_window(ac->wid);
				_app_group_reroute(pid);
				ac = __context_dup(ac);
				__group_remove(pid);
				if (ac)
					__do_recycle(ac);
			}
			*exit = 0;
		} else
			*exit = 1;
		return;
	}

	*exit = 0;
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->can_shift) {
				__detach_window(ac->wid);
				ac->can_shift = 0;
				__lower_window(ac->wid);
			}
			return;
		}
		i = g_list_next(i);
	}
}

static void __restart_app(app_group_context_t *ac, int pid, bundle *b)
{
	const char *pid_str;
	int cwid;

	ac->caller_pid = __get_caller_pid(b);

	if (ac->can_shift) {
		if (ac->wid != 0)
			__detach_window(ac->wid);
		ac->can_shift = 0;
	}

	pid_str = bundle_get_val(b, AUL_SVC_K_SHIFT_WINDOW);
	if (pid_str && !strcmp(pid_str, "true")) {
		ac->can_shift = 1;
		if (ac->wid != 0) {
			if (ac->caller_pid > 0) {
				cwid = _app_group_get_window(ac->caller_pid);
				if (cwid != 0)
					__attach_window(cwid, ac->wid);
				else
					_E("invalid caller wid");
			} else {
				_E("invalid caller pid");
			}
		}
	}
}

void _app_group_restart_app(int pid, bundle *b)
{
	GList *list;
	GList *i;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	app_group_context_t *ac;

	if (b == NULL)
		return;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid) {
				__restart_app(ac, pid, b);
				return;
			}
			i = g_list_next(i);
		}
	}
}

int _app_group_find_pid_from_recycle_bin(const char *appid)
{
	app_group_context_t *ac;
	app_status_h app_status;
	const char *appid_from_bin;
	GList *iter = recycle_bin;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		app_status = _app_status_find(ac->pid);
		appid_from_bin = _app_status_get_appid(app_status);
		if (appid && appid_from_bin && !strcmp(appid, appid_from_bin))
			return ac->pid;

		iter = g_list_next(iter);
	}

	return -1;
}

void _app_group_get_idle_pids(int *cnt, int **pids)
{
	GList *iter = recycle_bin;
	int idle_cnt = g_list_length(iter);
	int *idle_pids;
	int i = 0;
	app_group_context_t *ac;

	if (idle_cnt <= 0) {
		*cnt = 0;
		*pids = NULL;
		return;
	}

	idle_pids = (int *)malloc(sizeof(int) * idle_cnt);
	if (idle_pids == NULL) {
		_E("Out-of-memory");
		*cnt = 0;
		*pids = NULL;
		return;
	}

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		idle_pids[i] = ac->pid;
		iter = g_list_next(iter);
		i++;
	}

	*cnt = idle_cnt;
	*pids = idle_pids;
}

int _app_group_get_next_caller_pid(int pid)
{
	GList *list;
	GList *i;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid) {
				i = g_list_next(i);
				if (i == NULL)
					return -1;

				ac = (app_group_context_t *)i->data;
				return ac->caller_pid;
			}
			i = g_list_next(i);
		}
	}

	return -1;
}

int _app_group_activate_below(int pid, const char *below_appid)
{
	app_group_context_t *context = __get_context(pid);
	int wid;
	int tpid;
	GList *list;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	app_status_h app_status;
	const char *appid;

	if (!context) {
		_E("Invalid pid");
		return -1;
	}

	if (context->wid == 0) {
		_E("Caller wid was 0");
		return -1;
	}

	if (!below_appid) {
		_E("below_appid was null");
		return -1;
	}

	wid = context->wid;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		tpid = GPOINTER_TO_INT(key);
		app_status = _app_status_find(tpid);
		appid = _app_status_get_appid(app_status);
		if (appid && strcmp(appid, below_appid) == 0) {
			list = (GList *)value;
			context  = (app_group_context_t *)list->data;
			__activate_below(wid, context->wid);
			return 0;
		}
	}

	_E("Failed to find available appid to move");
	return -1;
}

