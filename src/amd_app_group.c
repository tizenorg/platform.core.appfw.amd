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
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <glib.h>
#include <aul.h>
#include <aul_svc.h>
#include <bundle_internal.h>
#include <aul_sock.h>

#include "amd_util.h"
#include "amd_app_group.h"
#include "amd_launch.h"
#include "amd_request.h"
#include "amd_status.h"
#include "app_signal.h"
#include "amd_appinfo.h"
#include "amd_share.h"

#define APP_SVC_K_LAUNCH_MODE   "__APP_SVC_LAUNCH_MODE__"

#ifdef WAYLAND
#include <Ecore_Wayland.h>
#include <wayland-client.h>
#include <tizen-extension-client-protocol.h>
static struct tizen_policy *tz_policy;

static void _reg_handle_global(void *data, struct wl_registry *reg,
		uint32_t id, const char *interface, uint32_t ver)
{
	if (!strcmp(interface, "tizen_policy")) {
		tz_policy = wl_registry_bind(reg,
				id,
				&tizen_policy_interface,
				1);
	}
}

static void _reg_handle_global_remove(void *data, struct wl_registry *reg,
		uint32_t id)
{
	/* do nothing */
}

static const struct wl_registry_listener reg_listener = {
	_reg_handle_global,
	_reg_handle_global_remove
};
#endif

static GHashTable *app_group_hash = NULL;
static int dead_pid = -1;
static int focused_leader_pid = -1;
static GList *recycle_bin = NULL;

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

static void __attach_window(int parent_wid, int child_wid)
{
#ifdef WAYLAND
	struct wl_display *dpy;
	struct wl_registry *reg;

	dpy = wl_display_connect(NULL);
	reg = wl_display_get_registry(dpy);
	wl_registry_add_listener(reg, &reg_listener, NULL);
	wl_display_roundtrip(dpy);

	if (!tz_policy) {
		_E("ERR: no tizen_policy global interface");
		wl_registry_destroy(reg);
		wl_display_disconnect(dpy);
		return;
	}

	tizen_policy_set_transient_for(tz_policy, child_wid, parent_wid);
	wl_display_roundtrip(dpy);

	tizen_policy_destroy(tz_policy);
	wl_registry_destroy(reg);
	wl_display_disconnect(dpy);
#else
	/* ecore_x_icccm_transient_for_set(child_wid, parent_wid); */
#endif
}

static void __detach_window(int child_wid)
{
#ifdef WAYLAND
	struct wl_display *dpy;
	struct wl_registry *reg;

	dpy = wl_display_connect(NULL);
	reg = wl_display_get_registry(dpy);
	wl_registry_add_listener(reg, &reg_listener, NULL);
	wl_display_roundtrip(dpy);

	if (!tz_policy) {
		_E("ERR: no tz_policy global interface");
		wl_registry_destroy(reg);
		wl_display_disconnect(dpy);
		return;
	}

	tizen_policy_unset_transient_for(tz_policy, child_wid);
	wl_display_roundtrip(dpy);

	tizen_policy_destroy(tz_policy);
	wl_registry_destroy(reg);
	wl_display_disconnect(dpy);
#else
	/* ecore_x_icccm_transient_for_unset(child_wid); */
#endif
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
			list = g_list_remove_link(list, itr);
			if (g_list_length(list) == 0) {
				g_list_free_full(list, __list_destroy_cb);
				return TRUE;
			} else
				return FALSE;
		}
		itr = g_list_next(itr);
	}

	return FALSE;
}

static GList* __find_removable_apps(int from)
{
	int cnt;
	int *pids = NULL;
	GList *list = NULL;
	gboolean found = FALSE;
	int i;
	int j;
	int *gpids = NULL;
	int gcnt;

	app_group_get_leader_pids(&cnt, &pids);

	for (i = 0; i < cnt; i++) {
		app_group_get_group_pids(pids[i], &gcnt, &gpids);
		for (j = 0; j < gcnt; j++) {
			if (gpids[j] == from) {
				found = TRUE;
				continue;
			}

			if (found)
				list = g_list_append(list, GINT_TO_POINTER(gpids[j]));
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

static void __prepare_to_suspend_services(int pid)
{
	/*
	int ret;
	int dummy;
	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	ret = aul_sock_send_raw_async(pid, getuid(), APP_SUSPEND, (unsigned char *)&dummy, sizeof(int));
	if (ret > 0)
		close(ret);
	*/
}

static void __prepare_to_wake_services(int pid)
{
	/*
	int ret;
	int dummy;
	SECURE_LOGD("[__SUSPEND__] pid: %d", pid);
	ret = aul_sock_send_raw_async(pid, getuid(), APP_WAKE, (unsigned char *)&dummy, sizeof(int));
	if (ret > 0)
		close(ret);
	*/
}

static void __set_fg_flag(int cpid, int flag, gboolean force)
{
	int lpid = app_group_get_leader_pid(cpid);
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	const char *appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;
	GList *list;
	GList *i;
	app_group_context_t *ac;
	int bg_category = 0x00;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);
		ac = (app_group_context_t *)i->data;
		if (ac && ac->pid == lpid) {
			while (i != NULL) {
				ac = (app_group_context_t*) i->data;
				if ((ac && ac->fg != flag) || force == TRUE) {
					appid = _status_app_get_appid_bypid(ac->pid);
					ai = appinfo_find(getuid(), appid);
					pkgid = appinfo_get_value(ai, AIT_PKGID);
					bg_category = (bool)appinfo_get_value(ai, AIT_BG_CATEGORY);

					if (flag) {
						_D("send_signal FG %s", appid);

						aul_send_app_status_change_signal(ac->pid, appid,
										pkgid,
										STATUS_FOREGROUND,
										APP_TYPE_UI);
						if (!bg_category)
							_status_find_service_apps(ac->pid, getuid(), STATUS_VISIBLE, __prepare_to_wake_services, false);

					} else {
						_D("send_signal BG %s", appid);
						aul_send_app_status_change_signal(ac->pid, appid,
										pkgid,
										STATUS_BACKGROUND,
										APP_TYPE_UI);
						if (!bg_category) {
							_status_find_service_apps(ac->pid, getuid(), STATUS_BG, __prepare_to_suspend_services, true);
							/*
							if (force == TRUE && cpid == ac->pid) {
								__prepare_to_suspend_services(ac->pid);
								_amd_suspend_add_timer(ac->pid, ai);
							}*/
						}


					}
					ac->fg = flag;
				}
				i = g_list_next(i);
			}
			break;
		}
	}
}

static gboolean __is_visible(int cpid)
{
	int lpid = app_group_get_leader_pid(cpid);
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
				ac = (app_group_context_t*) i->data;
				if (ac && ac->status == STATUS_VISIBLE)
					return TRUE;

				i = g_list_next(i);
			}
			break;
		}
	}

	return FALSE;
}

static gboolean __can_attach_window(bundle *b, const char *appid, app_group_launch_mode *launch_mode)
{
	char *str = NULL;
	const char *mode = NULL;
	const struct appinfo *ai = NULL;

	ai = appinfo_find(getuid(), appid);
	mode = appinfo_get_value(ai, AIT_LAUNCH_MODE);

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
			return TRUE;
		break;
	case APP_GROUP_LAUNCH_MODE_GROUP:
		return TRUE;
	case APP_GROUP_LAUNCH_MODE_SINGLE:
		return FALSE;
	}

	return FALSE;
}

static gboolean __can_be_leader(bundle *b)
{
	char *str = NULL;

	bundle_get_str(b, AUL_SVC_K_CAN_BE_LEADER, &str);

	if (str != NULL && strcmp(str, "true") == 0)
		return TRUE;

	return FALSE;
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
			ac = (app_group_context_t*)i->data;
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

static app_group_context_t* __detach_context_from_recycle_bin(int pid)
{
	GList *iter = recycle_bin;
	app_group_context_t *ac;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		if (ac && ac->pid == pid) {
			recycle_bin = g_list_remove_link(recycle_bin, iter);
			return ac;
		}

		iter = g_list_next(iter);
	}

	return NULL;

}

static void __group_add(int leader_pid, int pid, int wid, app_group_launch_mode mode,
			int caller_pid, int can_shift, int recycle)
{
	app_group_context_t *ac = NULL;
	GList *list;

	if ((ac = __detach_context_from_recycle_bin(pid)) == NULL) {
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
		if (g_list_find_custom(list, GINT_TO_POINTER(pid), __comp_pid) != NULL) {
			_E("pid exist");
			free(ac);
			return;
		}
	}

	list = g_list_append(list, ac);
	g_hash_table_insert(app_group_hash, GINT_TO_POINTER(leader_pid), list);

	if (ac->wid != 0)
		app_group_set_window(pid, ac->wid);
}

static void __group_remove(int pid)
{
	int ppid = __get_previous_pid(pid);

	g_hash_table_foreach_remove(app_group_hash, __hash_table_cb,
			GINT_TO_POINTER(pid));

	if (ppid != -1)
		app_group_set_status(ppid, -1, false);
}

static app_group_context_t* __get_context(int pid)
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
	const char *appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;

	if (context->fg) {
		appid = _status_app_get_appid_bypid(context->pid);
		ai = appinfo_find(getuid(), appid);
		pkgid = appinfo_get_value(ai, AIT_PKGID);

		_D("send_signal BG %s", appid);
		aul_send_app_status_change_signal(context->pid, appid, pkgid,
						STATUS_BACKGROUND,
						APP_TYPE_UI);
		_status_find_service_apps(context->pid, getuid(), STATUS_BG, __prepare_to_suspend_services, true);
		context->fg = 0;
	}
	recycle_bin = g_list_append(recycle_bin, context);
	_temporary_permission_drop(context->pid, getuid());
}

void app_group_init()
{
	app_group_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
			NULL);
}

void app_group_remove(int pid)
{
	app_group_context_t *context;

	__group_remove(pid);
	context = __detach_context_from_recycle_bin(pid);
	if (context)
		free(context);
}

void app_group_remove_from_recycle_bin(int pid)
{
	app_group_context_t *context = __detach_context_from_recycle_bin(pid);

	if (context)
		free(context);
}

int app_group_get_window(int pid)
{
	app_group_context_t *context = __get_context(pid);

	if (context)
		return context->wid;

	return -1;
}

int app_group_set_window(int pid, int wid)
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
			ac = (app_group_context_t*) i->data;
			if (ac == NULL) {
				i = g_list_next(i);
				continue;
			}

			if (ac && ac->pid == pid) {
				ac->wid = wid;
				if (previous_wid != 0)
					__attach_window(previous_wid, wid);

				if (ac->can_shift && ac->caller_pid > 0) {
					caller_wid = app_group_get_window(ac->caller_pid);
					if (caller_wid != 0)
						__attach_window(caller_wid, wid);
				}

				i = g_list_next(i);
				if (i) {
					ac = (app_group_context_t*) i->data;
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

void app_group_clear_top(int pid)
{
	int p;
	GList *list = __find_removable_apps(pid);

	if (list != NULL) {
		GList *itr = g_list_last(list);

		while (itr != NULL) {
			p = GPOINTER_TO_INT(itr->data);
			__detach_window(p);
			_term_sub_app(p);
			app_group_remove(p);
			itr = g_list_previous(itr);
		}
		g_list_free(list);
	}
}

gboolean app_group_is_group_app(bundle* kb)
{
	char *str = NULL;
	const char *mode = NULL;
	char *appid = NULL;
	const struct appinfo *ai = NULL;

	if (kb == NULL)
		return FALSE;

	bundle_get_str(kb, AUL_K_APPID, &appid);

	if (appid == NULL)
		return FALSE;

	ai = appinfo_find(getuid(), appid);
	mode = appinfo_get_value(ai, AIT_LAUNCH_MODE);

	if (mode != NULL && (strncmp(mode, "caller", 6) == 0 ||
				strncmp(mode, "singleton", 9) == 0)) {
		bundle_get_str(kb, APP_SVC_K_LAUNCH_MODE, &str);

		if (str != NULL && strncmp(str, "group", 5) == 0)
			return TRUE;
	} else if (mode != NULL && strncmp(mode, "group", 5) == 0) {
		return TRUE;
	}

	return FALSE;
}

void app_group_get_leader_pids(int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	int size = g_hash_table_size(app_group_hash);
	int *leader_pids;
	int i;

	if (size > 0) {
		leader_pids = (int*)malloc(sizeof(int) * size);
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

gboolean app_group_is_leader_pid(int pid)
{
	int cnt;
	int *pids = NULL;
	int i;

	app_group_get_leader_pids(&cnt, &pids);

	for (i = 0; i < cnt; i++) {
		if (pid == pids[i]) {
			free(pids);
			return TRUE;
		}
	}

	if (pids != NULL)
		free(pids);

	return FALSE;
}

void app_group_get_group_pids(int leader_pid, int *cnt, int **pids)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	int size;
	int *pid_array;
	int j;

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
					app_group_context_t *ac = (app_group_context_t*) i->data;

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

gboolean app_group_is_sub_app(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *found;;


	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		found = NULL;

		if (list != NULL) {
			if ((found = g_list_find_custom(list, GINT_TO_POINTER(pid), __comp_pid)) != NULL) {
				if (g_list_first(list) == found)
					return FALSE;
				return TRUE;
			}
		}
	}

	return FALSE;
}

void app_group_reroute(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *found = NULL;
	GList *before = NULL;
	GList *after = NULL;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		found = NULL;
		before = NULL;
		after = NULL;

		if (list != NULL) {
			if ((found = g_list_find_custom(list, GINT_TO_POINTER(pid), __comp_pid)) != NULL) {
				before = g_list_previous(found);
				after = g_list_next(found);

				if (before == NULL || after == NULL)
					return;

				_D("reroute");
				app_group_context_t *ac1 = (app_group_context_t*) before->data;
				app_group_context_t *ac2 = (app_group_context_t*) after->data;

				__detach_window(ac2->wid);
				__attach_window(ac1->wid, ac2->wid);
				break;
			}
		}
	}
}

int app_group_get_leader_pid(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	int lpid = -1;
	int again = 0;

repeat:
	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		if (list != NULL) {
			if (g_list_find_custom(list, GINT_TO_POINTER(pid), __comp_pid) != NULL) {
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

void app_group_set_dead_pid(int pid)
{
	focused_leader_pid = app_group_get_leader_pid(pid);
	dead_pid = pid;

	if (dead_pid == focused_leader_pid) {
	   focused_leader_pid = -1;
	   dead_pid = -1;
	}
}

int app_group_get_status(int pid)
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
			ac = (app_group_context_t*) i->data;
			if (ac && ac->pid == pid)
				return  ac->status;

			i = g_list_next(i);
		}
	}
	return -1;
}

int app_group_set_status(int pid, int status, gboolean force)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;
	GList *last;
	app_group_context_t *last_ac;
	char *appid = NULL;
	const char *pkgid = NULL;
	const struct appinfo *ai = NULL;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		i = g_list_first(list);

		while (i != NULL) {
			ac = (app_group_context_t*) i->data;
			if (ac && ac->pid == pid) {
				if (status > 0)
					ac->status = status;
				last = g_list_last(list);
				last_ac = (app_group_context_t *)last->data;

				if (last_ac->wid != 0 || status == STATUS_VISIBLE || force == TRUE) {
					if (__is_visible(pid)) {
						__set_fg_flag(pid, 1, force);
						if (!ac->group_sig && GPOINTER_TO_INT(key) != pid) {
							appid = _status_app_get_appid_bypid(pid);
							ai = appinfo_find(getuid(), appid);
							pkgid = appinfo_get_value(ai, AIT_PKGID);

							_D("send group signal %d", pid);
							aul_send_app_group_signal(GPOINTER_TO_INT(key), pid, pkgid);
							ac->group_sig = 1;
						}
					} else {
						__set_fg_flag(pid, 0, force);
					}
				}
				return 0;
			}
			i = g_list_next(i);
		}
	}
	return -1;
}

int app_group_get_fg_flag(int pid)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList*) value;
		i = g_list_first(list);
		while (i != NULL) {
			ac = (app_group_context_t*) i->data;
			if (ac && ac->pid == pid)
				return ac->fg;

			i = g_list_next(i);
		}
	}

	return 0;
}

int app_group_set_hint(int pid, bundle *kb)
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
				if (str_leader != NULL && strcmp(str_leader, "true") == 0)
					ac->can_be_leader = 1;
				if (str_reroute != NULL && strcmp(str_reroute, "true") == 0)
					ac->reroute = 1;
				return 0;
			}
			i = g_list_next(i);
		}
	}

	return -1;
}

int app_group_find_second_leader(int lpid)
{
	app_group_context_t *ac;
	GList *list = (GList *)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));
	if (list != NULL) {
		list = g_list_next(list);
		if (list != NULL) {
			ac = (app_group_context_t*) list->data;
			if (ac && ac->can_be_leader) {
				_W("found the second leader, lpid: %d, pid: %d", lpid, ac->pid);
				return ac->pid;
			}
		}
	}

	return -1;
}

void app_group_remove_leader_pid(int lpid)
{
	app_group_context_t *ac;
	GList *next;
	GList *list = (GList*)g_hash_table_lookup(app_group_hash,
			GINT_TO_POINTER(lpid));

	if (list != NULL) {
		next = g_list_next(list);
		if (next != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac)
				free(ac);
			list = g_list_remove_link(list, list);

			ac = (app_group_context_t *)next->data;
			g_hash_table_insert(app_group_hash, GINT_TO_POINTER(ac->pid), next);
			g_hash_table_remove(app_group_hash, GINT_TO_POINTER(lpid));
		}
	}
}

int app_group_can_start_app(const char *appid, bundle *b, gboolean *can_attach,
				int *lpid, app_group_launch_mode *mode)
{
	const char *val = NULL;
	int caller_pid;
	int caller_wid;

	*can_attach = FALSE;
	if (__can_attach_window(b, appid, mode)) {
		*can_attach = TRUE;

		val = bundle_get_val(b, AUL_K_ORG_CALLER_PID);
		if (val == NULL)
			val = bundle_get_val(b, AUL_K_CALLER_PID);

		if (val == NULL) {
			_E("no caller pid");
			return -1;
		}

		caller_pid = atoi(val);

		*lpid = app_group_get_leader_pid(caller_pid);
		if (*lpid != -1) {
			caller_wid = app_group_get_window(caller_pid);

			if (caller_wid == 0) {
				_E("caller window wasn't ready");
				if (__can_be_leader(b))
					*can_attach = FALSE;
				else
					*can_attach = TRUE;
			}

		} else {
			_E("no lpid");
			if (__can_be_leader(b))
				*can_attach = FALSE;
			else
				return -1;
		}
	}

	return 0;
}

void app_group_start_app(int pid, bundle *b, int lpid, gboolean can_attach,
			app_group_launch_mode mode)
{
	_E("app_group_start_app");

	int caller_pid = __get_caller_pid(b);
	int can_shift = 0;
	int recycle = 0;
	const char *str;

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
	app_group_set_hint(pid, b);
}

int app_group_find_singleton(const char *appid, int *found_pid, int *found_lpid)
{
	GHashTableIter iter;
	gpointer key = NULL;
	gpointer value = NULL;
	char *target = NULL;
	GList *list;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList *)value;
		while (list != NULL) {
			ac = (app_group_context_t *)list->data;
			if (ac && ac->launch_mode == APP_GROUP_LAUNCH_MODE_SINGLETON) {
				target = _status_app_get_appid_bypid(ac->pid);
				if (appid != NULL && target != NULL && strcmp(appid, target) == 0) {
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

int app_group_can_reroute(int pid)
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

void app_group_lower(int pid, int *exit)
{
	app_group_context_t *ac;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list;
	GList *i;

	if (app_group_is_sub_app(pid)) {
		if (__can_recycle(pid) && __can_reroute(pid)) {
			ac = __get_context(pid);
			if (ac) {
				if (ac->wid != 0)
					__detach_window(ac->wid);
				app_group_reroute(pid);
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
#ifdef WAYLAND
				ecore_wl_window_lower((Ecore_Wl_Window *)((intptr_t)ac->wid));
#else
				/* ecore_x_window_lower(ac->wid); */
#endif
			}
			return;
		}
		i = g_list_next(i);
	}
}

void app_group_restart_app(int pid, bundle *b)
{
	const char *pid_str;
	int cwid;
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
		list = (GList*) value;
		i = g_list_first(list);

		while (i != NULL) {
			ac = (app_group_context_t *)i->data;
			if (ac && ac->pid == pid) {
				ac->caller_pid = __get_caller_pid(b);

				if (ac->can_shift) {
					if (ac->wid != 0)
						__detach_window(ac->wid);
					ac->can_shift = 0;
				}

				pid_str = bundle_get_val(b, AUL_SVC_K_SHIFT_WINDOW);
				if (pid_str != NULL && strcmp(pid_str, "true") == 0) {
					ac->can_shift = 1;
					if (ac->wid != 0) {
						if (ac->caller_pid > 0) {
							cwid = app_group_get_window(ac->caller_pid);
							if (cwid != 0)
								__attach_window(cwid, ac->wid);
							else
								_E("invalid caller wid");
						} else {
							_E("invalid caller pid");
						}
					}
				}
				return;
			}
			i = g_list_next(i);
		}
	}
}

int app_group_find_pid_from_recycle_bin(const char *appid)
{
	app_group_context_t *ac;
	const char *appid_from_bin;
	GList *iter = recycle_bin;

	while (iter) {
		ac = (app_group_context_t *)iter->data;
		appid_from_bin = _status_app_get_appid_bypid(ac->pid);
		if (appid && appid_from_bin && strcmp(appid, appid_from_bin) == 0)
			return ac->pid;

		iter = g_list_next(iter);
	}

	return -1;
}

void app_group_get_idle_pids(int *cnt, int **pids)
{
	GList *iter = recycle_bin;
	int idle_cnt = g_list_length(iter);
	int *idle_pids = NULL;
	int i = 0;
	app_group_context_t *ac;

	if (idle_cnt <= 0) {
		*cnt = 0;
		*pids = NULL;
		return;
	}

	idle_pids = malloc(sizeof(int) * idle_cnt);
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

int app_group_get_next_caller_pid(int pid)
{
	GList *list;
	GList *i;
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	app_group_context_t *ac;

	g_hash_table_iter_init(&iter, app_group_hash);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		list = (GList*)value;
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
