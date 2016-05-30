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
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <glib.h>
#include <aul.h>
#include <string.h>
#include <linux/limits.h>
#include <gio/gio.h>
#include <vconf.h>
#include <time.h>
#include <aul_sock.h>
#include <aul_proc.h>
#include <sys/inotify.h>
#include <ctype.h>

#include "amd_config.h"
#include "amd_app_status.h"
#include "amd_appinfo.h"
#include "amd_request.h"
#include "amd_launch.h"
#include "amd_util.h"
#include "amd_app_group.h"
#include "amd_input.h"
#include "amd_suspend.h"

#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

enum app_type_e {
	AT_SERVICE_APP,
	AT_UI_APP,
	AT_WIDGET_APP,
	AT_WATCH_APP,
};

struct pkg_status_s {
	char *pkgid;
	int status;
	GSList *ui_list;
	GSList *svc_list;
};

struct app_status_s {
	char *appid;
	char *app_path;
	char *pkgid;
	int app_type;
	int pid;
	uid_t uid;
	int status;
	bool is_subapp;
	int leader_pid;
	int timestamp;
	int fg_count;
	bool managed;
	int org_caller_pid;
	struct pkg_status_s *pkg_status;
	GList *shared_info_list;
};

struct socket_watch_s {
	int fd;
	int wd;
	GIOChannel *io;
	guint wid;
};

static GSList *app_status_list;
static GHashTable *pkg_status_table;
static int limit_bg_uiapps;
static struct socket_watch_s sock_watch;

static int __get_managed_uiapp_cnt(void)
{
	GSList *iter;
	struct app_status_s *app_status;
	int cnt = 0;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->managed &&
				app_status->app_type == AT_UI_APP)
			cnt++;
	}

	return cnt;
}

static void __cleanup_bg_uiapps(int n)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;
	int i = 0;
	request_h req;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		if (i == n)
			break;

		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->status != STATUS_VISIBLE) {
			aul_send_app_terminate_request_signal(app_status->pid,
					NULL, NULL, NULL);
			req = _request_create_local(APP_TERM_BY_PID,
					app_status->uid, getpid(), NULL);
			_term_app(app_status->pid, req);
			_request_free_local(req);
			i++;
		}
	}
}

static gint __compare_app_status_for_sorting(gconstpointer p1, gconstpointer p2)
{
	struct app_status_s *app_status1 = (struct app_status_s *)p1;
	struct app_status_s *app_status2 = (struct app_status_s *)p2;
	int app_group_cnt1;
	int app_group_cnt2;
	int *app_group_pids1;
	int *app_group_pids2;

	if (app_status1->app_type != AT_UI_APP ||
			app_status2->app_type != AT_UI_APP)
		return 0;

	if (app_status1->timestamp > app_status2->timestamp)
		return 1;
	else if (app_status1->timestamp < app_status2->timestamp)
		return -1;

	_app_group_get_group_pids(app_status1->leader_pid, &app_group_cnt1,
			&app_group_pids1);
	_app_group_get_group_pids(app_status2->leader_pid, &app_group_cnt2,
			&app_group_pids2);
	free(app_group_pids1);
	free(app_group_pids2);

	if (app_group_cnt1 < app_group_cnt2)
		return 1;
	else if (app_group_cnt1 > app_group_cnt2)
		return -1;

	if (app_status1->fg_count > app_status2->fg_count)
		return 1;
	else if (app_status1->fg_count < app_status2->fg_count)
		return -1;

	return 0;
}

static void __check_running_uiapp_list(void)
{
	int len;
	int n;

	len = __get_managed_uiapp_cnt();
	if (len <= 0)
		return;

	n = len - limit_bg_uiapps;
	if (n <= 0)
		return;

	app_status_list = g_slist_sort(app_status_list,
			(GCompareFunc)__compare_app_status_for_sorting);
	__cleanup_bg_uiapps(n);
}

static void __vconf_cb(keynode_t *key, void *data)
{
	const char *name;

	name = vconf_keynode_get_name(key);
	if (name && strcmp(name, VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS) == 0) {
		limit_bg_uiapps = vconf_keynode_get_int(key);
		if (limit_bg_uiapps > 0)
			__check_running_uiapp_list();
	}
}

static void __update_leader_app_status(int leader_pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	if (leader_pid <= 0)
		return;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == leader_pid) {
			app_status->timestamp = time(NULL) / 10;
			app_status->fg_count++;
			break;
		}
	}
}

static void __remove_all_shared_info(struct app_status_s *app_status)
{
	GList *list;
	shared_info_t *shared_info;

	if (!app_status || !app_status->shared_info_list)
		return;

	list = app_status->shared_info_list;
	while (list) {
		shared_info = (shared_info_t *)list->data;
		if (shared_info) {
			if (shared_info->owner_appid)
				free(shared_info->owner_appid);
			free(shared_info);
		}
		list = g_list_next(list);
	}

	g_list_free(app_status->shared_info_list);
}

static void __add_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	if (app_status->app_type != AT_SERVICE_APP &&
			app_status->app_type != AT_UI_APP)
		return;

	if (pkg_status_table == NULL) {
		pkg_status_table = g_hash_table_new(g_str_hash, g_str_equal);
		if (pkg_status_table == NULL) {
			_E("out of memory");
			return;
		}
	}

	pkg_status = g_hash_table_lookup(pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL) {
		pkg_status = (struct pkg_status_s *)calloc(1,
				sizeof(struct pkg_status_s));
		if (pkg_status == NULL) {
			_E("out of memory");
			return;
		}

		pkg_status->pkgid = strdup(app_status->pkgid);
		if (pkg_status->pkgid == NULL) {
			_E("out of memory");
			free(pkg_status);
			return;
		}

		g_hash_table_insert(pkg_status_table, pkg_status->pkgid,
				pkg_status);
	}

	pkg_status->status = app_status->status;
	app_status->pkg_status = pkg_status;

	if (app_status->app_type == AT_SERVICE_APP) {
		pkg_status->svc_list = g_slist_append(pkg_status->svc_list,
				app_status);
	} else {
		pkg_status->ui_list = g_slist_append(pkg_status->ui_list,
				app_status);
	}
}

static int __get_ui_app_statusus_pkg_status(struct pkg_status_s *pkg_status)
{
	struct app_status_s *app_status;
	GSList *iter;

	for (iter = pkg_status->ui_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->status != STATUS_BG)
			return app_status->status;
	}

	return STATUS_BG;
}

static int __update_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;
	int ret;

	if (app_status == NULL)
		return -1;

	if (pkg_status_table == NULL)
		return -1;

	pkg_status = (struct pkg_status_s *)g_hash_table_lookup(
			pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL) {
		_E("pkgid(%s) is not on list", app_status->pkgid);
		return -1;
	}

	if (pkg_status->ui_list) {
		ret = __get_ui_app_statusus_pkg_status(pkg_status);
		if (ret > -1)
			pkg_status->status = ret;
	} else {
		pkg_status->status = STATUS_SERVICE;
	}

	return 0;
}

static void __remove_pkg_status(struct app_status_s *app_status)
{
	struct pkg_status_s *pkg_status;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	pkg_status = g_hash_table_lookup(pkg_status_table, app_status->pkgid);
	if (pkg_status == NULL)
		return;

	if (app_status->app_type == AT_SERVICE_APP) {
		pkg_status->svc_list = g_slist_remove(pkg_status->svc_list,
				app_status);
		_D("STATUS_SERVICE: appid(%s)", app_status->appid);
	} else {
		pkg_status->ui_list = g_slist_remove(pkg_status->ui_list,
				app_status);
		_D("~STATUS_SERVICE: appid(%s)", app_status->appid);
	}

	if (!pkg_status->svc_list && !pkg_status->ui_list) {
		g_hash_table_remove(pkg_status_table, pkg_status->pkgid);
		if (pkg_status->pkgid)
			free(pkg_status->pkgid);
		free(pkg_status);
	}
}

static void __destroy_app_status(struct app_status_s *app_status)
{
	if (app_status == NULL)
		return;

	__remove_all_shared_info(app_status);

	if (app_status->pkgid)
		free(app_status->pkgid);
	if (app_status->app_path)
		free(app_status->app_path);
	if (app_status->appid)
		free(app_status->appid);

	free(app_status);
}

static int __get_app_type(const char *comp_type)
{
	if (comp_type == NULL)
		return -1;

	if (strcmp(comp_type, APP_TYPE_SERVICE) == 0)
		return AT_SERVICE_APP;
	else if (strcmp(comp_type, APP_TYPE_UI) == 0)
		return AT_UI_APP;
	else if (strcmp(comp_type, APP_TYPE_WIDGET) == 0)
		return AT_WIDGET_APP;
	else if (strcmp(comp_type, APP_TYPE_WATCH) == 0)
		return AT_WATCH_APP;

	return -1;
}

static int __app_status_set_app_info(struct app_status_s *app_status,
		const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid)
{
	const char *appid;
	const char *app_path;
	const char *pkgid;
	const char *comp_type;
	const char *taskmanage;

	appid = _appinfo_get_value(ai, AIT_NAME);
	if (appid == NULL)
		return -1;

	app_status->appid = strdup(appid);
	if (app_status->appid == NULL) {
		_E("out of memory");
		return -1;
	}

	app_path = _appinfo_get_value(ai, AIT_EXEC);
	if (app_path == NULL)
		return -1;

	app_status->app_path = strdup(app_path);
	if (app_status->app_path == NULL) {
		_E("out of memory");
		return -1;
	}

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		return -1;

	app_status->pkgid = strdup(pkgid);
	if (app_status->pkgid == NULL) {
		_E("out of memory");
		return -1;
	}

	comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return -1;

	app_status->app_type = __get_app_type(comp_type);
	if (app_status->app_type == -1) {
		_E("Unknown component type: %s", comp_type);
		return -1;
	}

	if (app_status->app_type == AT_SERVICE_APP)
		app_status->status = STATUS_SERVICE;
	else
		app_status->status = STATUS_LAUNCHING;

	app_status->pid = pid;
	app_status->uid = uid;
	app_status->is_subapp = is_subapp;
	app_status->leader_pid = _app_group_get_leader_pid(pid);
	app_status->timestamp = time(NULL) / 10;
	app_status->org_caller_pid = caller_pid;

	taskmanage = _appinfo_get_value(ai, AIT_TASKMANAGE);
	if (taskmanage && strcmp(taskmanage, "true") == 0 &&
			app_status->leader_pid > 0 &&
			app_status->is_subapp == false)
		app_status->managed = true;

	return 0;
}

int _app_status_add_app_info(const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;
	int r;

	if (ai == NULL)
		return -1;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == pid) {
			if (app_status->uid == uid)
				return 0;

			app_status_list = g_slist_remove(app_status_list,
					app_status);
			__remove_pkg_status(app_status);
			__destroy_app_status(app_status);
			break;
		}
	}

	app_status = (struct app_status_s *)calloc(1,
			sizeof(struct app_status_s));
	if (app_status == NULL) {
		_E("out of memory");
		return -1;
	}

	r = __app_status_set_app_info(app_status, ai, pid, is_subapp, uid,
			caller_pid);
	if (r < 0) {
		__destroy_app_status(app_status);
		return -1;
	}

	app_status_list = g_slist_append(app_status_list, app_status);
	__add_pkg_status(app_status);

	return 0;
}

int _app_status_remove_all_app_info_with_uid(uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	struct app_status_s *app_status;

	GSLIST_FOREACH_SAFE(app_status_list, iter, iter_next) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->uid == uid) {
			app_status_list = g_slist_remove(app_status_list,
					app_status);
			__destroy_app_status(app_status);
		}
	}

	return 0;
}

int _app_status_remove(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	app_status_list = g_slist_remove(app_status_list, app_status);
	__remove_pkg_status(app_status);
	__destroy_app_status(app_status);

	return 0;
}

int _app_status_update_status(app_status_h app_status, int status, bool force)
{
	if (app_status == NULL)
		return -1;

	_D("pid: %d, status: %d", app_status->pid, status);
	_input_unlock();

	if (app_status->status == STATUS_DYING) {
		_E("%s is STATUS_DYING", app_status->appid);
		return -1;
	}

	app_status->status = status;
	if (app_status->status == STATUS_VISIBLE) {
		app_status->timestamp = time(NULL) / 10;
		app_status->fg_count++;
		if (!app_status->managed)
			__update_leader_app_status(app_status->leader_pid);
		if (app_status->fg_count == 1 && limit_bg_uiapps > 0)
			__check_running_uiapp_list();
	}

	__update_pkg_status(app_status);
	_D("pid: %d, appid: %s, pkgid: %s, status: %d",
			app_status->pid, app_status->appid, app_status->pkgid,
			app_status->status);

	_app_group_set_status(app_status->pid, app_status->status, force);

	return 0;
}

int _app_status_get_process_cnt(const char *appid)
{
	GSList *iter;
	struct app_status_s *app_status;
	int cnt = 0;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0)
			cnt++;
	}

	return cnt;
}

int _app_status_get_pid(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->pid;
}

int _app_status_is_running(app_status_h app_status)
{
	if (app_status == NULL || app_status->is_subapp)
		return -1;

	return app_status->pid;
}

int _app_status_get_status(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	return app_status->status;
}

uid_t _app_status_get_uid(app_status_h app_status)
{
	if (app_status == NULL)
		return (uid_t)-1;

	return app_status->uid;
}

const char *_app_status_get_appid(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->appid;
}

const char *_app_status_get_pkgid(app_status_h app_status)
{
	if (app_status == NULL)
		return NULL;

	return app_status->pkgid;
}

int _app_status_add_shared_info(app_status_h app_status, shared_info_t *info)
{
	if (app_status == NULL || info == NULL)
		return -1;

	app_status->shared_info_list = g_list_append(
			app_status->shared_info_list, info);

	return 0;
}

int _app_status_clear_shared_info_list(app_status_h app_status)
{
	if (app_status == NULL)
		return -1;

	__remove_all_shared_info(app_status);

	return 0;
}

GList *_app_status_get_shared_info_list(app_status_h app_status)
{
	return app_status->shared_info_list;
}

app_status_h _app_status_find(int pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->pid == pid)
			return app_status;
	}

	return NULL;
}

app_status_h _app_status_find_by_appid(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->uid == uid)
			return app_status;
	}

	return NULL;
}

app_status_h _app_status_find_with_org_caller(const char *appid, uid_t uid,
		int caller_pid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status && app_status->appid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->uid == uid &&
				app_status->org_caller_pid == caller_pid)
			return app_status;
	}

	return NULL;
}

void _app_status_find_service_apps(app_status_h app_status, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend)
{
	GSList *iter;
	GSList *svc_list = NULL;
	const struct appinfo *ai;
	struct app_status_s *svc_status;
	int bg_allowed;
	uid_t uid;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_status_get_uid(app_status);
	if (app_status->pkg_status && app_status->pkg_status->status == status)
		svc_list = app_status->pkg_status->svc_list;

	for (iter = svc_list; iter; iter = g_slist_next(iter)) {
		svc_status = (struct app_status_s *)iter->data;
		if (svc_status && svc_status->uid == uid) {
			ai = _appinfo_find(uid, svc_status->appid);
			bg_allowed = (intptr_t)_appinfo_get_value(ai,
					AIT_BG_CATEGORY);
			if (!bg_allowed) {
				send_event_to_svc_core(svc_status->pid, uid);
				if (suspend)
					_suspend_add_timer(svc_status->pid, ai);
				else
					_suspend_remove_timer(svc_status->pid);
			}
		}
	}
}

void _app_status_check_service_only(app_status_h app_status,
		void (*send_event_to_svc_core)(int, uid_t))
{
	GSList *iter;
	GSList *ui_list = NULL;
	struct app_status_s *ui_status;
	int ui_cnt = 0;
	int bg_allowed;
	const char *appid;
	const struct appinfo *ai;
	uid_t uid;

	if (app_status == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_status_get_uid(app_status);
	if (app_status->pkg_status && app_status->pkg_status->ui_list)
		ui_list = app_status->pkg_status->ui_list;

	for (iter = ui_list; iter; iter = g_slist_next(iter)) {
		ui_status = (struct app_status_s *)iter->data;
		if (_app_status_get_status(ui_status) != STATUS_DYING)
			ui_cnt++;
	}

	if (ui_cnt == 0) {
		appid = _app_status_get_appid(app_status);
		ai = _appinfo_find(uid, appid);
		bg_allowed = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);
		if (!bg_allowed) {
			send_event_to_svc_core(app_status->pid, uid);
			_suspend_add_timer(app_status->pid, ai);
		}
	}
}

int _app_status_send_running_appinfo(int fd, int cmd, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;
	char tmp_str[MAX_PID_STR_BUFSZ];
	char buf[AUL_SOCK_MAXBUFF - AUL_PKT_HEADER_SIZE] = {0,};
	int ret;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->uid != uid ||
				app_status->status == STATUS_DYING)
			continue;
		if (cmd != APP_ALL_RUNNING_INFO && app_status->is_subapp)
			continue;

		snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->pid);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, app_status->appid, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, app_status->app_path,
				sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, app_status->pkgid, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->status);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		snprintf(tmp_str, sizeof(tmp_str), "%d", app_status->is_subapp);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ";", sizeof(buf) - strlen(buf) - 1);
	}

	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)buf,
			strlen(buf), AUL_SOCK_NOREPLY);

	return ret;
}

int _app_status_terminate_apps(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_status_s *app_status;

	for (iter = app_status_list; iter; iter = g_slist_next(iter)) {
		app_status = (struct app_status_s *)iter->data;
		if (app_status->uid == uid &&
				strcmp(app_status->appid, appid) == 0 &&
				app_status->status != STATUS_DYING)
			_term_sub_app(app_status->pid);
	}

	return 0;
}

static int __get_appid_bypid(int pid, char *appid, int len)
{
	char *proc_appid;

	proc_appid = aul_proc_get_appid_bypid(pid);
	if (proc_appid == NULL)
		return -1;

	snprintf(appid, len, "%s", proc_appid);
	free(proc_appid);

	return 0;
}

int _app_status_get_appid_bypid(int fd, int pid)
{
	int cmd = APP_GET_INFO_ERROR;
	int len = 0;
	int pgid;
	char appid[MAX_PACKAGE_STR_SIZE] = {0,};
	int ret;

	ret = __get_appid_bypid(pid, appid, sizeof(appid));
	if (ret == 0) {
		SECURE_LOGD("appid for %d is %s", pid, appid);
		len = strlen(appid);
		cmd = APP_GET_INFO_OK;
		goto out;
	}

	/* Support app launched by shell script */
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1) {
		close(fd);
		return -1;
	}

	_D("second change pgid = %d, pid = %d", pgid, pid);
	ret = __get_appid_bypid(pgid, appid, sizeof(appid));
	if (ret == 0) {
		SECURE_LOGD("appid for %d(%d) is %s", pid, pgid, appid);
		len = strlen(appid);
		cmd = APP_GET_INFO_OK;
	}

out:
	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)appid,
			len, AUL_SOCK_NOREPLY);

	return ret;
}

static int __get_pkgid_bypid(int pid, char *pkgid, int len)
{
	char *appid;
	uid_t uid;
	const struct appinfo *ai;

	appid = aul_proc_get_appid_bypid(pid);
	if (appid == NULL)
		return -1;

	uid = aul_proc_get_usr_bypid(pid);
	if (uid == (uid_t)-1) {
		free(appid);
		return -1;
	}

	ai = _appinfo_find(uid, appid);
	if (ai == NULL) {
		free(appid);
		return -1;
	}

	snprintf(pkgid, len, "%s", _appinfo_get_value(ai, AIT_PKGID));
	free(appid);

	return 0;
}

int _app_status_get_pkgid_bypid(int fd, int pid)
{
	int cmd = APP_GET_INFO_ERROR;
	int len = 0;
	int pgid;
	char pkgid[MAX_PACKAGE_STR_SIZE] = {0,};
	int ret;

	ret = __get_pkgid_bypid(pid, pkgid, sizeof(pkgid));
	if (ret == 0) {
		SECURE_LOGD("pkgid for %d is %s", pid, pkgid);
		len = strlen(pkgid);
		cmd = APP_GET_INFO_OK;
		goto out;
	}

	/* Support app launched by shell script */
	_D("second chance");
	pgid = getpgid(pid);
	if (pgid <= 1) {
		close(fd);
		return -1;
	}

	_E("second change pgid = %d, pid = %d", pgid, pid);
	ret = __get_pkgid_bypid(pgid, pkgid, sizeof(pkgid));
	if (ret == 0) {
		SECURE_LOGD("appid for %d(%d) is %s", pid, pgid, pkgid);
		len = strlen(pkgid);
		cmd = APP_GET_INFO_OK;
	}

out:
	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)pkgid,
			len, AUL_SOCK_NOREPLY);

	return ret;
}

static gboolean __socket_monitor_cb(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	char buf[INOTIFY_BUF];
	ssize_t len = 0;
	int i = 0;
	struct inotify_event *event;
	char *p;
	int pid;
	int fd = g_io_channel_unix_get_fd(io);

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		_E("Failed to read");
		return TRUE;
	}

	while (i < len) {
		pid = -1;
		event = (struct inotify_event *)&buf[i];
		if (event->len) {
			p = event->name;
			if (p && isdigit(*p)) {
				pid = atoi(p);
				if (pid > 1) {
					_D("pid: %d", pid);
					_request_reply_for_pending_request(pid);
				}
			}
		}
		i += offsetof(struct inotify_event, name) + event->len;
	}

	return TRUE;
}

int _app_status_init(void)
{
	char buf[PATH_MAX];
	int ret;

	sock_watch.fd = inotify_init();
	if (sock_watch.fd < 0) {
		_E("inotify_init() is failed.");
		return -1;
	}

	snprintf(buf, sizeof(buf), "/run/user/%d", getuid());
	sock_watch.wd = inotify_add_watch(sock_watch.fd, buf, IN_CREATE);
	if (sock_watch.wd < 0) {
		_E("inotify_add_watch() is failed.");
		close(sock_watch.fd);
		return -1;
	}

	sock_watch.io = g_io_channel_unix_new(sock_watch.fd);
	if (sock_watch.io == NULL) {
		inotify_rm_watch(sock_watch.fd, sock_watch.wd);
		close(sock_watch.fd);
		return -1;
	}

	sock_watch.wid = g_io_add_watch(sock_watch.io, G_IO_IN,
			__socket_monitor_cb, NULL);

	ret = vconf_get_int(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			&limit_bg_uiapps);
	if (ret != VCONF_OK)
		_E("Failed to get %s", VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS);

	ret = vconf_notify_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			__vconf_cb, NULL);
	if (ret != 0) {
		_E("Failed to register callback for %s",
				VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS);
	}

	return 0;
}

int _app_status_finish(void)
{
	int ret;

	/* TODO: destroy all app app_status info */

	ret = vconf_ignore_key_changed(VCONFKEY_SETAPPL_DEVOPTION_BGPROCESS,
			__vconf_cb);
	if (ret != 0)
		_E("Failed to remove a callback");

	g_source_remove(sock_watch.wid);
	g_io_channel_unref(sock_watch.io);
	inotify_rm_watch(sock_watch.fd, sock_watch.wd);
	close(sock_watch.fd);

	return 0;
}

