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
#include "amd_app_stat.h"
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

struct pkg_stat_s {
	char *pkgid;
	int status;
	GSList *ui_list;
	GSList *svc_list;
};

struct app_stat_s {
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
	struct pkg_stat_s *pkg_stat;
	GList *shared_info_list;
};

struct socket_watch_s {
	int fd;
	int wd;
	GIOChannel *io;
	guint wid;
};

static GSList *app_stat_list;
static GHashTable *pkg_stat_table;
static int limit_bg_uiapps;
static struct socket_watch_s sock_watch;

static int __get_managed_uiapp_cnt(void)
{
	GSList *iter;
	struct app_stat_s *stat;
	int cnt = 0;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->managed && stat->app_type == AT_UI_APP)
			cnt++;
	}

	return cnt;
}

static void __cleanup_bg_uiapps(int n)
{
	GSList *iter;
	GSList *iter_next;
	struct app_stat_s *stat;
	int i = 0;
	request_h req;

	GSLIST_FOREACH_SAFE(app_stat_list, iter, iter_next) {
		if (i == n)
			break;

		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->status != STATUS_VISIBLE) {
			aul_send_app_terminate_request_signal(stat->pid, NULL,
					NULL, NULL);
			req = _request_create_local(APP_TERM_BY_PID, stat->uid,
					getpid(), NULL);
			_term_app(stat->pid, req);
			_request_free_local(req);
			i++;
		}
	}
}

static gint __compare_app_stat_for_sorting(gconstpointer p1, gconstpointer p2)
{
	struct app_stat_s *stat1 = (struct app_stat_s *)p1;
	struct app_stat_s *stat2 = (struct app_stat_s *)p2;
	int app_group_cnt1;
	int app_group_cnt2;
	int *app_group_pids1;
	int *app_group_pids2;

	if (stat1->app_type != AT_UI_APP || stat2->app_type != AT_UI_APP)
		return 0;

	if (stat1->timestamp > stat2->timestamp)
		return 1;
	else if (stat1->timestamp < stat2->timestamp)
		return -1;

	_app_group_get_group_pids(stat1->leader_pid, &app_group_cnt1,
			&app_group_pids1);
	_app_group_get_group_pids(stat2->leader_pid, &app_group_cnt2,
			&app_group_pids2);
	free(app_group_pids1);
	free(app_group_pids2);

	if (app_group_cnt1 < app_group_cnt2)
		return 1;
	else if (app_group_cnt1 > app_group_cnt2)
		return -1;

	if (stat1->fg_count > stat2->fg_count)
		return 1;
	else if (stat1->fg_count < stat2->fg_count)
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

	app_stat_list = g_slist_sort(app_stat_list,
			(GCompareFunc)__compare_app_stat_for_sorting);
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

static void __update_leader_app_stat(int leader_pid)
{
	GSList *iter;
	struct app_stat_s *stat;

	if (leader_pid <= 0)
		return;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->pid == leader_pid) {
			stat->timestamp = time(NULL) / 10;
			stat->fg_count++;
			break;
		}
	}
}

static void __remove_all_shared_info(struct app_stat_s *stat)
{
	GList *list;
	shared_info_t *shared_info;

	if (!stat || !stat->shared_info_list)
		return;

	list = stat->shared_info_list;
	while (list) {
		shared_info = (shared_info_t *)list->data;
		if (shared_info) {
			if (shared_info->owner_appid)
				free(shared_info->owner_appid);
			free(shared_info);
		}
		list = g_list_next(list);
	}

	g_list_free(stat->shared_info_list);
}

static void __add_pkg_stat(struct app_stat_s *stat)
{
	struct pkg_stat_s *pkg_stat;

	if (stat == NULL) {
		_E("Invalid parameter");
		return;
	}

	if (stat->app_type != AT_SERVICE_APP && stat->app_type != AT_UI_APP)
		return;

	if (pkg_stat_table == NULL) {
		pkg_stat_table = g_hash_table_new(g_str_hash, g_str_equal);
		if (pkg_stat_table == NULL) {
			_E("out of memory");
			return;
		}
	}

	pkg_stat = g_hash_table_lookup(pkg_stat_table, stat->pkgid);
	if (pkg_stat == NULL) {
		pkg_stat = (struct pkg_stat_s *)calloc(1,
				sizeof(struct pkg_stat_s));
		if (pkg_stat == NULL) {
			_E("out of memory");
			return;
		}

		pkg_stat->pkgid = strdup(stat->pkgid);
		if (pkg_stat->pkgid == NULL) {
			_E("out of memory");
			free(pkg_stat);
			return;
		}

		g_hash_table_insert(pkg_stat_table, pkg_stat->pkgid, pkg_stat);
	}

	pkg_stat->status = stat->status;
	stat->pkg_stat = pkg_stat;

	if (stat->app_type == AT_SERVICE_APP)
		pkg_stat->svc_list = g_slist_append(pkg_stat->svc_list, stat);
	else
		pkg_stat->ui_list = g_slist_append(pkg_stat->ui_list, stat);
}

static int __get_ui_app_status_pkg_stat(struct pkg_stat_s *pkg_stat)
{
	struct app_stat_s *app_stat;
	GSList *iter;

	for (iter = pkg_stat->ui_list; iter; iter = g_slist_next(iter)) {
		app_stat = (struct app_stat_s *)iter->data;
		if (app_stat->status != STATUS_BG)
			return app_stat->status;
	}

	return STATUS_BG;
}

static int __update_pkg_stat(struct app_stat_s *stat)
{
	struct pkg_stat_s *pkg_stat;
	int ret;

	if (stat == NULL)
		return -1;

	if (pkg_stat_table == NULL)
		return -1;

	pkg_stat = (struct pkg_stat_s *)g_hash_table_lookup(pkg_stat_table,
			stat->pkgid);
	if (pkg_stat == NULL) {
		_E("pkgid(%s) is not on list", stat->pkgid);
		return -1;
	}

	if (pkg_stat->ui_list) {
		ret = __get_ui_app_status_pkg_stat(pkg_stat);
		if (ret > -1)
			pkg_stat->status = ret;
	} else {
		pkg_stat->status = STATUS_SERVICE;
	}

	return 0;
}

static void __remove_pkg_stat(struct app_stat_s *stat)
{
	struct pkg_stat_s *pkg_stat;

	if (stat == NULL) {
		_E("Invalid parameter");
		return;
	}

	pkg_stat = g_hash_table_lookup(pkg_stat_table, stat->pkgid);
	if (pkg_stat == NULL)
		return;

	if (stat->app_type == AT_SERVICE_APP) {
		pkg_stat->svc_list = g_slist_remove(pkg_stat->svc_list, stat);
		_D("STATUS_SERVICE: appid(%s)", stat->appid);
	} else {
		pkg_stat->ui_list = g_slist_remove(pkg_stat->ui_list, stat);
		_D("~STATUS_SERVICE: appid(%s)", stat->appid);
	}

	if (!pkg_stat->svc_list && !pkg_stat->ui_list) {
		g_hash_table_remove(pkg_stat_table, pkg_stat->pkgid);
		if (pkg_stat->pkgid)
			free(pkg_stat->pkgid);
		free(pkg_stat);
	}
}

static void __destroy_app_stat(struct app_stat_s *stat)
{
	if (stat == NULL)
		return;

	__remove_all_shared_info(stat);

	if (stat->pkgid)
		free(stat->pkgid);
	if (stat->app_path)
		free(stat->app_path);
	if (stat->appid)
		free(stat->appid);

	free(stat);
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

static int __app_stat_set_app_info(struct app_stat_s *stat,
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

	stat->appid = strdup(appid);
	if (stat->appid == NULL) {
		_E("out of memory");
		return -1;
	}

	app_path = _appinfo_get_value(ai, AIT_EXEC);
	if (app_path == NULL)
		return -1;

	stat->app_path = strdup(app_path);
	if (stat->app_path == NULL) {
		_E("out of memory");
		return -1;
	}

	pkgid = _appinfo_get_value(ai, AIT_PKGID);
	if (pkgid == NULL)
		return -1;

	stat->pkgid = strdup(pkgid);
	if (stat->pkgid == NULL) {
		_E("out of memory");
		return -1;
	}

	comp_type = _appinfo_get_value(ai, AIT_COMPTYPE);
	if (comp_type == NULL)
		return -1;

	stat->app_type = __get_app_type(comp_type);
	if (stat->app_type == -1) {
		_E("Unknown component type: %s", comp_type);
		return -1;
	}

	if (stat->app_type == AT_SERVICE_APP)
		stat->status = STATUS_SERVICE;
	else
		stat->status = STATUS_LAUNCHING;

	stat->pid = pid;
	stat->uid = uid;
	stat->is_subapp = is_subapp;
	stat->leader_pid = _app_group_get_leader_pid(pid);
	stat->timestamp = time(NULL) / 10;
	stat->org_caller_pid = caller_pid;

	taskmanage = _appinfo_get_value(ai, AIT_TASKMANAGE);
	if (taskmanage && strcmp(taskmanage, "true") == 0 &&
			stat->leader_pid > 0 &&
			stat->is_subapp == false)
		stat->managed = true;

	return 0;
}

int _app_stat_add_app_info(const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid)
{
	GSList *iter;
	GSList *iter_next;
	struct app_stat_s *stat;
	int r;

	if (ai == NULL)
		return -1;

	GSLIST_FOREACH_SAFE(app_stat_list, iter, iter_next) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->pid == pid) {
			if (stat->uid == uid)
				return 0;

			app_stat_list = g_slist_remove(app_stat_list, stat);
			__remove_pkg_stat(stat);
			__destroy_app_stat(stat);
			break;
		}
	}

	stat = (struct app_stat_s *)calloc(1, sizeof(struct app_stat_s));
	if (stat == NULL) {
		_E("out of memory");
		return -1;
	}

	r = __app_stat_set_app_info(stat, ai, pid, is_subapp, uid, caller_pid);
	if (r < 0) {
		__destroy_app_stat(stat);
		return -1;
	}

	app_stat_list = g_slist_append(app_stat_list, stat);
	__add_pkg_stat(stat);

	return 0;
}

int _app_stat_remove_all_app_info_with_uid(uid_t uid)
{
	GSList *iter;
	GSList *iter_next;
	struct app_stat_s *stat;

	GSLIST_FOREACH_SAFE(app_stat_list, iter, iter_next) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->uid == uid) {
			app_stat_list = g_slist_remove(app_stat_list, stat);
			__destroy_app_stat(stat);
		}
	}

	return 0;
}

int _app_stat_remove(app_stat_h stat)
{
	if (stat == NULL)
		return -1;

	app_stat_list = g_slist_remove(app_stat_list, stat);
	__remove_pkg_stat(stat);
	__destroy_app_stat(stat);

	return 0;
}

int _app_stat_update_status(app_stat_h stat, int status, bool force)
{
	if (stat == NULL)
		return -1;

	_D("pid: %d, status: %d", stat->pid, status);
	_input_unlock();

	if (stat->status == STATUS_DYING) {
		_E("%s is STATUS_DYING", stat->appid);
		return -1;
	}

	stat->status = status;
	if (stat->status == STATUS_VISIBLE) {
		stat->timestamp = time(NULL) / 10;
		stat->fg_count++;
		if (!stat->managed)
			__update_leader_app_stat(stat->leader_pid);
		if (stat->fg_count == 1 && limit_bg_uiapps > 0)
			__check_running_uiapp_list();
	}

	__update_pkg_stat(stat);
	_D("pid: %d, appid: %s, pkgid: %s, status: %d",
			stat->pid, stat->appid, stat->pkgid, stat->status);

	_app_group_set_status(stat->pid, stat->status, force);

	return 0;
}

int _app_stat_get_process_cnt(const char *appid)
{
	GSList *iter;
	struct app_stat_s *stat;
	int cnt = 0;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->appid && strcmp(stat->appid, appid) == 0)
			cnt++;
	}

	return cnt;
}

int _app_stat_get_pid(app_stat_h stat)
{
	if (stat == NULL)
		return -1;

	return stat->pid;
}

int _app_stat_is_running(app_stat_h stat)
{
	if (stat == NULL || stat->is_subapp)
		return -1;

	return stat->pid;
}

int _app_stat_get_status(app_stat_h stat)
{
	if (stat == NULL)
		return -1;

	return stat->status;
}

uid_t _app_stat_get_uid(app_stat_h stat)
{
	if (stat == NULL)
		return (uid_t)-1;

	return stat->uid;
}

const char *_app_stat_get_appid(app_stat_h stat)
{
	if (stat == NULL)
		return NULL;

	return stat->appid;
}

const char *_app_stat_get_pkgid(app_stat_h stat)
{
	if (stat == NULL)
		return NULL;

	return stat->pkgid;
}

int _app_stat_add_shared_info(app_stat_h stat, shared_info_t *info)
{
	if (stat == NULL || info == NULL)
		return -1;

	stat->shared_info_list = g_list_append(stat->shared_info_list, info);

	return 0;
}

int _app_stat_clear_shared_info_list(app_stat_h stat)
{
	if (stat == NULL)
		return -1;

	__remove_all_shared_info(stat);

	return 0;
}

GList *_app_stat_get_shared_info_list(app_stat_h stat)
{
	return stat->shared_info_list;
}

app_stat_h _app_stat_find(int pid)
{
	GSList *iter;
	struct app_stat_s *stat;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->pid == pid)
			return stat;
	}

	return NULL;
}

app_stat_h _app_stat_find_by_appid(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_stat_s *stat;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->appid &&
				strcmp(stat->appid, appid) == 0 &&
				stat->uid == uid)
			return stat;
	}

	return NULL;
}

app_stat_h _app_stat_find_with_org_caller(const char *appid, uid_t uid,
		int caller_pid)
{
	GSList *iter;
	struct app_stat_s *stat;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat && stat->appid &&
				strcmp(stat->appid, appid) == 0 &&
				stat->uid == uid &&
				stat->org_caller_pid == caller_pid)
			return stat;
	}

	return NULL;
}

void _app_stat_find_service_apps(app_stat_h stat, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend)
{
	GSList *iter;
	GSList *svc_list = NULL;
	const struct appinfo *ai;
	struct app_stat_s *svc_stat;
	int bg_allowed;
	uid_t uid;

	if (stat == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_stat_get_uid(stat);
	if (stat->pkg_stat && stat->pkg_stat->status == status)
		svc_list = stat->pkg_stat->svc_list;

	for (iter = svc_list; iter; iter = g_slist_next(iter)) {
		svc_stat = (struct app_stat_s *)iter->data;
		if (svc_stat && svc_stat->uid == uid) {
			ai = _appinfo_find(uid, svc_stat->appid);
			bg_allowed = (intptr_t)_appinfo_get_value(ai,
					AIT_BG_CATEGORY);
			if (!bg_allowed) {
				send_event_to_svc_core(svc_stat->pid, uid);
				if (suspend)
					_suspend_add_timer(svc_stat->pid, ai);
				else
					_suspend_remove_timer(svc_stat->pid);
			}
		}
	}
}

void _app_stat_check_service_only(app_stat_h stat,
		void (*send_event_to_svc_core)(int, uid_t))
{
	GSList *iter;
	GSList *ui_list = NULL;
	struct app_stat_s *ui_stat;
	int ui_cnt = 0;
	int bg_allowed;
	const char *appid;
	const struct appinfo *ai;
	uid_t uid;

	if (stat == NULL) {
		_E("Invalid parameter");
		return;
	}

	uid = _app_stat_get_uid(stat);
	if (stat->pkg_stat && stat->pkg_stat->ui_list)
		ui_list = stat->pkg_stat->ui_list;

	for (iter = ui_list; iter; iter = g_slist_next(iter)) {
		ui_stat = (struct app_stat_s *)iter->data;
		if (ui_stat && _app_stat_get_status(ui_stat) != STATUS_DYING)
			ui_cnt++;
	}

	if (ui_cnt == 0) {
		appid = _app_stat_get_appid(stat);
		ai = _appinfo_find(uid, appid);
		bg_allowed = (intptr_t)_appinfo_get_value(ai, AIT_BG_CATEGORY);
		if (!bg_allowed) {
			send_event_to_svc_core(stat->pid, uid);
			_suspend_add_timer(stat->pid, ai);
		}
	}
}

int _app_stat_send_running_appinfo(int fd, int cmd, uid_t uid)
{
	GSList *iter;
	struct app_stat_s *stat;
	char tmp_str[MAX_PID_STR_BUFSZ];
	char buf[AUL_SOCK_MAXBUFF - AUL_PKT_HEADER_SIZE] = {0,};
	int ret;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat->uid != uid ||	stat->status == STATUS_DYING)
			continue;
		if (cmd != APP_ALL_RUNNING_INFO && stat->is_subapp)
			continue;

		snprintf(tmp_str, sizeof(tmp_str), "%d", stat->pid);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, stat->appid, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, stat->app_path, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		strncat(buf, stat->pkgid, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		snprintf(tmp_str, sizeof(tmp_str), "%d", stat->status);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ":", sizeof(buf) - strlen(buf) - 1);
		snprintf(tmp_str, sizeof(tmp_str), "%d", stat->is_subapp);
		strncat(buf, tmp_str, sizeof(buf) - strlen(buf) - 1);
		strncat(buf, ";", sizeof(buf) - strlen(buf) - 1);
	}

	ret = aul_sock_send_raw_with_fd(fd, cmd, (unsigned char *)buf,
			strlen(buf), AUL_SOCK_NOREPLY);

	return ret;
}

int _app_stat_terminate_apps(const char *appid, uid_t uid)
{
	GSList *iter;
	struct app_stat_s *stat;

	for (iter = app_stat_list; iter; iter = g_slist_next(iter)) {
		stat = (struct app_stat_s *)iter->data;
		if (stat->uid == uid &&
				strcmp(stat->appid, appid) == 0 &&
				stat->status != STATUS_DYING)
			_term_sub_app(stat->pid);
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

int _app_stat_get_appid_bypid(int fd, int pid)
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

int _app_stat_get_pkgid_bypid(int fd, int pid)
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

int _app_stat_init(void)
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

int _app_stat_finish(void)
{
	int ret;

	/* TODO: destroy all app stat info */

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

