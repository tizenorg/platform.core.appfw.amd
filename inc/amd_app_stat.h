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

#include <unistd.h>
#include <sys/types.h>
#include <glib.h>
#include <stdbool.h>
#include <aul.h>
#include <security-manager.h>

#include "amd_appinfo.h"

typedef struct _shared_info_t {
	char *owner_appid;
	private_sharing_req *handle;
} shared_info_t;

typedef struct app_stat_s *app_stat_h;

int _app_stat_add_app_info(const struct appinfo *ai, int pid,
		bool is_subapp, uid_t uid, int caller_pid);
int _app_stat_remove_all_app_info_with_uid(uid_t uid);
int _app_stat_remove(app_stat_h stat);
int _app_stat_update_status(app_stat_h stat, int status, bool force);
int _app_stat_get_process_cnt(const char *appid);
int _app_stat_get_pid(app_stat_h stat);
int _app_stat_is_running(app_stat_h stat);
int _app_stat_get_status(app_stat_h stat);
uid_t _app_stat_get_uid(app_stat_h stat);
const char *_app_stat_get_appid(app_stat_h stat);
const char *_app_stat_get_pkgid(app_stat_h stat);
int _app_stat_add_shared_info(app_stat_h stat, shared_info_t *info);
int _app_stat_clear_shared_info_list(app_stat_h stat);
GList *_app_stat_get_shared_info_list(app_stat_h stat);
app_stat_h _app_stat_find(int pid);
app_stat_h _app_stat_find_by_appid(const char *appid, uid_t uid);
app_stat_h _app_stat_find_with_org_caller(const char *appid, uid_t uid,
		int caller_pid);

void _app_stat_find_service_apps(app_stat_h stat, int status,
		void (*send_event_to_svc_core)(int, uid_t), bool suspend);
void _app_stat_check_service_only(app_stat_h stat,
		void (*send_event_to_svc_core)(int, uid_t));
int _app_stat_send_running_appinfo(int fd, int cmd, uid_t uid);
int _app_stat_terminate_apps(const char *appid, uid_t uid);
int _app_stat_get_appid_bypid(int fd, int pid);
int _app_stat_get_pkgid_bypid(int fd, int pid);
int _app_stat_init(void);
int _app_stat_finish(void);

