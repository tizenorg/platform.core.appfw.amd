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

#include <stdbool.h>

#include <bundle.h>

typedef enum {
	APP_GROUP_LAUNCH_MODE_SINGLE = 0,
	APP_GROUP_LAUNCH_MODE_GROUP,
	APP_GROUP_LAUNCH_MODE_CALLER,
	APP_GROUP_LAUNCH_MODE_SINGLETON,
} app_group_launch_mode;

void _app_group_init(void);
void _app_group_remove(int pid);
int _app_group_get_window(int pid);
int _app_group_set_window(int pid, int wid);
void _app_group_get_leader_pids(int *cnt, int **pids);
void _app_group_get_group_pids(int leader_pid, int *cnt, int **pids);
bool _app_group_is_leader_pid(int pid);
bool _app_group_is_group_app(bundle *kb);
bool _app_group_is_sub_app(int pid);
void _app_group_reroute(int pid);
void _app_group_clear_top(int pid);
int _app_group_get_leader_pid(int pid);
void _app_group_set_dead_pid(int pid);
int _app_group_get_status(int pid);
int _app_group_set_status(int pid, int status, bool force);
int _app_group_get_fg_flag(int pid);
int _app_group_set_hint(int pid, bundle *kb);
int _app_group_find_second_leader(int lpid);
void _app_group_remove_leader_pid(int lpid);
int _app_group_can_start_app(const char *appid, bundle *b, bool *can_attach,
		int *lpid, app_group_launch_mode *mode);
void _app_group_start_app(int pid, bundle *b, int lpid, bool can_attach,
		app_group_launch_mode mode);
int _app_group_find_singleton(const char *appid, int *found_pid,
		int *found_lpid);
int _app_group_can_reroute(int pid);
void _app_group_lower(int pid, int *exit);
void _app_group_restart_app(int pid, bundle *b);
int _app_group_find_pid_from_recycle_bin(const char *appid);
void _app_group_get_idle_pids(int *cnt, int **pids);
void _app_group_remove_from_recycle_bin(int pid);
int _app_group_get_next_caller_pid(int pid);
int _app_group_activate_below(int pid, const char *below_appid);

