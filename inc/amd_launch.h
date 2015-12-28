/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include "amd_util.h"
#include "amd_appinfo.h"

int _send_to_sigkill(int pid);
int _resume_app(int pid, int clifd);
int _pause_app(int pid, int clifd);
int _term_app(int pid, int clifd);
int _term_req_app(int pid, int clifd);
int _term_bgapp(int pid, int clifd);
int _term_sub_app(int pid);
int _fake_launch_app(int cmd, int pid, bundle * kb, int clifd);
int _start_app(const char* appid, bundle* kb, int cmd, int caller_pid, uid_t caller_uid, int fd, bool *pend);
int _start_app_local(uid_t uid, const char *appid);
int _start_app_local_with_bundle(uid_t uid, const char *appid, bundle *kb);
int _get_pid_of_last_launched_ui_app();
int _send_hint_for_visibility(uid_t uid);


