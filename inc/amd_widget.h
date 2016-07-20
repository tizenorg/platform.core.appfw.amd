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

#ifndef __AMD_WIDGET_H__
#define __AMD_WIDGET_H__

#include "amd_request.h"

int _widget_fini(void);
int _widget_add(const char *widget_id, const char *instance_id, int pid,
		int uid);
int _widget_del(const char *widget_id, const char *instance_id);
int _widget_list(const char *widget_id, request_h req);
int _widget_update(const char *widget_id, request_h req);
int _widget_cleanup(int pid, int uid);
bool _widget_exist(const char *widget_id, int pid, int uid);
int _widget_send_result(int pid, int uid);
char *_widget_get_id(int pid, int uid);
int _widget_send_dead_signal(char *widget_id, int pid);

#endif /* __AMD_WIDGET_H__ */

