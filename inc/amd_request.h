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

typedef struct request_s* request_h;

int _request_init(void);
int _request_send_result(request_h req, int res);
int _request_send_raw(request_h req, int cmd, unsigned char *data, int len);
int _request_get_fd(request_h req);
int _request_get_pid(request_h req);
int _request_get_cmd(request_h req);
request_h _request_create_local(int cmd, int uid, int pid);
void _request_free_local(request_h req);
int _request_remove_fd(request_h req);
int _request_reply_for_pending_request(int pid);
int _request_flush_pending_request(int pid);


