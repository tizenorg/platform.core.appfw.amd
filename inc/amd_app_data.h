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


#ifndef __AMD_APP_DATA_H__
#define __AMD_APP_DATA_H__

#include <amd_request.h>

int _app_data_init();
int _app_data_fini();
int _app_data_new(const char *key, request_h req);
int _app_data_get_raw(const char *key, request_h req);
int _app_data_get(const char *key, bundle *b, request_h req);
int _app_data_get_owner(const char *key, bundle *b, request_h req);
int _app_data_put(const char *key, bundle *b, request_h req);
int _app_data_del(const char *key, bundle *b, request_h req);
int _app_data_cleanup(int pid, int uid);

#endif /* __AMD_APP_DATA_H__ */
