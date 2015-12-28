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

#include <unistd.h>
#include <ctype.h>
#include <dlog.h>
#include <tzplatform_config.h>

#define GLOBAL_USER tzplatform_getuid(TZ_SYS_GLOBALAPP_USER)

#ifdef AMD_LOG
#undef LOG_TAG
#define LOG_TAG "AUL_AMD"
#endif

#define MAX_LOCAL_BUFSZ 128
#define MAX_PID_STR_BUFSZ 20
#define MAX_UID_STR_BUFSZ 20
#define AUL_UTIL_PID -2

#define MAX_PACKAGE_STR_SIZE 512
#define MAX_PACKAGE_APP_PATH_SIZE 512
#define MAX_RUNNING_APP_INFO 512

#define GSLIST_FOREACH_SAFE(list, l, l_next)   \
	for (l = list,                            \
			l_next = g_slist_next(l);       \
			l;                              \
			l = l_next,                     \
			l_next = g_slist_next(l))

#define _E(fmt, arg...) LOGE(fmt, ##arg)
#define _D(fmt, arg...) LOGD(fmt, ##arg)
#define _W(fmt, arg...) LOGW(fmt, ##arg)

#define retvm_if(expr, val, fmt, arg...) do { \
	if (expr) { \
		_E(fmt, ##arg); \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)

#define retv_if(expr, val) do { \
	if (expr) { \
		_E("(%s) -> %s() return", #expr, __FUNCTION__); \
		return (val); \
	} \
} while (0)
