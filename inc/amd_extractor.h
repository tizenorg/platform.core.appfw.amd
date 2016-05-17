/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <bundle.h>

#include "amd_appinfo.h"

typedef char **(_extractor_mountable)(const struct appinfo *ai);

char **_extractor_mountable_get_tep_paths(const struct appinfo *ai);
char **_extractor_mountable_get_tpk_paths(const struct appinfo *ai);
void _extractor_mount(const struct appinfo *ai, bundle *kb,
		_extractor_mountable mountable);
void _extractor_unmount(int pid, _extractor_mountable mountable);

