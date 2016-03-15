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

typedef struct splash_image_s *splash_image_h;

splash_image_h _splash_screen_create_image(const struct appinfo *ai,
				bundle *kb, int cmd);
void _splash_screen_send_image(splash_image_h si);
void _splash_screen_send_pid(splash_image_h si, int pid);
void _splash_screen_destroy_image(splash_image_h si);
int _splash_screen_init(void);
