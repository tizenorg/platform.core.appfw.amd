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

#include <glib.h>
#include <tizen-extension-client-protocol.h>

#include "amd_appinfo.h"

struct wl_splash_image {
	struct tizen_launch_image *image;
	guint tid;
};

void _destroy_splash_image(struct wl_splash_image *wl_si);
struct wl_splash_image *_send_image_to_wm(const struct appinfo *ai,
		                bundle *kb, int cmd);
void _send_pid_to_wm(struct wl_splash_image *wl_si, int pid);
int _wl_is_initialized(void);
int _wayland_init(void);
