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

#define _GNU_SOURCE

#include <aul.h>
#include <Ecore_Wayland.h>
#include <glib.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_input.h"

#define KEY_BACK "XF86Back"

static int locked_wid;
static guint timer;

static gboolean __timeout_handler(void *data)
{
	timer = 0;
	_input_unlock();
	return FALSE;
}

int _input_lock(int caller_wid)
{
	if (locked_wid > 0)
		_input_unlock();

	/* TODO: lock pointer */

	timer = g_timeout_add(5 * 1000, __timeout_handler, NULL);

	if (ecore_wl_window_keygrab_set(NULL, KEY_BACK, 0, 0, 0,
			ECORE_WL_WINDOW_KEYGRAB_EXCLUSIVE) == EINA_FALSE) {
		_E("Failed to set key grab");
		g_source_remove(timer);
		timer = 0;
		locked_wid = 0;
		return -1;
	}

	locked_wid = caller_wid;

	return 0;
}

int _input_unlock(void)
{
	if (locked_wid <= 0)
		return 0;

	/* TODO: unlock pointer */

	if (ecore_wl_window_keygrab_unset(NULL, KEY_BACK, 0, 0) == EINA_FALSE) {
		_E("Failed to unset key grab");
		return -1;
	}

	locked_wid = 0;
	if (timer > 0) {
		g_source_remove(timer);
		timer = 0;
	}

	return 0;
}

