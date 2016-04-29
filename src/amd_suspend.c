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

#include <gio/gio.h>
#include <stdlib.h>
#include <stdbool.h>
#include "amd_signal.h"
#include "amd_util.h"
#include "amd_suspend.h"

typedef struct proc_info {
	pid_t pid;
	guint timer_id;
} proc_info_t;

static GHashTable *proc_info_tbl = NULL;

static void __destroy_proc_info_value(gpointer data)
{
	proc_info_t *proc = (proc_info_t *)data;
	if (proc)
		free(proc);
}

void _suspend_init(void)
{
	if (!proc_info_tbl) {
		proc_info_tbl = g_hash_table_new_full(g_direct_hash,
				g_direct_equal, NULL,
				__destroy_proc_info_value);
	}

	_D("_amd_proc_init done");
}

void _suspend_fini(void)
{
	g_hash_table_destroy(proc_info_tbl);
	_D("_amd_proc_fini done");
}

proc_info_t *__create_proc_info(int pid)
{
	proc_info_t *proc = NULL;

	if (pid < 1) {
		_E("invalid pid");
		return NULL;
	}

	proc = (proc_info_t *)malloc(sizeof(proc_info_t));
	if (proc == NULL) {
		_E("insufficient memory");
		return NULL;
	}

	proc->pid = pid;
	proc->timer_id = 0;

	return proc;
}

proc_info_t *__find_proc_info(int pid)
{
	proc_info_t *proc = NULL;

	if (pid < 1) {
		_E("invalid pid");
		return NULL;
	}

	proc = (proc_info_t *)g_hash_table_lookup(proc_info_tbl,
			GINT_TO_POINTER(pid));
	if (proc == NULL) {
		_E("proc info not found");
		return NULL;
	}

	return proc;
}

int __add_proc_info(proc_info_t *proc)
{
	if (proc == NULL) {
		_E("invalid proc info");
		return -1;
	}

	if (proc->pid < 1) {
		_E("invalid pid");
		return -1;
	}

	g_hash_table_insert(proc_info_tbl, GINT_TO_POINTER(proc->pid), proc);

	return 0;
}

int _suspend_add_proc(int pid)
{
	proc_info_t *proc;

	proc = __create_proc_info(pid);
	if (proc)
		return __add_proc_info(proc);

	return -1;
}

int _suspend_remove_proc(int pid)
{
	proc_info_t *proc = NULL;

	if (pid < 1) {
		_E("invalid pid");
		return -1;
	}

	proc = (proc_info_t *)g_hash_table_lookup(proc_info_tbl,
			GINT_TO_POINTER(pid));
	if (proc == NULL) {
		_E("proc info not found");
		return -1;
	}

	g_hash_table_remove(proc_info_tbl, GINT_TO_POINTER(pid));

	return 0;
}

static gboolean __send_suspend_hint(gpointer data)
{
	proc_info_t *proc = NULL;
	int pid = GPOINTER_TO_INT(data);

	proc = __find_proc_info(pid);
	if (proc && proc->timer_id > 0) {
		_signal_send_proc_suspend(pid);
		proc->timer_id = 0;
	}

	return FALSE;
}

void _suspend_add_timer(int pid, const struct appinfo *ai)
{
	int bg_allowed = 0x00;
	proc_info_t *proc = NULL;

	bg_allowed = (intptr_t)appinfo_get_value(ai, AIT_BG_CATEGORY);
	if (bg_allowed)
		return;

	proc = __find_proc_info(pid);
	if (proc == NULL) {
		proc = __create_proc_info(pid);
		if (proc)
			__add_proc_info(proc);
	}

	if (proc) {
		proc->timer_id = g_timeout_add_seconds(10, __send_suspend_hint,
				GINT_TO_POINTER(pid));
	}
}

void _suspend_remove_timer(int pid)
{
	proc_info_t *proc = NULL;

	proc = __find_proc_info(pid);
	if (proc && proc->timer_id > 0) {
		g_source_remove(proc->timer_id);
		proc->timer_id = 0;
	}
}

