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

#define _GNU_SOURCE
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <aul.h>
#include <aul_sock.h>
#include <bundle.h>
#include <bundle_internal.h>

#include "amd_app_com.h"
#include "amd_request.h"
#include "amd_config.h"
#include "amd_util.h"
#include "amd_launch.h"
#include "amd_widget.h"

typedef struct _widget_t {
	char *widget_id;
	int pid;
	int uid;
	GList *instances;
} widget_t;

static GList *__widgets;

static void __free_widget(gpointer data)
{
	widget_t *widget = (widget_t *)data;

	free(widget->widget_id);
	g_list_free_full(widget->instances, free);
	free(widget);
}

int _widget_fini(void)
{
	if (__widgets)
		g_list_free_full(__widgets, __free_widget);

	return 0;
}

static widget_t *__find_widget(const char *widget_id, int pid, int uid)
{
	GList *widget_list = __widgets;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0) {
			if (widget->pid == pid && widget->uid == uid)
				return widget;
		}

		widget_list = widget_list->next;
	}

	return NULL;
}

static widget_t *__find_instance(const char *widget_id, const char *instance_id)
{
	GList *widget_list = __widgets;
	GList *instance_list;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0
						&& widget->instances) {
			instance_list = g_list_find_custom(widget->instances,
					instance_id, (GCompareFunc)g_strcmp0);

			if (instance_list)
				return widget;
		}

		widget_list = widget_list->next;
	}

	return NULL;
}

bool _widget_exist(int pid, int uid)
{
	GList *widget_list = __widgets;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (widget->pid == pid && widget->uid == uid)
			return true;

		widget_list = widget_list->next;
	}
	return false;
}

int _widget_send_dead_signal(int pid, int uid)
{
	bundle *kb;
	widget_t *widget = NULL;
	GList *widget_list = __widgets;
	int status = AUL_WIDGET_LIFE_CYCLE_EVENT_APP_DEAD;
	char sender_pid_str[MAX_PID_STR_BUFSZ];

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (widget->pid == pid && widget->uid == uid)
			break;
		widget_list = widget_list->next;
	}
	if (!widget) {
		_E("cannot find widget pid : %d, uid %d", pid, uid);
		return -1;
	}
	snprintf(sender_pid_str, MAX_PID_STR_BUFSZ, "%d", pid);

	kb = bundle_create();
	if (!kb) {
		_E("cannot create bundle out of memory");
		return -1;
	}
	bundle_add(kb, AUL_K_WIDGET_ID, widget->widget_id);
	bundle_add_byte(kb, AUL_K_WIDGET_STATUS, &status, sizeof(int));
	bundle_add(kb, AUL_K_COM_SENDER_PID, sender_pid_str);
	_app_com_send("widget.status", getpgid(pid), kb);
	bundle_free(kb);

	return 0;
}

int _widget_add(const char *widget_id, const char *instance_id, int pid,
		int uid)
{
	widget_t *widget;
	char *id;

	if (!widget_id || !instance_id)
		return -1;

	id = strdup(instance_id);
	if (!id) {
		_E("out of memory");
		return -1;
	}

	widget = __find_widget(widget_id, pid, uid);
	if (!widget) {
		widget = (widget_t *)calloc(1, sizeof(widget_t));
		if (!widget) {
			_E("out of memory");
			return -1;
		}

		widget->widget_id = strdup(widget_id);
		widget->pid = pid;
		widget->uid = uid;
		__widgets = g_list_append(__widgets, widget);
	}

	widget->instances = g_list_append(widget->instances, id);

	_D("widget instance added: %s - %s (%d:%d)", widget_id, instance_id,
								uid, pid);
	return 0;
}

int _widget_del(const char *widget_id, const char *instance_id)
{
	widget_t *widget;
	GList *stored_list;

	if (!widget_id || !instance_id)
		return -1;

	widget = __find_instance(widget_id, instance_id);
	if (!widget)
		return -1;

	stored_list = g_list_find_custom(widget->instances, instance_id,
			 (GCompareFunc)g_strcmp0);

	if (stored_list) {
		widget->instances = g_list_remove_link(widget->instances,
			stored_list);
		free(stored_list->data);
		g_list_free(stored_list);

		_D("widget instace deleted: %s - %s (%d:%d)", widget->widget_id,
				instance_id, widget->uid, widget->pid);
		return 0;
	}

	return -1;
}

int _widget_list(const char *widget_id, request_h req)
{
	bundle *rvalue;
	widget_t *widget;
	GList *widget_list = __widgets;
	GList *instance_list;
	char pid_buf[10];
	int fd;

	if (!widget_id)
		return -1;

	rvalue = bundle_create();
	if (!rvalue) {
		_E("out of memory");
		return -1;
	}

	_D("start instance list");

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		if (strcmp(widget->widget_id, widget_id) == 0) {
			instance_list = widget->instances;
			snprintf(pid_buf, sizeof(pid_buf), "%d", widget->pid);
			while (instance_list) {
				_D("%s - %s", widget_id, instance_list->data);
				bundle_add_str(rvalue, instance_list->data,
								pid_buf);
				instance_list = instance_list->next;
			}
		}
		widget_list = widget_list->next;
	}

	_D("end instance list");

	fd = _request_remove_fd(req);
	aul_sock_send_bundle_with_fd(fd, 0, rvalue, AUL_SOCK_NOREPLY);

	bundle_free(rvalue);

	return 0;
}

int _widget_update(const char *widget_id, request_h req)
{
	char *instance_id;
	char *appid;
	bundle *kb = _request_get_bundle(req);
	int ret = 0;
	widget_t *widget;
	GList *widget_list = __widgets;

	if (!kb || !widget_id)
		return -1;

	bundle_get_str(kb, AUL_K_APPID, &appid);
	if (!appid) {
		_E("missing appid:%s", widget_id);
		return -1;
	}

	bundle_get_str(kb, AUL_K_WIDGET_INSTANCE_ID, &instance_id);
	if (!instance_id) { /* all instances */
		while (widget_list) {
			widget = (widget_t *)widget_list->data;
			if (strcmp(widget->widget_id, widget_id) == 0) {
				bundle_del(kb, AUL_K_TARGET_PID);
				bundle_add_byte(kb, AUL_K_TARGET_PID,
						(void *)&widget->pid,
						sizeof(widget->pid));

				ret = _launch_start_app(appid, req);
				_D("update widget: %s(%d)", widget->widget_id,
								widget->pid);
			}
			widget_list = widget_list->next;
		}
	} else {
		widget = __find_instance(widget_id, instance_id);
		if (widget) {
			bundle_del(kb, AUL_K_TARGET_PID);
			bundle_add_byte(kb, AUL_K_TARGET_PID,
				(void *)&widget->pid, sizeof(widget->pid));
		}
		ret = _launch_start_app(appid, req);
		_D("update widget: %s", widget_id);
	}

	if (ret > 0)
		return 0;

	return ret;
}

int _widget_cleanup(int pid, int uid)
{
	GList *widget_list = __widgets;
	widget_t *widget;

	while (widget_list) {
		widget = (widget_t *)widget_list->data;
		widget_list = widget_list->next;
		if (widget->pid == pid && widget->uid == uid) {
			__widgets = g_list_remove(__widgets, widget);
			__free_widget(widget);
		}
	}

	_D("cleanup widget %d:%d", pid, uid);

	return 0;
}
