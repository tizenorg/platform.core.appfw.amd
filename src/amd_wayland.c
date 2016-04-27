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
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/inotify.h>

#include <glib.h>
#include <gio/gio.h>
#include <wayland-client.h>
#include <wayland-tbm-client.h>
#include <tizen-extension-client-protocol.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_wayland.h"

#define INOTIFY_BUF (1024 * ((sizeof(struct inotify_event)) + 16))

struct wl_watch {
	int fd;
	int wd_wl;
	int wd_wm;
	GIOChannel *io;
	guint wid;
};

struct wl_listen {
	listener_cb listener;
	listener_remove_cb listener_remove;
	void *data;
};

static int wl_0_ready;
static int wm_ready;
static struct wl_display *display;
static struct wl_registry *registry;
static GList *wl_list;

int _wayland_add_listener_cbs(listener_cb listener,
		listener_remove_cb listener_remove, void *data)
{
	struct wl_listen *listen;

	if (listener == NULL)
		return -1;

	listen = (struct wl_listen *)calloc(1, sizeof(struct wl_listen));
	if (listen == NULL) {
		_E("out of memory");
		return -1;
	}

	listen->listener = listener;
	listen->listener_remove = listener_remove;
	listen->data = data;

	wl_list = g_list_append(wl_list, listen);

	return 0;
}

struct wl_display *_wayland_get_display(void)
{
	return display;
}

static void __wl_listener_cb(void *data, struct wl_registry *reg,
		unsigned int id, const char *interface, unsigned int version)
{
	GList *iter;
	struct wl_listen *listen;

	for (iter = g_list_first(wl_list); iter; iter = g_list_next(iter)) {
		listen = (struct wl_listen *)iter->data;
		if (listen && listen->listener) {
			listen->listener(listen->data, reg, id, interface,
					version);
		}
	}
}

static void __wl_listener_remove_cb(void *data, struct wl_registry *reg,
		unsigned int id)
{
	GList *iter;
	struct wl_listen *listen;

	iter = g_list_first(wl_list);
	while (iter) {
		listen = (struct wl_listen *)iter->data;
		if (listen && listen->listener_remove)
			listen->listener_remove(listen->data, reg, id);

		iter = g_list_next(iter);
		wl_list = g_list_remove(wl_list, listen);
		free(listen);
	}
}


static const struct wl_registry_listener registry_listener = {
	__wl_listener_cb,
	__wl_listener_remove_cb,
};

static void __init_wl(void)
{
	display = wl_display_connect(NULL);
	if (display == NULL) {
		_E("Failed to connect wayland display");
		return;
	}

	registry = wl_display_get_registry(display);
	if (registry == NULL) {
		_E("Failed to get wayland registry");
		wl_display_disconnect(display);
		display = NULL;
		return;
	}

	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_flush(display);
	wl_display_roundtrip(display);
}

static gboolean __wl_monitor_cb(GIOChannel *io, GIOCondition cond,
		gpointer data)
{
	char buf[INOTIFY_BUF];
	ssize_t len = 0;
	int i = 0;
	struct inotify_event *event;
	char *p;
	int fd = g_io_channel_unix_get_fd(io);

	len = read(fd, buf, sizeof(buf));
	if (len < 0) {
		_E("Failed to read");
		return TRUE;
	}

	while (i < len) {
		event = (struct inotify_event *)&buf[i];
		if (event->len) {
			p = event->name;
			if (p && !strcmp(p, "wayland-0")) {
				_D("%s is created", p);
				wl_0_ready = 1;
			} else if (p && !strcmp(p, ".wm_ready")) {
				_D("%s is created", p);
				wm_ready = 1;
			}

			if (wm_ready && wl_0_ready) {
				__init_wl();
				return FALSE;
			}
		}
		i += offsetof(struct inotify_event, name) + event->len;
	}

	return TRUE;
}

static void __wl_watch_destroy_cb(gpointer data)
{
	struct wl_watch *watch = (struct wl_watch *)data;

	if (watch == NULL)
		return;

	g_io_channel_unref(watch->io);

	if (watch->wd_wm)
		inotify_rm_watch(watch->fd, watch->wd_wm);
	if (watch->wd_wl)
		inotify_rm_watch(watch->fd, watch->wd_wl);
	close(watch->fd);
	free(watch);
}

static int __check_wl_ready(void)
{
	char buf[PATH_MAX];
	struct wl_watch *watch;

	snprintf(buf, sizeof(buf), "/run/user/%d/wayland-0", getuid());
	if (access(buf, F_OK) == 0) {
		_D("%s exists", buf);
		wl_0_ready = 1;
	}

	if (access("/run/.wm_ready", F_OK) == 0) {
		_D("/run/.wm_ready exists");
		wm_ready = 1;
	}

	if (wm_ready && wl_0_ready)
		return 0;

	watch = (struct wl_watch *)calloc(1, sizeof(struct wl_watch));
	if (watch == NULL) {
		_E("out of memory");
		return -1;
	}

	watch->fd = inotify_init();
	if (watch->fd < 0) {
		_E("Failed to initialize inotify");
		free(watch);
		return -1;
	}

	if (!wl_0_ready) {
		snprintf(buf, sizeof(buf), "/run/user/%d", getuid());
		watch->wd_wl = inotify_add_watch(watch->fd, buf, IN_CREATE);
		if (watch->wd_wl < 0) {
			_E("Failed to add inotify watch");
			close(watch->fd);
			free(watch);
			return -1;
		}
	}

	if (!wm_ready) {
		watch->wd_wm = inotify_add_watch(watch->fd, "/run", IN_CREATE);
		if (watch->wd_wm < 0) {
			_E("Failed to add inotify watch");
			if (watch->wd_wl)
				inotify_rm_watch(watch->fd, watch->wd_wl);
			close(watch->fd);
			free(watch);
			return -1;
		}
	}

	watch->io = g_io_channel_unix_new(watch->fd);
	if (watch->io == NULL) {
		_E("Failed to create GIOChannel");
		if (watch->wd_wm)
			inotify_rm_watch(watch->fd, watch->wd_wm);
		if (watch->wd_wl)
			inotify_rm_watch(watch->fd, watch->wd_wl);
		close(watch->fd);
		free(watch);
		return -1;
	}

	watch->wid = g_io_add_watch_full(watch->io, G_PRIORITY_DEFAULT,
			G_IO_IN, __wl_monitor_cb, watch, __wl_watch_destroy_cb);

	return -1;
}

int _wayland_init(void)
{
	if (__check_wl_ready() < 0)
		return -1;

	__init_wl();

	return 0;
}

void _wayland_finish(void)
{
	if (registry)
		wl_registry_destroy(registry);

	if (display)
		wl_display_disconnect(display);
}

