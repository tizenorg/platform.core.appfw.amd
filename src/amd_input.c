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

#include <stdbool.h>
#include <malloc.h>
#include <aul.h>
#include <wayland-client.h>
#include <tizen-extension-client-protocol.h>
#include <glib.h>
#include <sys/mman.h>
#include <xkbcommon/xkbcommon.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_input.h"

#define TIMEOUT_VAL 1000

extern int _wl_is_initialized(void);

static bool locked = false;
static bool init_done = false;
static guint timer;
struct tizen_keyrouter *keyrouter;
struct tizen_input_device_manager *input_devmgr;
struct wl_display *display;
struct wl_registry *registry;
struct xkb_context *g_ctx;
struct xkb_keymap *g_keymap;
struct wl_keyboard *keyboard;

typedef struct _keycode_map {
	xkb_keysym_t keysym;
	xkb_keycode_t *keycodes;
	int nkeycodes;
} keycode_map;

static void __keyboard_keymap(void *data, struct wl_keyboard *keyboard,
				uint32_t format, int fd, uint32_t size)
{
	char *map = NULL;

	_D("format=%d, fd=%d, size=%d", format, fd, size);
	if (!g_ctx) {
		_E("This client failed to make xkb context");
		return;
	}

	if (format != WL_KEYBOARD_KEYMAP_FORMAT_XKB_V1) {
		_E("Invaild format: %d", format);
		return;
	}

	map = mmap(NULL, size, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED) {
		_E("Failed to mmap from fd(%d) size(%d)", fd, size);
		return;
	}

	g_keymap = xkb_map_new_from_string(g_ctx, map, XKB_KEYMAP_FORMAT_TEXT_V1, 0);

	munmap(map, size);
	if (!g_keymap)
		_E("Failed to get keymap from fd(%d)", fd);
}

static void __keyboard_enter(void *data, struct wl_keyboard *keyboard,
				uint32_t serial, struct wl_surface *surface, struct wl_array *keys)
{
	_D("serial=%d", serial);
}

static void __keyboard_leave(void *data, struct wl_keyboard *keyboard,
				uint32_t serial, struct wl_surface *surface)
{
	_D("serial=%d", serial);
}

static void __keyboard_key(void *data, struct wl_keyboard *keyboard,
				uint32_t serial, uint32_t time, uint32_t key, uint32_t state_w)
{
	_D("serial=%d, time=%d, key=%d, state_w=%d", serial, time, key, state_w);
}

static void __keyboard_modifiers(void *data, struct wl_keyboard *keyboard,
				uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched,
				uint32_t mods_locked, uint32_t group)
{
	_D("serial=%d, mods_depressed=%d, mods_latched=%d, mods_locked=%d, group=%d",
		serial, mods_depressed, mods_latched, mods_locked, group);
}

static const struct wl_keyboard_listener keyboard_listener = {
	.keymap = __keyboard_keymap,
	.enter = __keyboard_enter,
	.leave = __keyboard_leave,
	.key = __keyboard_key,
	.modifiers = __keyboard_modifiers
};

static void __global_registry_handler(void * data,
					struct wl_registry * registry,
					uint32_t id,
					const char * interface, uint32_t version)
{
	if (interface == NULL)
		return;

	if (strncmp(interface, "tizen_input_device_manager", 12) == 0) {
		input_devmgr = wl_registry_bind(registry, id,
				&tizen_input_device_manager_interface, 1);
		_D("input_devmgr = %p", input_devmgr);
	} else if (strncmp(interface, "tizen_keyrouter", 12) == 0) {
		keyrouter = wl_registry_bind(registry, id, &tizen_keyrouter_interface, 1);
		_D("keyrouter = %p", keyrouter);
	} else if (strncmp(interface, "wl_seat", 7) == 0) {
		struct wl_seat *seat = wl_registry_bind(registry, id, &wl_seat_interface, 1);
		if (seat)
			_D("Succeed to bind wl_seat_interface!");

		keyboard = wl_seat_get_keyboard(seat);
		wl_keyboard_add_listener(keyboard, &keyboard_listener, NULL);
		_D("keyboard = %p", keyboard);
	}
}

static void __global_registry_remover(void * data,
					struct wl_registry * registry,
					uint32_t id)
{
}

static const struct wl_registry_listener registry_listener = {
	__global_registry_handler,
	__global_registry_remover
};

static gboolean __timeout_handler(void *data)
{
	timer = 0;
	_input_unlock();
	return FALSE;
}

static void __find_keycode(struct xkb_keymap *keymap, xkb_keycode_t key,
				void *data)
{
	keycode_map *found_keycodes = (keycode_map *)data;
	xkb_keysym_t keysym = found_keycodes->keysym;
	int nsyms = 0;
	const xkb_keysym_t *syms_out = NULL;

	nsyms = xkb_keymap_key_get_syms_by_level(keymap, key, 0, 0, &syms_out);
	if (nsyms && syms_out) {
		if (*syms_out == keysym) {
			found_keycodes->nkeycodes++;
			found_keycodes->keycodes = realloc(found_keycodes->keycodes,
						sizeof(int) * found_keycodes->nkeycodes);
			found_keycodes->keycodes[found_keycodes->nkeycodes - 1] = key;
		}
	}
}

static int __xkb_keycode_from_keysym(struct xkb_keymap *keymap,
					xkb_keysym_t keysym,
					xkb_keycode_t **keycodes)
{
	keycode_map found_keycodes = {0,};
	found_keycodes.keysym = keysym;
	xkb_keymap_key_for_each(g_keymap, __find_keycode, &found_keycodes);

	*keycodes = found_keycodes.keycodes;
	return found_keycodes.nkeycodes;
}

static void __keygrab_request(struct tizen_keyrouter *tizen_keyrouter,
				struct wl_surface *surface, uint32_t key, uint32_t mode)
{
	tizen_keyrouter_set_keygrab(tizen_keyrouter, surface, key, mode);
	_D("request set_keygrab (key:%d, mode:%d)!", key, mode);
}

static void __keyungrab_request(struct tizen_keyrouter *tizen_keyrouter,
				struct wl_surface *surface, uint32_t key)
{
	tizen_keyrouter_unset_keygrab(tizen_keyrouter, surface, key);
	_D("request unset_keygrab (key:%d)!", key);
}

static void __do_keygrab(const char *keyname, uint32_t mode)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = __xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		_D("%s's keycode is %d (nkeycode: %d)", keyname, keycodes[i], nkeycodes);
		__keygrab_request(keyrouter, NULL, keycodes[i], mode);
	}
	free(keycodes);
	keycodes = NULL;
}

static void __do_keyungrab(const char *keyname)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = __xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		_D("%s's keycode is %d (nkeycode: %d)\n", keyname, keycodes[i], nkeycodes);
		__keyungrab_request(keyrouter, NULL, keycodes[i]);
	}
	free(keycodes);
	keycodes = NULL;
}

static int __xkb_init(void)
{
	g_ctx = xkb_context_new(0);
	if (!g_ctx) {
		_E("Failed to get xkb_context");
		return -1;
	}

	return 0;
}

static void __xkb_fini(void)
{
	if (g_ctx) {
		xkb_context_unref(g_ctx);
		g_ctx = NULL;
	}
}

static void __cb_device_add(void *data,
				struct tizen_input_device_manager *tizen_input_device_manager,
				uint32_t serial, const char *name, struct tizen_input_device *device,
				struct wl_seat *seat)
{
	_D("device is added!", name);
}

static void __cb_device_remove(void *data,
				struct tizen_input_device_manager *tizen_input_device_manager,
				uint32_t serial, const char *name, struct tizen_input_device *device,
				struct wl_seat *seat)
{
	_D("%s device is removed!", name);
}

static void __cb_error(void *data,
			struct tizen_input_device_manager *tizen_input_device_manager,
			uint32_t errorcode)
{
	_E("error: %d", errorcode);
}

static void __cb_block_expired(void *data,
				struct tizen_input_device_manager *tizen_input_device_manager)
{
	_D("block expired");
}

static struct tizen_input_device_manager_listener input_devmgr_listener = {
	__cb_device_add,
	__cb_device_remove,
	__cb_error,
	__cb_block_expired
};

int _input_init(void)
{
	if (!_wl_is_initialized())
		return -1;

	display = wl_display_connect(NULL);
	if (!display) {
		_E("Failed to connect to wayland compositor");
		return -1;
	}

	if (__xkb_init() < 0)
		return -1;

	_D("Connected to wayland compositor!");

	registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &registry_listener, NULL);
	wl_display_flush(display);
	wl_display_roundtrip(display);

	if (input_devmgr == NULL) {
		_E("input_devmgr is null");
		return -1;
	}

	if (keyrouter == NULL) {
		_E("keyrouter is null");
		return -1;
	}

	if (tizen_input_device_manager_add_listener(input_devmgr,
		&input_devmgr_listener, NULL) < 0) {
		_E("Failed to add listener");
	}
	wl_display_flush(display);
	wl_display_roundtrip(display);

	init_done = true;

	return 0;
}

int _input_fini(void)
{
	__xkb_fini();

	if (keyrouter) {
		tizen_keyrouter_destroy(keyrouter);
		keyrouter = NULL;
	}

	if (input_devmgr) {
		tizen_input_device_manager_destroy(input_devmgr);
		input_devmgr = NULL;
	}

	if (keyboard) {
		wl_keyboard_destroy(keyboard);
		keyboard = NULL;
	}

	if (registry) {
		wl_registry_destroy(registry);
		registry = NULL;
	}

	if (display) {
		wl_display_disconnect(display);
		display = NULL;
	}
	return 0;
}

int _input_lock(void)
{
	if (locked)
		_input_unlock();

	if (!init_done && _input_init() < 0)
		return -1;

	_D("call tizen_input_device_manager_block_events");
	tizen_input_device_manager_block_events(input_devmgr, 0,
		TIZEN_INPUT_DEVICE_MANAGER_CLAS_TOUCHSCREEN |
		TIZEN_INPUT_DEVICE_MANAGER_CLAS_MOUSE, TIMEOUT_VAL);
	timer = g_timeout_add(TIMEOUT_VAL, __timeout_handler, NULL);
	__do_keygrab("XF86Back", TIZEN_KEYROUTER_MODE_EXCLUSIVE);
	wl_display_roundtrip(display);

	locked = true;

	return 0;
}

int _input_unlock(void)
{
	if (!locked)
		return 0;

	if (!init_done && _input_init() < 0)
		return -1;

	_D("call tizen_input_device_manager_unblock_events");
	tizen_input_device_manager_unblock_events(input_devmgr, 0);
	__do_keyungrab("XF86Back");
	wl_display_roundtrip(display);

	locked = false;
	if (timer > 0) {
		g_source_remove(timer);
		timer = 0;
	}

	return 0;
}

