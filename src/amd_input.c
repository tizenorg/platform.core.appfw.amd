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
#include <wayland-client.h>
#include <tizen-extension-client-protocol.h>
#include <glib.h>
#include <sys/mman.h>
#include <xkbcommon/xkbcommon.h>

#include "amd_config.h"
#include "amd_util.h"
#include "amd_input.h"

#define KEYCODE_GAP 8 /* keycode gap between kernel keycode and appside keycode */

static int locked_wid;
static guint timer;
struct tizen_keyrouter *keyrouter;
struct tizen_input_device_manager *input_devmgr;
struct wl_display *display;
struct xkb_context *g_ctx;
struct xkb_keymap *g_keymap;
struct wl_keyboard *keyboard;

typedef struct _keycode_map {
	xkb_keysym_t keysym;
	xkb_keycode_t *keycodes;
	int nkeycodes;
} keycode_map;

static void keyboard_keymap(void *data, struct wl_keyboard *keyboard,
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
	if (!g_keymap) {
		_E("Failed to get keymap from fd(%d)", fd);
	}
}

static void keyboard_enter(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface, struct wl_array *keys)
{
}

static void keyboard_leave(void *data, struct wl_keyboard *keyboard,
                           uint32_t serial, struct wl_surface *surface)
{
}

static void keyboard_key(void *data, struct wl_keyboard *keyboard,
                         uint32_t serial, uint32_t time, uint32_t key, uint32_t state_w)
{
}

static void keyboard_modifiers(void *data, struct wl_keyboard *keyboard,
                               uint32_t serial, uint32_t mods_depressed, uint32_t mods_latched,
                               uint32_t mods_locked, uint32_t group)
{
}

/* Define keyboard event handlers */
static const struct wl_keyboard_listener keyboard_listener = {
	.keymap = keyboard_keymap,
	.enter = keyboard_enter,
	.leave = keyboard_leave,
	.key = keyboard_key,
	.modifiers = keyboard_modifiers
};

static void global_registry_handler(void * data, struct wl_registry * registry,
                                    uint32_t id,
                                    const char * interface, uint32_t version)
{
	if (0 == strncmp(interface, "tizen_input_device_manager", 12)) {
		input_devmgr = wl_registry_bind(registry, id,
		                                &tizen_input_device_manager_interface, 1);
	} else if (0 == strncmp(interface, "tizen_keyrouter", 12)) {
		keyrouter = wl_registry_bind(registry, id, &tizen_keyrouter_interface, 1);
	} else if (0 == strncmp(interface, "wl_seat", 7)) {
		struct wl_seat *seat = wl_registry_bind(registry, id, &wl_seat_interface, 1);
		if (seat)
			_D("Succeed to bind wl_seat_interface!");

		keyboard = wl_seat_get_keyboard(seat);
		wl_keyboard_add_listener(keyboard, &keyboard_listener, NULL);
	}

}

static void global_registry_remover(void * data, struct wl_registry * registry,
                                    uint32_t id)
{
}

static const struct wl_registry_listener registry_listener = {
	global_registry_handler,
	global_registry_remover
};

static gboolean __timeout_handler(void *data)
{
	timer = 0;
	_input_unlock();
	return FALSE;
}

static void find_keycode(struct xkb_keymap *keymap, xkb_keycode_t key,
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

static int xkb_keycode_from_keysym(struct xkb_keymap *keymap,
                                   xkb_keysym_t keysym,
                                   xkb_keycode_t **keycodes)
{
	keycode_map found_keycodes = {0,};
	found_keycodes.keysym = keysym;
	xkb_keymap_key_for_each(g_keymap, find_keycode, &found_keycodes);

	*keycodes = found_keycodes.keycodes;
	return found_keycodes.nkeycodes;
}

static void keygrab_request(struct tizen_keyrouter *tizen_keyrouter,
                            struct wl_surface *surface, uint32_t key, uint32_t mode)
{
	tizen_keyrouter_set_keygrab(tizen_keyrouter, surface, key, mode);
	_D("GOGO request set_keygrab (key:%d, mode:%d)!", key, mode);
}

static void keyungrab_request(struct tizen_keyrouter *tizen_keyrouter,
                              struct wl_surface *surface, uint32_t key)
{
	tizen_keyrouter_unset_keygrab(tizen_keyrouter, surface, key + KEYCODE_GAP);
	_D("GOGO request unset_keygrab (key:%d)!", key);
}

static void do_keygrab(const char *keyname, uint32_t mode)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		_D("%s's keycode is %d (nkeycode: %d)", keyname, keycodes[i], nkeycodes);
		keygrab_request(keyrouter, NULL, keycodes[i], mode);
	}
	free(keycodes);
	keycodes = NULL;
}

static void do_keyungrab(const char *keyname)
{
	xkb_keysym_t keysym = 0x0;
	int nkeycodes = 0;
	xkb_keycode_t *keycodes = NULL;
	int i;

	keysym = xkb_keysym_from_name(keyname, XKB_KEYSYM_NO_FLAGS);
	nkeycodes = xkb_keycode_from_keysym(g_keymap, keysym, &keycodes);

	for (i = 0; i < nkeycodes; i++) {
		_D("%s's keycode is %d (nkeycode: %d)\n", keyname, keycodes[i], nkeycodes);
		keyungrab_request(keyrouter, NULL, keycodes[i]);
	}
	free(keycodes);
	keycodes = NULL;
}

static int xkb_init(void)
{
	g_ctx = xkb_context_new(0);
	if (!g_ctx) {
		_E("Failed to get xkb_context");
		return -1;
	}

	return 0;
}

int _input_init(void)
{
	display = wl_display_connect(NULL);
	if (!display) {
		_E("Failed to connect to wayland compositor");
		return -1;
	}

	if (xkb_init() < 0)
		return -1;

	_D("Connected to wayland compositor!");

	struct wl_registry *registry = wl_display_get_registry(display);
	wl_registry_add_listener(registry, &registry_listener, NULL);

	return 0;
}

int _input_fini(void)
{
	//TODO
	return 0;
}

int _input_lock(int caller_wid)
{
	if (locked_wid > 0)
		_input_unlock();

	tizen_input_device_manager_block_events(input_devmgr, 0,
	                                        TIZEN_INPUT_DEVICE_MANAGER_CLASS_KEYBOARD |
	                                        TIZEN_INPUT_DEVICE_MANAGER_CLASS_MOUSE |
	                                        TIZEN_INPUT_DEVICE_MANAGER_CLASS_TOUCHSCREEN
	                                        , 5000);


	timer = g_timeout_add(5 * 1000, __timeout_handler, NULL);
	do_keygrab("XF86Back", TIZEN_KEYROUTER_MODE_EXCLUSIVE);
	locked_wid = caller_wid;

	return 0;
}

int _input_unlock(void)
{
	if (locked_wid <= 0)
		return 0;

	tizen_input_device_manager_unblock_events(input_devmgr, 0);
	do_keyungrab("XF86Back");
	locked_wid = 0;
	if (timer > 0) {
		g_source_remove(timer);
		timer = 0;
	}

	return 0;
}

