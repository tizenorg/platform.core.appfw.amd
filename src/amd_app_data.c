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

#include <stdlib.h>
#include <glib.h>
#include <bundle.h>
#include <aul.h>
#include <aul_sock.h>
#include <amd_config.h>
#include <amd_util.h>
#include <amd_app_status.h>
#include <amd_request.h>
#include <amd_app_data.h>

typedef struct _app_data_t {
	int uid;
	char *pkgid;
	char *key;
	GHashTable *tbl_val;
	GHashTable *tbl_pid;
} app_data_t;

static GList *__app_data_list;

int _app_data_init()
{
	return 0;
}

static void __free_app_data(gpointer data)
{
	app_data_t *store = (app_data_t *)data;

	g_hash_table_destroy(store->tbl_pid);
	g_hash_table_destroy(store->tbl_val);
	free(store->pkgid);
	free(store->key);
	free(store);	
}

int _app_data_fini()
{
	if (__app_data_list)
		g_list_free_full(__app_data_list, __free_app_data);

	return 0;
}

int __get_store(const char *key, request_h req, app_data_t **store)
{
	//get caller appid
	app_data_t *s;
	app_status_h status;
	GList *list = __app_data_list;
	int pid = _request_get_pid(req);
	int uid = _request_get_uid(req);
	const char *pkgid = NULL;
	status = _app_status_find(pid);
	if (status)
		pkgid = _app_status_get_pkgid(status);

	while (list) {
		s = (app_data_t *)list->data;
		list = list->next;

		if (!s)
			continue;

		if (s->uid != uid)
			continue;

		if (g_strcmp0(s->key, key) != 0)
			continue;

		if (pkgid && s->pkgid && g_strcmp0(s->pkgid, pkgid) != 0) {
			*store = NULL;
			_E("illegal access on app data of %s by %d", s->pkgid, pid);
			return AUL_R_EILLACC;
		}

		*store = s;
		return 0;
	}

	*store = NULL;
	return AUL_R_ENOAPP;
}

static void __put(app_data_t *store, const char *key, const char *val, request_h req)
{
	gpointer insert_key;
	gpointer insert_val;

	insert_key = g_strdup(key);
	if (!insert_key) {
		_E("out of memory");
		return;
	}

	insert_val = g_strdup(val);
	if (!insert_val) {
		g_free(insert_key);
		_E("out of memory");
		return;
	}

	if (g_hash_table_contains(store->tbl_val, insert_key)) {
		g_hash_table_remove(store->tbl_pid, insert_key);
		g_hash_table_remove(store->tbl_val, insert_key);
	}

	g_hash_table_insert(store->tbl_val, insert_key, insert_val);
	g_hash_table_insert(store->tbl_pid, insert_key, GINT_TO_POINTER(_request_get_pid(req)));

	_D("put: %s:%s (%d)", insert_key, insert_val, _request_get_pid(req));
}

static void __get(app_data_t *store, const char *key, char **val)
{
	*val = g_hash_table_lookup(store->tbl_val, key);
}

static void __get_owner(app_data_t *store, const char *key, int *val)
{
	*val = GPOINTER_TO_INT(g_hash_table_lookup(store->tbl_pid, key));
}

static void __del(app_data_t *store, const char *key)
{
	g_hash_table_remove(store->tbl_pid, key);
	g_hash_table_remove(store->tbl_val, key);
}

struct __del_spec {
	app_data_t *store;
	int pid;
};

static gboolean __del_pid(gpointer key, gpointer val, gpointer data)
{
	struct __del_spec *spec = (struct __del_spec *)data;

	if (GPOINTER_TO_INT(val) == GPOINTER_TO_INT(spec->pid)) {
		g_hash_table_remove(spec->store->tbl_val, key);
		return TRUE;
	}

	return FALSE;
}

static void __cleanup(app_data_t *store, int pid, int uid)
{
	struct __del_spec spec;
	spec.store = store;
	spec.pid = pid;

	g_hash_table_foreach_remove(store->tbl_pid, __del_pid, &spec);
}

int _app_data_cleanup(int pid, int uid)
{
	app_data_t *store;
	GList *list = __app_data_list;

	while (list) {
		store = (app_data_t *)list->data;
		list = list->next;

		if (!store)
			continue;

		if (store->uid != uid)
			continue;

		__cleanup(store, pid, uid);
	}

	/* TODO destory app_data_t item if no more reference exists */

	return 0;
}

int _app_data_new(const char *key, request_h req)
{
	app_data_t *store;
	const char *pkgid = NULL;
	int ret;
	app_status_h status;

	ret = __get_store(key, req, &store);
	if (store == NULL && ret == AUL_R_ENOAPP) {
		store = calloc(1, sizeof(app_data_t));
		if (store == NULL) {
			_E("out of memory");
			return -1;
		}

		store->key = strdup(key);
		store->uid = _request_get_uid(req);
		status = _app_status_find(_request_get_pid(req));
		if (status)
			pkgid = _app_status_get_pkgid(status);

		if (pkgid)
			store->pkgid = strdup(pkgid);

		store->tbl_val = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		store->tbl_pid = g_hash_table_new(g_str_hash, g_str_equal);
		if (!store->key || !store->pkgid || !store->tbl_val || !store->tbl_pid) {
			_E("out of memory");
			return -1;
		}

		__app_data_list = g_list_append(__app_data_list, store);
		return 0;
	}
	
	return ret;
}

static void __to_bundle(gpointer key, gpointer value, gpointer user_data)
{
	bundle *b = (bundle *)user_data;
	bundle_add_str(b, (const char *)key, (const char *)value);
}

int _app_data_get_raw(const char *key, request_h req)
{
	app_data_t *store = NULL;
	int ret;
	int fd;
	bundle *kb;

	fd = _request_remove_fd(req);

	ret = __get_store(key, req, &store);
	if (!store || ret < 0) {
		_E("can not find appropriate data:%s", key);
		aul_sock_send_raw_with_fd(fd, ret, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	kb = bundle_create();
	if (!kb) {
		_E("out of memory");
		aul_sock_send_raw_with_fd(fd, -1, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	g_hash_table_foreach(store->tbl_val, __to_bundle, kb);

	aul_sock_send_bundle_with_fd(fd, 0, kb, AUL_SOCK_NOREPLY);

	bundle_free(kb);

	return 0;
}

static void __get_cb(const char *key, const int type, const bundle_keyval_t *kv, void *user_data)
{
	char **dest = user_data;
	if (*dest != NULL)
		return;

	*dest = (char *)key;
}

int _app_data_get(const char *key, bundle *b, request_h req)
{
	app_data_t *store;
	char *data_key = NULL;
	char *data_val = NULL;
	int fd;
	int ret;

	ret = __get_store(key, req, &store);

	if (ret < 0 || store == NULL) {
		int fd = _request_remove_fd(req);
		aul_sock_send_raw_with_fd(fd, ret, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	bundle_foreach(b, __get_cb, &data_key);
	if (data_key)
		__get(store, data_key, &data_val);

	fd = _request_remove_fd(req);

	if (data_val == NULL) {
		_E("can not find key in bundle");
		aul_sock_send_raw_with_fd(fd, -1, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	aul_sock_send_raw_with_fd(fd, 0, (unsigned char *)data_val, strlen(data_val) + 1,
			AUL_SOCK_NOREPLY); /* send trailing '\0' */

	return 0;
}

int _app_data_get_owner(const char *key, bundle *b, request_h req)
{
	app_data_t *store;
	char *data_key = NULL;
	int data_val = 0;
	int fd;
	int ret;

	ret = __get_store(key, req, &store);

	if (ret < 0 || store == NULL) {
		int fd = _request_remove_fd(req);
		aul_sock_send_raw_with_fd(fd, ret, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	bundle_foreach(b, __get_cb, &data_key);
	if (data_key)
		__get_owner(store, data_key, &data_val);

	fd = _request_remove_fd(req);

	if (data_val == 0) {
		_E("can not find key in bundle");
		aul_sock_send_raw_with_fd(fd, -1, NULL, 0, AUL_SOCK_NOREPLY);
		return -1;
	}

	_D("found onwer of %s : %d", data_key, data_val);

	aul_sock_send_raw_with_fd(fd, 0, (unsigned char *)&data_val, sizeof(int),
			AUL_SOCK_NOREPLY);

	return 0;
}


static void __del_cb(const char *key, const int type, const bundle_keyval_t *kv, void *user_data)
{
	app_data_t *store = (app_data_t *)user_data;
	__del(store, key);
}

int _app_data_del(const char *key, bundle *b, request_h req)
{
	app_data_t *store;
	int ret;

	ret = __get_store(key, req, &store);
	if (ret < 0 || store == NULL)
		return ret;

	if (b && store) {
		bundle_foreach(b, __del_cb, store);
	} else {
		_E("can not find appropriate data");
		return -1;
	}

	return 0;
}

struct __app_data_req {
	app_data_t *store;
	request_h req;
};

static void __put_cb(const char *key, const int type,
				const bundle_keyval_t *kv, void *user_data)
{
	void *val = NULL;
	size_t val_size = 0;
	struct __app_data_req *store_req = (struct __app_data_req *)user_data;

	bundle_keyval_get_basic_val((bundle_keyval_t *)kv, &val, &val_size);
	__put(store_req->store, key, (const char *)val, store_req->req);
	_D("app data put: %s: %s", key, val); 
}

int _app_data_put(const char *key, bundle *b, request_h req)
{
	app_data_t *store;
	struct __app_data_req store_req;
	int ret;

	ret = __get_store(key, req, &store);
	if (ret < 0 || store == NULL) {
		_E("can not find store: %d", ret);
		return ret;
	}

	_D("bundle size: %d", bundle_get_count(b));

	if (b && store) {
		store_req.store = store;
		store_req.req = req;
		bundle_foreach(b, __put_cb, &store_req);
	} else {
		_E("can not find appropriate data");
		return -1;
	}

	return 0;
}

