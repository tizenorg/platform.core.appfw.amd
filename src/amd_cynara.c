/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <malloc.h>
#include <cynara-client.h>
#include <cynara-creds-socket.h>
#include <cynara-session.h>
#include <bundle.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>

#include "amd_util.h"

#define PRIVILEGE_APPMANAGER_LAUNCH "http://tizen.org/privilege/appmanager.launch"
#define PRIVILEGE_APPMANAGER_KILL "http://tizen.org/privilege/appmanager.kill"
#define PRIVILEGE_APPMANAGER_KILL_BGAPP "http://tizen.org/privilege/appmanager.kill.bgapp"
#define PRIVILEGE_DOWNLOAD "http://tizen.org/privilege/download"
#define PRIVILEGE_CALL "http://tizen.org/privilege/call"
#define PRIVILEGE_APPMANAGER_ADMIN "http://tizen.org/privilege/appmanager.admin"

static cynara *r_cynara;

static const char *__convert_cmd_to_privilege(int cmd)
{
	switch (cmd) {
	case APP_OPEN:
	case APP_RESUME:
	case APP_START:
	case APP_START_RES:
		return PRIVILEGE_APPMANAGER_LAUNCH;
	case APP_TERM_BY_PID_WITHOUT_RESTART:
	case APP_TERM_BY_PID_ASYNC:
	case APP_TERM_BY_PID:
	case APP_KILL_BY_PID:
		return PRIVILEGE_APPMANAGER_KILL;
	case APP_TERM_BGAPP_BY_PID:
		return PRIVILEGE_APPMANAGER_KILL_BGAPP;
	case APP_ALL_RUNNING_INFO:
		return PRIVILEGE_APPMANAGER_ADMIN;
	default:
		return NULL;
	}
}

static const char *__convert_operation_to_privilege(const char *operation)
{
	if (!strcmp(operation, AUL_SVC_OPERATION_DOWNLOAD))
		return PRIVILEGE_DOWNLOAD;
	else if (!strcmp(operation, AUL_SVC_OPERATION_CALL))
		return PRIVILEGE_CALL;
	else
		return NULL;
}

static int _get_caller_info_from_cynara(int sockfd, char **client, char **user, char **session)
{
	pid_t pid;
	int r;
	char buf[MAX_LOCAL_BUFSZ];

	r = cynara_creds_socket_get_pid(sockfd, &pid);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_pid failed: %s", buf);
		return -1;
	}

	*session = cynara_session_from_pid(pid);
	if (*session == NULL) {
		_E("cynara_session_from_pid failed.");
		return -1;
	}

	r = cynara_creds_socket_get_user(sockfd, USER_METHOD_DEFAULT, user);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_cred_socket_get_user failed.");
		return -1;
	}

	r = cynara_creds_socket_get_client(sockfd, CLIENT_METHOD_DEFAULT, client);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_client failed.");
		return -1;
	}

	return 0;
}

static int __check_privilege(const char *client, const char *session, const char *user, const char *privilege)
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];

	ret = cynara_check(r_cynara, client, session, user, privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		_D("%s(%s) from user %s privilege %s allowed.", client, session, user, privilege);
		ret = 0;
		break;
	case CYNARA_API_ACCESS_DENIED:
		_E("%s(%s) from user %s privilege %s denied.", client, session, user, privilege);
		ret = -1;
		break;
	default:
		cynara_strerror(ret, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_check failed: %s", buf);
		ret = -1;
		break;
	}

	return ret;
}

int check_privilege_by_cynara(int sockfd, const app_pkt_t *pkt)
{
	int r;
	int ret;
	char *client = NULL;
	char *session = NULL;
	char *user = NULL;
	bundle *kb = NULL;
	const char *privilege;
	char *operation;

	privilege = __convert_cmd_to_privilege(pkt->cmd);
	if (privilege == NULL)
		return 0;

	r = _get_caller_info_from_cynara(sockfd, &client, &user, &session);
	if (r < 0) {
		ret = -1;
		goto end;
	}

	ret = __check_privilege(client, session, user, privilege);
	if (ret < 0)
		goto end;

	if (pkt->cmd == APP_START || pkt->cmd == APP_OPEN ||
			pkt->cmd == APP_RESUME || pkt->cmd == APP_START_RES) {
		kb = bundle_decode(pkt->data, pkt->len);
		if (kb == NULL)
			goto end;
		if (bundle_get_str(kb, AUL_SVC_K_OPERATION, &operation))
			goto end;
		privilege = __convert_operation_to_privilege(operation);
		if (privilege == NULL)
			goto end;
		ret = __check_privilege(client, session, user, privilege);
	}

end:
	if (user)
		free(user);
	if (session)
		free(session);
	if (client)
		free(client);
	if (kb)
		bundle_free(kb);

	return ret;
}

int init_cynara(void)
{
	int ret;

	ret  = cynara_initialize(&r_cynara, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		_E("cynara initialize failed.");
		return ret;
	}

	return 0;
}

void finish_cynara(void)
{
	if (r_cynara)
		cynara_finish(r_cynara);
	r_cynara = NULL;
}
