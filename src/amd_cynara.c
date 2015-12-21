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

#include "simple_util.h"

static cynara *r_cynara = NULL;

static int _get_caller_info_from_cynara(int sockfd, char **client, char **user, char **session)
{
	pid_t pid;
	int r;
	char buf[MAX_LOCAL_BUFSZ] = {0,};

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

int check_privilege_by_cynara(int sockfd, const char *privilege)
{
	int r;
	int ret;
	char buf[MAX_LOCAL_BUFSZ] = {0,};
	char *client = NULL;
	char *session = NULL;
	char *user = NULL;

	r = _get_caller_info_from_cynara(sockfd, &client, &user, &session);
	if (r < 0) {
		ret = -1;
		goto end;
	}

	r = cynara_check(r_cynara, client, session, user, privilege);
	switch (r) {
	case CYNARA_API_ACCESS_ALLOWED:
		_D("%s(%s) from user %s privilege %s allowed.", client, session, user, privilege);
		ret = 0;
		break;
	case CYNARA_API_ACCESS_DENIED:
		_E("%s(%s) from user %s privilege %s denied.", client, session, user, privilege);
		ret = -1;
		break;
	default:
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_check failed: %s", buf);
		ret = -1;
		break;
	}

end:
	if (user)
		free(user);
	if (session)
		free(session);
	if (client)
		free(client);

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
