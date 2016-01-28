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
#define PRIVILEGE_APPMANAGER_ADMIN "http://tizen.org/privilege/packagemanager.info"

static cynara *r_cynara;

struct caller_info {
	char *user;
	char *client;
	char *session;
};

typedef int (*checker_func)(struct caller_info *info, const app_pkt_t *pkt, void *data);

struct checker_info {
	int cmd;
	checker_func checker;
	void *data;
};

static const char *__convert_operation_to_privilege(const char *operation)
{
	if (!strcmp(operation, AUL_SVC_OPERATION_DOWNLOAD))
		return PRIVILEGE_DOWNLOAD;
	else if (!strcmp(operation, AUL_SVC_OPERATION_CALL))
		return PRIVILEGE_CALL;
	else
		return NULL;
}

static void __destroy_caller_info(struct caller_info *info)
{
	if (info) {
		if (info->client)
			free(info->client);

		if (info->session)
			free(info->session);

		if (info->user)
			free(info->user);
	}
}

static int __get_caller_info_from_cynara(int sockfd, struct caller_info *info)
{
	pid_t pid;
	int r;
	char buf[MAX_LOCAL_BUFSZ];

	if (info == NULL)
		return -1;

	r = cynara_creds_socket_get_pid(sockfd, &pid);
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_pid failed: %s", buf);
		return -1;
	}

	info->session = cynara_session_from_pid(pid);
	if (info->session == NULL) {
		_E("cynara_session_from_pid failed.");
		return -1;
	}

	r = cynara_creds_socket_get_user(sockfd, USER_METHOD_DEFAULT, &(info->user));
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_cred_socket_get_user failed.");
		return -1;
	}

	r = cynara_creds_socket_get_client(sockfd, CLIENT_METHOD_DEFAULT, &(info->client));
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_creds_socket_get_client failed.");
		return -1;
	}

	return 0;
}

static int __check_privilege(struct caller_info *info, const char *privilege)
{
	int ret;
	char buf[MAX_LOCAL_BUFSZ];

	ret = cynara_check(r_cynara, info->client, info->session, info->user, privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		_D("%s(%s) from user %s privilege %s allowed.", info->client, info->session, info->user, privilege);
		ret = 0;
		break;
	case CYNARA_API_ACCESS_DENIED:
		_E("%s(%s) from user %s privilege %s denied.", info->client, info->session, info->user, privilege);
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

static int __simple_checker(struct caller_info *info, const app_pkt_t *pkt, void *data)
{
	return __check_privilege(info, (const char *)data);
}

static int __appcontrol_checker(struct caller_info *info, const app_pkt_t *pkt, void *data)
{
	bundle *appcontrol;
	const char *op_priv;
	char *op;
	int ret;

	ret = __check_privilege(info, PRIVILEGE_APPMANAGER_LAUNCH);

	if (ret < 0)
		return ret;

	appcontrol = bundle_decode(pkt->data, pkt->len);
	if (appcontrol == NULL)
		goto end;

	bundle_get_str(appcontrol, AUL_SVC_K_OPERATION, &op);
	if (op == NULL)
		goto end;

	op_priv = __convert_operation_to_privilege(op);
	if (op_priv == NULL)
		goto end;

	ret = __check_privilege(info, op_priv);

end:
	if (appcontrol)
		bundle_free(appcontrol);

	return ret;
}

static struct checker_info checker_table[] = {
	{APP_OPEN, __appcontrol_checker, NULL},
	{APP_RESUME, __appcontrol_checker, NULL},
	{APP_START, __appcontrol_checker, NULL},
	{APP_START_RES, __appcontrol_checker, NULL},
	{APP_TERM_BY_PID_WITHOUT_RESTART, __simple_checker, PRIVILEGE_APPMANAGER_KILL},
	{APP_TERM_BY_PID_ASYNC, __simple_checker, PRIVILEGE_APPMANAGER_KILL},
	{APP_TERM_BY_PID, __simple_checker, PRIVILEGE_APPMANAGER_KILL},
	{APP_KILL_BY_PID, __simple_checker, PRIVILEGE_APPMANAGER_KILL},
	{APP_TERM_BGAPP_BY_PID, __simple_checker, PRIVILEGE_APPMANAGER_KILL_BGAPP},
	{APP_ALL_RUNNING_INFO, __simple_checker, PRIVILEGE_APPMANAGER_ADMIN},
};

static int checker_len = sizeof(checker_table) / sizeof(struct checker_info);

static int __check_privilege_by_checker(int cmd, struct caller_info *info, const app_pkt_t *pkt)
{
	int i = 0;

	for (i = 0; i < checker_len; i++) {
		if (checker_table[i].cmd == cmd)
			return checker_table[i].checker(info, pkt, checker_table[i].data);
	}

	return 0;
}

static int __check_command(int cmd)
{
	int i = 0;

	for (i = 0; i < checker_len; i++) {
		if (checker_table[i].cmd == cmd)
			return 1;
	}

	return 0;
}

int check_privilege_by_cynara(int sockfd, const app_pkt_t *pkt)
{
	int r;
	struct caller_info info = {NULL, NULL, NULL};

	if (!__check_command(pkt->cmd))
		return 0;

	r = __get_caller_info_from_cynara(sockfd, &info);
	if (r < 0) {
		_E("failed to get caller info");
		__destroy_caller_info(&info);
		return -1;
	}

	r = __check_privilege_by_checker(pkt->cmd, &info, pkt);

	__destroy_caller_info(&info);

	return r;
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
