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
#include <malloc.h>

#include <cynara-client.h>
#include <cynara-creds-socket.h>
#include <cynara-session.h>
#include <bundle.h>
#include <aul_sock.h>
#include <aul_svc.h>
#include <aul_svc_priv_key.h>
#include <amd_app_com.h>
#include <amd_request.h>
#include <amd_appinfo.h>
#include <aul.h>

#include "amd_config.h"
#include "amd_util.h"

#define REGULAR_UID_MIN     5000

#define PRIVILEGE_WIDGET_VIEWER \
	"http://tizen.org/privilege/widget.viewer"
#define PRIVILEGE_APPMANAGER_LAUNCH \
	"http://tizen.org/privilege/appmanager.launch"
#define PRIVILEGE_APPMANAGER_KILL \
	"http://tizen.org/privilege/appmanager.kill"
#define PRIVILEGE_APPMANAGER_KILL_BGAPP \
	"http://tizen.org/privilege/appmanager.kill.bgapp"
#define PRIVILEGE_DOWNLOAD \
	"http://tizen.org/privilege/download"
#define PRIVILEGE_CALL \
	"http://tizen.org/privilege/call"
#define PRIVILEGE_SYSTEM_SETTING \
	"http://tizen.org/privilege/systemsettings.admin"
#define PRIVILEGE_PLATFORM \
	"http://tizen.org/privilege/internal/default/platform"

static cynara *r_cynara;

struct caller_info {
	char *user;
	char *client;
	char *session;
};

typedef int (*checker_func)(struct caller_info *info, request_h req,
		void *data);

struct checker_info {
	int cmd;
	checker_func checker;
	void *data;
};

static const char *__convert_operation_to_privilege(const char *operation)
{
	if (operation == NULL)
		return NULL;
	else if (!strcmp(operation, AUL_SVC_OPERATION_DOWNLOAD))
		return PRIVILEGE_DOWNLOAD;
	else if (!strcmp(operation, AUL_SVC_OPERATION_CALL))
		return PRIVILEGE_CALL;
	else if (!strcmp(operation, AUL_SVC_OPERATION_LAUNCH_WIDGET))
		return PRIVILEGE_WIDGET_VIEWER;

	return NULL;
}

static void __destroy_caller_info(struct caller_info *info)
{
	if (info == NULL)
		return;

	if (info->client)
		free(info->client);

	if (info->session)
		free(info->session);

	if (info->user)
		free(info->user);
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

	r = cynara_creds_socket_get_user(sockfd, USER_METHOD_DEFAULT,
			&(info->user));
	if (r != CYNARA_API_SUCCESS) {
		cynara_strerror(r, buf, MAX_LOCAL_BUFSZ);
		_E("cynara_cred_socket_get_user failed.");
		return -1;
	}

	r = cynara_creds_socket_get_client(sockfd, CLIENT_METHOD_DEFAULT,
			&(info->client));
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

	ret = cynara_check(r_cynara, info->client, info->session, info->user,
			privilege);
	switch (ret) {
	case CYNARA_API_ACCESS_ALLOWED:
		_D("%s(%s) from user %s privilege %s allowed.", info->client,
				info->session, info->user, privilege);
		ret = 0;
		break;
	case CYNARA_API_ACCESS_DENIED:
		_E("%s(%s) from user %s privilege %s denied.", info->client,
				info->session, info->user, privilege);
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

static int __simple_checker(struct caller_info *info, request_h req, void *data)
{
	return __check_privilege(info, (const char *)data);
}

static int __widget_viewer_checker(struct caller_info *info, request_h req,
		void *data)
{
	char *appid = NULL;
	const char *apptype;
	struct appinfo *appinfo;
	bundle *appcontrol = _request_get_bundle(req);

	if (!appcontrol) {
		_E("wrong argument");
		return -1;
	}

	bundle_get_str(appcontrol, AUL_K_APPID, &appid);
	if (!appid) {
		_E("can not resolve appid. request denied.");
		return -1;
	}

	appinfo = _appinfo_find(_request_get_target_uid(req), appid);
	if (!appinfo) {
		_E("can not resolve appinfo of %s. request denied.", appid);
		return -1;
	}

	apptype = _appinfo_get_value(appinfo, AIT_COMPTYPE);
	if (!apptype) {
		_E("can not resolve apptype of %s. request denied.", appid);
		return -1;
	}

	if (!strcmp(apptype, APP_TYPE_WIDGET) ||
			!strcmp(apptype, APP_TYPE_WATCH))
		return __check_privilege(info, PRIVILEGE_WIDGET_VIEWER);

	_E("illegal app type of request: %s - " \
			"only widget or watch apps are allowed", apptype);

	return -1;
}

static int __appcontrol_checker(struct caller_info *info, request_h req,
		void *data)
{
	bundle *appcontrol;
	const char *op_priv = NULL;
	char *op = NULL;
	int ret;

	appcontrol = _request_get_bundle(req);
	if (appcontrol == NULL)
		return 0;

	ret = bundle_get_str(appcontrol, AUL_SVC_K_OPERATION, &op);
	if (ret == BUNDLE_ERROR_NONE)
		op_priv = __convert_operation_to_privilege(op);

	if (op_priv) {
		if (!strcmp(op_priv, PRIVILEGE_WIDGET_VIEWER))
			return __widget_viewer_checker(info, req, data);

		ret = __check_privilege(info, op_priv);
		if (ret < 0)
			return ret;
	}

	ret = __check_privilege(info, PRIVILEGE_APPMANAGER_LAUNCH);

	return ret;
}

static int __com_create_checker(struct caller_info *info, request_h req,
		void *data)
{
	char *privilege = NULL;
	bundle *kb = _request_get_bundle(req);

	bundle_get_str(kb, AUL_K_COM_PRIVILEGE, &privilege);
	if (!privilege)
		return 0; /* non-privileged */

	return __check_privilege(info, privilege);
}

static int __com_join_checker(struct caller_info *info, request_h req,
		void *data)
{
	char *endpoint = NULL;
	const char *privilege;
	bundle *kb = _request_get_bundle(req);

	bundle_get_str(kb, AUL_K_COM_ENDPOINT, &endpoint);
	if (!endpoint)
		return -1;

	privilege = _app_com_get_privilege(endpoint);
	if (!privilege)
		return 0; /* non-privileged */

	return __check_privilege(info, privilege);
}

static struct checker_info checker_table[] = {
	{
		.cmd = APP_OPEN,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_RESUME,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_START,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_START_RES,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_TERM_BY_PID_WITHOUT_RESTART,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BY_PID_ASYNC,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BY_PID,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_KILL_BY_PID,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_TERM_BGAPP_BY_PID,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL_BGAPP
	},
	{
		.cmd = APP_COM_JOIN,
		.checker = __com_create_checker,
		.data = NULL
	},
	{
		.cmd = APP_COM_CREATE,
		.checker = __com_join_checker,
		.data = NULL
	},
	{
		.cmd = APP_SET_APP_CONTROL_DEFAULT_APP,
		.checker = __simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_UNSET_APP_CONTROL_DEFAULT_APP,
		.checker = __simple_checker,
		.data = PRIVILEGE_SYSTEM_SETTING
	},
	{
		.cmd = APP_START_ASYNC,
		.checker = __appcontrol_checker,
		.data = NULL
	},
	{
		.cmd = APP_TERM_BY_PID_SYNC,
		.checker = __simple_checker,
		.data = PRIVILEGE_APPMANAGER_KILL
	},
	{
		.cmd = APP_UPDATE_RUA_STAT,
		.checker = __simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_ADD_HISTORY,
		.checker = __simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
	{
		.cmd = APP_REMOVE_HISTORY,
		.checker = __simple_checker,
		.data = PRIVILEGE_PLATFORM
	},
};

static int checker_len = sizeof(checker_table) / sizeof(struct checker_info);

static int __check_privilege_by_checker(request_h req, struct caller_info *info)
{
	int i;
	int ret;

	for (i = 0; i < checker_len; i++) {
		if (checker_table[i].cmd == _request_get_cmd(req)) {
			ret = checker_table[i].checker(info, req,
					checker_table[i].data);
			return ret;
		}
	}

	return 0;
}

static int __check_command(int cmd)
{
	int i;

	for (i = 0; i < checker_len; i++) {
		if (checker_table[i].cmd == cmd)
			return 1;
	}

	return 0;
}

int _cynara_check_privilege(request_h req)
{
	int r;
	struct caller_info info = {NULL, NULL, NULL};

	if (!__check_command(_request_get_cmd(req)))
		return 0;

	r = __get_caller_info_from_cynara(_request_get_fd(req), &info);
	if (r < 0) {
		_E("Failed to get caller info");
		__destroy_caller_info(&info);
		return -1;
	}

	r = __check_privilege_by_checker(req, &info);

	__destroy_caller_info(&info);

	return r;
}

int _cynara_init(void)
{
	int ret;

	ret = cynara_initialize(&r_cynara, NULL);
	if (ret != CYNARA_API_SUCCESS) {
		_E("cynara initialize failed.");
		return ret;
	}

	return 0;
}

void _cynara_finish(void)
{
	if (r_cynara == NULL)
		return;

	cynara_finish(r_cynara);
	r_cynara = NULL;
}

