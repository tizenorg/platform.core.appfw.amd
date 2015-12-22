/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#pragma once

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <aul_cmd.h>

#define AUL_SOCK_PREFIX "/tmp/alaunch"
#define AUL_SOCK_MAXBUFF 65535
#define LAUNCHPAD_PID -1
#define WEB_LAUNCHPAD_PID -3
#define DEBUG_LAUNCHPAD_PID -4
#define ELOCALLAUNCH_ID 128
#define EILLEGALACCESS 127
#define ETERMINATING 126
#define ENOLAUNCHPAD 125
#define EREJECTED 123
#define UNIX_PATH_MAX 108

#define PAD_CMD_LAUNCH		0
#define PAD_CMD_VISIBILITY	10
#define PAD_CMD_ADD_LOADER	11
#define PAD_CMD_REMOVE_LOADER	12

typedef struct _app_pkt_t {
	int cmd;
	int len;
	unsigned char data[1];
} app_pkt_t;
#define AUL_PKT_HEADER_SIZE (sizeof(int) + sizeof(int))

typedef struct _pkt_t {
	uid_t caller_uid;
	app_pkt_t *pkt;
} pkt_t;

int __create_server_sock(int pid);
int __create_client_sock(int pid, uid_t uid);
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_noreply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_delay_reply(int pid, int cmd, unsigned char *kb_data, int datalen);
int __app_send_raw_with_delay_reply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __app_agent_send_raw(int uid, const char *pad_type, int cmd, unsigned char *kb_data, int datalen);
int __app_agent_send_raw_with_noreply(int uid, const char *pad_type, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr);
app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen);
app_pkt_t *__app_send_cmd_with_result_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen);
int __create_agent_client_sock(int uid, const char *pad_type);
int __create_server_sock_by_path(char *path);
int __create_sock_activation(void);


