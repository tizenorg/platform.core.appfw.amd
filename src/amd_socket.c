/*
 * Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>

#include <bundle.h>
#include <systemd/sd-daemon.h>
#include <aul_sock.h>

#include "amd_util.h"

int _create_sock_activation(void)
{
	int fds;
	char sock_path[PATH_MAX];

	fds = sd_listen_fds(0);
	if (fds == 1) {
		snprintf(sock_path, sizeof(sock_path),
				"/run/aul/daemons/%d/.amd-sock", getuid());
		if (chmod(sock_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0)
			_E("change mode error: %d", errno);
		return SD_LISTEN_FDS_START;
	}

	if (fds > 1)
		_E("Too many file descriptors received.\n");
	else
		_D("There is no socket stream");

	return -1;
}

static inline void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };  /* 5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int _create_server_sock(void)
{
	int fd;
	struct sockaddr_un addr;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) {
		_E("create socket error: %d", errno);
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
			"/run/aul/daemons/%d/.amd-sock", getuid());
	unlink(addr.sun_path);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr))) {
		_E("bind error: %d", errno);
		close(fd);
		return -1;
	}

	if (chmod(addr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		_E("change mode error: %d", errno);
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error: %d", errno);
		close(fd);
		return -1;
	}

	return fd;
}

static int __connect_client_sock(int fd, const struct sockaddr *saptr,
		socklen_t salen, int nsec)
{
	int flags;
	int ret;
	int error;
	socklen_t len;
	fd_set readfds;
	fd_set writefds;
	struct timeval timeout;

	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	error = 0;
	ret = connect(fd, (struct sockaddr *)saptr, salen);
	if (ret < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			fcntl(fd, F_SETFL, flags);
			return -2;
		}
	}

	/* Do whatever we want while the connect is taking place. */
	if (ret == 0)
		goto done;	/* connect completed immediately */

	FD_ZERO(&readfds);
	FD_SET(fd, &readfds);
	writefds = readfds;
	timeout.tv_sec = 0;
	timeout.tv_usec = nsec;

	ret = select(fd + 1, &readfds, &writefds, NULL,
		     nsec ? &timeout : NULL);
	if (ret == 0) {
		close(fd);	/* timeout */
		errno = ETIMEDOUT;
		return -1;
	}

	if (FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds)) {
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return -1;	/* Solaris pending error */
	} else {
		return -1;	/* select error: sockfd not set*/
	}

done:
	(void)fcntl(fd, F_SETFL, flags);
	if (error) {
		close(fd);
		errno = error;
		return -1;
	}

	return 0;
}

static int __create_launchpad_client_sock(const char *pad_type, uid_t uid)
{
	int fd = -1;
	struct sockaddr_un saddr = { 0, };
	int retry = 1;
	int ret = -1;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	/*  support above version 2.6.27*/
	if (fd < 0) {
		if (errno == EINVAL) {
			fd = socket(AF_UNIX, SOCK_STREAM, 0);
			if (fd < 0) {
				_E("second chance - socket create error");
				return -1;
			}
		} else {
			_E("socket error");
			return -1;
		}
	}

	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, sizeof(saddr.sun_path),
			"/run/aul/daemons/%d/%s", uid, pad_type);
 retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr,
			sizeof(saddr), 100 * 1000);
	if (ret < -1) {
		_E("maybe peer not launched or peer daed\n");
		if (retry > 0) {
			usleep(100 * 1000);
			retry--;
			goto retry_con;
		}
	}
	if (ret < 0) {
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 1);

	return fd;
}

int _send_cmd_to_launchpad(const char *pad_type, uid_t uid, int cmd, bundle *kb)
{
	int fd;
	int len;
	int res;
	char err_buf[1024];

	fd = __create_launchpad_client_sock(pad_type, uid);
	if (fd < 0)
		return -1;

	res = aul_sock_send_bundle_with_fd(fd, cmd, kb, AUL_SOCK_ASYNC);
	if (res < 0) {
		close(fd);
		return res;
	}

retry_recv:
	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			res = -EAGAIN;
		} else if (errno == EINTR) {
			_D("recv : %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			goto retry_recv;
		} else {
			_E("recv error : %s",
				strerror_r(errno, err_buf, sizeof(err_buf)));
			res = -ECOMM;
		}
	}

	close(fd);

	return res;
}

void _send_result_to_client(int fd, int res)
{
	if (fd < 3)
		return;

	if (send(fd, &res, sizeof(int), MSG_NOSIGNAL) < 0) {
		if (errno == EPIPE)
			_E("send failed due to EPIPE.");
		_E("send fail to client");
	}

	close(fd);
}

