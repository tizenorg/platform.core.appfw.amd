/*
 * Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <systemd/sd-daemon.h>

#include "app_sock.h"
#include "simple_util.h"

#define MAX_NR_OF_DESCRIPTORS 2

static int __connect_client_sock(int sockfd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec);


static inline void __set_sock_option(int fd, int cli)
{
	int size;
	struct timeval tv = { 5, 200 * 1000 };	/* 5.2 sec */

	size = AUL_SOCK_MAXBUFF;
	setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
	setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	if (cli)
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int __create_server_sock(int pid)
{
	struct sockaddr_un saddr;
	struct sockaddr_un p_saddr;
	int fd;

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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "/run/user/%d/%d", getuid(), pid);
	unlink(saddr.sun_path);

	/* labeling to socket for SMACK */
	if (getuid() == 0) {	/* this is meaningful iff current user is ROOT */
		if (fsetxattr(fd, "security.SMACK64IPOUT", "@", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPOUT) error");
				close(fd);
				return -1;
			}
		}
		if (fsetxattr(fd, "security.SMACK64IPIN", "*", 1, 0) < 0) {
			/* in case of unsupported filesystem on 'socket' */
			/* or permission error by using 'emulator', bypass*/
			if ((errno != EOPNOTSUPP) && (errno != EPERM)) {
				_E("labeling to socket(IPIN) error");
				close(fd);
				return -1;
			}
		}
	}

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore*/
		_E("failed to change the socket permission");
		close(fd);
		return -1;
	}

	__set_sock_option(fd, 0);

	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}

	/* support app launched by shell script */
	if (pid != LAUNCHPAD_PID) {
		int pgid;
		pgid = getpgid(pid);
		if (pgid > 1) {
			snprintf(p_saddr.sun_path, UNIX_PATH_MAX, "/run/user/%d/%d",
				 getuid(), pgid);
			if (link(saddr.sun_path, p_saddr.sun_path) < 0) {
				if (errno == EEXIST)
					_D("pg path - already exists");
				else
					_E("pg path - unknown create error");
			}
		}
	}

	return fd;
}


int __create_server_sock_by_path(char *path)
{
	struct sockaddr_un saddr;
	int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
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

	memset(&saddr, 0, sizeof(saddr));
	saddr.sun_family = AF_UNIX;
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "%s", path);
	unlink(saddr.sun_path);

	if (bind(fd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
		_E("bind error");
		close(fd);
		return -1;
	}

	if (chmod(saddr.sun_path, (S_IRWXU | S_IRWXG | S_IRWXO)) < 0) {
		/* Flawfinder: ignore*/
		_E("failed to change the socket permission");
		close(fd);
		return -1;
	}
	__set_sock_option(fd, 0);
	if (listen(fd, 128) == -1) {
		_E("listen error");
		close(fd);
		return -1;
	}
	return fd;
}

int __create_sock_activation(void)
{
	int fds;

	fds = sd_listen_fds(0);
	if (fds == 1)
		return SD_LISTEN_FDS_START;

	if (fds > 1)
		_E("Too many file descriptors received.\n");
	else
		_D("There is no socket stream");

	return -1;
}

int __create_agent_client_sock(int uid, const char *pad_type)
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
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "/run/user/%d/%s", uid, pad_type);
 retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr, sizeof(saddr),
			100 * 1000);
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


int __create_client_sock(int pid, uid_t uid)
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
	snprintf(saddr.sun_path, UNIX_PATH_MAX, "/run/user/%d/%d", uid, pid);
 retry_con:
	ret = __connect_client_sock(fd, (struct sockaddr *)&saddr, sizeof(saddr),
			100 * 1000);
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

static int __connect_client_sock(int fd, const struct sockaddr *saptr, socklen_t salen,
		   int nsec)
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
	if ((ret = connect(fd, (struct sockaddr *)saptr, salen)) < 0) {
		if (errno != EAGAIN && errno != EINPROGRESS) {
			fcntl(fd, F_SETFL, flags);
			return (-2);
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

	if ((ret = select(fd + 1, &readfds, &writefds, NULL,
			nsec ? &timeout : NULL)) == 0) {
		close(fd);	/* timeout */
		errno = ETIMEDOUT;
		return (-1);
	}

	if (FD_ISSET(fd, &readfds) || FD_ISSET(fd, &writefds)) {
		len = sizeof(error);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
			return (-1);	/* Solaris pending error */
	} else
		return (-1);	/* select error: sockfd not set*/

 done:
	(void) fcntl(fd, F_SETFL, flags);
	if (error) {
		close(fd);
		errno = error;
		return (-1);
	}
	return (0);
}

/**
 * @brief	Send data (in raw) to the process with 'pid' via socket
 */
int __app_send_raw(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	return __app_send_raw_for_uid(pid, getuid(), cmd, kb_data, datalen);
}

int __app_send_raw_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error pid:%d, fd:%d (errno %d)", pid, fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);

retry_recv:
	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else if (errno == EINTR) {
			_D("recv : %s", strerror(errno));
			goto retry_recv;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}
	close(fd);

	return res;
}

int __app_agent_send_raw(int uid, const char *pad_type,
		int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("uid(%d) : cmd(%d)", uid, cmd);

	fd = __create_agent_client_sock(uid, pad_type);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error uid:%d, fd:%d (errno %d)", uid, fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);

retry_recv:
	len = recv(fd, &res, sizeof(int), 0);
	if (len == -1) {
		if (errno == EAGAIN) {
			_E("recv timeout : %s", strerror(errno));
			res = -EAGAIN;
		} else if (errno == EINTR) {
			_D("recv : %s", strerror(errno));
			goto retry_recv;
		} else {
			_E("recv error : %s", strerror(errno));
			res = -ECOMM;
		}
	}
	close(fd);

	return res;
}


int __app_agent_send_raw_with_noreply(int uid, const char *pad_type,
		int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("uid(%d) : cmd(%d)", uid, cmd);

	fd = __create_agent_client_sock(uid, pad_type);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error uid:%d, fd:%d (errno %d)", uid, fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);
	close(fd);

	return res;
}

int __app_send_raw_with_noreply(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	return __app_send_raw_with_noreply_for_uid(pid, getuid(), cmd, kb_data, datalen);
}

int __app_send_raw_with_noreply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int sent = 0;
	int res = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error pid:%d, fd:%d (errno %d)", pid, fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);
	close(fd);

	return res;
}

int __app_send_raw_with_delay_reply(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	return __app_send_raw_with_delay_reply_for_uid(pid, getuid(), cmd, kb_data, datalen);
}

int __app_send_raw_with_delay_reply_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int sent = 0;
	app_pkt_t *pkt = NULL;

	if (kb_data == NULL) {
		_E("keybundle error\n");
		return -EINVAL;
	}

	_D("pid(%d) : cmd(%d)", pid, cmd);

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return -ECOMM;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return -ENOMEM;
	}

	pkt->cmd = cmd;
	pkt->len = datalen;
	memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error pid:%d, fd:%d (errno %d)", pid, fd, errno);
			close(fd);
			free(pkt);
			return -ECOMM;
		}
		sent += len;
	}

	free(pkt);

	return fd;
}

app_pkt_t *__app_recv_raw(int fd, int *clifd, struct ucred *cr)
{
	int len;
	int ret;
	struct sockaddr_un aul_addr = { 0, };
	int sun_size;
	app_pkt_t *pkt = NULL;
	int cl = sizeof(struct ucred);
	unsigned char buf[AUL_SOCK_MAXBUFF];
	int cmd;
	int datalen;

	sun_size = sizeof(struct sockaddr_un);

	if ((*clifd = accept(fd, (struct sockaddr *)&aul_addr,
			     (socklen_t *) &sun_size)) == -1) {
		if (errno != EINTR)
			_E("accept error");
		return NULL;
	}

	if (getsockopt(*clifd, SOL_SOCKET, SO_PEERCRED, cr,
		       (socklen_t *) &cl) < 0) {
		_E("peer information error");
		close(*clifd);
		return NULL;
	}

	__set_sock_option(*clifd, 1);

 retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(*clifd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(*clifd);
		return NULL;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&datalen, buf + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + datalen + 1);
	if (pkt == NULL) {
		close(*clifd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;

	len = 0;
	while (len != pkt->len) {
		ret = recv(*clifd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			_E("recv error %d %d", len, pkt->len);
			free(pkt);
			close(*clifd);
			return NULL;
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}

	return pkt;
}

app_pkt_t *__app_send_cmd_with_result(int pid, int cmd, unsigned char *kb_data, int datalen)
{
	return (app_pkt_t *)__app_send_cmd_with_result_for_uid(pid, getuid(), cmd, kb_data, datalen);
}

app_pkt_t *__app_send_cmd_with_result_for_uid(int pid, uid_t uid, int cmd, unsigned char *kb_data, int datalen)
{
	int fd;
	int len;
	int ret;
	int sent = 0;
	app_pkt_t *pkt = NULL;
	unsigned char buf[AUL_SOCK_MAXBUFF];

	fd = __create_client_sock(pid, uid);
	if (fd < 0)
		return NULL;

	pkt = (app_pkt_t *)malloc(AUL_PKT_HEADER_SIZE + datalen);
	if (NULL == pkt) {
		_E("Malloc Failed!");
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = datalen;
	if (kb_data)
		memcpy(pkt->data, kb_data, pkt->len);

	while (sent != AUL_PKT_HEADER_SIZE + pkt->len) {
		len = send(fd, pkt, AUL_PKT_HEADER_SIZE + pkt->len - sent, 0);
		if (len <= 0) {
			_E("send error pid:%d, fd:%d (errno %d)", pid, fd, errno);
			close(fd);
			free(pkt);
			return NULL;
		}
		sent += len;
	}
	free(pkt);

retry_recv:
	/* receive header(cmd, datalen) */
	len = recv(fd, buf, AUL_PKT_HEADER_SIZE, 0);
	if (len < 0)
		if (errno == EINTR)
			goto retry_recv;

	if (len < AUL_PKT_HEADER_SIZE) {
		_E("recv error");
		close(fd);
		return NULL;
	}
	memcpy(&cmd, buf, sizeof(int));
	memcpy(&len, buf + sizeof(int), sizeof(int));

	/* allocate for a null byte */
	pkt = (app_pkt_t *)calloc(1, AUL_PKT_HEADER_SIZE + len + 1);
	if (pkt == NULL) {
		close(fd);
		return NULL;
	}
	pkt->cmd = cmd;
	pkt->len = len;

	len = 0;
	while (len != pkt->len) {
		ret = recv(fd, pkt->data + len, pkt->len - len, 0);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				_E("recv error %s\n", strerror(errno));
				free(pkt);
				close(fd);
				return NULL;
			}
		}
		len += ret;
		_D("recv len %d %d", len, pkt->len);
	}
	close(fd);

	return pkt;
}
