/**
 * Copyright (C) 2016 - ARM Ltd
 *
 * Heavily inspired from from kvmtool/kvm-ipc.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <linux/list.h>

#define LOG_PREFIX "serv: "

#include "smmute-ipc.h"
#include "smmute-lib.h"
#include "smmute-vfio.h"

enum loglevel loglevel = LOG_INFO;

struct program_options {
	enum smmute_backend		backend;
	char				*device;
	bool				unified;
	struct smmute_mem_options	mem;
};

struct smmute_dma_buf {
	struct list_head		list;
	dma_addr_t			iova;
	void				*va;
	size_t				size;
};

struct smmute_dma_buffers {
	struct list_head		list;
	pthread_mutex_t			lock;
};

struct server {
	struct sockaddr_un		name;
	int				sock;
	int				epoll;

	/* Keep track of the va-iova mappings requested by clients */
	struct smmute_dma_buffers	bufs;
	struct smmute_dev		dev;

	struct program_options		*opts;
};

static int server_stop;

static void smmute_server_stop(int signr)
{
	u64 val = 1;

	if (write(server_stop, &val, 8) != 8)
		perror("Unable to stop server");
}

static int smmute_server_map(struct server *serv, int sock,
			     struct smmute_ipc_map *map,
			     struct smmute_ipc_map_resp *resp)
{
	int fd;
	int ret = 0;
	struct smmute_dma_buf *buf;

	resp->hdr.size = sizeof(*resp);

	buf = malloc(sizeof(*buf));
	if (!buf)
		return ENOMEM;

	fd = shm_open(map->shm_name, O_RDWR, 0);
	if (fd < 0) {
		free(buf);
		return errno;
	}

	map->prot &= PROT_READ | PROT_WRITE;

	buf->size = map->size;
	buf->va = mmap(NULL, map->size, map->prot, MAP_SHARED, fd, map->shm_offset);
	if (buf->va == MAP_FAILED) {
		ret = errno;
		free(buf);
		goto out_close_fd;
	}

	/* If the address space is unified, backend should return the iova */
	ret = smmute_dma_map_buffer(&serv->dev, buf->va, &buf->iova, map->size,
				    map->prot, &serv->opts->mem);
	if (ret) {
		munmap(buf->va, map->size);
		free(buf);
	} else {
		resp->iova = buf->iova;
		pthread_mutex_lock(&serv->bufs.lock);
		list_add(&buf->list, &serv->bufs.list);
		pthread_mutex_unlock(&serv->bufs.lock);
	}

out_close_fd:
	/* Doesn't affect the memory mapping */
	close(fd);

	return ret;
}

static int smmute_server_unmap(struct server *serv, int sock,
			       struct smmute_ipc_unmap *unmap,
			       struct smmute_ipc_unmap_resp *resp)
{
	int ret;
	struct smmute_dma_buf *tmp, *buf = NULL;

	resp->hdr.size = sizeof(*resp);

	pthread_mutex_lock(&serv->bufs.lock);
	list_for_each_entry(tmp, &serv->bufs.list, list) {
		if (tmp->iova == unmap->iova) {
			buf = tmp;
			break;
		}
	}
	pthread_mutex_unlock(&serv->bufs.lock);
	if (!buf)
		return ESRCH;

	if (buf->size != unmap->size) {
		ret = EINVAL;
		goto out_free_buf;
	}

	ret = smmute_dma_unmap_buffer(&serv->dev, (void *)buf->va, buf->iova,
				      buf->size, &serv->opts->mem);
	if (ret)
		pr_warn("DMA unmap failed... but we'll still try to free the buffer");

	/*
	 * We assume for the moment that all clients are well-behaved, and won't
	 * try to unmap stuff they don't own.
	 */
	ret = munmap((void *)buf->va, buf->size);
	if (ret)
		ret = errno;

out_free_buf:
	pthread_mutex_lock(&serv->bufs.lock);
	list_del(&buf->list);
	pthread_mutex_unlock(&serv->bufs.lock);
	free(buf);

	return ret;
}

static int smmute_server_launch(struct server *serv, int sock,
				struct smmute_ipc_launch *launch,
				struct smmute_ipc_launch_resp *resp)
{
	int ret;
	resp->hdr.size = sizeof(*resp);

	/* Use unified address space if possible */
	if (launch->params.common.flags & SMMUTE_FLAG_SVA &&
	    serv->opts->mem.unified) {
		launch->params.common.flags |= SMMUTE_FLAG_SVA;
		launch->params.common.pasid = serv->opts->mem.pasid;
	}

	/* Clients are trusted. Let the driver do the sanity checking. */
	ret = smmute_launch_transaction(&serv->dev, launch->cmd, &launch->params);
	if (!ret)
		resp->transaction_id = launch->params.common.transaction_id;

	return ret;
}

static int smmute_server_bind_task(struct server *serv, int sock,
				   struct smmute_ipc_bind_task *bind,
				   struct smmute_ipc_bind_resp *resp)
{
	int ret;
	int pasid;
	resp->hdr.size = sizeof(*resp);

	ret = smmute_bind(&serv->dev, bind->pid, &pasid);
	if (ret)
		return ret;

	resp->pasid = pasid;
	return 0;
}

static int smmute_server_unbind_task(struct server *serv, int sock,
				     struct smmute_ipc_unbind_task *unbind,
				     struct smmute_ipc_unbind_resp *resp)
{
	resp->hdr.size = sizeof(*resp);
	return smmute_unbind(&serv->dev, unbind->pid, unbind->pasid);
}

static int smmute_server_result(struct server *serv, int sock,
				struct smmute_ipc_result *result,
				struct smmute_ipc_result_resp *resp)
{
	resp->hdr.size = sizeof(*resp);

	resp->result.transaction_id = result->transaction_id;
	return smmute_get_result(&serv->dev, &resp->result);
}

static int smmute_server_reply(struct server *serv, int sock,
			       union smmute_ipc_resp *resp)
{
	int n;

	pr_debug("Reply %s sz:%u st:%d on %d\n",
		 smmute_ipc_command_str(resp->hdr.command), resp->hdr.size,
		 resp->hdr.status, sock);
	/* Should retry if this fails */
	n = write(sock, resp, resp->hdr.size);
	if (n != resp->hdr.size)
		pr_err("Cannot send %d bytes\n", resp->hdr.size);

	return !(n == resp->hdr.size);
}

#define UCRED_SIZE CMSG_SPACE(sizeof(struct ucred))

static int get_pid_from_ancillary(struct msghdr *hdr)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(hdr); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(hdr, cmsg)) {
		struct ucred *ucred = (void *)CMSG_DATA(cmsg);

		if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_CREDENTIALS)
			continue;

		return ucred->pid;
	}

	return -1;
}

static int smmute_server_handle(struct server *serv, int sock)
{
	int n;
	int ret;
	int pid, pid_tmp;
	union smmute_ipc_msg msg;
	union smmute_ipc_resp resp = {
		.hdr.command	= SMMUTE_IPC_INVALID,
		.hdr.size	= sizeof(struct smmute_ipc_resp_err),
		.hdr.status	= EPROTO,
	};
	struct iovec iovec = {
		.iov_base	= &msg.hdr,
		.iov_len	= sizeof(msg.hdr),
	};
	union {
		struct cmsghdr hdr;
		char buf[UCRED_SIZE];
	} u;

	struct msghdr msghdr = {
		.msg_iov		= &iovec,
		.msg_iovlen		= 1,
		.msg_control		= &u.buf,
		.msg_controllen		= UCRED_SIZE,
	};

	n = recvmsg(sock, &msghdr, 0);
	if (n != sizeof(msg.hdr))
		return EINVAL;

	pid = get_pid_from_ancillary(&msghdr);

	iovec.iov_base = (void *)&msg.hdr + n;
	iovec.iov_len = msg.hdr.size - n;
	n = recvmsg(sock, &msghdr, 0);
	if (n != iovec.iov_len)
		return smmute_server_reply(serv, sock, &resp);

	pid_tmp = get_pid_from_ancillary(&msghdr);
	if (pid != pid_tmp) {
		pr_err("PID differs ?!\n");
		return smmute_server_reply(serv, sock, &resp);
	}

	pr_debug("Recv %s sz:%u from %d on %d\n",
		 smmute_ipc_command_str(msg.hdr.command), msg.hdr.size, pid,
		 sock);

	resp.hdr.command = msg.hdr.command;

	switch (msg.hdr.command) {
	case SMMUTE_IPC_MAP:
		ret = smmute_server_map(serv, sock, &msg.map, &resp.map);
		break;
	case SMMUTE_IPC_UNMAP:
		ret = smmute_server_unmap(serv, sock, &msg.unmap, &resp.unmap);
		break;

	case SMMUTE_IPC_LAUNCH_TRANSACTION:
		ret = smmute_server_launch(serv, sock, &msg.launch,
					   &resp.launch);
		break;
	case SMMUTE_IPC_GET_RESULT:
		ret = smmute_server_result(serv, sock, &msg.result,
					   &resp.result);
		break;

	case SMMUTE_IPC_BIND_TASK:
		if (msg.bind_task.pid != pid)
			ret = EACCES;
		else
			ret = smmute_server_bind_task(serv, sock,
						      &msg.bind_task,
						      &resp.bind);
		break;

	case SMMUTE_IPC_UNBIND_TASK:
		if (msg.unbind_task.pid != pid)
			ret = EACCES;
		else
			ret = smmute_server_unbind_task(serv, sock,
							&msg.unbind_task,
							&resp.unbind);
		break;

	case SMMUTE_IPC_INVALID:
	default:
		ret = EBADMSG;
		break;
	}

	resp.hdr.status = ret;

	return smmute_server_reply(serv, sock, &resp);
}

#define MAX_EVENTS 16

int smmute_server_one_event(struct server *serv, struct epoll_event *ev)
{
	int client_sock;
	int fd, ret;
	struct epoll_event new_ev;

	fd = ev->data.fd;

	if (fd == server_stop) {
		pr_debug("stop requested\n");
		return 1;
	}

	if (fd == serv->sock) {
		while (true) {
			client_sock = accept(serv->sock, NULL, NULL);
			if (client_sock < 0)
				break;

			pr_debug("new connection on sock %d\n", client_sock);

			new_ev.events = EPOLLIN | EPOLLRDHUP;
			new_ev.data.fd = client_sock;
			if (epoll_ctl(serv->epoll, EPOLL_CTL_ADD, client_sock,
				      &new_ev) < 0) {
				perror("epoll_ctl(add)");
				close(client_sock);
				return 0;
			}
		}

		if (client_sock < 0 && errno != EAGAIN)
			perror("accept");

		return 0;
	}

	if (ev->events & (EPOLLERR | EPOLLRDHUP | EPOLLHUP)) {
		pr_debug("closing connection %d (%#x)\n", fd, ev->events);
		ret = epoll_ctl(serv->epoll, EPOLL_CTL_DEL, fd, NULL);
		if (ret)
			perror("epoll_ctl(del)");
		close(fd);
		return 0;
	}

	ret = smmute_server_handle(serv, fd);
	if (ret)
		pr_debug("failed to handle msg on %d\n", fd);

	return 0;
}

int smmute_server_listen(struct server *serv)
{
	int i;
	int ret;
	int stop = 0;
	struct epoll_event ev[MAX_EVENTS];

	pr_info("Server listening on %s...\n", serv->name.sun_path);

	while (!stop) {
		ret = epoll_wait(serv->epoll, ev, MAX_EVENTS, -1);
		if (ret <= 0)
			continue;

		for (i = 0; i < ret; i++) {
			stop = smmute_server_one_event(serv, ev + i);
			if (stop)
				break;
		}
	}

	return 0;
}

static int smmute_connection_create(struct server *serv)
{
	int ret;
	int passcred = 1;
	pid_t pid = getpid();
	struct epoll_event ev;

	serv->name.sun_family = AF_UNIX;

	/* TODO: allow user to set a socket name/fd */
	if (!snprintf(serv->name.sun_path, sizeof(serv->name.sun_path) - 1,
		      "/tmp/smmute-ipc-%d.sock", pid))
		return 1;

	unlink(serv->name.sun_path); /* Just in case */

	serv->sock = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (serv->sock < 0) {
		perror("socket");
		return 1;
	}

	ret = bind(serv->sock, (const struct sockaddr *)&serv->name,
		   sizeof(serv->name));
	if (ret) {
		pr_err("unable to bind to %s\n", serv->name.sun_path);
		goto err_close;
	}

	ret = setsockopt(serv->sock, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred));
	if (ret) {
		perror("setsockopt(SO_PASSCRED)");
	}

	ret = listen(serv->sock, 8);
	if (ret) {
		perror("listen");
		goto err_close;
	}

	ret = epoll_create1(0);
	if (ret < 0) {
		perror("epoll_create");
		goto err_unbind;
	}
	serv->epoll = ret;

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = serv->sock;
	ret = epoll_ctl(serv->epoll, EPOLL_CTL_ADD, serv->sock, &ev);
	if (ret < 0) {
		perror("set sock evfd");
		goto err_close_epoll;
	}

	ev.events = EPOLLIN | EPOLLET;
	ev.data.fd = server_stop;
	ret = epoll_ctl(serv->epoll, EPOLL_CTL_ADD, server_stop, &ev);
	if (ret < 0) {
		perror("set stop evfd");
		goto err_close_epoll;
	}

	return 0;

err_close_epoll:
	close(serv->epoll);

err_unbind:
	unlink(serv->name.sun_path);

err_close:
	close(serv->sock);

	return ret;
}

static void smmute_connection_close(struct server *serv)
{
	unlink(serv->name.sun_path);
	close(serv->sock);
}

int smmute_server_create(struct server *serv)
{
	int ret;

	pthread_mutex_init(&serv->bufs.lock, 0);
	INIT_LIST_HEAD(&serv->bufs.list);

	smmute_backend_init(serv->opts->backend, NULL);

	serv->dev.backend = serv->opts->backend;
	ret = smmute_device_open(&serv->dev, serv->opts->device, 0);
	if (ret) {
		pr_err("cannot open device '%s' with backend %d: %s\n",
		       serv->opts->device, serv->opts->backend, strerror(ret));
		return ret;
	}

	if (serv->opts->mem.unified) {
		ret = smmute_bind(&serv->dev, getpid(), &serv->opts->mem.pasid);
		if (ret) {
			pr_err("cannot bind to device\n");
			goto err_close;
		}
	}

	ret = smmute_connection_create(serv);
	if (ret)
		goto err_close;

	return 0;

err_close:
	smmute_device_close(&serv->dev);
	return ret;
}

void smmute_server_close(struct server *serv)
{
	if (serv->opts->mem.unified) {
		if (smmute_unbind(&serv->dev, getpid(), serv->opts->mem.pasid))
			pr_err("cannot unbind from device\n");
	}

	smmute_connection_close(serv);
	smmute_device_close(&serv->dev);
}


static const char *optstring = "b:dhqu";
static void print_help(char *progname)
{
	pr_err(
"Usage: %s [opts] <dev>                                                  \n\n"
"Create a common driver process for smmute. Clients send commands using the\n"
"IPC backend, that the server relays to the device using the selected      \n"
"backend. This allows multiple client to share a device driven by VFIO.  \n\n"
"  OPTION           DESCRIPTION                                     DEFAULT\n"
"  <dev>            device to open        /sys/bus/pci/devices/0000:00:03.0\n"
"  -b <backend>     backend (driver): k[ernel], v[fio], i[pc]          vfio\n"
"  -d               debug - print additional messages                      \n"
"  -q               quiet - only print errors                              \n"
"  -u               unified - bind server address space to device          \n",
	progname);
}

static int parse_options(int argc, char *argv[], struct program_options *opts)
{
	int ret;

	/* optind, opterr, optopt and optarg are defined in unistd */
	optind = 1;
	/* Print error messages */
	opterr = 1;
	while ((ret = getopt(argc, argv, optstring)) != -1) {
		switch (ret) {
		case 'b':
			if (optarg[0] == 'v') {
				opts->backend = SMMUTE_BACKEND_VFIO;
			} else if (optarg[0] == 'k') {
				opts->backend = SMMUTE_BACKEND_KERNEL;
			} else if (optarg[0] == 'i') {
				opts->backend = SMMUTE_BACKEND_IPC;
			} else {
				pr_err("unkown backend '%s'\n", optarg);
				return 1;
			}
			break;
		case 'd':
			loglevel = LOG_DEBUG;
			break;
		case 'q':
			loglevel = LOG_ERROR;
			break;
		case 'u':
			opts->mem.unified = true;
			break;
		case 'h':
		default:
			print_help(argv[0]);
			return 1;
		}
	}

	if (optind < argc)
		opts->device = argv[optind];

	return 0;
};
int main(int argc, char **argv)
{
	int ret;
	struct server server;
	struct program_options options = {
		.backend	= SMMUTE_BACKEND_VFIO,
		.device		= "/sys/bus/pci/devices/0000:00:03.0",
		.mem		= {
			.unified	= false,
			.pasid		= 0,
			.in_file_path	= NULL,
			.out_file_path	= NULL,
			.in_file	= -1,
			.out_file	= -1,
		}
	};

	memset(&server, 0, sizeof(server));

	ret = parse_options(argc, argv, &options);
	if (ret)
		return ret;

	server.opts = &options;

	server_stop = eventfd(0, 0);
	if (server_stop < 0) {
		perror("eventfd");
		return server_stop;
	}

	signal(SIGINT, smmute_server_stop);
	signal(SIGQUIT, smmute_server_stop);
	signal(SIGTERM, smmute_server_stop);

	ret = smmute_server_create(&server);
	if (ret)
		return ret;

	ret = smmute_server_listen(&server);

	smmute_server_close(&server);

	return ret;
}

