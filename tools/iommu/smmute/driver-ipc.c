#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <linux/list.h>

#include "smmute-lib.h"
#include "smmute-ipc.h"

struct smmute_ipc_dma_buf {
	off_t				offset;
	void				*va;
	size_t				size;
	struct list_head		list;
};

struct smmute_dma_buffers {
	struct list_head		list;
	pthread_mutex_t			lock;
};

struct smmute_ipc_shm {
	pthread_mutex_t			lock;
	int				fd;
	char				name[SMMUTE_SHM_NAME_MAX];
	off_t				offset;
};

/* Structure is shared between child processes */
struct smmute_ipc_shared {
	pthread_mutex_t			sock_lock;
	struct smmute_ipc_shm		shm;
};

struct smmute_ipc_dev {
	int				sock;
	struct smmute_dma_buffers	bufs;
	struct smmute_ipc_shared	*shr;
};

#define to_ipc_dev(dev)	((struct smmute_ipc_dev *)(dev)->private)

static int smmute_ipc_transmit(struct smmute_ipc_dev *idev, void *msg_ptr,
			       void *resp_ptr)
{
	int n;
	struct smmute_ipc_msg_hdr *msg = msg_ptr;
	struct smmute_ipc_resp_hdr *resp = resp_ptr;
	unsigned int resp_size = resp->size;

	/*
	 * Doing the command in a critical section is incredibly wasteful, but
	 * we don't support async. TODO
	 */
	pthread_mutex_lock(&idev->shr->sock_lock);
	n = write(idev->sock, msg, msg->size);
	if (n != msg->size) {
		pr_err("Failed to send msg %u (%u != %u)\n", msg->command, n,
		       msg->size);
		pthread_mutex_unlock(&idev->shr->sock_lock);
		return EIO;
	}

	n = read(idev->sock, resp, resp->size);
	pthread_mutex_unlock(&idev->shr->sock_lock);

	if (n != resp->size) {
		pr_err("Failed to recv resp %u (%u != %u)\n", msg->command, n,
		       resp->size);
		return EIO;
	}

	if (resp->command != msg->command) {
		pr_err("Invalid resp command: %u != %u\n", resp->command,
		       msg->command);
		return ESTRPIPE;
	}

	if (resp_size != resp->size)
		pr_warn("Invalid size reported: %u != %u. Oh well.\n",
			resp_size, resp->size);

	return resp->status;
}

static int smmute_ipc_launch_transaction(struct smmute_dev *dev, int cmd,
					 union smmute_transaction_params *params)
{
	int ret;
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_launch launch = {
		.hdr.size	= sizeof(launch),
		.hdr.command	= SMMUTE_IPC_LAUNCH_TRANSACTION,
		.cmd		= cmd,
		.params		= *params,
	};
	struct smmute_ipc_launch_resp resp = {
		.hdr.size	= sizeof(resp),
	};

	ret = smmute_ipc_transmit(idev, &launch, &resp);
	if (ret)
		return ret;

	params->common.transaction_id = resp.transaction_id;

	return 0;
}

static int smmute_ipc_get_result(struct smmute_dev *dev,
				 struct smmute_transaction_result *result)
{
	int ret;
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_result result_msg = {
		.hdr.size	= sizeof(result_msg),
		.hdr.command	= SMMUTE_IPC_GET_RESULT,
		.transaction_id	= result->transaction_id,
	};
	struct smmute_ipc_result_resp resp = {
		.hdr.size	= sizeof(resp),
	};

	ret = smmute_ipc_transmit(idev, &result_msg, &resp);
	if (ret)
		return ret;

	*result = resp.result;

	return 0;
}

static void *smmute_ipc_alloc_buffer(struct smmute_dev *dev, size_t size,
				     int prot, struct smmute_mem_options *opts)
{
	int ret;
	off_t off;
	struct smmute_ipc_dma_buf *buf;
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_shm *shm = &idev->shr->shm;

	if (opts->unified)
		return smmute_lib_alloc_buffer(-1, size, prot, opts);

	buf = malloc(sizeof(*buf));
	if (!buf)
		return NULL;

	size = PAGE_ALIGN(size);

	/*
	 * TODO: first/best-fit allocation. Is it really needed? The SHM is an
	 * artificial file after all, it shouldn't waste any space to just keep
	 * increasing the offset. We would wrap at some point but not with our
	 * use-cases.
	 */
	pthread_mutex_lock(&shm->lock);

	off = shm->offset;
	shm->offset += size;
	ret = ftruncate(shm->fd, shm->offset);
	if (ret)
		shm->offset -= size;

	pthread_mutex_unlock(&shm->lock);

	if (ret) {
		perror("ftruncate");
		free(buf);
		return NULL;
	}

	buf->va = mmap(NULL, size, prot, MAP_SHARED, shm->fd, off);
	if (buf->va == MAP_FAILED) {
		perror("mmap");
		free(buf);
		return NULL; /* leaving a hole in the shm */
	}
	buf->offset = off;
	buf->size = size;

	pthread_mutex_lock(&idev->bufs.lock);
	list_add(&buf->list, &idev->bufs.list);
	pthread_mutex_unlock(&idev->bufs.lock);

	return buf->va;
}

static void smmute_ipc_free_buffer(struct smmute_dev *dev, void *va, size_t size,
				   struct smmute_mem_options *opts)
{
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_dma_buf *tmp, *buf = NULL;

	if (opts->unified) {
		smmute_lib_free_buffer(va, size, opts);
		return;
	}

	size = PAGE_ALIGN(size);

	pthread_mutex_lock(&idev->bufs.lock);
	list_for_each_entry(tmp, &idev->bufs.list, list) {
		if (tmp->va == va) {
			buf = tmp;
			break;
		}
	}
	pthread_mutex_unlock(&idev->bufs.lock);

	if (!buf) {
		pr_warn("could not find IPC buf\n");
		return;
	}

	pthread_mutex_lock(&idev->bufs.lock);
	list_del(&buf->list);
	pthread_mutex_unlock(&idev->bufs.lock);

	if (munmap(va, size))
		pr_warn("failed to munmap IPC buf\n");

	free(buf);
}

static int smmute_ipc_map_buffer(struct smmute_dev *dev, void *va,
				 dma_addr_t *iova, size_t size, int prot,
				 struct smmute_mem_options *opts)
{
	int ret;
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_dma_buf *tmp, *buf = NULL;

	struct smmute_ipc_map map = {
		.hdr.size	= sizeof(map),
		.hdr.command	= SMMUTE_IPC_MAP,
		.prot		= prot,
		.size		= size,
	};
	struct smmute_ipc_map_resp resp = {
		.hdr.size	= sizeof(resp),
	};

	if (opts->unified) {
		*iova = (uint64_t)va;
		return 0;
	}

	pthread_mutex_lock(&idev->bufs.lock);
	list_for_each_entry(tmp, &idev->bufs.list, list) {
		if (tmp->va == va) {
			buf = tmp;
			break;
		}
	}
	pthread_mutex_unlock(&idev->bufs.lock);

	if (!buf) {
		pr_err("no IPC buf found\n");
		return ESRCH;
	}

	strncpy(map.shm_name, idev->shr->shm.name, SMMUTE_SHM_NAME_MAX);
	map.shm_offset = buf->offset;

	ret = smmute_ipc_transmit(idev, &map, &resp);
	if (ret) {
		pr_err("failed to map buffer: %s\n", strerror(ret));
		return ret;
	}

	*iova = resp.iova;

	return 0;
}

static int smmute_ipc_unmap_buffer(struct smmute_dev *dev, void *va,
				   dma_addr_t iova, size_t size,
				   struct smmute_mem_options *opts)
{
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_unmap unmap = {
		.hdr.size	= sizeof(unmap),
		.hdr.command	= SMMUTE_IPC_UNMAP,
		.iova		= iova,
		.size		= size,
	};
	struct smmute_ipc_unmap_resp resp = {
		.hdr.size	= sizeof(resp),
	};

	if (opts->unified)
		return 0;

	return smmute_ipc_transmit(idev, &unmap, &resp);
}

static int smmute_ipc_bind(struct smmute_dev *dev, pid_t pid, int *pasid)
{
	int ret;
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_bind_task bind = {
		.hdr.size	= sizeof(bind),
		.hdr.command	= SMMUTE_IPC_BIND_TASK,
		.pid		= pid,
	};
	struct smmute_ipc_bind_resp resp = {
		.hdr.size	= sizeof(resp),
		.pasid		= 0,
	};

	ret = smmute_ipc_transmit(idev, &bind, &resp);
	if (ret)
		return ret;

	*pasid = resp.pasid;
	return 0;
}

static int smmute_ipc_unbind(struct smmute_dev *dev, pid_t pid, int pasid)
{
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);
	struct smmute_ipc_unbind_task unbind = {
		.hdr.size	= sizeof(unbind),
		.hdr.command	= SMMUTE_IPC_UNBIND_TASK,
		.pid		= pid,
		.pasid		= pasid,
	};
	struct smmute_ipc_unbind_resp resp = {
		.hdr.size	= sizeof(resp),
	};

	return smmute_ipc_transmit(idev, &unbind, &resp);
}

static int smmute_ipc_open(struct smmute_dev *dev, const char *path, int flags)
{
	int i, ret;
	char *path2;
	size_t addr_size;
	pthread_mutexattr_t attr;
	struct smmute_ipc_dev *idev;
	struct sockaddr_un addr = {
		.sun_family = AF_UNIX,
	};
	struct timeval timeout = {
		.tv_sec	= 10 * 60,
		.tv_usec = 0,
	};

	idev = calloc(1, sizeof(*idev));
	if (!idev)
		return ENOMEM;

	idev->shr = mmap(NULL, PAGE_ALIGN(sizeof(*idev->shr)), PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (idev->shr == MAP_FAILED) {
		ret = errno;
		goto err_free_idev;
	}

	idev->sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (idev->sock < 0) {
		ret = errno;
		goto err_free_shr;
	}

	addr_size = sizeof(addr.sun_path);
	memcpy(addr.sun_path, path, addr_size);

	ret = connect(idev->sock, (const struct sockaddr *)&addr, addr_size);
	if (ret) {
		perror("connect");
		ret = errno;
		goto err_close_sock;
	}

	ret = setsockopt(idev->sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	if (ret) {
		ret = errno;
		perror("setsockopt(SO_RCVTIMEO)");
		goto err_close_sock;
	}

	ret = setsockopt(idev->sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	if (ret) {
		ret = errno;
		perror("setsockopt(SO_SNDTIMEO)");
		goto err_close_sock;
	}

	/*
	 * Process can connect to multiple IPC servers. Create a different shm
	 * file for each server
	 */
	path2 = strdup(path);
	if (!path2) {
		ret = errno;
		goto err_close_sock;
	}

	for (i = 0; i < strlen(path2); i++) {
		if (path2[i] == '/')
			path2[i] = '-';
	}

	ret = snprintf(idev->shr->shm.name, SMMUTE_SHM_NAME_MAX, "/smmute-shm-%d-%s",
		       getpid(), path2);
	free(path2);
	if (ret < 0) {
		pr_err("cannot snprintf shm name\n");
		ret = errno;
		goto err_close_sock;
	}

	idev->shr->shm.fd = shm_open(idev->shr->shm.name, O_RDWR | O_CREAT |
				     O_EXCL, 0777);
	if (idev->shr->shm.fd < 0) {
		ret = errno;
		pr_err("cannot open SHM %s\n", idev->shr->shm.name);
		goto err_close_sock;
	}

	if (pthread_mutexattr_init(&attr) ||
	    pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED))
		goto err_close_sock;

	if (pthread_mutex_init(&idev->shr->sock_lock, &attr) ||
	    pthread_mutex_init(&idev->shr->shm.lock, &attr) ||
	    pthread_mutex_init(&idev->bufs.lock, NULL))
		goto err_close_sock;
	INIT_LIST_HEAD(&idev->bufs.list);

	dev->private = idev;

	return 0;

err_close_sock:
	close(idev->sock);

err_free_shr:
	munmap(idev->shr, PAGE_ALIGN(sizeof(*idev->shr)));

err_free_idev:
	free(idev);

	return ret;
}

static void smmute_ipc_close(struct smmute_dev *dev)
{
	struct smmute_ipc_dev *idev = to_ipc_dev(dev);

	if (!idev)
		return;

	/* TODO: unmap all bufs */

	close(idev->shr->shm.fd);
	if (shm_unlink(idev->shr->shm.name))
		pr_err("failed to unlink SHM %s\n", idev->shr->shm.name);

	munmap(idev->shr, PAGE_ALIGN(sizeof(*idev->shr)));
	close(idev->sock);
	free(idev);
}

static int smmute_ipc_init(struct smmute_backend_options *opts)
{
	return 0;
}

static void smmute_ipc_exit(void)
{
}

struct smmute_device_ops ipc_ops = {
	.init			= smmute_ipc_init,
	.exit			= smmute_ipc_exit,

	.open			= smmute_ipc_open,
	.close			= smmute_ipc_close,

	.bind			= smmute_ipc_bind,
	.unbind			= smmute_ipc_unbind,

	.alloc_buffer		= smmute_ipc_alloc_buffer,
	.free_buffer		= smmute_ipc_free_buffer,

	.map_buffer		= smmute_ipc_map_buffer,
	.unmap_buffer		= smmute_ipc_unmap_buffer,

	.launch_transaction	= smmute_ipc_launch_transaction,
	.get_result		= smmute_ipc_get_result,
};
