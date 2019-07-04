#include <errno.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smmute-lib.h"

extern struct smmute_device_ops kernel_ops;

static struct smmute_device_ops *backend_ops[SMMUTE_NR_BACKENDS] = {
	[SMMUTE_BACKEND_KERNEL]		= &kernel_ops,
};

void *smmute_lib_alloc_buffer(int fd, size_t size, int prot,
			      struct smmute_mem_options *opts)
{
	int ret;
	int flags;
	void *buf;
	bool use_file = false;

	if (opts->unified || fd == -1)
		flags = MAP_SHARED | MAP_ANONYMOUS;
	else
		/* Let the driver create an (anonymous) mapping */
		flags = MAP_SHARED;

	if (opts->unified & UNIFIED_MEM_MALLOC) {
		buf = malloc(size);
		if (!buf) {
			perror("malloc()");
			return NULL;
		}
	} else {
		/*
		 * For unified+mmap, use file-backed mappings if requested on
		 * the cmdline
		 */
		if (prot == PROT_READ && opts->in_file >= 0) {
			fd = opts->in_file;
			use_file = true;
		} else if (prot == PROT_WRITE && opts->out_file >= 0) {
			fd = opts->out_file;
			ret = ftruncate(fd, size);
			if (ret) {
				perror("ftruncate");
				return NULL;
			}
			use_file = true;
		}

		if (use_file)
			flags = MAP_SHARED;

		buf = mmap(NULL, size, prot, flags, fd, 0);
		if (buf == MAP_FAILED) {
			perror("mmap()");
			return NULL;
		}
	}

	if (opts->unified & UNIFIED_MEM_LOCK) {
		/* TODO: ensure PAGE_SIZE alignment */
		void *aligned_buf = buf;
		size_t total_size = size + buf - aligned_buf;

		ret = mlock(aligned_buf, total_size);
		if (ret) {
			perror("mlock()");
			goto err_unmap;
		}
	}

	return buf;

err_unmap:
	if (opts->unified & UNIFIED_MEM_MALLOC)
		free(buf);
	else
		ret = munmap(buf, size);

	return NULL;
}

void smmute_lib_free_buffer(void *buf, size_t size, struct smmute_mem_options *opts)
{
	int ret;

	if (opts->unified & UNIFIED_MEM_STACK)
		return;

	if (opts->unified & UNIFIED_MEM_LOCK) {
		void *aligned_buf = buf;
		size_t total_size = size + buf - aligned_buf;

		ret = munlock(aligned_buf, total_size);
		if (ret)
			perror("munlock()");
	}

	if (opts->unified & UNIFIED_MEM_MALLOC) {
		free(buf);
	} else {
		ret = munmap(buf, size);
		if (ret)
			perror("munmap()");
	}
}

/**
 * smmute_device_open - open and initialize device
 *
 * @dev: device info
 *       Caller must allocate dev and initialise dev->backend with the required
 *       backend.
 * @path: string describing a single device to the backend
 * @flags: unused
 *
 * returns 0 on success, an error code otherwise
 */
int smmute_device_open(struct smmute_dev *dev, const char *path, int flags)
{
	int ret;

	if (dev->ops)
		return EBUSY;

	if (dev->backend >= SMMUTE_NR_BACKENDS)
		return EINVAL;

	if (!backend_ops[dev->backend])
		return ENODEV;

	dev->ops = backend_ops[dev->backend];

	ret = dev->ops->open(dev, path, flags);
	if (ret)
		dev->ops = NULL;

	return ret;
}

/**
 * smmute_device_close - close device and release resources
 *
 * @dev: device info
 */
void smmute_device_close(struct smmute_dev *dev)
{
	if (!dev->ops)
		return;

	dev->ops->close(dev);
	dev->ops = NULL;
	dev->private = NULL;
}

int smmute_backend_init(enum smmute_backend backend,
			struct smmute_backend_options *opts)
{
	int ret;

	if (backend < 0 || backend >= SMMUTE_NR_BACKENDS)
		return EINVAL;

	if (!backend_ops[backend])
		return ENODEV;

	ret = backend_ops[backend]->init(opts);

	/* Disable backend if initialisation/probing fails */
	if (ret)
		backend_ops[backend] = NULL;

	return ret;
}

void smmute_backend_exit(enum smmute_backend backend)
{
	if (backend < 0 || backend >= SMMUTE_NR_BACKENDS)
		return;

	if (backend_ops[backend])
		backend_ops[backend]->exit();
}
