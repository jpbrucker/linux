#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "smmute-lib.h"

struct smmute_kdev {
	int		fd;
};

#define to_kdev(dev)	((struct smmute_kdev *)(dev)->private)


static int smmute_kernel_launch_transaction(struct smmute_dev *dev, int cmd,
					    union smmute_transaction_params *params)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	if (ioctl(kdev->fd, cmd, params))
		return errno;

	return 0;
}

static int smmute_kernel_get_result(struct smmute_dev *dev,
				    struct smmute_transaction_result *result)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	if (ioctl(kdev->fd, SMMUTE_IOCTL_GET_RESULT, result))
		return errno;

	return 0;
}

static int smmute_kernel_bind(struct smmute_dev *dev)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	if (ioctl(kdev->fd, SMMUTE_IOCTL_BIND_TASK))
		return errno;

	return 0;
}

static int smmute_kernel_unbind(struct smmute_dev *dev)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	if (ioctl(kdev->fd, SMMUTE_IOCTL_UNBIND_TASK))
		return errno;

	return 0;
}

static void *smmute_kernel_alloc_buffer(struct smmute_dev *dev, size_t size,
					int prot, struct smmute_mem_options *opts)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	return smmute_lib_alloc_buffer(kdev->fd, size, prot, opts);
}

static void smmute_kernel_free_buffer(struct smmute_dev *dev, void *buf,
				      size_t size, struct smmute_mem_options *opts)
{
	smmute_lib_free_buffer(buf, size, opts);
}

static int smmute_kernel_map_buffer(struct smmute_dev *dev, void *va, dma_addr_t *iova,
				    size_t size, int prot, struct smmute_mem_options *opts)
{
	/*
	 * Even when unified is disabled, alloc_buffer uses the driver to back
	 * the mmap, so it's already mapped. We don't have access to the actual
	 * IOVA, the driver translates our VA internally.
	 */
	*iova = (uint64_t)va;

	return 0;
}

static int smmute_kernel_unmap_buffer(struct smmute_dev *dev, void *va, dma_addr_t iova,
				      size_t size, struct smmute_mem_options *opts)
{
	return 0;
}

static int smmute_kernel_open(struct smmute_dev *dev, const char *path, int flags)
{
	int ret;
	struct smmute_kdev *kdev;
	struct smmute_version version = {
		.major		= SMMUTE_VERSION_MAJOR,
		.minor		= SMMUTE_VERSION_MINOR,
	};

	kdev = malloc(sizeof(*kdev));
	if (!kdev)
		return ENOMEM;

	kdev->fd = open(path, O_RDWR);
	if (kdev->fd < 0) {
		free(kdev);
		return errno;
	}

	ret = ioctl(kdev->fd, SMMUTE_IOCTL_VERSION, &version);
	if (ret) {
		pr_err("unsupported smmute version %u.%u\n", version.major,
		       version.minor);
		close(kdev->fd);
		free(kdev);
		return ENODEV;
	}

	dev->private = kdev;

	return 0;
}

static void smmute_kernel_close(struct smmute_dev *dev)
{
	struct smmute_kdev *kdev = to_kdev(dev);

	close(kdev->fd);
	free(kdev);
}

static int smmute_kernel_init(struct smmute_backend_options *opts)
{
	return 0;
}

static void smmute_kernel_exit(void)
{
}

struct smmute_device_ops kernel_ops = {
	.init			= smmute_kernel_init,
	.exit			= smmute_kernel_exit,

	.open			= smmute_kernel_open,
	.close			= smmute_kernel_close,

	.bind			= smmute_kernel_bind,
	.unbind			= smmute_kernel_unbind,

	.alloc_buffer		= smmute_kernel_alloc_buffer,
	.free_buffer		= smmute_kernel_free_buffer,

	.map_buffer		= smmute_kernel_map_buffer,
	.unmap_buffer		= smmute_kernel_unmap_buffer,

	.launch_transaction	= smmute_kernel_launch_transaction,
	.get_result		= smmute_kernel_get_result,
};


