#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_DEBUG;

struct vfio_buffer {
	dma_addr_t	iova;
	int		prot;
	void		*ptr;
	size_t		size;
};

/* Need this statically */
#define S_PAGE_SIZE	0x1000UL
#define IOVA_SIZE	(1ULL << 48)

#define TEST_BISECT_BASE	0xfffe000000
#define TEST_BISECT_SIZE	0x40000

/* VFIO accepts 64-bit addresses (doesn't send map/unmap to iommu) */
//#define VFIO_HACKED

static struct vfio_buffer buffers[] = {
	{
		.iova	= 0x0,
		.size	= S_PAGE_SIZE,
		.prot	= PROT_READ,
	},
	{
		.iova	= S_PAGE_SIZE,
		.size	= 10 * S_PAGE_SIZE,
		.prot	= PROT_READ | PROT_WRITE,
	},
	{
		.iova	= TEST_BISECT_BASE,
		.size	= TEST_BISECT_SIZE,
		.prot	= PROT_READ,
	},
	{
		.iova	= IOVA_SIZE - 10 * S_PAGE_SIZE,
		.size	= S_PAGE_SIZE,
		.prot	= PROT_READ,
	},
	{
		.iova	= IOVA_SIZE - S_PAGE_SIZE,
		.size	= S_PAGE_SIZE,
		.prot	= PROT_READ,
	},
#ifdef VFIO_HACKED
	{
		.iova	= -S_PAGE_SIZE,
		.size	= S_PAGE_SIZE,
		.prot	= PROT_READ,
	},
#endif
};

#define NUM_BUFFERS	(sizeof(buffers) / sizeof(buffers[0]))

int do_map_unmap(struct smmute_dev *dev)
{
	int i, ret;
	struct smmute_mem_options opts = {
		.force_iova	= true,
	};

	for (i = 0; i < NUM_BUFFERS; i++) {
		struct vfio_buffer *buf = &buffers[i];

		buf->ptr = mmap(NULL, buf->size, buf->prot, MAP_PRIVATE |
				MAP_ANONYMOUS, -1, 0);
		if (buf->ptr == MAP_FAILED) {
			pr_err("mmap for 0x%llx:0x%llx failed: %d %s\n",
			       buf->iova, buf->iova + buf->size - 1, errno,
			       strerror(errno));
			return errno;
		}

		ret = smmute_dma_map_buffer(dev, buf->ptr, &buf->iova,
					    buf->size, buf->prot, &opts);
		if (ret) {
			pr_err("VFIO map failed 0x%llx:0x%llx.\n", buf->iova,
			       buf->iova + buf->size - 1);
			return ret;
		}

		pr_info("mapped 0x%llx:0x%llx -> %p\n", buf->iova, buf->iova +
			buf->size - 1, buf->ptr);
	}

	ret = smmute_dma_unmap_buffer(dev, NULL, TEST_BISECT_BASE,
				      TEST_BISECT_SIZE - S_PAGE_SIZE, &opts);
	if (ret)
		pr_debug("couldn't unmap bisect region, as expected\n");
	else
		pr_err("Unmap invalid size succeeded!\n");

	ret = smmute_dma_unmap_buffer(dev, NULL, TEST_BISECT_BASE + S_PAGE_SIZE,
				      TEST_BISECT_SIZE - S_PAGE_SIZE, &opts);
	if (ret)
		pr_debug("couldn't unmap bisect region, as expected\n");
	else
		pr_err("Unmap invalid size succeeded!\n");


	/* Unmap two halves of the AS (doesn't support unmap-all) */
	ret = smmute_dma_unmap_buffer(dev, NULL, 0, 1UL << 63, &opts);
	if (ret)
		pr_err("could not unmap 0, 1UL << 63\n");

	ret = smmute_dma_unmap_buffer(dev, NULL, 1UL << 63, 1UL << 63, &opts);
	if (ret)
		pr_err("could not unmap 1UL << 63, 1UL << 63\n");

	return 0;
}

int main()
{
	int ret;
	const char *dev_path = "/sys/bus/pci/devices/0000:00:03.0";
	struct smmute_dev dev = {
		.backend = SMMUTE_BACKEND_VFIO,
	};

	if (PAGE_SIZE != S_PAGE_SIZE) {
		pr_err("FIXME: unhandled page size %zu\n", PAGE_SIZE);
		return -1;
	}

	ret = smmute_backend_init(SMMUTE_BACKEND_VFIO, NULL);
	if (ret)
		return ret;


	ret = smmute_device_open(&dev, dev_path, 0);
	if (ret) {
		pr_err("Could not open '%s'\n", dev_path);
		return ret;
	}

	return do_map_unmap(&dev);
}
