#include <stdlib.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_INFO;
static struct smmute_dev dev;

int dev_init(void)
{
	int ret;

	dev.backend = SMMUTE_BACKEND_KERNEL;
	ret = smmute_backend_init(SMMUTE_BACKEND_KERNEL, NULL);
	if (ret)
		return ret;

	ret = smmute_device_open(&dev, "/dev/smmute0", 0);
	if (ret)
		return ret;

	return 0;
}

/*
 * DMA to a range of pages. Perform a memcpy to each stride
 */
uint64_t dma_range(void *dma_start, size_t dma_size, size_t stride)
{
	int ret;
	unsigned int attr = SMMUTE_ATTR_WBRAWA_SH;
	union smmute_transaction_params params = {
		.common.input_start = (uint64_t)dma_start,
		.common.size = dma_size,
		.common.stride = stride,
		.common.seed = 1, // randomly pick next transaction
		.common.flags = SMMUTE_FLAG_SVA,
		.common.attr = SMMUTE_TRANSACTION_ATTR(attr, attr),
	};
	struct smmute_transaction_result result = {
		.blocking = true,
	};

	ret = smmute_launch_transaction(&dev, SMMUTE_IOCTL_RAND48, &params);
	if (ret) {
		pr_err("could not launch DMA: %d\n", ret);
		return ret;
	}

	result.transaction_id = params.common.transaction_id;

	ret = smmute_get_result(&dev, &result);
	if (ret) {
		pr_err("could not get result: %d\n", ret);
		return ret;
	}

	/* On fault, return the faulting address */
	if (result.status != 0)
		return result.value ?: -1ULL;
	return 0;
}

int sva_bind(void)
{
	int pasid;
	return smmute_bind(&dev, -1, &pasid);
}

void sva_unbind(void)
{
	smmute_unbind(&dev, -1, 0);
}
