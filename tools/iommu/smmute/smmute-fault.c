#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_INFO;

int transaction(struct smmute_dev *dev, uint64_t iova, size_t size, void *va)
{
	int ret;
	struct smmute_transaction_result result;
	int attr = SMMUTE_TRANSACTION_ATTR(SMMUTE_ATTR_WBRAWA_SH,
					   SMMUTE_ATTR_WBRAWA_SH);
	union smmute_transaction_params params = {
		.common = {
			.input_start	= iova,
			.size		= size,
			.attr		= attr,
			.stride		= 1,
			.seed		= 0,
		},
	};

	ret = smmute_launch_transaction(dev, SMMUTE_IOCTL_RAND48, &params);
	if (ret) {
		pr_err("could not launch transaction\n");
		return ret;
	}

	memset(&result, 0, sizeof(result));
	result.transaction_id = params.common.transaction_id;
	result.blocking = true;

	ret = smmute_get_result(dev, &result);
	if (ret) {
		pr_err("could not get result\n");
		return ret;
	}

	pr_debug("Result: 0x%lx, val: 0x%llx, status: %d\n", *(uint64_t *)va,
		result.value, result.status);

	return result.status != 0;
}

int test_one(struct smmute_dev *dev, dma_addr_t iova, bool failure,
	     int i, int j)
{
	int ret;
	int k = 0;
	void *ptr;
	size_t size = 0x1000;
	int prot = PROT_READ | PROT_WRITE;
	struct smmute_mem_options opts = {
		.force_iova	= true,
	};

	ptr = mmap(NULL, size, PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS,
		   -1, 0);
	if (ptr == MAP_FAILED)
		return errno;

	if (failure) {
		pr_debug("Starting faulty transaction at 0x%llx\n", iova);
		ret = transaction(dev, iova, size, ptr);
		if (!ret) {
			pr_err("Transaction at 0x%llx-0x%llx didn't fail!\n",
			       iova, iova + size - 1);
			pr_err("FAIL (%d, %d, %d)\n", i, j, k);
			return ret;
		}
		pr_err("SUCCESS (%d, %d, %d)\n", i, j, k++);
	}

	ret = smmute_dma_map_buffer(dev, ptr, &iova, size, prot, &opts);
	if (ret) {
		pr_err("could not map %p -> 0x%llx\n", ptr, iova);
		return ret;
	}

	pr_debug("Starting normal transaction at 0x%llx\n", iova);
	ret = transaction(dev, iova, size, ptr);
	if (ret) {
		pr_err("Transaction at 0x%llx-0x%llx failed\n", iova, iova +
		       size - 1);
		pr_err("FAIL (%d, %d, %d)\n", i, j, k);
		smmute_dma_unmap_buffer(dev, ptr, iova, size, ptr);
		munmap(ptr, size);
		return ret;
	}

	ret = smmute_dma_unmap_buffer(dev, ptr, iova, size, &opts);
	if (ret)
		pr_err("could not unmap %p -> 0x%llx\n", ptr, iova);

	ret = munmap(ptr, size);
	if (ret)
		perror("munmap");

	pr_err("SUCCESS (%d, %d, %d)\n", i, j, k);
	return ret;
}

int test(struct smmute_dev *dev, int i)
{
	int ret;
	int j = 0;
	int final_ret = 0;

	/*
	 * map, write, unmap, ...
	 */
	ret = test_one(dev, 0x30000000, false, i, 0);
	if (ret)
		final_ret = ret;

	/*
	 * write (->fault), map, write, unmap, ...
	 */
	j++;
	ret = test_one(dev, 0x30000000, true, i, 1);
	if (ret)
		final_ret = ret;

	return final_ret;
}

int main(int argc, char **argv)
{
	int ret, i;
	int final_ret = 0;
	const char *dev_path = "/sys/bus/pci/devices/0000:00:03.0";
	struct smmute_dev dev = {
		.backend = SMMUTE_BACKEND_VFIO,
	};

	if (argc > 1)
		loglevel = LOG_DEBUG;

	ret = smmute_backend_init(SMMUTE_BACKEND_VFIO, NULL);
	if (ret)
		return ret;

	for (i = 0; i < 2; i++) {
		ret = smmute_device_open(&dev, dev_path, 0);
		if (ret) {
			pr_err("Could not open '%s'\n", dev_path);
			return ret;
		}

		ret = test(&dev, i);
		if (ret)
			final_ret = ret;

		smmute_device_close(&dev);
	}

	return final_ret;
}
