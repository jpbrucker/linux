/*
 * $ setup_vfio 00:03.0 00:04.0 00:05.0 00:06.0
 * $ test-vfio-replay
 *
 * Try to replay bind() onto a group.
 * - open devA
 * - bind to current
 * - exec transaction on devA
 * - open devB, put it in the same container
 * - exec transaction on devB
 * - close devA
 * - exec transaction on devB
 * - unbind devB
 * - exec transaction on devB, expect fault.
 *
 * Variation 2:
 * - open devA
 * - bind to current
 * - open devB
 * - exec transaction on devB
 * - unbind from devA
 * - exec transaction on devB, expect fault
 *
 * Variation 3:
 * - open devA
 * - bind to current
 * - map buffer
 * - exec transaction on devA
 * - unmap buffer
 * - open devB
 * - exec transaction on devB, expect fault
 * - map buffer
 * - exec transaction on devB
 *
 * Variation 4:
 * - open devA, devB, devC, devD
 * - bind devD to current
 * - exec transaction on devA, devB, devC, devD
 * - unbind devC
 * - exec transaction on devA, devB, devC, devD, expect fault
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_INFO;

int transaction_rand(struct smmute_dev *dev, void *va, size_t size, int pasid,
		     int i)
{
	int ret;
	struct smmute_transaction_result result = {
		.blocking = true,
	};
	int attr = SMMUTE_TRANSACTION_ATTR(SMMUTE_ATTR_WBRAWA_SH,
					   SMMUTE_ATTR_WBRAWA_SH);
	union smmute_transaction_params params = {
		.common = {
			.input_start	= (uint64_t)va,
			.size		= size,
			.attr		= attr,
			.stride		= 1,
			.seed		= i,
			.flags		= SMMUTE_FLAG_SVA,
			.pasid		= pasid,
		},
	};

	ret = smmute_launch_transaction(dev, SMMUTE_IOCTL_RAND48, &params);
	if (ret) {
		pr_err("could not launch transaction\n");
		return ret;
	}

	result.transaction_id = params.common.transaction_id;

	ret = smmute_get_result(dev, &result);
	if (ret) {
		pr_err("could not get result\n");
		return ret;
	}

	pr_debug("Result: 0x%lx, val: 0x%llx, status: %d\n", result.status ? 0 :
		 *(uint64_t *)va, result.value, result.status);

	return result.status != 0;
}

#define err(ret, fmt, ...)						\
	if (ret) { pr_err("T%d: " fmt, test_nr, ##__VA_ARGS__); return (ret); }

int test_1(int test_nr, struct smmute_dev *devs, const char **dev_paths)
{
	int ret;
	int pasid;
	void *buf;
	int i = 0;
	size_t size = 0x42927;

	pr_debug("\n################ TEST %d ################\n", test_nr);

	ret = smmute_device_open(&devs[0], dev_paths[0], 0);
	err(ret, "Could not open dev %s\n", dev_paths[0]);

	ret = smmute_bind(&devs[0], -1, &pasid);
	err(ret, "Could not bind dev %s\n", dev_paths[0]);

	buf = malloc(size);
	err(!buf, "malloc");

	ret = transaction_rand(&devs[0], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	ret = smmute_device_open(&devs[1], dev_paths[1], 0);
	err(ret, "Could not open dev %s\n", dev_paths[1]);

	/*
	 * No bind, should be done automatically since they're using the same
	 * container
	 */

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	smmute_device_close(&devs[0]);

	/* Device 1 is still bound */
	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	smmute_unbind(&devs[1], -1, pasid);

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(!ret, "Transaction %d didn't fail\n", i);

	smmute_device_close(&devs[1]);
	free(buf);

	return 0;
}

int test_2(int test_nr, struct smmute_dev *devs, const char **dev_paths)
{
	int ret;
	int pasid;
	void *buf;
	int i = 0;
	size_t size = 0x10293;

	pr_debug("\n################ TEST %d ################\n", test_nr);

	buf = malloc(size);
	err(!buf, "malloc");

	ret = smmute_device_open(&devs[0], dev_paths[0], 0);
	err(ret, "Could not open dev %s\n", dev_paths[0])

	ret = smmute_bind(&devs[0], getpid(), &pasid);
	err(ret, "Could not bind dev %s\n", dev_paths[0]);

	ret = smmute_device_open(&devs[1], dev_paths[1], 0);
	err(ret, "Could not open dev %s\n", dev_paths[1]);

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	smmute_unbind(&devs[1], -1, pasid);

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(!ret, "Transaction %d didn't fail\n", i);

	smmute_device_close(&devs[0]);
	smmute_device_close(&devs[1]);
	free(buf);

	return 0;
}

int test_3(int test_nr, struct smmute_dev *devs, const char **dev_paths)
{
	int ret;
	int pasid;
	void *buf;
	int i = 0;
	size_t size = 0x16000;

	pr_debug("\n################ TEST %d ################\n", test_nr);

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |
		   MAP_SHARED, -1, 0);
	err(buf == MAP_FAILED, "mmap\n");

	ret = smmute_device_open(&devs[0], dev_paths[0], 0);
	err(ret, "Could not open dev %s\n", dev_paths[0])

	ret = smmute_bind(&devs[0], -1, &pasid);
	err(ret, "Could not bind dev %s\n", dev_paths[0]);

	ret = transaction_rand(&devs[0], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	ret = smmute_device_open(&devs[1], dev_paths[1], 0);
	err(ret, "Could not open dev %s\n", dev_paths[1]);

	munmap(buf, size);

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(!ret, "Transaction %d didn't fail\n", i);

	buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS |
		   MAP_SHARED, -1, 0);
	err(buf == MAP_FAILED, "mmap\n");

	ret = transaction_rand(&devs[1], buf, size, pasid, ++i);
	err(ret, "Transaction %d failed\n", i);

	smmute_device_close(&devs[0]);
	smmute_device_close(&devs[1]);
	munmap(buf, size);

	return 0;
}

int test_4(int test_nr, struct smmute_dev *devs, const char **dev_paths)
{
	int ret;
	int dev;
	int pasid;
	void *buf;
	int i = 0;
	size_t size = 0x74921;

	pr_debug("\n################ TEST %d ################\n", test_nr);

	buf = malloc(size);
	err(!buf, "malloc\n");

	for (dev = 0; dev < 4; dev++) {
		ret = smmute_device_open(&devs[dev], dev_paths[dev], 0);
		err(ret, "Could not open dev %s\n", dev_paths[dev]);
	}

	ret = smmute_bind(&devs[3], -1, &pasid);
	err(ret, "Could not bind dev %s\n", dev_paths[3]);

	for (dev = 0; dev < 4; dev++) {
		ret = transaction_rand(&devs[dev], buf, size, pasid, ++i);
		err(ret, "Transaction %d failed\n", i);
	}

	ret = smmute_unbind(&devs[2], getpid(), pasid);
	err(ret, "Could not unbind dev %s\n", dev_paths[2]);

	for (dev = 3; dev >= 0; dev--) {
		ret = transaction_rand(&devs[dev], buf, size, pasid, ++i);
		err(!ret, "Transaction %d didn't fail\n", i);
	}

	for (dev = 0; dev < 4; dev++)
		smmute_device_close(&devs[dev]);
	free(buf);

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	const char *dev_paths[] = {
		"/sys/bus/pci/devices/0000:00:03.0",
		"/sys/bus/pci/devices/0000:00:04.0",
		"/sys/bus/pci/devices/0000:00:05.0",
		"/sys/bus/pci/devices/0000:00:06.0",
	};
	struct smmute_backend_options bk_opts = {
		.flags = SMMUTE_BACKEND_VFIO_FLAG_MERGE,
	};
	struct smmute_dev devs[] = {
		{ .backend = SMMUTE_BACKEND_VFIO, },
		{ .backend = SMMUTE_BACKEND_VFIO, },
		{ .backend = SMMUTE_BACKEND_VFIO, },
		{ .backend = SMMUTE_BACKEND_VFIO, },
	};

	if (argc > 1)
		loglevel = LOG_DEBUG;

	ret = smmute_backend_init(SMMUTE_BACKEND_VFIO, &bk_opts);
	if (ret)
		return ret;

	ret = test_1(1, devs, dev_paths);
	if (ret)
		return ret;

	ret = test_2(2, devs, dev_paths);
	if (ret)
		return ret;

	ret = test_3(3, devs, dev_paths);
	if (ret)
		return ret;

	ret = test_4(4, devs, dev_paths);
	if (ret)
		return ret;

	return 0;
}
