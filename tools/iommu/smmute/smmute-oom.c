/*
 * Let the OOM killer kill a process that was bound to the Test engine.
 *
 * Running this with -l will highlight the problem for mm_exit. As the smmute
 * driver's voluntarily exagerates and sleeps for seconds, exit_mmap() doesn't
 * finish fast enough and the OOM killer selects additional innocent tasks to
 * kill. Normally the reaper thread cleans the dying process' address space even
 * if its mm_exit takes a while, but with -l the allocated memory is locked and
 * the reaper cannot clean up.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include "smmute-lib.h"

struct program_options {
	bool	mlock;
};

enum loglevel loglevel = LOG_DEBUG;

static struct smmute_dev dev;

#define NR_CHILDREN 4

/*
 * Set overcommit_memory to 1, "the kernel pretends there is always enough
 * memory until it actually runs out". When 0, mmap returns ENOMEM once there
 * isn't enough memory. When 1, mmap returns success, and the OOM killer does
 * its thing when we populate the allocated range.
 */
static int setup_vm(void)
{
	FILE *file;
	char oldval, newval = '1';

	file = fopen("/proc/sys/vm/overcommit_memory", "r+");
	if (!file) {
		perror("fopen");
		return 1;
	}
	if (fscanf(file, "%c", &oldval) != 1) {
		perror("fscanf");
		return 1;
	}
	fseek(file, 0, SEEK_SET);
	if (fprintf(file, "%c", newval) < 1) {
		perror("fprintf");
		return 1;
	}
	fclose(file);

	pr_info("Changed vm.overcommit_memory from %c to %c\n", oldval, newval);
	return 0;
}

struct dma_range {
	void	*addr;
	size_t	size;
};


struct child_dma {
	struct smmute_dev	*dev;
	pthread_mutex_t		mutex;
	struct dma_range	*ranges;
	size_t			nr_ranges;
	size_t			read_ranges;
};

void *dma_thread_fn(void *data)
{
	int ret;
	int pasid;
	void *addr;
	size_t size;
	size_t range_nr = 0;
	struct child_dma *dma_cmd = data;

	unsigned int attr = SMMUTE_ATTR_WBRAWA_SH;
	union smmute_transaction_params params = {
		.common.stride		= PAGE_SIZE,
		.common.attr		= SMMUTE_TRANSACTION_ATTR(attr, attr),
		.common.flags		= SMMUTE_FLAG_SVA,
	};
	struct smmute_transaction_result result = {
		.blocking = true,
	};

	ret = smmute_bind(dma_cmd->dev, -1, &pasid);
	if (ret) {
		pr_err("bind failed with %d\n", ret);
		return NULL;
	}

	while (true) {
		pthread_mutex_lock(&dma_cmd->mutex);
		addr = 0;
		if (dma_cmd->nr_ranges > range_nr) {
			addr = dma_cmd->ranges[range_nr].addr;
			size = dma_cmd->ranges[range_nr].size;
			range_nr++;
			dma_cmd->read_ranges = range_nr;
		}
		pthread_mutex_unlock(&dma_cmd->mutex);

		if (!addr) {
			/* Wait next mmap. We could use a pthread cond here. */
			usleep(1000);
			continue;
		}

		params.common.input_start = (uint64_t)addr;
		params.common.size = size;
		ret = smmute_launch_transaction(dma_cmd->dev,
						SMMUTE_IOCTL_RAND48, &params);
		if (ret) {
			pr_err("could not launch DMA: %d\n", ret);
			return NULL;
		}

		result.transaction_id = params.common.transaction_id;

		ret = smmute_get_result(dma_cmd->dev, &result);
		if (ret) {
			pr_err("could not get result: %d\n", ret);
			return NULL;
		}

		/* On fault, return the faulting address */
		if (result.status != 0) {
			pr_err("DMA fault %d at %llx\n", result.status,
			       result.value ?: -1ULL);
			return NULL;
		}
	}

	return NULL;
}

static int child_alloc(int child_nr, struct smmute_dev *dev,
		       struct program_options *opts)
{
	int ret;
	char *addr;
	void *retval;
	size_t lead;
	size_t total = 0;
	pthread_t dma_thread;
	size_t range_size = 64 * 1024 * PAGE_SIZE; // 256M
	size_t range_nr = 0, nr_ranges = 0;

	struct child_dma dma_cmd = {
		.dev = dev,
		.mutex = PTHREAD_MUTEX_INITIALIZER,
	};

	ret = pthread_create(&dma_thread, NULL, dma_thread_fn, &dma_cmd);
	if (ret)
		return ret;

	do {
		if (!pthread_tryjoin_np(dma_thread, &retval)) {
			pr_err("DMA thread exited\n");
			return EFAULT;
		}

		addr = mmap(NULL, range_size, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (addr == MAP_FAILED) {
			/*
			 * In theory we shouldn't get there because mmap is in
			 * overcommit mode. It's the faults below that should
			 * trigger an OOM
			 */
			pr_err("Allocated %zu pages until OOM\n", total);
			break;
		}

		total += range_size;

		if (opts->mlock) {
			/*
			 * This makes all pages resident in RAM, so the
			 * following code isn't really necessary
			 */
			ret = mlock2(addr, range_size, MLOCK_ONFAULT);
			if (ret)
				pr_err("Couldn't mlock %p\n", addr);
		}

		/*
		 * Half the children populate new pages themselves, the others
		 * do it with DMA.
		 */
		if (child_nr % 2) {
			int i;

			for (i = 0; i < range_size / PAGE_SIZE; i++)
				addr[i * PAGE_SIZE] = i;
			continue;
		}

		/*
		 * Append range to DMA commands, to be treated by the background
		 * thread at its earliest convenience.
		 */
		pthread_mutex_lock(&dma_cmd.mutex);
		if (range_nr >= nr_ranges) {
			nr_ranges = nr_ranges ? nr_ranges * 2 : 8;
			dma_cmd.ranges = realloc(dma_cmd.ranges, nr_ranges *
						 sizeof(struct dma_range));
		}

		dma_cmd.ranges[range_nr++] = (struct dma_range) {
			.addr	= addr,
			.size	= range_size,
		};
		dma_cmd.nr_ranges = range_nr;

		lead = dma_cmd.nr_ranges - dma_cmd.read_ranges;
		pthread_mutex_unlock(&dma_cmd.mutex);

		while (lead > 10) {
			/* We're going too fast. Throttle */
			usleep(100000);

			if (!pthread_tryjoin_np(dma_thread, &retval)) {
				pr_err("DMA thread exited\n");
				return EFAULT;
			}

			pthread_mutex_lock(&dma_cmd.mutex);
			lead = dma_cmd.nr_ranges - dma_cmd.read_ranges;
			pthread_mutex_unlock(&dma_cmd.mutex);
		}

	} while (addr != MAP_FAILED);

	while (true)
		;

	return 0;
}

/*
 * Bind the process and start DMA. Allocate enough memory to force the kernel to
 * kill us.
 */
static int test_oom(struct smmute_dev *dev, struct program_options *opts)
{
	int i, j;
	char *buf;
	pid_t pid;
	int wstatus;
	unsigned long nr_dead = 0;
	pid_t victims[NR_CHILDREN];

	/*
	 * FIXME Problem: we don't have a way to do background DMA... Once the
	 * process is killed, DMA stops pretty much immediately. Same if we have
	 * a child doing the DMA. Could the smmute driver get a "continuous"
	 * mode?
	 */

	for (i = 0; i < NR_CHILDREN; i++) {
		pid = fork();
		if (pid < 0) {
			perror("fork");
			break;
		} else if (pid > 0) {
			victims[i] = pid;
			continue;
		}

		return child_alloc(i, dev, opts);
	}

	/*
	 * Fork a few more children that don't participate. They shouldn't get
	 * killed by the reaper.
	 */
	for (j = 0; j < NR_CHILDREN; j++) {
		pid = fork();
		if (pid < 0) {
			perror("fork");
			break;
		} else if (pid > 0) {
			continue;
		}

		/* Child */
		buf = mmap(NULL, 1024 * PAGE_SIZE, PROT_WRITE|PROT_READ,
			   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
		if (buf == MAP_FAILED) {
			perror("mmap");
		}
		for (i = 0; i < 1024; i++)
			buf[i * PAGE_SIZE] = i;
		while (true)
			;
	}

	while (nr_dead < NR_CHILDREN) {
		pid = waitpid(-1, &wstatus, 0);
		if (WIFEXITED(wstatus)) {
			pr_debug("child %d exited with %d\n", pid,
				 WEXITSTATUS(wstatus));
		} else if (WIFSIGNALED(wstatus)) {
			pr_debug("child %d killed by %d\n", pid,
				 WTERMSIG(wstatus));
		} else {
			pr_err("unhandled signal\n");
		}

		for (i = 0; i < NR_CHILDREN; i++) {
			if (victims[i] == pid) {
				nr_dead++;
				break;
			}
		}
		if (i == NR_CHILDREN)
			pr_err("Sacrificed innocent child %d :(\n", pid);
	}

	/*
	 * Now that the memory gluttons are dead, we should be able to allocate
	 * loads of memory...
	 */
	{
		size_t mb = 1024 * 1024;
		size_t size = 2048 * mb;

		pr_info("Now allocating %zu Mbytes\n", size / mb);
		for (i = 0; i < (size / mb); i++) {
			buf = mmap(NULL, mb, PROT_WRITE|PROT_READ,
				   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
			if (buf == MAP_FAILED) {
				perror("mmap");
				return ENOMEM;
			}
			for (j = 0; j < mb / PAGE_SIZE; j++)
				buf[j * PAGE_SIZE] = j;
		}
		pr_info("Success!\n");
	}

	kill(0, SIGTERM);
	return 0;
}

int parse_args(int argc, char **argv, struct program_options *opts)
{
	int ret;

	/* optind, opterr, optopt and optarg are defined in unistd */
	optind = 1;
	/* Print error messages */
	opterr = 1;

	while ((ret = getopt(argc, argv, "lh")) != -1) {
		switch (ret) {
		case 'l':
			opts->mlock = true;
			break;
		case 'h':
		default:
			pr_info("Usage: %s [-l]\n"
				"  -l		lock memory\n",
				argv[0]);
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	struct program_options opts = {
		.mlock		= false,
	};
	const char *dev_path = "/dev/smmute0";

	ret = parse_args(argc, argv, &opts);
	if (ret)
		return ret;

	ret = setup_vm();
	if (ret)
		return ret;

	ret = smmute_backend_init(SMMUTE_BACKEND_KERNEL, NULL);
	if (ret)
		return ret;

	dev.backend = SMMUTE_BACKEND_KERNEL;

	ret = smmute_device_open(&dev, dev_path, 0);
	if (ret) {
		pr_err("Could not open '%s'\n", dev_path);
		return ret;
	}

	return test_oom(&dev, &opts);
}
