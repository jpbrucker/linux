#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_INFO;

enum test_mode {
	TEST_BIND_RACE,
	TEST_UNBIND_EXIT_RACE,
};

struct program_options {
	int nr_children;
	int nr_threads;
	int nr_loops;
	const char *dev_path;
	enum test_mode test;
};

struct smmute_bind_child {
	struct smmute_dev	*dev;
	pid_t			pid;
	int			pasid;
	int			ret;
	bool			bind_done;
};

/*
 * Max number of bindable tasks are generally limited by the number of ASIDs. At
 * two 8-bit ASIDs per task, minus some reserve for the allocator, that would be
 * 118 tasks. 16-bit ASIDs allow a lot more.
 */
#define NR_CHILDREN	32
#define NR_THREADS	32
#define NR_LOOPS	32

/* Not particularly useful since we don't allow remote unbind anymore */
static int test_unbind_exit_race(struct program_options *opts)
{
	int i;
	int ret;
	pid_t pid;
	size_t shared_data_size;
	struct {
		pthread_mutex_t mutex;
		pthread_cond_t bind_done;
		struct smmute_bind_child children[];
	} *shared_data;
	pthread_condattr_t cond_shared;
	pthread_mutexattr_t mutex_shared;
	struct smmute_bind_child *child;
	struct smmute_dev dev = {
		.backend = SMMUTE_BACKEND_KERNEL,
	};

	pthread_condattr_init(&cond_shared);
	pthread_condattr_setpshared(&cond_shared, PTHREAD_PROCESS_SHARED);
	pthread_mutexattr_init(&mutex_shared);
	pthread_mutexattr_setpshared(&mutex_shared, PTHREAD_PROCESS_SHARED);

	pr_debug("Testing unbind race with %u children\n", opts->nr_children);
	ret = smmute_device_open(&dev, opts->dev_path, 0);
	if (ret) {
		pr_err("Could not open '%s'\n", opts->dev_path);
		return ret;
	}

	shared_data_size = sizeof(*shared_data) +
		sizeof(shared_data->children[0]) * opts->nr_children;
	shared_data = mmap(NULL, shared_data_size, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared_data == MAP_FAILED)
		return ENOMEM;

	pthread_mutex_init(&shared_data->mutex, &mutex_shared);
	pthread_cond_init(&shared_data->bind_done, &cond_shared);

	for (i = 0; i < opts->nr_children; i++) {
		child = &shared_data->children[i];

		pid = fork();
		if (pid < 0) {
			goto err_kill_children;
		} else if (pid == 0) {
			/* Child process */

			child->dev = &dev;
			child->pid = getpid();
			ret = smmute_bind(&dev, &child->pasid);

			pthread_mutex_lock(&shared_data->mutex);
			child->bind_done = true;
			pthread_cond_signal(&shared_data->bind_done);
			pthread_mutex_unlock(&shared_data->mutex);

			if (ret) {
				pr_warn("bind %d failed with %d\n", i, ret);
				return 1;
			}

			while (true)
				sleep(1);
			return 0;
		}

		/* Parent process */
		pthread_mutex_lock(&shared_data->mutex);
		while (!child->bind_done)
			pthread_cond_wait(&shared_data->bind_done,
					  &shared_data->mutex);
		pthread_mutex_unlock(&shared_data->mutex);
		pr_debug("child pid=%d pasid=%d\n", child->pid, child->pasid);
	}

	for (i = 0; i < opts->nr_children; i++) {
		child = &shared_data->children[i];
		kill(child->pid, SIGINT);
	}
	smmute_device_close(&dev);

	munmap(shared_data, shared_data_size);

	return ret;

err_kill_children:
	pr_info("Kill all!\n");
	kill(0, SIGKILL);
	return EINVAL;
}

struct bind_thread_ctx {
	struct program_options *opts;
	pthread_cond_t parent_ready;
	pthread_cond_t thread_ready;
	pthread_mutex_t mutex;
	bool go;
	unsigned int nr_threads;
};

static void *bind_thread(void *ptr)
{
	int i;
	int ret;
	int pasid;
	void *buf;
	size_t buf_size = 0x7000;
	struct bind_thread_ctx *ctx = ptr;
	struct smmute_dev dev = {
		.backend = SMMUTE_BACKEND_KERNEL,
	};

	unsigned int attr = SMMUTE_ATTR_WBRAWA_SH;
	union smmute_transaction_params params = {
		.common.size = buf_size,
		.common.stride = 1,
		.common.seed = 1,
		.common.flags = SMMUTE_FLAG_SVA,
		.common.attr = SMMUTE_TRANSACTION_ATTR(attr, attr),
	};
	struct smmute_transaction_result result = {
		.blocking = true,
	};

	buf = malloc(buf_size);
	if (!buf)
		return (void *)(long)ENOMEM;

	params.common.input_start = (uint64_t)buf;

	ret = smmute_device_open(&dev, ctx->opts->dev_path, 0);
	if (ret)
		return (void *)(long)EINVAL;

	pthread_mutex_lock(&ctx->mutex);
	pr_debug("fork'd tid=%ld\n", syscall(SYS_gettid));
	ctx->nr_threads++;
	pthread_cond_signal(&ctx->thread_ready);
	while (!ctx->go)
		pthread_cond_wait(&ctx->parent_ready, &ctx->mutex);
	pthread_mutex_unlock(&ctx->mutex);

	/*
	 * All threads are doing bind/unbind in a loop. Since they all have the
	 * same mm, the smmute driver creates one task object and issues a
	 * single iommu_sva_bind call. The object is released when all threads
	 * have called smmute_unbind()
	 */
	for (i = 0; i < ctx->opts->nr_loops; i++) {
		ret = smmute_bind(&dev, &pasid);
		if (ret) {
			perror("bind failed");
			break;
		}

		ret = smmute_launch_transaction(&dev, SMMUTE_IOCTL_RAND48,
						&params);
		if (ret)
			break;
		result.transaction_id = params.common.transaction_id;

		ret = smmute_get_result(&dev, &result);
		if (ret)
			break;
		if (result.status != 0) {
			pr_err("transaction failed st=%x\n", result.status);
			ret = EFAULT;
			break;
		}

		ret = smmute_unbind(&dev, pasid);
		if (ret) {
			perror("unbind failed");
			break;
		}
	}

	free(buf);
	smmute_device_close(&dev);
	return (void *)(long)ret;
}

/*
 * Create tons of threads that all try to bind the device (via a different fd)
 */
static int test_bind_race(struct program_options *opts)
{
	int i, j;
	int ret = 0;
	void *thread_ret;
	pthread_t *threads;
	struct bind_thread_ctx ctx = {
		.opts = opts,
		.nr_threads = 0,
		.go = 0,
	};

	pr_debug("Testing bind race\n");

	threads = calloc(opts->nr_threads, sizeof(pthread_t));
	if (!threads)
		return ENOMEM;

	pthread_cond_init(&ctx.parent_ready, NULL);
	pthread_cond_init(&ctx.thread_ready, NULL);
	pthread_mutex_init(&ctx.mutex, NULL);

	for (i = 0; i < opts->nr_threads; i++) {
		if (pthread_create(&threads[i], NULL, bind_thread, &ctx)) {
			perror("pthread_create");
			break;
		}
	}

	/* All that just to synchronize the threads. */
	pthread_mutex_lock(&ctx.mutex);
	while (ctx.nr_threads < i) {
		struct timespec delay;

		clock_gettime(CLOCK_REALTIME, &delay);
		delay.tv_sec += 10;

		ret = pthread_cond_timedwait(&ctx.thread_ready, &ctx.mutex, &delay);

		/* See if one of the threads exited early */
		for (j = 0; ret == ETIMEDOUT && j < i; j++) {
			if (pthread_tryjoin_np(threads[j], &thread_ret) == 0) {
				pr_info("thread %d exited early\n", j);
				ret = (long)thread_ret;
				if (!ret)
					ret = EINVAL;
				break;
			}
		}

		if (ret && ret != ETIMEDOUT) {
			pthread_mutex_unlock(&ctx.mutex);
			return ret;
		}
	}
	pthread_mutex_unlock(&ctx.mutex);

	pr_debug("created %d threads\n", i);
	ctx.go = 1;
	pthread_cond_broadcast(&ctx.parent_ready);

	for (; i > 0; --i) {
		pthread_join(threads[i - 1], &thread_ret);
		ret |= (long)thread_ret;
	}

	free(threads);
	return ret;
}

static int parse_options(int argc, char **argv, struct program_options *opts)
{
	int ret;
	const char helpstr[] = "usage: %s [opts] [dev]\n\n"
"  -d                   display debug messages\n"
"  -h                   display this help\n"
"  -l <loops>           number of loops, where applicable\n"
"  -m <test>            choose test between 'bind', 'unbind'\n"
"  -f <children>        number of child processes, where applicable\n"
"  -t <threads>         number of threads, where applicable\n"
;

	optind = 1;
	opterr = 1;

	while ((ret = getopt(argc, argv, "df:hl:m:t:")) != -1) {
		switch (ret) {
		case 'd':
			loglevel = LOG_DEBUG;
			break;
		case 'f':
			if (parse_ul(optarg, &opts->nr_children))
				return 1;
			break;
		case 'l':
			if (parse_ul(optarg, &opts->nr_loops))
				return 1;
			break;
		case 'm':
			switch (optarg[0]) {
			case 'b':
				opts->test = TEST_BIND_RACE;
				break;
			case 'u':
				opts->test = TEST_UNBIND_EXIT_RACE;
				break;
			}
			break;
		case 't':
			if (parse_ul(optarg, &opts->nr_threads))
				return 1;
			break;
		case 'h':
		default:
			pr_err(helpstr, argv[0]);
			return 1;
		}
	}

	if (optind < argc)
		opts->dev_path = argv[optind];
	return 0;
}

int main(int argc, char **argv)
{
	int ret;
	struct program_options options = {
		.dev_path	= "/dev/smmute0",
		.nr_children	= NR_CHILDREN,
		.nr_threads	= NR_THREADS,
		.nr_loops	= NR_LOOPS,
		.test		= TEST_UNBIND_EXIT_RACE,
	};

	ret = parse_options(argc, argv, &options);
	if (ret)
		return ret;

	ret = smmute_backend_init(SMMUTE_BACKEND_KERNEL, NULL);
	if (ret)
		return ret;

	switch (options.test) {
	case TEST_UNBIND_EXIT_RACE:
		return test_unbind_exit_race(&options);
	case TEST_BIND_RACE:
		return test_bind_race(&options);
	}

	return EINVAL;
}
