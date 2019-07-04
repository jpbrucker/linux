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
	pthread_t		thread;
	int			pasid;
	int			ret;
};

/*
 * Max number of bindable tasks are generally limited by the number of ASIDs. At
 * two 8-bit ASIDs per task, minus some reserve for the allocator, that would be
 * 118 tasks. 16-bit ASIDs allow a lot more.
 */
#define NR_CHILDREN	32
#define NR_THREADS	32
#define NR_LOOPS	32

static struct smmute_bind_child *children;

static void *kill_unbind_child(void *arg)
{
	struct smmute_bind_child *child = arg;

	kill(child->pid, SIGINT);
//	usleep(5000);
	child->ret = smmute_unbind(child->dev, child->pid, child->pasid);
	if (child->ret)
		pr_warn("unbind %d failed with %d\n", child->pid, child->ret);

	return NULL;
}

static int test_unbind_exit_race(struct program_options *opts)
{
	int i;
	int ret;
	pid_t pid;
	struct smmute_bind_child *child;
	struct smmute_dev dev = {
		.backend = SMMUTE_BACKEND_KERNEL,
	};

	pr_debug("Testing unbind race with %u children\n", opts->nr_children);
	ret = smmute_device_open(&dev, opts->dev_path, 0);
	if (ret) {
		pr_err("Could not open '%s'\n", opts->dev_path);
		return ret;
	}

	/* Fork a process, bind it, kill it, unbind it */
	children = calloc(opts->nr_children, sizeof(children[0]));
	if (!children)
		return ENOMEM;

	for (i = 0; i < opts->nr_children; i++) {
		pid = fork();

		if (pid < 0) {
			goto err_kill_children;
		} else if (pid == 0) {
			/* Child process idles */
			while (true)
				asm volatile ("wfe" ::: "memory");
			return 0;
		}

		/* Parent process */
		child = &children[i];
		child->pid = pid;
		child->dev = &dev;

		ret = smmute_bind(&dev, pid, &child->pasid);
		if (ret) {
			pr_warn("bind %d failed with %d\n", i, ret);
			goto err_kill_children;
		}
		pr_debug("child pid=%d pasid=%d\n", child->pid, child->pasid);
	}

	for (i = 0; i < opts->nr_children; i++) {
		child = &children[i];
		pthread_create(&child->thread, NULL, kill_unbind_child, child);
	}

	for (i = 0; i < opts->nr_children; i++) {
		child = &children[i];
		pthread_join(child->thread, NULL);
		ret |= child->ret;
	}

	free(children);
	sleep(5);

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
		ret = smmute_bind(&dev, -1, &pasid);
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

		ret = smmute_unbind(&dev, -1, pasid);
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
