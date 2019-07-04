// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "thp-utils.h"
#include "thp-dma.h"

#define BUF_BASE ((void *)0x10000000)

/* parse_long(const char *optarg, unsigned/signed long *dest) */
#define _parse_long(optarg, dest, fn)				\
({								\
	errno = 0;						\
	char *__endptr = (optarg);				\
	*(dest) = fn((optarg), &__endptr, 0);			\
	if (errno || __endptr == (optarg))			\
		pr_err("invalid number '%s'\n", (optarg));	\
	errno || __endptr == (optarg);				\
})

#define parse_ul(optarg, dest) _parse_long(optarg, dest, strtoul)

struct program_options {
	size_t		nr_children;
	size_t		nr_hugepages;
	size_t		nr_loops;
	size_t		test_nr;
	size_t		subtest_nr;
	int		lru_sync;
};
typedef int (*test_fn_t)(struct program_options *opts);

static int run_test(size_t test_nr, struct program_options *opts, bool header);

/*
 * Calling map_huge_memory alone would immediately allocate a huge page on the
 * first fault. Here we want khugepaged to find this range and collapse it, so
 * map and set pages one by one. We can't do bigger chunks because khugepaged
 * doesn't work with compound pages.
 *
 * When @half is set, only initialize half the pages. If
 * /sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none is less than
 * 256, then khugepaged won't collapse the pages until someone faults in the
 * missing pages.
 */
static int map_huge_single(void *buf, size_t nr_pages, bool half)
{
	int i;
	void *page;

	for (i = 0; i < nr_pages; i++) {
		if (half && i % 2)
			/* Create a pte_none entry */
			page = map_huge_memory(buf + PAGE(i), PAGE_SIZE);
		else
			/* Map and allocate the page immediately */
			page = map_and_set_memory(buf + PAGE(i), PAGE_SIZE);
		if (!page)
			return 1;
	}

	return 0;
}


/*
 * Check that THP is supported, by doing a fixed mmap and checking that it
 * results in a huge page allocation.
 */
static int test_1(struct program_options *opts)
{
	uint8_t *buf;
	size_t buf_size = HPAGE_SIZE;
	void *buf_base = BUF_BASE;

	if (sva_bind())
		return 1;

	/*
	 * Map some anonymous memory, but don't populate yet. Even without the
	 * madvise(HUGE), the kernel will allocate a huge pmd on first fault
	 * since /sys/kernel/mm/transparent_hugepage/enabled is 'always'.
	 */
	buf = map_huge_memory(buf_base, buf_size);
	if (!buf)
		return 1;

	if (nr_huge(buf))
		pr_err("buf is already huge!\n");

	/* Increase thp_fault_alloc from DMA */
	dma_range(buf_base, buf_size, PAGE_SIZE);

	if (nr_huge(buf) != buf_size) {
		pr_err("THP not enabled\n");
		return 1;
	}

	pr_debug("THP is supported\n");
	munmap(buf, buf_size);
	sva_unbind();
	return 0;
}

/*
 * Check that unmapping a fragment of huge page causes a split
 */
static int test_2(struct program_options *opts)
{
	uint8_t *buf;
	size_t buf_size = HPAGE_SIZE;
	void *buf_base = BUF_BASE;

	buf = map_and_set_memory(buf_base, buf_size);
	if (!buf)
		return 1;

	if (nr_huge(buf) != buf_size) {
		pr_err("THP didn't alloc\n");
		return 1;
	}

	/* This should do a thp_split_pmd */
	munmap(buf + PAGE_SIZE, buf_size - PAGE_SIZE);

	if (nr_huge(buf)) {
		pr_err("pmd didn't split\n");
		return 1;
	}
	munmap(buf, buf_size);
	return 0;
}

/* Create fragments of a huge page, and let khugepaged collapse them */
static int test_3(struct program_options *opts)
{
	ssize_t page;
	size_t buf_size = HPAGE_SIZE;
	size_t buf_pages = buf_size >> PAGE_SHIFT;
	void *buf = BUF_BASE;

	/* Create small pages */
	if (map_huge_single(buf, buf_pages, false))
		return 1;

	/*
	 * Since mm adds pages to the LRU by pagevec batch, make sure that the
	 * pagevec containing the last few pages of 0x200000000-0x20200000 is
	 * committed by __lru_cache_add. To be collapsable, pages must have the
	 * LRU bit.
	 */
	lru_sync(opts->lru_sync);

	page = 0;
	while (nr_huge(buf) < buf_size) {
		/* Keep pages young. */
		*(volatile uint8_t *)(buf + PAGE(page)) = page;
		page = (page + 1) % buf_pages;
	}

	munmap(buf, buf_size);
	return 0;
}

/*
 * Basically the same as test 3, but let DMA cause the collapsing.
 * khugepaged_init sets max_ptes_none to a suitable value, ensuring that the
 * pages don't get collapsed prematurely.
 */
static int test_4(struct program_options *opts)
{
	int ret;
	size_t buf_size = opts->nr_hugepages * HPAGE_SIZE;
	size_t buf_pages = buf_size >> PAGE_SHIFT;
	void *buf = BUF_BASE;

	if (sva_bind())
		return 1;

	/* Only map half of the pages, to delay collapsing */
	if (map_huge_single(buf, buf_pages, true))
		return 1;

	if (nr_huge(buf)) {
		pr_err("Huge pages already allocated?\n");
		return 1;
	}

	while (nr_huge(buf) < buf_size) {
		ret = dma_range(buf, buf_size, PAGE_SIZE);
		if (ret)
			return ret;

		lru_sync(opts->lru_sync);
	}

	munmap(buf, buf_size);
	sva_unbind();
	return 0;
}

/* Ok that was fun. Now let's try it with N children */
int test_5(struct program_options *opts)
{
	int i;
	int wstatus;
	pid_t pid;
	int nr_success = 0;
	int nr_failures = 0;

	if (opts->subtest_nr == opts->test_nr)
		return -EINVAL;

	for (i = 0; i < opts->nr_children; i++) {
		pid = fork();
		if (pid < 0) {
			perror("fork");
			break;
		}

		if (pid > 0)
			continue;

		/* Child */
		exit(run_test(opts->subtest_nr, opts, false));
	}

	for (; i > 0; i--) {
		pid = waitpid(-1, &wstatus, 0);
		if (WIFEXITED(wstatus)) {
			pr_debug("child %d exited with %d\n", pid,
				 WEXITSTATUS(wstatus));
			if (WEXITSTATUS(wstatus) == 0)
				nr_success++;
			else
				nr_failures++;
		} else if (WIFSIGNALED(wstatus)) {
			pr_debug("child %d killed by %d\n", pid,
				 WTERMSIG(wstatus));
			nr_failures++;
		} else {
			pr_err("unhandled signal\n");
			nr_failures++;
		}
	}
	pr_info("%d success, %d failures\n", nr_success, nr_failures);
	return 0;
}

struct dma_param {
	void		*buf;
	size_t		buf_size;
	pthread_mutex_t	mutex;
	pthread_cond_t	cond;
	off_t		invalid_page;
	bool		run;
};

/* Launch DMA in the background */
static void *dma_thread_fn(void *arg)
{
	uint64_t fault_addr;
	struct dma_param *param = arg;

	sva_bind();

	pthread_mutex_lock(&param->mutex);
	while (!param->run)
		pthread_cond_wait(&param->cond, &param->mutex);
	pthread_mutex_unlock(&param->mutex);

	while (param->run) {
		pthread_mutex_lock(&param->mutex);
		fault_addr = dma_range(param->buf, param->buf_size, PAGE_SIZE);

		/*
		 * Parent unmaps stuff under our nose. Only exit when the
		 * mappings were supposed to be valid
		 */
		if (fault_addr && (fault_addr % HPAGE_SIZE) >> PAGE_SHIFT ==
		    param->invalid_page)
			fault_addr = 0;
		pthread_mutex_unlock(&param->mutex);

		if (fault_addr) {
			pr_err("DMA fault at 0x%lx\n", fault_addr);
			return NULL;
		}
	}

	sva_unbind();
	return NULL;
}

/*
 * A bit heavier: split, collapse, split, collapse in a loop, with DMA launched
 * in the background. Use $0 -t 5 -s 6 to run this in multiple processes.
 */
static int test_6(struct program_options *opts)
{
	int i, j, ret;
	pthread_t dma_thread;
	size_t buf_size = opts->nr_hugepages * HPAGE_SIZE;
	size_t buf_pages = buf_size >> PAGE_SHIFT;
	void *buf = BUF_BASE;
	struct dma_param dma_param = {
		.buf		= buf,
		.buf_size	= buf_size,
		.mutex		= PTHREAD_MUTEX_INITIALIZER,
		.cond		= PTHREAD_COND_INITIALIZER,
		.run		= false,
	};

	/* Start a thread that launches DMA for each small page. */
	ret = pthread_create(&dma_thread, NULL, dma_thread_fn, &dma_param);
	if (ret)
		return 1;

	srand48(1);
	pthread_mutex_lock(&dma_param.mutex);
	dma_param.run = true;
	for (i = 0; i < opts->nr_loops; i++) {
		map_huge_single(buf, buf_pages, true);
		pthread_mutex_unlock(&dma_param.mutex);

		while (nr_huge(buf) < buf_size) {
			void *retval;

			lru_sync(opts->lru_sync);
			usleep(1000);

			if (!pthread_tryjoin_np(dma_thread, &retval)) {
				pr_err("thread exited!\n");
				return 1;
			}
		}

		/* Now split the huge page */
		pr_info("split\n");

		pthread_mutex_lock(&dma_param.mutex);
		dma_param.invalid_page = lrand48() % (HPAGE_SIZE / PAGE_SIZE);
		for (j = 0; j < opts->nr_hugepages; j++) {
			munmap(buf + HPAGE(j) + PAGE(dma_param.invalid_page),
			       PAGE_SIZE);
		}
		pthread_mutex_unlock(&dma_param.mutex);

		while (nr_huge(buf))
			usleep(1000);

		usleep(50000);

		pr_info("merge\n");

		/*
		 * Unfortunately the remaining pages are still backed by the
		 * compound page allocated earlier, which khugepaged will
		 * ignore. We need to unmap everything and restart.
		 */
		pthread_mutex_lock(&dma_param.mutex);
		dma_param.invalid_page = -1U;

		munmap(buf, buf_size);
	}

	dma_param.run = false;
	/* prevent faults while we wait for the dma thread to finish */
	map_huge_memory(buf, buf_size);
	pthread_mutex_unlock(&dma_param.mutex);

	pthread_join(dma_thread, NULL);

	return 0;
}

int parse_args(int argc, char **argv, struct program_options *opts)
{
	int opt;

	/* optind, opterr, optopt and optarg are defined in unistd */
	optind = 1;
	/* Print error messages */
	opterr = 1;

	while ((opt = getopt(argc, argv, "hf:l:n:s:t:")) != -1) {
		switch (opt) {
		case 'f':
			if (parse_ul(optarg, &opts->nr_children))
				return 1;
			break;
		case 'l':
			if (parse_ul(optarg, &opts->nr_loops))
				return 1;
			break;
		case 'n':
			if (parse_ul(optarg, &opts->nr_hugepages))
				return 1;
			break;
		case 's':
			if (parse_ul(optarg, &opts->subtest_nr))
				return 1;
			break;
		case 't':
			if (parse_ul(optarg, &opts->test_nr))
				return 1;
			break;
		case 'h':
		default:
			pr_info("Usage: %s [opts]\n\n", argv[0]);
			pr_info("  -h		print this help\n");
			pr_info("  -f <n>	number of children (where applicable)\n");
			pr_info("  -l <n>	number of loops (where applicable)\n");
			pr_info("  -n <n>	number of huge pages (where applicable)\n");
			pr_info("  -s <n>	subtest number (default 4)\n");
			pr_info("  -t <n>	test number (default 0: all)\n");
			return 1;
		}
	}

	return 0;
}

static test_fn_t tests[] = {
	NULL, // wildcard
	test_1,
	test_2,
	test_3,
	test_4,
	test_5,
	test_6,
};
#define NR_TESTS (sizeof(tests) / sizeof(tests[0]))

static int run_test(size_t test_nr, struct program_options *opts, bool header)
{
	if (!test_nr || test_nr >= NR_TESTS) {
		pr_err("no test %zu\n", test_nr);
		return EINVAL;
	}

	if (header)
		pr_info("========== TEST %zu ==========\n", test_nr);
	return tests[test_nr](opts);
}

int main(int argc, char **argv)
{
	int ret, i;
	struct program_options opts = {
		.subtest_nr	= 4, /* test 5 launches test 4 by default */
		.nr_children	= 4,
		.nr_hugepages	= 4,
		.nr_loops	= 4,
		.lru_sync	= LRU_SYNC_SYSCALL,
	};

	khugepaged_init();

	if (dev_init())
		return ENODEV;

	if (parse_args(argc, argv, &opts))
		return EINVAL;

	if (opts.test_nr) {
		ret = run_test(opts.test_nr, &opts, true);
	} else {
		for (i = 1; i < NR_TESTS; i++) {
			ret = run_test(i, &opts, true);
			if (ret)
				break;
		}
	}

	khugepaged_stats();

	return ret;
}
