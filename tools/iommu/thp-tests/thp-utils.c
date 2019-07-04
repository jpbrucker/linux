// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2014 Linaro Ltd.
 * Copyright (C) 2018 Arm Ltd.
 * authors: Steve Capper <steve.capper@linaro.org>
 *          Jean-Philippe Brucker <jean-philippe.brucker@arm.com>
 */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "thp-utils.h"

static unsigned long khugepaged_collapsed;
static unsigned long khugepaged_full_scans;

/*
 * How to flush the pagevec? I have yet to find a clean method. At the moment,
 * either use a test syscall (won't ever be in mainline) that calls
 * lru_add_drain_all, or mmap 15 new pages (leak)
 */
#define PAGEVEC_SIZE 15
void lru_sync(unsigned long mode)
{
	int i;
	int *page;

	if (mode == LRU_SYNC_MMAP) {
		for (i = 0; i < PAGEVEC_SIZE; i++) {
			page = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
				    MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
			*page = i;
		}
	} else {
		syscall(293, (unsigned long)0);
	}
}

/*
 * Return number of bytes of huge pages in the VMA containing address @addr
 */
ssize_t nr_huge(void *addr)
{
	int retval = 0, inrange = 0;
	char *line = NULL;
	size_t length = 0;
	FILE *smaps;

	smaps = fopen("/proc/self/smaps", "r");
	if (!smaps) {
		perror("Unable to open smaps");
		return 0;
	}

	while (getline(&line, &length, smaps) > 0) {
		void *r1, *r2;
		if (sscanf(line, "%p-%p", &r1, &r2) == 2) {
			inrange = (r1 == addr);
		} else if (inrange) {
			int hugekbs;
			if (sscanf(line, "AnonHugePages: %d", &hugekbs) == 1) {
				retval = hugekbs << 10;
				goto close;
			}
		}
	}

close:
	fclose(smaps);
	if (line)
		free(line);
	return retval;
}

uint8_t *map_huge_memory(void *mapaddr, size_t memsize)
{
        uint8_t *mem;
        int ret;

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE     0x100000
#endif
        mem = mmap(mapaddr, memsize, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, 0, 0);

        if (mem == MAP_FAILED) {
                perror("Unable to map memory");
                return NULL;
        }

        ret = madvise(mem, memsize, MADV_HUGEPAGE);
        if (ret) {
                perror("Unable to madvise memory");
                return NULL;
        }

        return mem;
}

uint8_t *map_and_set_memory(void *mapaddr, size_t memsize)
{
        uint8_t *mem;

        mem = map_huge_memory(mapaddr, memsize);
        if (!mem)
                return NULL;

	mem[0] = 1;

        return mem;
}

/* Tweak khugepaged parameters. Global and sticky. TODO: restore params */
int khugepaged_init(void)
{
	FILE *file;
	unsigned long scan_sleep;
	unsigned long max_ptes_none;
	unsigned long new_scan_sleep = 10; // ms
	unsigned long new_max_ptes_none = 128;

	file = fopen("/sys/kernel/mm/transparent_hugepage/enabled", "w");
	if (!file)
		return 1;
	if (fprintf(file, "always") < 6)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/defrag", "w");
	if (!file)
		return 1;
	if (fprintf(file, "always") < 6)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_millisecs",
		     "r+");
	if (!file)
		return 1;
	if (fscanf(file, "%lu", &scan_sleep) != 1)
		return 1;
	fseek(file, 0, SEEK_SET);
	if (fprintf(file, "%lu", new_scan_sleep) < 2)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/max_ptes_none", "r+");
	if (!file)
		return 1;
	if (fscanf(file, "%lu", &max_ptes_none) != 1)
		return 1;
	fseek(file, 0, SEEK_SET);
	if (fprintf(file, "%lu", new_max_ptes_none) < 3)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/pages_collapsed", "r");
	if (fscanf(file, "%lu", &khugepaged_collapsed) != 1)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/full_scans", "r");
	if (fscanf(file, "%lu", &khugepaged_full_scans) != 1)
		return 1;
	fclose(file);

	if (scan_sleep != new_scan_sleep)
		pr_debug("scan_sleep was %lu, now %lu\n", scan_sleep,
			 new_scan_sleep);

	if (max_ptes_none != new_max_ptes_none)
		pr_debug("max_ptes_none was %lu, now %lu\n", max_ptes_none,
			 new_max_ptes_none);

	return 0;
}

int khugepaged_stats(void)
{
	FILE *file;
	unsigned long collapsed, full_scans;

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/pages_collapsed", "r");
	if (fscanf(file, "%lu", &collapsed) != 1)
		return 1;
	fclose(file);

	file = fopen("/sys/kernel/mm/transparent_hugepage/khugepaged/full_scans", "r");
	if (fscanf(file, "%lu", &full_scans) != 1)
		return 1;
	fclose(file);

	pr_info("Collapsed: %lu\n", collapsed - khugepaged_collapsed);
	pr_info("Full scans: %lu\n", full_scans - khugepaged_full_scans);

	return 0;
}
