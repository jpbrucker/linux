/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2014 Linaro Ltd.
 * Copyright (C) 2018 Arm Ltd.
 * authors: Steve Capper <steve.capper@linaro.org>
 *	    Jean-Philippe Brucker <jean-philippe.brucker@arm.com>
 */
#ifndef THP_UTILS_H_
#define THP_UTILS_H_

#include <linux/log2.h>

#ifdef DEBUG
#define pr_debug	printf
#else
#define pr_debug(...)
#endif
#define pr_info		printf
#define pr_err		printf

#ifndef PAGE_SIZE
#define PAGE_SIZE	sysconf(_SC_PAGE_SIZE)
#endif
#define PAGE_SHIFT	ilog2(PAGE_SIZE)
#define HPAGE_SIZE	(PAGE_SIZE == 0x00001000 ? 0x00200000 : \
			 PAGE_SIZE == 0x00004000 ? 0x02000000 : \
						   0x20000000)
#define HPAGE_SHIFT	ilog2(HPAGE_SIZE)

#define PAGE(n)		((uint64_t)(n) << PAGE_SHIFT)
#define HPAGE(n)	((uint64_t)(n) << HPAGE_SHIFT)

#define LRU_SYNC_SYSCALL	1
#define LRU_SYNC_MMAP		2

void lru_sync(unsigned long mode);
uint8_t *map_huge_memory(void *mapaddr, size_t memsize);
uint8_t *map_and_set_memory(void *mapaddr, size_t memsize);
ssize_t nr_huge(void *addr);

int khugepaged_init(void);
int khugepaged_stats(void);

#endif
