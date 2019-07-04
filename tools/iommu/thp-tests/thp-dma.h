#ifndef __THP_DMA_H_
#define __THP_DMA_H_

#include <stdint.h>
#include <stdlib.h>

extern int dev_init(void);

/* Bind current process to device */
extern int sva_bind(void);
extern void sva_unbind(void);

/*
 * Perform N = (dma_size / stride) writes from the device, in random order.
 * Return 0 on success, or the faulting address.
 */
extern uint64_t dma_range(void *dma_start, size_t dma_size, size_t stride);

#endif
