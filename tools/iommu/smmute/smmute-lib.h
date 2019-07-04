#ifndef _SMMUTE_LIB_H
#define _SMMUTE_LIB_H

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <linux/smmu-test-engine.h>

#define PAGE_SIZE		sysconf(_SC_PAGE_SIZE)

#ifndef dma_addr_t
#define dma_addr_t		unsigned long long
#endif

/*
 * Logging stuff
 */
enum loglevel {
	LOG_NONE	= 0,
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
};
extern enum loglevel loglevel;

#ifndef STREAM_OUT
#define STREAM_OUT		stdout
#endif
#ifndef STREAM_ERR
#define STREAM_ERR		stderr
#endif

#ifndef LOG_PREFIX
#define LOG_PREFIX
#endif

#define log_msg(stream, min_level, fmt, ...)					\
	do {									\
		if (loglevel >= (min_level))					\
			fprintf((stream), LOG_PREFIX fmt, ##__VA_ARGS__);	\
	} while (0)

#define pr_debug(fmt, ...)	log_msg(STREAM_OUT, LOG_DEBUG, fmt, ##__VA_ARGS__)
#define pr_info(fmt, ...)	log_msg(STREAM_OUT, LOG_INFO,  fmt, ##__VA_ARGS__)
#define pr_warn(fmt, ...)	log_msg(STREAM_ERR, LOG_WARN,  fmt, ##__VA_ARGS__)
#define pr_err(fmt, ...)	log_msg(STREAM_ERR, LOG_ERROR, fmt, ##__VA_ARGS__)

/* Buffer allocation parameters */
#define UNIFIED_MEM_NONE	0x0000
#define UNIFIED_MEM_MALLOC	0x0001
#define UNIFIED_MEM_MMAP	0x0002
#define UNIFIED_MEM_STACK	0x0004

#define UNIFIED_MEM_MODE_MASK	0x0007

#define UNIFIED_MEM_LOCK	0x0100
#define UNIFIED_MEM_IN_FILE	0x0200
#define UNIFIED_MEM_OUT_FILE	0x0400
#define UNIFIED_MEM_ADV_RAND	0x0800
#define UNIFIED_MEM_ADV_SEQ	0x1000
#define UNIFIED_MEM_ADV_WNEED	0x2000
#define UNIFIED_MEM_ADV_DNEED	0x4000

#define UNIFIED_MEM_FLAGS_MASK	0x7f00

#define	UNIFIED_MEM_MODE(v) ((v) & UNIFIED_MEM_MODE_MASK)

struct smmute_mem_options {
	/* UNIFIED_MEM* flags */
	unsigned long			unified;

	/* mmap parameters */
	char				*in_file_path;
	char				*out_file_path;
	int				in_file;
	int				out_file;
};

/* Buffer allocation helpers */
void *smmute_lib_alloc_buffer(int fd, size_t size, int prot,
			      struct smmute_mem_options *opts);

void smmute_lib_free_buffer(void *buf, size_t size,
			    struct smmute_mem_options *opts);


/*
 * Common smmute client API
 * These function redirect the call to the selected backend, either kernel driver
 * or vfio.
 */

enum smmute_backend {
	SMMUTE_BACKEND_NONE,
	SMMUTE_BACKEND_KERNEL,

	SMMUTE_NR_BACKENDS
};

struct smmute_backend_options {
	int				flags;
};

struct smmute_dev;

struct smmute_device_ops {
	int (*init)(struct smmute_backend_options *opts);
	void (*exit)(void);

	int (*open)(struct smmute_dev *, const char *path, int flags);
	void (*close)(struct smmute_dev *);

	int (*bind)(struct smmute_dev *);
	int (*unbind)(struct smmute_dev *);

	void *(*alloc_buffer)(struct smmute_dev *, size_t size, int prot,
			      struct smmute_mem_options *opts);
	void (*free_buffer)(struct smmute_dev *, void *va, size_t size,
			    struct smmute_mem_options *opts);

	int (*map_buffer)(struct smmute_dev *, void *va, dma_addr_t *iova,
			  size_t size, int prot, struct smmute_mem_options *opts);
	int (*unmap_buffer)(struct smmute_dev *, void *buf, dma_addr_t iova,
			    size_t size, struct smmute_mem_options *opts);

	int (*launch_transaction)(struct smmute_dev *, int cmd,
				  union smmute_transaction_params *params);

	int (*get_result)(struct smmute_dev *,struct smmute_transaction_result *params);
};

struct smmute_dev {
	enum smmute_backend		backend;

	/* Backend ops */
	struct smmute_device_ops	*ops;

	/* Data private to the backend */
	void				*private;
};

int smmute_backend_init(enum smmute_backend, struct smmute_backend_options *opts);
void smmute_backend_exit(enum smmute_backend);

int smmute_device_open(struct smmute_dev *, const char *path, int flags);
void smmute_device_close(struct smmute_dev *);

static inline int smmute_bind(struct smmute_dev *dev)
{
	if (dev->ops && dev->ops->bind)
		return dev->ops->bind(dev);

	return ENODEV;
}

static inline int smmute_unbind(struct smmute_dev *dev)
{
	if (dev->ops && dev->ops->unbind)
		return dev->ops->unbind(dev);

	return ENODEV;
}

/*
 * We have to use a macro wrapper, since buffers allocated with alloca are freed
 * when leaving the caller
 */
#define smmute_alloc_buffer(dev, size, prot, opts)				\
	({									\
		void *__buf = NULL;						\
		if ((dev)->ops && (dev)->ops->alloc_buffer) {			\
			if ((opts)->unified & UNIFIED_MEM_STACK)		\
				__buf = alloca(size);				\
			else							\
				__buf = (dev)->ops->alloc_buffer(dev, size,	\
								 prot, opts);	\
		}								\
		__buf;								\
	})

static inline void smmute_free_buffer(struct smmute_dev *dev, void *va,
				      size_t size, struct smmute_mem_options *opts)
{
	if (dev->ops && dev->ops->free_buffer)
		dev->ops->free_buffer(dev, va, size, opts);
}

/**
 * Map a buffer previously allocated with smmute_alloc_buffer
 *
 * @va: address of the allocated buffer
 * @iova: output DMA address
 * @size: size of the buffer, must be the same as allocation
 * @prot: protections flags, as mmap
 *
 * On success, return 0 and fill in the iova. It might be the same as va
 * depending on the backend and the opts.
 */
static inline int smmute_dma_map_buffer(struct smmute_dev *dev, void *va,
					dma_addr_t *iova, size_t size, int prot,
					struct smmute_mem_options *opts)
{
	if (!dev->ops || !dev->ops->map_buffer)
		return ENODEV;

	return dev->ops->map_buffer(dev, va, iova, size, prot, opts);
}

static inline int smmute_dma_unmap_buffer(struct smmute_dev *dev, void *va,
					  dma_addr_t iova, size_t size,
					  struct smmute_mem_options *opts)
{
	if (!dev->ops || !dev->ops->unmap_buffer)
		return ENODEV;

	return dev->ops->unmap_buffer(dev, va, iova, size, opts);
}

static inline int smmute_launch_transaction(struct smmute_dev *dev, int cmd,
					    union smmute_transaction_params *params)
{
	if (dev->ops && dev->ops->launch_transaction)
		return dev->ops->launch_transaction(dev, cmd, params);

	return ENODEV;
}

static inline int smmute_get_result(struct smmute_dev *dev,
				    struct smmute_transaction_result *result)
{
	if (dev->ops && dev->ops->get_result)
		return dev->ops->get_result(dev, result);

	return ENODEV;
}

#endif /* _SMMUTE_LIB_H */
