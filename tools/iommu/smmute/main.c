#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "smmute-lib.h"

static void print_help(char *progname)
{
	pr_err(
"Usage: %s [opts] [/dev/smmuteX]                                           \n"
"Control the SMMU test engine driver                                     \n\n"
"  OPTION           DESCRIPTION                                     DEFAULT\n"
"  -b <backend>     backend (driver): k[ernel]                       kernel\n"
"  -c               check buffer values                                    \n"
"  -d               debug - print additional messages                      \n"
"  -f <mode>        fault - inject a fault                                 \n"
"                   <mode> tells where to inject the fault:                \n"
"                    * read (invalid read access)                          \n"
"                    * write (invalid write access)                        \n"
"                    * drv (let kernel driver generate a translation fault)\n"
"                    * tlb (buffer is unreachable after unmap)             \n"
"                    * pasid (buffer is unreachable after unbind)          \n"
"  -g <n>           seed for mmap hints and init values                   0\n"
"  -k <when|how>    Simulate a bug by killing self.                        \n"
"                   <when> is required, and tells at which point to die    \n"
"                    * bind: after binding, trigger exit_mm                \n"
"                    * tsac: after launching the transaction, die          \n"
"                   <how> tells which signal to send:                      \n"
"                    * int: SIGINT (the default)                           \n"
"                    * segv: SIGSEGV                                       \n"
"  -m m/r/s/p       mode: memcpy, rand48, sum64 or p2p                    m\n"
"  -n <n>           number of transactions                                1\n"
"  -o <n>           offset into input and output DMA regions              0\n"
"  -q               quiet - only print errors                              \n"
"  -r <n>           number of repetitions per transaction                 1\n"
"  -s <n>           size of the transaction in bytes              PAGE_SIZE\n"
"  -t <n>           sleep duration between repetitions, in seconds        0\n"
"  -u <mode>[,<flags>]                                                     \n"
"                   unified address space - share page tables and pass     \n"
"                   userspace pointers to the device.                      \n"
"                   <mode> is the method used to allocate buffers:         \n"
"                    * malloc                                              \n"
"                    * mmap                                                \n"
"                    * stack - using alloca                                \n"
"                   <flags> may be one of                                  \n"
"                    * lock - mlock mmap'd buffers (no major write fault)  \n"
"                    * in_file=<file> - file-backed mmap for input buffers \n"
"                    * out_file=<file> - ditto, for output buffers         \n",
	progname);
}

static const char *optstring = "b:cdf:g:k:m:n:o:qr:s:t:u:h";

enum loglevel loglevel = LOG_INFO;

enum transaction_type {
	MEMCPY,
	RAND48,
	SUM64,
	P2P,
};

#define INJECT_FAULT_READ		(1 << 0)
#define INJECT_FAULT_WRITE		(1 << 1)
#define INJECT_FAULT_TLB		(1 << 2)
#define INJECT_FAULT_PASID		(1 << 3)
#define INJECT_FAULT_DRIVER		(1 << 4)

#define KILL_BIND			1
#define KILL_TSAC			2

struct program_options {
	enum smmute_backend		backend;
	char				*device;
	enum transaction_type		transaction_type;
	size_t				size;
	off_t				offset;
	size_t				nr_transactions;
	size_t				nr_repetitions;

	size_t				seed;
	unsigned int			sleep_time;

	bool				check_buffers;

	/* INJECT_FAULT_* */
	unsigned int			fault;
	unsigned int			kill;
	unsigned int			kill_sig;

	struct smmute_mem_options	mem;
};

static int get_cmd(enum transaction_type type)
{
	switch (type) {
	case MEMCPY:
		return SMMUTE_IOCTL_MEMCPY;
	case RAND48:
		return SMMUTE_IOCTL_RAND48;
	case SUM64:
		return SMMUTE_IOCTL_SUM64;
	case P2P:
		return SMMUTE_IOCTL_P2P;
	default:
		pr_err("invalid type %d\n", type);
		return -1;
	}
}

/* Number of hex digits needed to represent len */
static unsigned int nr_digits(unsigned long len)
{
	const unsigned int bits_per_long = sizeof(unsigned long) << 3;
	unsigned long lz;

	asm volatile ("clz %0, %1" : "=r" (lz) : "r" (len));

	return 1 + ((bits_per_long - 1 - lz) >> 2);
}

static void hexdump(char *buf, int index_digits, size_t start, size_t len)
{
	size_t i;
	const size_t rows = 16;
	const size_t iter_start = start & ~(rows - 1);

	for (i = iter_start; i < len; i++) {
		if ((i % rows) == 0) {
			if (i != iter_start)
				pr_info("\n");
			pr_info("%.*zx: ", index_digits, i);
		}
		if (i < start)
			pr_info("   ");
		else
			pr_info("%02x ", buf[i]);
	}
	if ((i - 1) % rows)
		pr_info("\n");
}

static void hexdump_ellipsis(char *buf, size_t buf_len, size_t print_len)
{
	const int index_digits = nr_digits(buf_len);

	if (buf_len <= 2 * print_len) {
		hexdump(buf, index_digits, 0, buf_len);
		return;
	}

	hexdump(buf, index_digits, 0, print_len);
	pr_info(" ...\n");
	hexdump(buf, index_digits, buf_len - print_len, buf_len);
}

/*
 * Of course switching buffer permissions back and forth isn't efficient, but
 * this program is about correctness and exercising as much as possible the mm
 * subsystem.
 */
static int mprotect_buffer(void *buf, off_t offset,
			   struct program_options *opts, int prot)
{
	int ret;
	bool is_mmap = !(UNIFIED_MEM_MODE(opts->mem.unified) & ~UNIFIED_MEM_MMAP);

	/* Can't use mprotect on a buffer that wasn't reserved with mmap */
	if (!buf || !is_mmap)
		return 0;

	ret = mprotect(buf, offset + opts->size, prot);
	if (ret)
		perror("mprotect");
	return ret;
}

static int madvise_buffer(void *buf, off_t offset,
			  struct program_options *opts, bool output)
{
	int madvise_flags = 0; /* MADV_NORMAL */
	int unified = opts->mem.unified;

	if (!buf)
		return 0;

	if (unified & UNIFIED_MEM_ADV_RAND) {
		madvise_flags = MADV_RANDOM;
	} else if (unified & UNIFIED_MEM_ADV_SEQ) {
		madvise_flags = MADV_SEQUENTIAL;
	} else if (unified & UNIFIED_MEM_ADV_WNEED) {
		madvise_flags = MADV_WILLNEED;
	} else if (unified & UNIFIED_MEM_ADV_DNEED) {
		/* we don't want to thrash an initialised anonymous mapping */
		if (output || opts->mem.in_file != -1)
			madvise_flags |= MADV_DONTNEED;
	}

	if (madvise_flags && madvise(buf, offset + opts->size, madvise_flags))
		pr_warn("madvise failed with %d - %s\n", errno, strerror(errno));

	return 0;
}

static int init_buffers(char *in_buf, off_t in_offset, char *out_buf,
			off_t out_offset, struct program_options *opts)
{
	int i;
	int ret;

	if (opts->mem.in_file_path)
		/* buffer is already PROT_READ */
		return 0;

	ret = mprotect_buffer(in_buf, in_offset, opts, PROT_READ | PROT_WRITE);
	if (ret)
		return ret;

	/* Poison the areas that shouldn't be read from/written to. */
	if (opts->check_buffers && in_buf) {
		for (i = 0; i < in_offset; i++)
			in_buf[i] = 0xa;
	}

	if (opts->check_buffers && out_buf) {
		for (i = 0; i < out_offset; i++)
			out_buf[i] = 0x5;
	}

	switch (opts->transaction_type) {
	case MEMCPY:
		for (i = 0; i < opts->size; i++)
			in_buf[i + in_offset] = (char)i - opts->seed;
		break;
	case SUM64:
		/* with this, sum(region) == size */
		for (i = 0; i < opts->size / sizeof(unsigned long); i++) {
			unsigned long *buf = (void *)in_buf + in_offset;
			buf[i] = 1;
		}
		break;
	case P2P:
		*(unsigned long *)(in_buf + in_offset) = 0x0;
		/*
		 * Second command overwrites the input buffer, so don't remove
		 * PROT_WRITE.
		 */
		return 0;
	default:
		break;
	}

	return mprotect_buffer(in_buf, in_offset, opts, PROT_READ);
}

static unsigned long long smmute_random_seed(unsigned int seed)
{
	/* srand48(seed) */
	return seed << 16 | 0x330e;
}

static unsigned int smmute_random(unsigned long long *storage)
{
	unsigned int tmp;

	/* lrand48() */
	*storage = (*storage * 0x00000005deece66d + 0xb) & 0x0000ffffffffffff;
	tmp = (*storage >> 17) & 0x7fffffff;

	*storage = (*storage * 0x00000005deece66d + 0xb) & 0x0000ffffffffffff;

	return tmp | (*storage & 0x80000000);
}

static int check_rand(const char *buf, off_t in_offset,
		      struct program_options *opts)
{
	int i;
	int ret = 0;
	size_t diff = 0;
	size_t diff_max = 16;
	unsigned int seed;
	unsigned long val;
	unsigned char expect;
	unsigned long long storage = 0;
	unsigned long address = (unsigned long)(buf + in_offset);
	unsigned long p = address;

	for (i = 0; i < opts->size; i++, p++) {
		if (i == 0 || (p & 0xfff) == 0) {
			seed = opts->seed ^ (p >> 32) ^ (p & 0xffffffff);
			storage = smmute_random_seed(seed);
		}

		expect = buf[i + in_offset];
		val = (char)smmute_random(&storage);
		if (expect == (char)val)
			continue;

		if (++diff >= diff_max)
			continue;

		pr_err("Random failed: 0x%x != 0x%x\n", expect, (char)val);

		ret = EFAULT;
	}

	if (diff > diff_max)
		pr_err(" ... and %zu more\n", diff - diff_max);

	return ret;
}

static int check_output(char *buf, off_t offset, struct program_options *opts)
{
	int ret = 0;
	unsigned long i;
	size_t diff = 0;
	size_t diff_max = 16;

	if (!opts->check_buffers && loglevel < LOG_INFO)
		return 0;

	if (mprotect_buffer(buf, offset, opts, PROT_READ))
		return 1;

	pr_info("Output buffer:\n");
	hexdump_ellipsis(buf + offset, opts->size, 64);

	if (!opts->check_buffers || opts->mem.in_file_path)
		goto out_protect;

	/* Check that the poisoned areas didn't change, and the result is sane */
	for (i = 0; i < offset; i++) {
		if (buf[i] == 0x5)
			continue;

		if (++diff >= diff_max)
			continue;

		pr_err("Byte %p (%lu) shouldn't have been written to, "
		       "but value is now 0x%x\n", buf + i, i, buf[i]);
		ret = EFAULT;
	}

	if (diff > diff_max)
		pr_err(" ... and %zu more\n", diff - diff_max);

	switch (opts->transaction_type) {
	case MEMCPY:
		diff = 0;
		for (i = 0; i < opts->size; i++) {
			char val = buf[i + offset];
			char expect = (char)i - opts->seed;

			if (val == expect)
				continue;

			if (++diff >= diff_max)
				continue;

			pr_err("Byte %p (%lu) differs from expected result (0x%x != 0x%x)\n",
			       buf + i + offset, i, val, expect);
			ret = EFAULT;
		}

		if (diff > diff_max)
			pr_err(" ... and %zu more\n", diff - diff_max);
		break;
	case RAND48:
		/*
		 * We can't reproduce the random algorithm if we're not aware of
		 * the virtual address used.
		 */
		if (opts->mem.unified)
			ret |= check_rand(buf, offset, opts);
		break;
	default:
		break;
	}

out_protect:
	if (mprotect_buffer(buf, offset, opts, PROT_WRITE))
		return 1;

	return ret;
}

static int perform_one_transaction(struct smmute_dev *dev,
				   struct program_options *opts,
				   union smmute_transaction_params *params)
{
	int ret;
	int cmd = get_cmd(opts->transaction_type);
	struct smmute_transaction_result result;
	struct timeval begin, end;
	unsigned long long duration = 0;
	bool time_invalid = false;

	if (!cmd)
		return 1;

	time_invalid |= gettimeofday(&begin, NULL);
	ret = smmute_launch_transaction(dev, cmd, params);
	if (ret) {
		pr_err("failed to launch transaction: %s\n", strerror(ret));
		return ret;
	}
	if (params->common.transaction_id == 0) {
		pr_err("invalid transaction ID");
		return 1;
	}

	result.transaction_id = params->common.transaction_id;
	result.blocking = true;
	result.keep = false;

	if (opts->kill == KILL_TSAC && kill(0, opts->kill_sig)) {
		perror("kill()");
		return 1;
	}

	ret = smmute_get_result(dev, &result);
	if (ret) {
		pr_err("could not get result: %s\n", strerror(ret));
		return ret;
	}
	time_invalid |= gettimeofday(&end, NULL);

	if (!time_invalid) {
		// TODO: add meaningful statistics
		duration = (end.tv_sec - begin.tv_sec) * 1000000
			 + (end.tv_usec - begin.tv_usec);
	}
	pr_info("Result:\n"
		"- transaction          = %llu\n"
		"- status               = %u %s\n"
		"- value                = 0x%llx\n"
		"- duration             = %lld us\n",
		result.transaction_id,
		result.status,
		strerror(result.status),
		result.value,
		duration);

	if (cmd == SMMUTE_IOCTL_P2P) {
		int status_prev = result.status;

		result.transaction_id = params->p2p.secondary.transaction_id;
		result.blocking = true;
		result.keep = false;

		ret = smmute_get_result(dev, &result);
		if (ret) {
			pr_err("could not get secondary result: %s\n", strerror(ret));
			/* Keep collecting */
		} else {
			pr_info("Result 2:\n"
			        "- transaction          = %llu\n"
			        "- status               = %u %s\n",
				result.transaction_id,
				result.status,
				strerror(result.status));
		}

		/* Report any failed status */
		if (status_prev)
			result.status = status_prev;
	} else if (cmd == SMMUTE_IOCTL_SUM64 && !result.status &&
		   !opts->mem.in_file_path) {
		/* Test engine rejects sizes not aligned on dword */
		unsigned long long expect = opts->size >> 3;
		if (result.value != expect) {
			pr_err("result is wrong (%llu != %llu)\n", result.value,
			       expect);
			return EFAULT;
		}
	}

	return result.status != 0;
}

/*
 * Note! We *really* need this to be inlined, since smmute_alloc_buffer (a
 * macro) might call alloca when the user asks for it (UNIFIED_MEM_STACK). So we
 * mandate the caller of smmute_create_buffer not to return before the buffer is
 * destroyed.
 */
__attribute__((always_inline))
static inline int smmute_create_buffer(struct smmute_dev *dev, void **va, 
				dma_addr_t *iova, size_t size, int prot,
				struct program_options *opts)
{
	int ret;
	struct smmute_mem_options *mopts = &opts->mem;
	void *addr = smmute_alloc_buffer(dev, size, prot, mopts);

	if (!addr)
		return ENOMEM;

	if (((opts->fault & INJECT_FAULT_READ) && (prot & PROT_READ)) ||
	    ((opts->fault & INJECT_FAULT_WRITE) && (prot & PROT_WRITE))) {
		*va = addr;
		*iova = 0;
		pr_debug("injecting fault at va=%p\n", *va);
		return 0;
	}

	ret = smmute_dma_map_buffer(dev, addr, iova, size, prot, mopts);
	if (ret) {
		smmute_free_buffer(dev, addr, size, mopts);
		return ret;
	}

	*va = addr;
	pr_debug("created buffer va=%p iova=%#llx size=%zu prot=0x%x\n", *va,
		 *iova, size, prot);

	return 0;
}

static void smmute_destroy_buffer(struct smmute_dev *dev, void *va,
				  dma_addr_t iova, size_t size,
				  struct program_options *opts)
{
	if (!va)
		return;

	if (iova && smmute_dma_unmap_buffer(dev, va, iova, size, &opts->mem))
		pr_err("unable to unmap %p->%#llx (%zu) buffer!\n", va, iova, size);

	smmute_free_buffer(dev, va, size, &opts->mem);

	pr_debug("destroyed buffer va=%p, iova=%#llx, size=%zu\n", va, iova, size);
}

static int do_transaction(struct smmute_dev *dev, struct program_options *opts)
{
	int i;
	int ret = 0;
	void *in_buf_va = NULL;
	void *out_buf_va = NULL;
	bool do_unbind = !!opts->mem.unified;
	dma_addr_t in_buf_iova, out_buf_iova;
	/*
	 * In the future, we might want to separate input and output offsets. At
	 * the moment, we don't care.
	 */
	off_t in_offset = opts->offset;
	off_t out_offset = opts->offset;
	size_t in_size = in_offset + opts->size;
	size_t out_size = out_offset + opts->size;
	union smmute_transaction_params params;
	/*
	 * Accesses to DRAM are cacheable, inner- and outer-shareable,
	 * read-allocate, write-allocate, write-back.
	 */
	unsigned int attr = SMMUTE_ATTR_WBRAWA_SH;
	/* MMIO accesses are Dev-nGnRE */
	unsigned int devattr = SMMUTE_ATTR_DEVICE;

	enum transaction_type type = opts->transaction_type;

	memset(&params, 0, sizeof(params));

	if (opts->mem.unified) {
		ret = smmute_bind(dev);
		if (ret) {
			pr_err("cannot bind task: %s\n", strerror(ret));
			return ret;
		}

		if (opts->kill == KILL_BIND && kill(0, opts->kill_sig)) {
			perror("kill()");
			return 1;
		}
	}

	if (type == MEMCPY || type == SUM64 || type == P2P) {
		ret = smmute_create_buffer(dev, &in_buf_va, &in_buf_iova,
					   in_size, PROT_READ, opts);
		if (ret)
			return ret;
	}

	if (type == MEMCPY || type == RAND48 || type == P2P) {
		ret = smmute_create_buffer(dev, &out_buf_va, &out_buf_iova,
					   out_size, PROT_WRITE, opts);
		if (ret)
			goto out_unmap;
	}

	if (type == MEMCPY || type == SUM64 || type == P2P)
		params.common.input_start = in_buf_iova + in_offset;
	else
		/* Weird, I know. */
		params.common.input_start = out_buf_iova + out_offset;

	params.common.size	= opts->size;
	params.common.stride	= 1;
	params.common.seed	= opts->seed;
	params.common.attr	= SMMUTE_TRANSACTION_ATTR(attr, attr);

	if (opts->mem.unified)
		params.common.flags |= SMMUTE_FLAG_SVA;
	if (opts->fault & INJECT_FAULT_DRIVER)
		params.common.flags |= SMMUTE_FLAG_FAULT;

	if (type == MEMCPY) {
		params.memcpy.output_start = (__u64)out_buf_iova + out_offset;
	} else if (type == P2P) {
		params.p2p.secondary.input_start = (__u64)out_buf_iova + out_offset;
		/*
		 * Put MEMCPY here, set max inflight transactions to 1 in the
		 * model, watch it burn
		 */
		params.p2p.command = SMMUTE_IOCTL_RAND48;

		params.common.size = 8;
		params.common.attr = SMMUTE_TRANSACTION_ATTR(attr, devattr);

		params.p2p.secondary.size = params.common.size;
		params.p2p.secondary.attr = params.common.attr;
		params.p2p.secondary.seed = params.common.seed;
		params.p2p.secondary.stride = params.common.stride;
		params.p2p.secondary.flags = params.common.flags;
	}

	init_buffers(in_buf_va, in_offset, out_buf_va, out_offset, opts);

	madvise_buffer(in_buf_va, in_offset, opts, false);
	madvise_buffer(out_buf_va, out_offset, opts, true);

	for (i = 0; i < opts->nr_repetitions; i++) {
		ret = perform_one_transaction(dev, opts, &params);
		if (ret)
			break;

		if (type == P2P) {
			/* Second command, if RAND48, modified the in_buf_va */
			pr_info("Command is now %#llx\n",
				 *(__u64 *)(in_buf_va + in_offset));
			break;
		} else if (out_buf_va) {
			/* Dump output buffer (if LOG_INFO) and check its values */
			ret = check_output(out_buf_va, out_offset, opts);
			if (ret)
				break;
		}

		if (opts->sleep_time)
			sleep(opts->sleep_time);
	}

	/* TLB fault injection: retry access after unmap/unbind */
	if (!ret && opts->fault & INJECT_FAULT_TLB) {
		if (out_buf_va) {
			smmute_destroy_buffer(dev, out_buf_va, out_buf_iova,
					      out_size, opts);
			out_buf_va = NULL;
		} else {
			smmute_destroy_buffer(dev, in_buf_va, in_buf_iova,
					      in_size, opts);
			in_buf_va = NULL;
		}

		/*
		 * If buffers are obtained with malloc or stack, then this will
		 * likely succeed and corrupt user mem, since the PTE is present
		 * even though the buffer was freed.
		 */
		ret = perform_one_transaction(dev, opts, &params);
		if (!ret)
			pr_info("Critical: access succeeded after unmap!\n");
	} else if (!ret && opts->fault & INJECT_FAULT_PASID && opts->mem.unified) {
		do_unbind = false;
		ret = smmute_unbind(dev);
		if (ret) {
			pr_err("cannot unbind task: %s\n", strerror(ret));
			goto out_unmap;
		}

		ret = perform_one_transaction(dev, opts, &params);
		if (!ret)
			/*
			 * This is expected with the kernel driver, since it
			 * automatically rebinds when performing the transaction
			 */
			pr_info("Critical: access succeeded after unbind!\n");
	}

	if (opts->fault) {
		/*
		 * Invert fault status: a return value of 0 means that we
		 * successfully triggered an error :)
		 */
		ret = ret ? 0 : EFAULT;
	}

out_unmap:
	smmute_destroy_buffer(dev, out_buf_va, out_buf_iova, out_size, opts);
	smmute_destroy_buffer(dev, in_buf_va, in_buf_iova, in_size, opts);

	if (do_unbind) {
		int ret2 = smmute_unbind(dev);
		if (ret2) {
			pr_err("cannot unbind task: %s\n", strerror(ret2));
			ret |= 2;
		}
	}

	return ret;
}

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
#define parse_sl(optarg, dest) _parse_long(optarg, dest, strtol)

static int parse_fault_option(struct program_options *opts)
{
	if (!optarg || opts->fault)
		return 1;

	if (!strncmp(optarg, "read", 4)) {
		opts->fault |= INJECT_FAULT_READ;
	} else if (!strncmp(optarg, "write", 5)) {
		opts->fault |= INJECT_FAULT_WRITE;
	} else if (!strncmp(optarg, "tlb", 3)) {
		opts->fault |= INJECT_FAULT_TLB;
	} else if (!strncmp(optarg, "drv", 3)) {
		opts->fault |= INJECT_FAULT_DRIVER;
	} else if (!strncmp(optarg, "pasid", 5)) {
		opts->fault |= INJECT_FAULT_PASID;
	} else {
		pr_err("Unknown mode '%s'\n", optarg);
		return 1;
	}

	return 0;
}

static int parse_kill_option(struct program_options *opts)
{
	if (!optarg || opts->fault)
		return 1;

	if (!strcmp(optarg, "bind")) {
		opts->kill = KILL_BIND;
	} else if (!strcmp(optarg, "tsac")) {
		opts->kill = KILL_TSAC;
	} else if (!strcmp(optarg, "segv")) {
		opts->kill_sig = SIGSEGV;
	} else if (!strcmp(optarg, "int")) {
		opts->kill_sig = SIGINT;
	} else {
		pr_err("unknown mode '%s'\n", optarg);
		return 1;
	}

	return 0;
}

static int parse_unified_option(struct smmute_mem_options *opts)
{
	int flag_len;
	char *flag = optarg;
	char *next_flag;

	if (!optarg || UNIFIED_MEM_MODE(opts->unified))
		return 1;

	/*
	 * We assume here that optarg is a \0-terminated string. I don't know
	 * how vulnerable this is.
	 */
	next_flag = strchr(optarg, ',');

	if (!strncmp(optarg, "malloc", 6)) {
		opts->unified |= UNIFIED_MEM_MALLOC;
	} else if (!strncmp(optarg, "mmap", 4)) {
		opts->unified |= UNIFIED_MEM_MMAP;
	} else if (!strncmp(optarg, "stack", 5)) {
		opts->unified |= UNIFIED_MEM_STACK;
	} else {
		flag_len = next_flag ? next_flag - optarg : strlen(optarg);
		pr_err("Unknown mode '%.*s'\n", flag_len, optarg);
		return 1;
	}

	if (!(opts->unified & UNIFIED_MEM_MMAP)) {
		if (next_flag)
			pr_err("flags '%s' ignored\n", next_flag);
		return 0;
	}

	while ((flag = next_flag) != NULL) {
		flag++;
		next_flag = strchr(flag, ',');

		flag_len = next_flag ? next_flag - flag : strlen(flag);

#define	flag_equals(name) (!strncmp(flag, (name), sizeof(name) - 1))

		if (flag_equals("lock")) {
			opts->unified |= UNIFIED_MEM_LOCK;
		} else if (flag_equals("madv_random")) {
			opts->unified |= UNIFIED_MEM_ADV_RAND;
		} else if (flag_equals("madv_sequential")) {
			opts->unified |= UNIFIED_MEM_ADV_SEQ;
		} else if (flag_equals("madv_dontneed")) {
			opts->unified |= UNIFIED_MEM_ADV_DNEED;
		} else if (flag_equals("madv_willneed")) {
			opts->unified |= UNIFIED_MEM_ADV_WNEED;
		} else if (flag_equals("in_file=")) {
			if (opts->in_file_path) {
				pr_err("duplicate in_file flag\n");
				continue;
			}
			opts->unified |= UNIFIED_MEM_IN_FILE;
			opts->in_file_path = strndup(flag + 8, flag_len - 8);
			opts->in_file = open(opts->in_file_path, O_RDONLY);
			if (opts->in_file < 0) {
				pr_err("unable to open %s for reading: %s\n",
				       opts->in_file_path, strerror(errno));
				free(opts->in_file_path);
				opts->in_file_path = NULL;
				return 1;
			}
		} else if (flag_equals("out_file=")) {
			if (opts->out_file_path) {
				pr_err("duplicate out_file flag\n");
				continue;
			}
			opts->unified |= UNIFIED_MEM_OUT_FILE;
			opts->out_file_path = strndup(flag + 9, flag_len - 9);
			opts->out_file = open(opts->out_file_path,
					      O_RDWR | O_TRUNC | O_CREAT, 0664);
			if (opts->out_file < 0) {
				pr_err("unable to open %s for writing: %s\n",
				       opts->out_file_path, strerror(errno));
				free(opts->out_file_path);
				opts->out_file_path = NULL;
				return 1;
			}
		} else {
			pr_err("Unknown flag '%.*s'\n", flag_len, flag);
		}
	}
#undef flag_equals

	return 0;
}

static int parse_options(int argc, char *argv[], struct program_options *opts)
{
	int ret;

	/* optind, opterr, optopt and optarg are defined in unistd */
	optind = 1;
	/* Print error messages */
	opterr = 1;

	while ((ret = getopt(argc, argv, optstring)) != -1) {
		switch (ret) {
		case 'b':
			if (optarg[0] == 'k') {
				opts->backend = SMMUTE_BACKEND_KERNEL;
			} else {
				pr_err("unkown backend '%s'\n", optarg);
				return 1;
			}
			break;
		case 'c':
			opts->check_buffers = true;
			break;
		case 'd':
			loglevel = LOG_DEBUG;
			break;
		case 'f':
			if (parse_fault_option(opts))
				return 1;
			break;
		case 'g':
			if (parse_ul(optarg, &opts->seed))
				return 1;
			break;
		case 'k':
			if (parse_kill_option(opts))
				return 1;
			break;
		case 'm':
			switch (optarg[0]) {
			case 'M':
			case 'm':
				opts->transaction_type = MEMCPY;
				break;
			case 'R':
			case 'r':
				opts->transaction_type = RAND48;
				break;
			case 'S':
			case 's':
				opts->transaction_type = SUM64;
				break;
			case 'P':
			case 'p':
				opts->transaction_type = P2P;
				break;
			default:
				pr_err("invalid mode: %c\n", optarg[0]);
				return 1;
			}
			if (optarg[1]) {
				pr_warn("ignored %s\n", optarg + 1);
			}
			break;
		case 'n':
			if (parse_ul(optarg, &opts->nr_transactions))
				return 1;
			break;
		case 'o':
			if (parse_sl(optarg, &opts->offset))
				return 1;
			if (opts->offset < 0) {
				pr_err("Cannot have negative offsets\n");
				return 1;
			}
			break;
		case 'q':
			loglevel = LOG_ERROR;
			break;
		case 'r':
			if (parse_ul(optarg, &opts->nr_repetitions))
				return 1;
			break;
		case 's':
			if (parse_ul(optarg, &opts->size))
				return 1;
			break;
		case 't':
			if (parse_ul(optarg, &opts->sleep_time))
				return 1;
			break;
		case 'u':
			if (parse_unified_option(&opts->mem))
				return 1;
			break;
		case 'h':
		default:
			print_help(argv[0]);
			return 1;
		}
	}

	if (optind < argc) {
		opts->device = argv[optind];
	}

	return 0;
}

static int prepare_stack(struct program_options *opts)
{
	size_t needed_size;
	float margin = 0.9;
	struct rlimit rlim;
	int ret;

	if (!(opts->mem.unified & UNIFIED_MEM_STACK))
		return 0;

	/*
	 * Ensure stack rlimit is large enough for the buffer. Otherwise we'll
	 * segfault.
	 */
	/* FIXME: overflow? */
	needed_size = opts->offset + opts->size;
	if (opts->transaction_type == MEMCPY)
		needed_size *= 2;

	ret = getrlimit(RLIMIT_STACK, &rlim);
	if (ret) {
		perror("getrlimit");
		return ret;
	}

	if (needed_size > rlim.rlim_max) {
		pr_err("Requested size %zu larger than max stack size %zu\n",
		       needed_size, rlim.rlim_max);
		return ENOMEM;

	} else if (needed_size > rlim.rlim_cur * margin) {
		pr_debug("Updating stack rlimit %zu -> %zu\n", rlim.rlim_cur,
			 rlim.rlim_max);
		rlim.rlim_cur = rlim.rlim_max;
		ret = setrlimit(RLIMIT_STACK, &rlim);
		if (ret) {
			perror("setrlimit");
			return ret;
		}
	}

	if (needed_size > rlim.rlim_max * margin)
		pr_warn("Stack limit %zu close to requested buffer size %zu. Might segfault.\n",
			rlim.rlim_max, needed_size);
	return 0;
}

int main(int argc, char *argv[])
{
	size_t i;
	int ret;
	struct smmute_dev dev;
	struct program_options options = {
		.backend			= SMMUTE_BACKEND_KERNEL,
		.device				= "/dev/smmute0",
		.transaction_type		= MEMCPY,
		.size				= PAGE_SIZE,
		.offset				= 0,
		.nr_repetitions			= 1,
		.nr_transactions		= 1,
		.seed				= 0,
		.sleep_time			= 0,

		.check_buffers			= false,
		.kill_sig			= SIGINT,

		.mem = {
			.unified		= 0,
			.in_file_path		= NULL,
			.out_file_path		= NULL,
			.in_file		= -1,
			.out_file		= -1,
		},
	};

	ret = parse_options(argc, argv, &options);
	if (ret)
		return ret;

	if (prepare_stack(&options))
		return ENOMEM;

	ret = smmute_backend_init(options.backend, NULL);
	if (ret)
		return ret;

	memset(&dev, 0, sizeof(dev));
	dev.backend = options.backend;

	ret = smmute_device_open(&dev, options.device, 0);
	if (ret) {
		pr_err("cannot open device %s: %s\n", options.device, strerror(ret));
		return ret;
	}

	for (i = 0; i < options.nr_transactions; i++) {
		ret = do_transaction(&dev, &options);
		if (ret)
			break;
		options.seed += 0xb00f;
	}

	smmute_device_close(&dev);

	if (options.mem.in_file_path) {
		free(options.mem.in_file_path);
		close(options.mem.in_file);
	}
	if (options.mem.out_file_path) {
		free(options.mem.out_file_path);
		close(options.mem.out_file);
	}

	smmute_backend_exit(options.backend);

	return ret;
}
