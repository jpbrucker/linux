/*
 * Try to stress the SMMU SVM API - bind multiple devices from multiple children
 */

#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "smmute-lib.h"

enum loglevel loglevel = LOG_INFO;
const char *optstring = "cdf:hkmn:s:y";
static void print_help(char *progname)
{
	pr_err(
"Usage: %s [opts] [dev [dev [...]]]                                        \n"
"Launch child processes that bind to all given devices and launch memcpy   \n"
"transactions. Devices may either be paths to normal smmute devices        \n"
"(/dev/smmuteX), VFIO devices (/sys/...) or IPC sockets.                 \n\n"
"  OPTION           DESCRIPTION                                     DEFAULT\n"
"  -c               check copied values                               false\n"
"  -d               debug                                                  \n"
"  -f <num>         number of children (forks)                           10\n"
"  -h               print this message                                     \n"
"  -k               kill self during transactions                          \n"
"  -m               merge - put all devices in the same VFIO container     \n"
"  -n <num>         number of transactions per device                    16\n"
"  -s <num>         transaction size in bytes                         10000\n"
"  -y               sync processes before launching transaction            \n",
		progname);
}

struct device_options {
	char *name;
	int backend;
};

struct program_options {
	struct device_options	*devices;
	size_t			nr_devices;
	size_t 			max_children;
	size_t 			nr_transactions;
	size_t 			buf_size;
	bool			merge;
	bool			check;
	bool			sync;
	bool			kill;
};

struct shared_data {
	pthread_mutex_t		child_mutex;
	pthread_cond_t		child_cond;
	int			nr_waiters;
	int			nr_children;
};

static struct shared_data *shr;

int run_child(struct program_options *opts, struct smmute_dev *devs, int seed)
{
	int i, j, k;
	int pasid = 0;
	int ret = ENOMEM;
	char random_state[8] = {0};
	struct random_data random_data = {0};
	size_t nr_devs = opts->nr_devices;
	union smmute_transaction_params *tsacs;
	struct smmute_transaction_result *results;
	void *in_buf = NULL, *out_buf = NULL;

	pid_t pid = getpid();
	int devices_bound = 0;
	int transactions_success = 0;
	int transactions_launched = 0;
	int transactions_returned = 0;

	size_t nr_tsacs = opts->nr_transactions;

	tsacs = calloc(nr_devs * nr_tsacs,
		       sizeof(union smmute_transaction_params));
	if (!tsacs) {
		pr_err("calloc(tsacs)\n");
		return ENOMEM;
	}

	results = calloc(nr_devs * nr_tsacs,
			 sizeof(struct smmute_transaction_result));
	if (!results) {
		pr_err("calloc(results)\n");
		goto out_free_tsacs;
	}

	in_buf = malloc(opts->buf_size);
	if (!in_buf) {
		pr_err("malloc(in_buf)\n");
		goto out_free_results;
	}

	initstate_r(seed, random_state, 8, &random_data);
	for (i = 0; i < opts->buf_size; i++) {
		int32_t rv;
		random_r(&random_data, &rv);
		*(char *)(in_buf + i) = (char)rv;
	}

	out_buf = malloc(opts->buf_size * nr_devs * nr_tsacs);
	if (!out_buf) {
		pr_err("Cannot allocate buffer of size %zu\n", opts->buf_size *
		       nr_devs * nr_tsacs);
		goto out_free_bufs;
	}

	for (i = 0; i < nr_devs; i++) {
		int new_pasid;

		ret = smmute_bind(&devs[i], pid, &new_pasid);
		if (ret) {
			pr_err("Cannot bind pid %d: %s\n", pid, strerror(ret));
			break;
		}

		devices_bound++;

		if (pasid && new_pasid != pasid) {
			pr_err("Different PASID for same task!\n");
			break;
		}

		pasid = new_pasid;
	}

	if (ret)
		goto out_unbind;

	for (i = 0; i < nr_tsacs; i++) {
		for (j = 0; j < nr_devs; j++) {
			size_t idx = j * nr_tsacs + i;
			union smmute_transaction_params *params = &tsacs[idx];
			unsigned int attr = SMMUTE_ATTR_WBRAWA_SH;

			params->common.input_start = (uint64_t)in_buf;
			params->common.size = opts->buf_size;
			params->common.attr = SMMUTE_TRANSACTION_ATTR(attr, attr);
			params->common.flags = SMMUTE_FLAG_SVA;
			params->common.seed = 0;
			params->common.stride = 1;
			params->common.pasid = pasid;
			params->memcpy.output_start = (uint64_t)out_buf +
				                      idx * opts->buf_size;

			ret = smmute_launch_transaction(&devs[j],
							SMMUTE_IOCTL_MEMCPY,
							params);
			if (ret) {
				pr_err("Cannot launch transaction "
				       "pid:%d dev:%d t:%d - %s\n", pid, j, i,
				       strerror(ret));
				continue;
			}

			results[idx].transaction_id = params->common.transaction_id;
			transactions_launched++;
		}
	}

	if (opts->sync) {
		pthread_mutex_lock(&shr->child_mutex);
		shr->nr_waiters++;
		pthread_cond_broadcast(&shr->child_cond);
		while (shr->nr_waiters != shr->nr_children)
			pthread_cond_wait(&shr->child_cond, &shr->child_mutex);
		pthread_mutex_unlock(&shr->child_mutex);
	}

	if (opts->kill && kill(0, SIGINT))
	    perror("kill()");

	for (i = 0; i < nr_tsacs; i++) {
		for (j = 0; j < nr_devs; j++) {
			size_t idx = j * nr_tsacs + i;
			struct smmute_transaction_result *res = &results[idx];
			if (!res->transaction_id)
				continue;

			res->blocking = 1;
			res->keep = 0;

			ret = smmute_get_result(&devs[j], res);
			if (ret) {
				pr_err("Cannot get result for transaction "
				       "pid:%d dev:%d t:%d - %s\n", pid, j, i,
				       strerror(ret));
				continue;
			}

			transactions_returned++;

			/* Check copied value */
			initstate_r(seed, random_state, 8, &random_data);
			for (k = 0; opts->check && k < opts->buf_size; k++) {
				int32_t rv;
				size_t byte_pos = idx * opts->buf_size + k;
				char v = *((char *)out_buf + byte_pos);

				random_r(&random_data, &rv);
				if (v != (char)rv) {
					pr_err("Invalid value at out_buf[%zu]",
					       byte_pos);
					res->status = EIO;
					break;
				}
			}

			if (res->status)
				pr_err("Transaction pid:%d dev:%d t:%d failed with %u\n",
				       pid, j, i, res->status);
			else
				transactions_success++;
		}
	}

	pr_info("Child %d: %d/%zu transactions launched, %d returned, %d succeeded\n",
		pid, transactions_launched, nr_tsacs * nr_devs, transactions_returned,
		transactions_success);

	ret = 0;

out_unbind:
	for (i = 0; i < devices_bound; i++)
		smmute_unbind(&devs[i], pid, pasid);

out_free_bufs:
	if (in_buf)
		free(in_buf);

	if (out_buf)
		free(out_buf);

out_free_results:
	free(results);

out_free_tsacs:
	free(tsacs);

	return ret;
}

int run(struct program_options *opts)
{
	int i;
	int wstatus;
	pid_t child;
	int nr_children;
	int ret = ENODEV;
	int devices_opened = 0;
	struct smmute_dev *devs;
	size_t nr_devs = opts->nr_devices;

	devs = calloc(nr_devs, sizeof(struct smmute_dev));
	if (!devs)
		return ENOMEM;

	for (i = 0; i < nr_devs; i++) {
		devs[i].backend = opts->devices[i].backend;
		ret = smmute_device_open(&devs[i], opts->devices[i].name, 0);
		if (ret)
			break;

		devices_opened++;
	}

	if (ret)
		goto out_close;

	if (opts->sync) {
		pthread_condattr_t condattr;
		pthread_mutexattr_t mutexattr;

		ret = EINVAL;

		shr = mmap(NULL, PAGE_ALIGN(sizeof(*shr)), PROT_READ |
			   PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (shr == MAP_FAILED)
			goto out_close;

		if (pthread_condattr_init(&condattr) ||
		    pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED) ||
		    pthread_cond_init(&shr->child_cond, &condattr))
			goto out_close;

		if (pthread_mutexattr_init(&mutexattr) ||
		    pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED) ||
		    pthread_mutex_init(&shr->child_mutex, &mutexattr))
			goto out_close;

		shr->nr_children = opts->max_children;
	}

	for (nr_children = 0; nr_children < opts->max_children; nr_children++) {
		pid_t pid = fork();

		if (pid < 0) {
			ret = errno;
			pr_err("Can't fork! %s\n", strerror(errno));
			break;
		}

		if (pid == 0) {
			/*
			 * Use seed 'thread+1', since seeds 0 and 1 produce the
			 * same random sequence.
			 */
			return run_child(opts, devs, nr_children + 1);
		}

		pr_debug("Created child %d\n", pid);
	}

	if (opts->sync) {
		pthread_mutex_lock(&shr->child_mutex);
		/* Maybe we spawned less than expected */
		shr->nr_children = nr_children;
		pthread_cond_broadcast(&shr->child_cond);
		pthread_mutex_unlock(&shr->child_mutex);
	}

	while (nr_children) {
		child = waitpid(-1, &wstatus, 0);
		if (WIFEXITED(wstatus)) {
			pr_debug("Child %d exited with %d\n",
				 child, WEXITSTATUS(wstatus));
			nr_children--;
			if (WEXITSTATUS(wstatus))
				ret = 1;
		} else if (WIFSIGNALED(wstatus)) {
			pr_debug("Child %d killed with signal %d\n",
				 child, WTERMSIG(wstatus));
			nr_children--;
			ret = 1;
		} else {
			pr_err("shouldn't be here\n");
		}
	}

out_close:
	for (i = 0; i < devices_opened; i++)
		smmute_device_close(&devs[i]);

	free(devs);

	return ret;
}

static int parse_options(int argc, char *argv[], struct program_options *opts)
{
	int i;
	int ret;

	/* optind, opterr, optopt and optarg are defined in unistd */
	optind = 1;
	/* Print error messages */
	opterr = 1;

	while ((ret = getopt(argc, argv, optstring)) != -1) {
		switch (ret) {
		case 'c':
			opts->check = true;
			break;
		case 'd':
			loglevel = LOG_DEBUG;
			break;
		case 'k':
			opts->kill = opts->sync = true;
			break;
		case 'n':
			parse_ul(optarg, &opts->nr_transactions);
			break;
		case 'm':
			opts->merge = true;
			break;
		case 'f':
			parse_ul(optarg, &opts->max_children);
			break;
		case 's':
			parse_ul(optarg, &opts->buf_size);
			break;
		case 'y':
			opts->sync = true;
			break;
		case 'h':
		default:
			print_help(argv[0]);
			return 1;
		}
	}

	if (argc == optind)
		return 0;

	opts->nr_devices = argc - optind;
	for (i = 0; i < opts->nr_devices; i++)
		opts->devices[i].name = argv[optind + i];

	return 0;
}

static bool initted_backend[SMMUTE_NR_BACKENDS];

static int detect_backends(struct program_options *opts)
{
	int bk;
	int i, ret;
	char path[PATH_MAX];
	char *resolved_path;
	struct smmute_backend_options bk_opts = {
		.flags = 0,
	};

	for (i = 0; i < opts->nr_devices; i++) {
		resolved_path = realpath(opts->devices[i].name, path);
		if (!resolved_path) {
			pr_err("cannot resolve path %s\n", opts->devices[i].name);
			return errno;
		}

		if (!strncmp(resolved_path, "/dev/", 5)) {
			bk = SMMUTE_BACKEND_KERNEL;
		} else if (!strncmp(resolved_path, "/sys/", 5)) {
			bk = SMMUTE_BACKEND_VFIO;
			if (opts->merge)
				bk_opts.flags |= SMMUTE_BACKEND_VFIO_FLAG_MERGE;
		} else {
			bk = SMMUTE_BACKEND_IPC;
		}

		opts->devices[i].backend = bk;
		if (initted_backend[bk])
			continue;

		ret = smmute_backend_init(bk, NULL);
		if (ret)
			return ret;

		initted_backend[bk] = true;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	int ret, i;

	/*
	 * Gonna need buf_size * max_children * (1 + nr_devices *
	 * nr_transactions) bytes for transaction buffers. With default
	 * settings, 40M worth of malloc.
	 */
	struct device_options default_devices[] = {
		{ .name = "/dev/smmute0" },
		{ .name = "/dev/smmute1" },
		{ .name = "/dev/smmute2" },
		{ .name = "/dev/smmute3" },
	};
	struct program_options opts = {
		.devices		= default_devices,
		.nr_devices		= 4,
		.nr_transactions	= 16,
		.max_children		= 10,
		.buf_size		= 0x10000,
		.merge			= false,
		.check			= false,
		.sync			= false,
		.kill			= false,
	};

	ret = parse_options(argc, argv, &opts);
	if (ret)
		return ret;

	ret = detect_backends(&opts);

	if (!ret)
		ret = run(&opts);

	for (i = 0; i < SMMUTE_NR_BACKENDS; i++) {
		if (initted_backend[i])
			smmute_backend_exit(i);
	}

	return ret;
}
