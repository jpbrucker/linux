#ifndef SMMUTE_IPC_H
#define SMMUTE_IPC_H

#include <linux/smmu-test-engine.h>

#define SMMUTE_SHM_NAME_MAX		64

#define __packed__ __attribute__((packed))

enum smmute_ipc_command {
	SMMUTE_IPC_INVALID		= 0,

	SMMUTE_IPC_MAP			= 1,
	SMMUTE_IPC_UNMAP		= 2,

	SMMUTE_IPC_LAUNCH_TRANSACTION	= 3,
	SMMUTE_IPC_GET_RESULT		= 4,

	SMMUTE_IPC_BIND_TASK		= 5,
	SMMUTE_IPC_UNBIND_TASK		= 6,

	SMMUTE_IPC_NR_COMMANDS,
};

__packed__
struct smmute_ipc_msg_hdr {
	uint32_t			command;	/* smmute_ipc_command */
	uint32_t			size;		/* message size */
	uint32_t			version;	/* protocol version 0 */
	uint32_t			pad[5];		/* unused: res0 */
	/*
	 * - Might be useful to add a message ID if we switch to a
	 *   non-sequential transport.
	 * - We could also let the server handle multiple devices. In that case,
	 *   we could add a devid to this structure. But for the moment, one IPC
	 *   socket represents one device and it is good.
	 */
};

__packed__
struct smmute_ipc_resp_hdr {
	uint32_t			command;
	uint32_t			size;
	uint32_t			version;	/* 0 */
	uint32_t			status;		/* errno */
	uint32_t			pad[4];
};

/* Client asks to map some memory from its SHM file */
__packed__
struct smmute_ipc_map {
	struct smmute_ipc_msg_hdr	hdr;
	char				shm_name[SMMUTE_SHM_NAME_MAX];
	uint64_t			shm_offset;
	uint64_t			size;
	uint32_t			prot;
};

/* Server returns the mapped iova when successful (hdr.status = 0) */
__packed__
struct smmute_ipc_map_resp {
	struct smmute_ipc_resp_hdr	hdr;
	uint64_t			iova;
};

/* Client asks to unmap some memory from its SHM file */
__packed__
struct smmute_ipc_unmap {
	struct smmute_ipc_msg_hdr	hdr;
	uint64_t			iova;
	uint64_t			size;
};

__packed__
struct smmute_ipc_unmap_resp {
	struct smmute_ipc_resp_hdr	hdr;
};

/* Client asks to launch a transaction */
__packed__
struct smmute_ipc_launch {
	struct smmute_ipc_msg_hdr	hdr;
	uint32_t			cmd;
	union smmute_transaction_params	params;
};

/* Server returns the transaction ID when successful (hdr.status = 0) */
__packed__
struct smmute_ipc_launch_resp {
	struct smmute_ipc_resp_hdr	hdr;
	uint64_t			transaction_id;
};

/* Client asks to bind its task */
__packed__
struct smmute_ipc_bind_task {
	struct smmute_ipc_msg_hdr	hdr;
	int32_t				pid;
};

/* Server returns a PASID when successful */
__packed__
struct smmute_ipc_bind_resp {
	struct smmute_ipc_resp_hdr	hdr;
	uint64_t			pasid;
};

__packed__
struct smmute_ipc_unbind_task {
	struct smmute_ipc_msg_hdr	hdr;
	int32_t				pid;
	uint64_t			pasid;
};

__packed__
struct smmute_ipc_unbind_resp {
	struct smmute_ipc_resp_hdr	hdr;
};

/* Client asks for updates on a transaction */
__packed__
struct smmute_ipc_result {
	struct smmute_ipc_msg_hdr	hdr;
	uint64_t			transaction_id;
};

/*
 * Server returns the transaction status (hdr.status is ignored, result.status
 * is used)
 */
__packed__
struct smmute_ipc_result_resp {
	struct smmute_ipc_resp_hdr	hdr;
	struct smmute_transaction_result result;
};

/*
 * Server can tell the client it didn't understand a message. hdr.command is
 * SMMUTE_IPC_INVALID in that case.
 */
__packed__
struct smmute_ipc_resp_err {
	struct smmute_ipc_msg_hdr	hdr;
};


union smmute_ipc_msg {
	struct smmute_ipc_msg_hdr	hdr;
	struct smmute_ipc_map		map;
	struct smmute_ipc_unmap		unmap;
	struct smmute_ipc_launch	launch;
	struct smmute_ipc_bind_task	bind_task;
	struct smmute_ipc_unbind_task	unbind_task;
	struct smmute_ipc_result	result;
};

union smmute_ipc_resp {
	struct smmute_ipc_resp_hdr	hdr;
	struct smmute_ipc_resp_err	err;
	struct smmute_ipc_map_resp	map;
	struct smmute_ipc_unmap_resp	unmap;
	struct smmute_ipc_bind_resp	bind;
	struct smmute_ipc_unbind_resp	unbind;
	struct smmute_ipc_launch_resp	launch;
	struct smmute_ipc_result_resp	result;
};

static inline const char *smmute_ipc_command_str(enum smmute_ipc_command cmd)
{
	switch (cmd) {
	case SMMUTE_IPC_INVALID:
		return "invalid";
	case SMMUTE_IPC_MAP:
		return "map";
	case SMMUTE_IPC_UNMAP:
		return "unmap";
	case SMMUTE_IPC_LAUNCH_TRANSACTION:
		return "launch";
	case SMMUTE_IPC_GET_RESULT:
		return "get_result";
	case SMMUTE_IPC_BIND_TASK:
		return "bind_task";
	case SMMUTE_IPC_UNBIND_TASK:
		return "unbind_task";
	default:
		return "unknown";
	}
}

#endif /* SMMUTE_IPC_H */
