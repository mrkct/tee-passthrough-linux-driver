#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <linux/tee.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#define SHARED_MEM_SIZE 1024

// This is the "Increment Number" TA's UUID hardcoded in the module
// clang-format off
uint8_t TA_UUID[] = {
	0xaa, 0xaa, 0xaa, 0xaa,
	0xbb, 0xbb,
	0xcc, 0xcc,
	0xdd, 0xdd,
	0xee, 0xee, 0xee, 0xee, 0xee, 0xee
};
// clang-format on

static int do_open_session(int fd)
{
	int rc;
	union {
		struct tee_ioctl_open_session_arg arg;
		uint8_t data[sizeof(struct tee_ioctl_open_session_arg) +
			     sizeof(struct tee_ioctl_param) * 4];
	} open_session_arg;
	struct tee_ioctl_buf_data open_session_buf_data = {
		.buf_len = sizeof(open_session_arg),
		.buf_ptr = (uintptr_t)&open_session_arg
	};
	struct tee_ioctl_open_session_arg *open_session = &open_session_arg.arg;
	open_session->clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	open_session->num_params = 4;
	memcpy(open_session->uuid, TA_UUID, sizeof(TA_UUID));

	for (int i = 0; i < 4; i++)
		open_session->params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	if ((rc = ioctl(fd, TEE_IOC_OPEN_SESSION, &open_session_buf_data))) {
		perror("failed ioctl for OPEN_SESSION");
		return rc;
	}
	printf("session opened\n\tret: %u\n\torigin: %u\n\tsession_id: %u\n",
	       open_session->ret, open_session->ret_origin,
	       open_session->session);

	return open_session->session;
}

static int alloc_shared_mem_buffer(int fd, size_t size, uint64_t *shmem_id,
				   uint8_t **m)
{
	int mem_fd;

	struct tee_ioctl_shm_alloc_data data;
	memset(&data, 0, sizeof(data));

	data.size = size;
	mem_fd = ioctl(fd, TEE_IOC_SHM_ALLOC, &data);
	assert(mem_fd > 0);
	*shmem_id = data.id;

	*m = mmap(NULL, data.size, PROT_READ | PROT_WRITE, MAP_SHARED, mem_fd,
		  0);
	assert(*m != (void *)MAP_FAILED);
	close(mem_fd);

	return 0;
}

static int invoke_func(int fd, int session_id, int function_id,
		       uint64_t shmem_id, uint64_t offset, uint64_t size,
		       uint64_t attr)
{
	int rc;

	const size_t arg_size = sizeof(struct tee_ioctl_invoke_arg) +
				4 * sizeof(struct tee_ioctl_param);
	union {
		struct tee_ioctl_invoke_arg arg;
		uint8_t data[arg_size];
	} invoke_arg;
	struct tee_ioctl_buf_data buf_data = { .buf_len = sizeof(invoke_arg),
					       .buf_ptr =
						       (uintptr_t)&invoke_arg };
	struct tee_ioctl_invoke_arg *arg = &invoke_arg.arg;
	arg->num_params = 4;

	arg->session = session_id;
	arg->func = function_id;
	struct tee_ioctl_param *params = (struct tee_ioctl_param *)(arg + 1);

	for (int i = 1; i < 4; i++)
		arg->params[i].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	params[0] = (struct tee_ioctl_param){
		.attr = attr, .a = offset, .b = size, .c = shmem_id
	};

	if ((rc = ioctl(fd, TEE_IOC_INVOKE, &buf_data))) {
		perror("failed ioctl for INVOKE");
		return rc;
	}
	printf("invoke_request: res=%d   ret_origin=%d\n", arg->ret,
	       arg->ret_origin);

	return rc;
}

int main(int argc, char **argv)
{
	char const *tee_path = "/dev/tee0";

	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--help") == 0 ||
		    strcmp(argv[i], "-h") == 0) {
			printf("You can pass the path to the TEE device to query, otherwise "
			       "by default this programs queries /dev/tee0\n");

			return 0;
		} else {
			tee_path = argv[i];
		}
	}

	int fd, session_id;

	if ((fd = open(tee_path, O_RDWR)) < 0) {
		perror("failed to open TEE");
		return fd;
	}

	assert((session_id = do_open_session(fd)) != 0);

	uint64_t shmem_id;
	uint8_t *shared_mem;
	assert(alloc_shared_mem_buffer(fd, SHARED_MEM_SIZE, &shmem_id,
				       &shared_mem) == 0);

	printf("shmem id: %lx    shmem ptr: %p\n", shmem_id, shared_mem);

	// Test buffer in output, expect numbers from 0 to 63
	assert(invoke_func(fd, session_id, 1235, shmem_id, 0, 64,
			   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT) == 0);
	for (int i = 0; i < 64; i++)
		assert(shared_mem[i] == i);

	// Test buffer inout, expect numbers to be incremented (from 1 to 64)
	assert(invoke_func(fd, session_id, 1235, shmem_id, 0, 64,
			   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT) == 0);
	for (int i = 0; i < 64; i++)
		assert(shared_mem[i] == (i + 1));

	// Test buffer input, expect numbers not to be changed (check dmesg)
	assert(invoke_func(fd, session_id, 1235, shmem_id, 0, 64,
			   TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT) == 0);
	for (int i = 0; i < 64; i++)
		assert(shared_mem[i] == (i + 1));

	// FIXME: Add a test passing NULL ptr

	printf("---- SUCCESS ----\n");

	return 0;
}
