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
#include "tee_client_api.h"


// This is the "HelloWorld" TA's UUID taken from OP-TEE's examples
// clang-format off
uint8_t HELLO_WORLD_TA_UUID[] = { 
	0x8a, 0xaa, 0xf2, 0x00, 
	0x24, 0x50, 
	0x11, 0xe4, 0xab, 0xe2, 0x00, 0x02, 0xa5, 0xd5, 0xc5, 0x1b
};
// clang-format on

int main(int argc, char **argv)
{
	int rc;
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

	int fd;
	if ((fd = open(tee_path, O_RDWR)) < 0) {
		perror("failed to open TEE");
		return fd;
	}

	union {
		struct tee_ioctl_open_session_arg arg;
		uint8_t data[sizeof(struct tee_ioctl_open_session_arg) +
			     sizeof(struct tee_ioctl_param) * TEEC_CONFIG_PAYLOAD_REF_COUNT];
	} open_session_arg;
	struct tee_ioctl_buf_data open_session_buf_data = { .buf_len = sizeof(open_session_arg), .buf_ptr = (uintptr_t)&open_session_arg };
	struct tee_ioctl_open_session_arg *open_session = &open_session_arg.arg;
	open_session->clnt_login = TEE_IOCTL_LOGIN_PUBLIC;
	open_session->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;

	open_session->params[0].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	open_session->params[1].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	open_session->params[2].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;
	open_session->params[3].attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE;

	memcpy(open_session->uuid, HELLO_WORLD_TA_UUID, sizeof(HELLO_WORLD_TA_UUID));
	if ((rc = ioctl(fd, TEE_IOC_OPEN_SESSION, &open_session_buf_data))) {
		perror("failed ioctl for OPEN_SESSION");
		return rc;
	}
	printf("session opened\n\tret: %x\n\torigin: %x\n\tsession_id: %u\n",
	       open_session->ret, open_session->ret_origin, open_session->session);
	unsigned int session_id = open_session->session;

	const size_t arg_size = sizeof(struct tee_ioctl_invoke_arg) + 
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);
	union {
		struct tee_ioctl_invoke_arg arg;
		uint8_t data[arg_size];
	} invoke_arg;
	struct tee_ioctl_buf_data buf_data = {.buf_len = sizeof(invoke_arg), .buf_ptr = (uintptr_t)&invoke_arg };
	struct tee_ioctl_invoke_arg *arg = &invoke_arg.arg;
	struct tee_ioctl_param *params = (struct tee_ioctl_param *)(arg + 1);

	arg->session = open_session->session;
	// ID of the function we want to request inside this TA. 
	// The HelloWorld TA has 2 functions: 0=>increment number, 1=>decrement number module
	arg->func = 0;
	arg->num_params = TEEC_CONFIG_PAYLOAD_REF_COUNT;
	
	params[0] = (struct tee_ioctl_param){
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT, 
		.a = 0x1111, .b = 0x2222, .c = 0x3333
	};
	params[1] = (struct tee_ioctl_param){
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE, 
		.a = 0, .b = 0, .c = 0
	};
	params[2] = (struct tee_ioctl_param){
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE, 
		.a = 0, .b = 0, .c = 0
	};
	params[3] = (struct tee_ioctl_param){
		.attr = TEE_IOCTL_PARAM_ATTR_TYPE_NONE, 
		.a = 0, .b = 0, .c = 0
	};

    if ((rc = ioctl(fd, TEE_IOC_INVOKE, &buf_data))) {
        perror("failed ioctl for INVOKE");
		printf("invoke_request = {.res = %x, .origin=%x}\n", arg->ret, arg->ret_origin);
        return rc;
    }
	printf("invoke_request: res=%d   ret_origin=%d\n", arg->ret, arg->ret_origin);
	printf("a=%llx b=%llx c=%llx\n", params[0].a, params[0].b, params[0].c);

	struct tee_ioctl_close_session_arg close_session_arg;
	close_session_arg.session = session_id;
	if ((rc = ioctl(fd, TEE_IOC_CLOSE_SESSION, &close_session_arg))) {
		perror("failed ioctl for CLOSE_SESSION");
		return rc;
	}
	printf("session closed successfully\n");

	return 0;
}
