#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/crash_dump.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/tee_drv.h>
#include <linux/tee.h>
#include <linux/types.h>
#include <linux/workqueue.h>
#include <linux/platform_device.h>
#include "register_map.h"
#include "driver.h"
#include "tee_client_api.h"

static struct tee_device *tee_dev;

static uint8_t *mmio_reg_base_address;
static volatile uint64_t *reg_open_tee;
static volatile uint64_t *reg_close_tee;
static volatile uint64_t *reg_status;
static volatile uint64_t *reg_command_ptr;
static volatile uint32_t *reg_send_command;

#define LOG_SPAM 0
#define IS_MEMREF(a)                                                           \
	(a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||                       \
	 a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT ||                        \
	 a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT)

#define ATTR_TO_STR(a) \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT ? "VALUE_INPUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT ? "VALUE_OUTPUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT ? "VALUE_INOUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT ? "MEMREF_INPUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ? "MEMREF_OUTPUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT ? "MEMREF_INOUT" : \
	(a) == TEE_IOCTL_PARAM_ATTR_TYPE_NONE ? "NONE" : "INVALID_ATTR"

inline void wait_until_not_busy(void)
{
	// FIXME: This should take a lock instead
	while (ioread64(reg_status) & TP_MMIO_REG_STATUS_FLAG_BUSY)
		;
}

inline bool last_operation_completed_successfully(void)
{
	return !(ioread64(reg_status) & TP_MMIO_REG_STATUS_FLAG_ERROR);
}

// Note: You need to ensure that 'buf' was allocated via kmalloc
//       or this won't
static int wrap_and_send_command_to_passthrough(enum CommandId command_id,
						void *data, size_t data_length)
{
	struct CommandWrapper *wrapper = NULL;

	if (command_id >= __TP_CMD_Len || command_id < 0)
		return -ENOTSUPP;

	wrapper = kmalloc(sizeof(struct CommandWrapper), GFP_KERNEL);
	if (wrapper == NULL)
		return -ENOMEM;
	wrapper->cmd_id = command_id;
	wrapper->data = (uint64_t)virt_to_phys(data);
	wrapper->data_length = data_length;

	wait_until_not_busy();
	iowrite64(virt_to_phys(wrapper), reg_command_ptr);
	iowrite32(1, reg_send_command);
	wait_until_not_busy();

	kfree(wrapper);

	if (!last_operation_completed_successfully()) {
		// FIXME: Actually handle the error
		pr_info("[tee_passthrough]: Something went wrong while making the ioctl\n");
		return -ENOTSUPP;
	}

	return 0;
}

static int ensure_memrefs_in_params_are_synched_with_host(
	struct tee_context *ctx, struct tee_param *params, size_t num_params)
{
	int i, rc;
	struct CommandEnsureMemoryBuffersAreSynchronized *command;
	struct tee_passthrough_data *ctx_data = ctx->data;

	// First, let's check if we can skip this whole process if there
	// are no memrefs in the params
	for (i = 0; i < num_params; i++) {
		if (IS_MEMREF(params[i].attr))
			goto actually_sync;
	}
	return 0;

actually_sync:

	command = kmalloc(sizeof(*command), GFP_KERNEL);
	if (command == NULL)
		return -ENOMEM;

	command->guest_fd = ctx_data->fd;
	for (i = 0; i < num_params; i++) {
		if (!IS_MEMREF(params[i].attr)) {
			command->buffers[i].id = -1;
			continue;
		}

		command->buffers[i].id = params[i].u.memref.shm->id;
		command->buffers[i].size = params[i].u.memref.shm->size;
		command->buffers[i].flags = params[i].u.memref.shm->flags;
		command->buffers[i].paddr = params[i].u.memref.shm->paddr;
	}

	rc = wrap_and_send_command_to_passthrough(
		TP_CMD_EnsureMemoryBuffersAreSynchronized, command,
		sizeof(*command));

	kfree(command);

	return rc;
}

// FIXME: rename this to 'copy back values from cloned params'?
static int sync_back_param_changes_after_command(
	struct tee_context *ctx, struct tee_param *user_params,
	struct tee_ioctl_param *updated_params, size_t num_params)
{
	int i, rc = 0;

	for (i = 0; i < num_params; i++) {
		if (user_params[i].attr != updated_params[i].attr) {
			pr_info("[driver]: local.attr = %llx    updated.attr = %llx\n",
				user_params[i].attr, updated_params[i].attr);
			panic("[driver]: local and copied params do not have the same attr!");
		}

		if (user_params[i].attr ==
			    TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT ||
		    user_params[i].attr ==
			    TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
			user_params[i].u.value.a = updated_params[i].a;
			user_params[i].u.value.b = updated_params[i].b;
			user_params[i].u.value.c = updated_params[i].c;
		} else if (user_params[i].attr == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT || user_params[i].attr == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
			// I'm sure the size can change, otherwise regression 8001.* all fail because they start at size 2048 and shrink to 42 after
			// I'm not sure about the offset though, it shouldn't hurt to rewrite it though
			user_params[i].u.memref.shm_offs = updated_params[i].a;
			user_params[i].u.memref.size = updated_params[i].b;
		}
	}

	return rc;
}

static void tp_get_version(struct tee_device *tee_device,
			   struct tee_ioctl_version_data *ver)
{
	struct CommandGetVersion *cmd_version = NULL;

	cmd_version = kzalloc(sizeof(*cmd_version), GFP_KERNEL);
	if (cmd_version == NULL ||
	    wrap_and_send_command_to_passthrough(TP_CMD_GetVersion, cmd_version,
						 sizeof(*cmd_version))) {
		pr_err("[tee_passthrough]: failed to alloc memory, cannot talk with the external tee\n");
		*ver = (struct tee_ioctl_version_data){ .gen_caps = 0,
							.impl_caps = 0,
							.impl_id = 0 };
	} else {
		memcpy(ver, &cmd_version->version_data,
		       sizeof(cmd_version->version_data));
	}

	if (cmd_version != NULL)
		kfree(cmd_version);
}

static int tp_open(struct tee_context *ctx)
{
	int fd;
	struct tee_passthrough_data *ctx_data;

	ctx_data = kzalloc(sizeof(struct tee_passthrough_data), GFP_KERNEL);
	if (!ctx_data) {
		return -ENOMEM;
	}

	pr_info("[tee_passthrough]: tp_open was called\n");
	pr_info("[tee_passthrough]: reg_base=%px\n", mmio_reg_base_address);
	pr_info("[tee_passthrough]: reg_open_tee=%px\n", reg_open_tee);

	wait_until_not_busy();
	pr_info("[tee_passthrough]: not busy, going to open tee\n");
	fd = (int)ioread64(reg_open_tee);
	if (!last_operation_completed_successfully()) {
		pr_info("[tee_passthrough]: error flag is set, something bad happened");
		kfree(ctx_data);
		return -EAGAIN;
	}

	pr_info("[tee_passthrough]: Internal fd is %d\n", fd);

	ctx_data->fd = fd;

	ctx->data = ctx_data;

	return 0;
}

static void tp_release(struct tee_context *ctx)
{
	struct tee_passthrough_data *ctx_data = ctx->data;

	pr_info("[tee_passthrough]: tp_release was called\n");
	wait_until_not_busy();
	iowrite64((uint64_t)ctx_data->fd, reg_close_tee);

	kfree(ctx_data);
}

static int tp_open_session(struct tee_context *ctx,
			   struct tee_ioctl_open_session_arg *arg,
			   struct tee_param *params)
{
	int i, rc;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct CommandOpenSession *cmd = NULL;
	const size_t size_of_command_plus_params =
		sizeof(struct CommandOpenSession) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);
	struct tee_ioctl_param *cloned_params;

#if LOG_SPAM
	pr_info("[driver]: uuid: '%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x'\n"
		"\targ.clnt_uuid: '%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x'\n"
		"\tclnt_login: %x (TEE_IOCTL_LOGIN_PUBLIC=0)\n"
		"\tcancel_id: %x\n"
		"\tsession: %x\n"
		"\tret: %x\n"
		"\tret_origin: %x\n"
		"\tnum_params: %u\n",
		arg->uuid[0], arg->uuid[1], arg->uuid[2], arg->uuid[3],
		arg->uuid[4], arg->uuid[5], arg->uuid[6], arg->uuid[7],
		arg->uuid[8], arg->uuid[9], arg->uuid[10], arg->uuid[11],
		arg->uuid[12], arg->uuid[13], arg->uuid[14], arg->uuid[15],

		arg->clnt_uuid[0], arg->clnt_uuid[1], arg->clnt_uuid[2],
		arg->clnt_uuid[3], arg->clnt_uuid[4], arg->clnt_uuid[5],
		arg->clnt_uuid[6], arg->clnt_uuid[7], arg->clnt_uuid[8],
		arg->clnt_uuid[9], arg->clnt_uuid[10], arg->clnt_uuid[11],
		arg->clnt_uuid[12], arg->clnt_uuid[13], arg->clnt_uuid[14],
		arg->clnt_uuid[15],

		arg->clnt_login, arg->cancel_id, arg->session, arg->ret,
		arg->ret_origin, arg->num_params);
#endif

	if (arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT) {
		pr_err("[driver]: arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT\n");
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;

		return -EINVAL;
	}

	// We want these values to be contiguous in memory
	cmd = kmalloc(size_of_command_plus_params, GFP_KERNEL);
	cloned_params = (struct tee_ioctl_param *)(cmd + 1);

	if (cmd == NULL) {
		pr_err("[driver]: kmalloc failed");
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;

		return -ENOMEM;
	}
	memset(cmd, 0, size_of_command_plus_params);

	// Setup the values for the command
	cmd->fd = ctx_data->fd;
	memcpy(&cmd->open_session_arg, arg, sizeof(*arg));
	for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
		cloned_params[i].attr = params[i].attr;
		cloned_params[i].a = params[i].u.value.a;
		cloned_params[i].b = params[i].u.value.b;
		cloned_params[i].c = params[i].u.value.c;
	}

	ensure_memrefs_in_params_are_synched_with_host(ctx, params,
						       arg->num_params);

	if ((rc = wrap_and_send_command_to_passthrough(TP_CMD_OpenSession, cmd,
					     size_of_command_plus_params))) {
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		arg->ret = rc;
	}
	
	sync_back_param_changes_after_command(ctx, params, cloned_params,
					      arg->num_params);
	memcpy(arg, &cmd->open_session_arg, sizeof(*arg));

	kfree(cmd);

	return 0;
}

static int tp_close_session(struct tee_context *ctx, u32 session)
{
	struct tee_passthrough_data *ctx_data = ctx->data;
	int rc;
	struct CommandCloseSession *command =
		kmalloc(sizeof(*command), GFP_KERNEL);
	if (command == NULL)
		return -ENOMEM;

	command->fd = ctx_data->fd;
	command->close_session_arg.session = session;
	rc = wrap_and_send_command_to_passthrough(TP_CMD_CloseSession, command,
						  sizeof(*command));
	kfree(command);

	return rc;
}

static int tp_invoke_func(struct tee_context *ctx,
			  struct tee_ioctl_invoke_arg *arg,
			  struct tee_param *params)
{
	int i, rc;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct CommandInvokeFunction *cmd = NULL;
	const size_t size_of_command_plus_params =
		sizeof(struct CommandInvokeFunction) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);
	struct tee_ioctl_param *cloned_params;

#if LOG_SPAM
	pr_info("[driver]: invoke_func\n"
		"\t func: %u\n"
		"\t session: %u\n"
		"\t cancel_id: %u\n"
		"\t ret: %u\n"
		"\t ret_origin: %u\n"
		"\t num_params: %u\n",
		arg->func, arg->session, arg->cancel_id, arg->ret,
		arg->ret_origin, arg->num_params);
#endif

	if (arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT) {
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		pr_err("[driver]: arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT\n");

		return -EINVAL;
	}

	// We want these values to be contiguous in memory
	cmd = kmalloc(size_of_command_plus_params, GFP_KERNEL);
	cloned_params = (struct tee_ioctl_param *)(cmd + 1);

	if (cmd == NULL) {
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;

		return -ENOMEM;
	}
	memset(cmd, 0, size_of_command_plus_params);

	// Setup the values for the command
	cmd->fd = ctx_data->fd;
	memcpy(&cmd->invoke_function_arg, arg, sizeof(*arg));
	for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
		cloned_params[i].attr = params[i].attr;
		if (IS_MEMREF(params[i].attr)) {
			cloned_params[i].a = params[i].u.memref.shm_offs;
			cloned_params[i].b = params[i].u.memref.size;
			cloned_params[i].c = params[i].u.memref.shm->id;
		} else {
			cloned_params[i].a = params[i].u.value.a;
			cloned_params[i].b = params[i].u.value.b;
			cloned_params[i].c = params[i].u.value.c;
		}
	}

	ensure_memrefs_in_params_are_synched_with_host(ctx, params,
						       arg->num_params);
	if ((rc = wrap_and_send_command_to_passthrough(TP_CMD_InvokeFunction, cmd,
					     size_of_command_plus_params))) {
		arg->ret_origin = TEEC_ORIGIN_COMMS;
		arg->ret = rc;
	}
	sync_back_param_changes_after_command(ctx, params, cloned_params,
					      arg->num_params);
	memcpy(arg, &cmd->invoke_function_arg, sizeof(*arg));

	kfree(cmd);

	return 0;
}

static int tp_cancel_req(struct tee_context *ctx, u32 cancel_id, u32 session)
{
	struct tee_passthrough_data *ctx_data = ctx->data;
	int rc;
	struct CommandCancelRequest *command =
		kmalloc(sizeof(*command), GFP_KERNEL);
	if (command == NULL)
		return -ENOMEM;

	command->fd = ctx_data->fd;
	command->cancel_request_arg.cancel_id = cancel_id;
	command->cancel_request_arg.session = session;

	rc = wrap_and_send_command_to_passthrough(TP_CMD_CancelRequest, command,
						  sizeof(*command));
	kfree(command);

	return rc;
}

static const struct tee_driver_ops tee_ops = {
	.get_version = tp_get_version,
	.open = tp_open,
	.release = tp_release,
	.open_session = tp_open_session,
	.close_session = tp_close_session,
	.invoke_func = tp_invoke_func,
	.cancel_req = tp_cancel_req,
};

static int tp_pool_alloc(struct tee_shm_pool_mgr *pool, struct tee_shm *shm,
			 size_t size)
{
	unsigned int order = get_order(size);
	unsigned long va;

	/*
	 * Ignore alignment since this is already going to be page aligned
	 * and there's no need for any larger alignment.
	 */
	va = __get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
	if (!va)
		return -ENOMEM;

	shm->kaddr = (void *)va;
	shm->paddr = virt_to_phys((void *)va);
	shm->size = PAGE_SIZE << order;

	/* 
	 * Note that we don't immediately call qemu to alloc the shared memory
	 * because the TEE subsystem has not yet assigned shm->id here and
	 * therefore we cannot pass it to create the mapping.
	 * Instead it will be created the first time we invoke a function using
	 * that shm->id
	 */

	return 0;
}

static void tp_pool_free(struct tee_shm_pool_mgr *pool, struct tee_shm *shm)
{
	struct CommandFreeSharedMemoryBuffer *command;
	struct tee_passthrough_data *ctx_data = shm->ctx->data;

	free_pages((unsigned long)shm->kaddr, get_order(shm->size));
	shm->kaddr = NULL;

	command = kmalloc(sizeof(*command), GFP_KERNEL);
	if (command == NULL)
		panic("out of memory");

	command->guest_fd = ctx_data->fd;
	command->shmem_id = shm->id;
	wrap_and_send_command_to_passthrough(TP_CMD_FreeSharedMemoryBuffer,
					     command, sizeof(*command));
}

static void tp_pool_destroy(struct tee_shm_pool_mgr *pool)
{
	kfree(pool);
}

static const struct tee_shm_pool_mgr_ops pool_ops = {
	.alloc = tp_pool_alloc,
	.free = tp_pool_free,
	.destroy_poolmgr = tp_pool_destroy,
};

static struct tee_shm_pool_mgr *pool_mem_mgr_alloc(void)
{
	struct tee_shm_pool_mgr *mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);

	if (!mgr)
		return ERR_PTR(-ENOMEM);

	mgr->ops = &pool_ops;

	return mgr;
}

static struct tee_shm_pool *tp_alloc_shm_pool(void)
{
	struct tee_shm_pool_mgr *priv_mgr;
	struct tee_shm_pool_mgr *dmabuf_mgr;
	void *rc;

	rc = pool_mem_mgr_alloc();
	if (IS_ERR(rc))
		return rc;
	priv_mgr = rc;

	rc = pool_mem_mgr_alloc();
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		return rc;
	}
	dmabuf_mgr = rc;

	rc = tee_shm_pool_alloc(priv_mgr, dmabuf_mgr);
	if (IS_ERR(rc)) {
		tee_shm_pool_mgr_destroy(priv_mgr);
		tee_shm_pool_mgr_destroy(dmabuf_mgr);
	}

	return rc;
}

static const struct tee_desc tee_desc = {
	.name = "tee-passthrough-clnt",
	.ops = &tee_ops,
	.owner = THIS_MODULE,
};

static int tp_driver_init(void)
{
	int rc;
	struct tee_shm_pool *pool;
	uint8_t *base;

	pr_info("[tee_passthrough]: Initializing TEE Passthrough\n");

	base = ioremap(TP_MMIO_BASE_ADDRESS, TP_MMIO_AREA_SIZE);
	pr_info("[tee_passthrough]: Remapped MMIO area to %px\n", base);

	mmio_reg_base_address = base;
	reg_open_tee = (uint64_t *)&base[TP_MMIO_REG_OFFSET_OPEN_TEE];
	reg_close_tee = (uint64_t *)&base[TP_MMIO_REG_OFFSET_CLOSE_TEE];
	reg_status = (uint64_t *)&base[TP_MMIO_REG_OFFSET_STATUS];
	reg_command_ptr = (uint64_t *)&base[TP_MMIO_REG_OFFSET_COMMAND_PTR];
	reg_send_command = (uint32_t *)&base[TP_MMIO_REG_OFFSET_SEND_COMMAND];

	pr_info("[tee_passthrough]: Allocating the shared memory pool\n");
	pool = tp_alloc_shm_pool();
	if (!pool) {
		pr_err("[tee_passthrough]: Fatal while allocating shared memory pool\n");
		return -ENOMEM;
	}

	tee_dev = tee_device_alloc(&tee_desc, NULL, pool, NULL);
	if (IS_ERR(tee_dev)) {
		pr_err("[tee_passthrough]: Fatal while allocating the device. Err: %ld\n",
		       PTR_ERR(tee_dev));
		return PTR_ERR(tee_dev);
	}

	rc = tee_device_register(tee_dev);
	if (rc) {
		pr_err("[tee_passthrough]: Fatal while registering the device. Err: %d\n",
		       rc);
	}
	return rc;
}
module_init(tp_driver_init);

void tp_driver_cleanup(void)
{
	pr_info("[tee_passthrough]: driver removed");
	iounmap(mmio_reg_base_address);
	tee_device_unregister(tee_dev);
}
module_exit(tp_driver_cleanup);

MODULE_AUTHOR("Marco Cutecchia");
MODULE_DESCRIPTION("TEE-Passthrough Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL v2");
