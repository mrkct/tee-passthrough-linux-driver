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

static volatile uint32_t *reg_base;
static volatile uint32_t *reg_open_tee;
static volatile uint32_t *reg_close_tee;
static volatile uint32_t *reg_status;
static volatile uint64_t *reg_ioctl_fd;
static volatile uint64_t *reg_ioctl_num;
static volatile uint64_t *reg_ioctl_phys_data_buffer;
static volatile uint64_t *reg_ioctl_phys_data_buffer_length;
static volatile uint64_t *reg_test;

#define LOG_SPAM 1
#define IS_MEMREF_ATTR(a) ( 							\
		a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT ||	\
		a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT ||	\
		a == TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT 	\
	)


inline void wait_until_not_busy(void)
{
	// FIXME: This should take a lock instead
	while(*reg_status & TP_MMIO_REG_STATUS_FLAG_BUSY)
		;
}

inline bool last_operation_completed_successfully(void)
{
	return !(*reg_status & TP_MMIO_REG_STATUS_FLAG_ERROR);
}

// Note: You need to ensure that 'buf' was allocated via kmalloc
//       or this won't
static int make_external_ioctl(int fd, uint64_t ioctl, void *buf, size_t buf_len)
{
	wait_until_not_busy();

	*reg_ioctl_num = ioctl;
	*reg_ioctl_phys_data_buffer = virt_to_phys(buf);
	*reg_ioctl_phys_data_buffer_length = buf_len;
	*reg_ioctl_fd = fd;

	wait_until_not_busy();

	if (!last_operation_completed_successfully()) {
		// FIXME: Actually handle the error
		pr_info("[tee_passthrough]: Something went wrong while making the ioctl\n");
		return -ENOTSUPP;
	}

	return 0;
}


static void synchronize_shared_memory_buffer_with_host(
	enum SynchonizeSharedMemoryBufferDirection direction, 
	struct tee_shm *shm, 
	size_t update_subsection_offset,
	size_t update_subsection_size
)
{
	
}

static void sync_allocated_shared_memory_buffers_in_params_with_host(
	struct tee_context *ctx,
	struct tee_param *params,
	size_t num_params
)
{
	int i;

	for (i = 0; i < num_params; i++) {
		if (!IS_MEMREF(params[i].attr))
			continue;
		
		synchronize_shared_memory_buffer_with_host(
			SYNC_GUEST_TO_HOST, 
			params[i].u.memref.shm, 
			params[i].u.memref.shm_offs, 
			params[i].u.memref.size
		);
	}
}

static void sync_back_param_changes_after_external_ioctl(
	struct tee_context *ctx,
	struct tee_param *user_params,
	struct tee_ioctl_param *updated_params,
	size_t num_params
)
{
	int i, rc = 0;
	struct tee_shm *shm;

	pr_info("[driver]: sync_back_param_changes_after_external_ioctl\n");
	for (i = 0; i < num_params; i++) {
		if (user_params[i].attr != updated_params[i].attr) {
			pr_info("[driver]: local.attr = %llx    updated.attr = %llx\n", user_params[i].attr, updated_params[i].attr);
			panic("[driver]: local and copied params do not have the same attr!");
		}
		
		switch(user_params[i].attr) {
		case TEE_IOCTL_PARAM_ATTR_TYPE_NONE:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INPUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INPUT:
		continue;

		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_INOUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_VALUE_OUTPUT:
			user_params[i].u.value.a = updated_params[i].a;
			user_params[i].u.value.b = updated_params[i].b;
			user_params[i].u.value.c = updated_params[i].c;
			break;
		
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_INOUT:
		case TEE_IOCTL_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
			if (user_params[i].u.memref.shm c != updated_params[i].c) {
				rc = -EINVAL;
				break;
			}
			
			shm = tee_shm_get_from_id(ctx, params[i].c);
			if (IS_ERR(shm)) {
				rc = -EINVAL;
				break;
			}


			break;
		default:
			panic("[driver]: unknown type attr %llx\n", user_params[i].attr);
		}
	}

	return rc;
}

static void tp_get_version(struct tee_device *tee_device,
				struct tee_ioctl_version_data *ver)
{
	void *temp_buf;

	pr_info("[tee_passthrough]: tp_get_version was called\n");
	temp_buf = kzalloc(sizeof(*ver), GFP_KERNEL);
	if (temp_buf == NULL) {
		pr_err("[tee_passthrough]: failed to alloc memory, cannot talk with the external tee\n");
		*ver = (struct tee_ioctl_version_data){
			.gen_caps = 0,
			.impl_caps = 0,
			.impl_id = 0
		};
		return;
	}

	// TEE_IOC_VERSION is a special case for which any file descriptor
	// (even a non-existant one) will work
	make_external_ioctl(0, TEE_IOC_VERSION, temp_buf, sizeof(*ver));
	memcpy(ver, temp_buf, sizeof(*ver));
	kfree(temp_buf);	
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
	pr_info("[tee_passthrough]: reg_base=%px\n", reg_base);
	pr_info("[tee_passthrough]: reg_open_tee=%px\n", reg_open_tee);

	wait_until_not_busy();
	pr_info("[tee_passthrough]: not busy, going to open tee\n");
	fd = (int) (*reg_open_tee);
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
	*reg_close_tee = ctx_data->fd;

	kfree(ctx_data);
}

static int tp_open_session(struct tee_context *ctx,
				struct tee_ioctl_open_session_arg *arg,
				struct tee_param *param)
{
	int rc = 0;
	int i;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct tee_ioctl_buf_data *local_buf_data = NULL;
	struct tee_ioctl_open_session_arg *local_arg = NULL;
	struct tee_ioctl_param *local_params = NULL;

	const size_t arg_size = sizeof(struct tee_ioctl_open_session_arg) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);
	const size_t total_memory = sizeof(struct tee_ioctl_buf_data) + arg_size;

#if LOG_SPAM
	pr_info(
        "[driver]: uuid: '%x%x%x%x-%x%x-%x%x-%x%x-%x%x%x%x%x%x'\n"
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

        arg->clnt_uuid[0], arg->clnt_uuid[1], arg->clnt_uuid[2], arg->clnt_uuid[3],
		arg->clnt_uuid[4], arg->clnt_uuid[5], arg->clnt_uuid[6], arg->clnt_uuid[7],
		arg->clnt_uuid[8], arg->clnt_uuid[9], arg->clnt_uuid[10], arg->clnt_uuid[11],
		arg->clnt_uuid[12], arg->clnt_uuid[13], arg->clnt_uuid[14], arg->clnt_uuid[15],

	    arg->clnt_login,
        arg->cancel_id,
        arg->session,
        arg->ret,
        arg->ret_origin,
        arg->num_params
	);
#endif

	if (arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT) {
		rc = -EINVAL;
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;

		goto cleanup;
	}
	
	// We want these values to be contiguous in memory
	local_buf_data = kmalloc(sizeof(total_memory), GFP_KERNEL);
	local_arg = (struct tee_ioctl_open_session_arg*)(local_buf_data + 1);
	local_params = (struct tee_ioctl_param*)(local_arg + 1);
	
	if (local_buf_data == NULL) {
		rc = -ENOMEM;
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;

		goto cleanup;
	}
	memset(local_buf_data, 0, total_memory);
	local_buf_data->buf_ptr = virt_to_phys(local_arg); 
	local_buf_data->buf_len = arg_size;
	
	memcpy(local_arg, arg, sizeof(*local_arg));
	for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
		local_params[i].attr = param[i].attr;
		local_params[i].a = param[i].u.value.a;
		local_params[i].b = param[i].u.value.b;
		local_params[i].c = param[i].u.value.c;
	}

	if (ctx_data->requires_updating_allocated_shared_mem_bufs) {
		sync_allocated_shared_memory_buffers_in_params_with_host(ctx, param, arg->num_params);
		ctx_data->requires_updating_allocated_shared_mem_bufs = 0;
	}

	rc = make_external_ioctl(
		ctx_data->fd, 
		TEE_IOC_OPEN_SESSION, 
		local_buf_data, sizeof(*local_buf_data)
	);

	sync_back_param_changes_after_external_ioctl(param, local_params, arg->num_params);
	memcpy(arg, local_arg, sizeof(*arg));
cleanup:
	if (local_buf_data != NULL)
		kfree(local_buf_data);

	return rc;
}

static int tp_close_session(struct tee_context *ctx, u32 session)
{
	int rc;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct tee_ioctl_close_session_arg *arg = kmalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;

	arg->session = session;
	rc = make_external_ioctl(ctx_data->fd, TEE_IOC_CLOSE_SESSION, arg, sizeof(*arg));
	kfree(arg);	

	return rc;
}

static int tp_invoke_func(struct tee_context *ctx,
			       struct tee_ioctl_invoke_arg *arg,
			       struct tee_param *param)
{
	int rc = 0;
	int i;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct tee_ioctl_buf_data *local_buf_data = NULL;
	struct tee_ioctl_invoke_arg *local_arg = NULL;
	struct tee_ioctl_param *local_params = NULL;

	const size_t arg_size = sizeof(struct tee_ioctl_invoke_arg) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT * sizeof(struct tee_ioctl_param);
	const size_t total_memory = sizeof(struct tee_ioctl_buf_data) + arg_size;

#if LOG_SPAM
	pr_info(
		"[driver]: invoke_func\n"
		"\t func: %u\n"
		"\t session: %u\n"
		"\t cancel_id: %u\n"
		"\t ret: %u\n"
		"\t ret_origin: %u\n"
		"\t num_params: %u\n",
		arg->func,
		arg->session,
		arg->cancel_id,
		arg->ret,
		arg->ret_origin,
		arg->num_params
	);
#endif

	if (arg->num_params > TEEC_CONFIG_PAYLOAD_REF_COUNT) {
		rc = -EINVAL;
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_BAD_PARAMETERS;

		goto cleanup;
	}
	
	// We want these values to be contiguous in memory
	local_buf_data = kmalloc(sizeof(total_memory), GFP_KERNEL);
	local_arg = (struct tee_ioctl_invoke_arg*)(local_buf_data + 1);
	local_params = (struct tee_ioctl_param*)(local_arg + 1);
	
	if (local_buf_data == NULL) {
		rc = -ENOMEM;
		arg->ret_origin = TEEC_ORIGIN_API;
		arg->ret = TEEC_ERROR_OUT_OF_MEMORY;

		goto cleanup;
	}
	memset(local_buf_data, 0, total_memory);
	local_buf_data->buf_ptr = virt_to_phys(local_arg); 
	local_buf_data->buf_len = arg_size;
	
	memcpy(local_arg, arg, sizeof(*local_arg));
	for (i = 0; i < TEEC_CONFIG_PAYLOAD_REF_COUNT; i++) {
		local_params[i].attr = param[i].attr;
		local_params[i].a = param[i].u.value.a;
		local_params[i].b = param[i].u.value.b;
		local_params[i].c = param[i].u.value.c;
	}

	convert_params_to_use_physical_addresses(local_params, arg->num_params);

	rc = make_external_ioctl(
		ctx_data->fd, 
		TEE_IOC_INVOKE, 
		local_buf_data, sizeof(*local_buf_data)
	);

	sync_back_param_changes_after_external_ioctl(param, local_params, arg->num_params);
	memcpy(arg, local_arg, sizeof(*arg));

	#if LOG_SPAM
	pr_info(
		"[driver]: invoke_func (post external ioctl)\n"
		"\t func: %u\n"
		"\t session: %u\n"
		"\t cancel_id: %u\n"
		"\t ret: %u\n"
		"\t ret_origin: %u\n"
		"\t num_params: %u\n",
		arg->func,
		arg->session,
		arg->cancel_id,
		arg->ret,
		arg->ret_origin,
		arg->num_params
	);
#endif
cleanup:
	if (local_buf_data != NULL)
		kfree(local_buf_data);

	return rc;	
}

static int tp_cancel_req(struct tee_context *ctx, u32 cancel_id,
			      u32 session)
{
	int rc;
	struct tee_passthrough_data *ctx_data = ctx->data;
	struct tee_ioctl_cancel_arg *arg = kmalloc(sizeof(*arg), GFP_KERNEL);
	if (arg == NULL)
		return -ENOMEM;
	
	arg->cancel_id = cancel_id;
	arg->session = session;
	rc = make_external_ioctl(ctx_data->fd, TEE_IOC_CANCEL, arg, sizeof(*arg));

	kfree(arg);
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

static int tp_pool_alloc(struct tee_shm_pool_mgr *pool,
			      struct tee_shm *shm, size_t size)
{
	struct tee_passthrough_data *ctx_data = shm->ctx->data;
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
	ctx_data->requires_updating_allocated_shared_mem_bufs = 1;

	return 0;
}

static void tp_pool_free(struct tee_shm_pool_mgr *pool,
			      struct tee_shm *shm)
{
	free_pages((unsigned long)shm->kaddr, get_order(shm->size));
	shm->kaddr = NULL;
	// TODO: call qemu and free the associated space

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

	reg_base = (uint32_t*) base;
	reg_open_tee = (uint32_t*) &base[TP_MMIO_REG_OFFSET_OPEN_TEE];
	reg_close_tee = (uint32_t*) &base[TP_MMIO_REG_OFFSET_CLOSE_TEE];
	reg_status = (uint32_t*) &base[TP_MMIO_REG_OFFSET_STATUS];
	reg_ioctl_fd = (uint64_t*) &base[TP_MMIO_REG_IOCTL_FD];
	reg_ioctl_phys_data_buffer = (uint64_t*) &base[TP_MMIO_REG_IOCTL_PHYS_DATA_BUFFER];
	reg_ioctl_phys_data_buffer_length = (uint64_t*) &base[TP_MMIO_REG_IOCTL_PHYS_DATA_BUFFER_LEN];
	reg_ioctl_num = (uint64_t*) &base[TP_MMIO_REG_IOCTL_NUM];
	reg_test = (uint64_t*) &base[0x50];

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
		pr_err("[tee_passthrough]: Fatal while registering the device. Err: %d\n", rc);
	}
	return rc;
}
module_init(tp_driver_init);

void tp_driver_cleanup(void)
{
	pr_info("[tee_passthrough]: driver removed");
	iounmap(reg_base);
	tee_device_unregister(tee_dev);
}
module_exit(tp_driver_cleanup);

MODULE_AUTHOR("Marco Cutecchia");
MODULE_DESCRIPTION("TEE-Passthrough Driver");
MODULE_VERSION("0.1");
MODULE_LICENSE("GPL v2");
