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

static struct tee_device *tee_dev;

static volatile uint64_t *reg_base;
static volatile uint64_t *reg_open_tee;
static volatile uint64_t *reg_close_tee;
static volatile uint64_t *reg_status;

static void tp_get_version(struct tee_device *tee_device,
				struct tee_ioctl_version_data *ver)
{
	pr_info("[tee_passthrough]: Requested version\n");
	ver->impl_id = 1234;
	ver->impl_caps = 0xcafebabe;
	ver->gen_caps = 0xdeadb33f;
}

static int tp_open(struct tee_context *ctx)
{
	pr_info("[tee_passthrough]: tp_open was called\n");

	return 0;
}

static void tp_release(struct tee_context *ctx)
{
	pr_info("[tee_passthrough]: tp_release was called\n");
}

static int tp_open_session(struct tee_context *ctx,
				struct tee_ioctl_open_session_arg *arg,
				struct tee_param *param)
{
	pr_info("[tee_passthrough]: tp_open_session was called\n");
	return -1;
}

static int tp_close_session(struct tee_context *ctx, u32 session)
{
	pr_info("[tee_passthrough]: tp_close_session\n");
	return 0;
}

static int tp_invoke_func(struct tee_context *ctx,
			       struct tee_ioctl_invoke_arg *arg,
			       struct tee_param *param)
{
	pr_info("[tee_passthrough]: tp_invoke_func was called\n");
	return -1;
}

static int tp_cancel_req(struct tee_context *ctx, u32 cancel_id,
			      u32 session)
{
	pr_info("[tee_passthrough]: tp_cancel_req was called\n");
	return -4321;
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

	return 0;
}

static void tp_pool_free(struct tee_shm_pool_mgr *pool,
			      struct tee_shm *shm)
{
	free_pages((unsigned long)shm->kaddr, get_order(shm->size));
	shm->kaddr = NULL;
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
	pr_info("[tee_passthrough]: Remapped MMIO area to %p\n", base);

	reg_base = (uint64_t*) base;
	reg_open_tee = (uint64_t*) &base[TP_MMIO_REG_OFFSET_OPEN_TEE];
	reg_close_tee = (uint64_t*) &base[TP_MMIO_REG_OFFSET_CLOSE_TEE];

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
