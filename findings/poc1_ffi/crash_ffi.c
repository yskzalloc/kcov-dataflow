// SPDX-License-Identifier: GPL-2.0
/*
 * crash_ffi.c - Demonstrate FFI contract violation → NULL deref → panic
 * Models binder_alloc_buf() returning success with buffer=NULL
 * Any user can trigger via: echo 1 > /dev/crash_ffi
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/miscdevice.h>

MODULE_LICENSE("GPL");

struct ffi_alloc {
	void *buffer;
	u64 data_size;
	u32 free_async;
	u32 flags;
};

/* Buggy C allocator (models binder_alloc_buf async path) */
static noinline int ffi_alloc_buf(struct ffi_alloc *alloc, u64 data_size,
				  u64 offsets_size, int is_async)
{
	if (!is_async) {
		alloc->buffer = kmalloc(data_size, GFP_KERNEL);
		if (!alloc->buffer)
			return -ENOMEM;
		return 0;
	}
	/* BUG: pool exhausted, returns 0 but buffer stays NULL */
	if (alloc->free_async == 0) {
		alloc->buffer = NULL;
		return 0; /* should be -ENOSPC */
	}
	alloc->buffer = kmalloc(data_size, GFP_KERNEL);
	alloc->free_async--;
	return 0;
}

/* Caller that trusts the return code (models Rust FFI caller) */
static noinline void caller_trusts_retcode(int is_async, u32 free_pool)
{
	struct ffi_alloc alloc = { .buffer = NULL, .free_async = free_pool };
	int ret;

	ret = ffi_alloc_buf(&alloc, 256, 16, is_async);
	if (ret == 0) {
		/* Contract: ret==0 means buffer is valid */
		pr_info("crash_ffi: ret=0, buffer=%px, dereferencing...\n",
			alloc.buffer);
		/* This is what a Rust caller would do after checking ret==0 */
		memset(alloc.buffer, 0x41, 16); /* ← NULL DEREF PANIC */
		kfree(alloc.buffer);
	} else {
		pr_info("crash_ffi: alloc failed with %d (expected)\n", ret);
	}
}

static ssize_t crash_write(struct file *f, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	pr_info("crash_ffi: triggering with is_async=1, free_async=0\n");
	caller_trusts_retcode(1, 0); /* triggers the bug */
	return count;
}

static const struct file_operations crash_fops = { .owner = THIS_MODULE, .write = crash_write };

static struct miscdevice crash_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "crash_ffi",
	.fops = &crash_fops,
	.mode = 0666, /* world-writable — any user can trigger */
};

static int __init crash_ffi_init(void)
{
	int ret = misc_register(&crash_misc);
	if (ret)
		return ret;
	pr_info("crash_ffi: loaded. Any user: echo 1 > /dev/crash_ffi\n");
	return 0;
}

static void __exit crash_ffi_exit(void)
{
	misc_deregister(&crash_misc);
}

module_init(crash_ffi_init);
module_exit(crash_ffi_exit);
