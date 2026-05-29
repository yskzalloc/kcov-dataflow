// SPDX-License-Identifier: GPL-2.0
// poc1_ffi_helper.c - C side of FFI contract violation
// Contract: returns 0 → out->buffer is valid. Returns <0 → undefined.
// BUG: returns 0 but leaves buffer=NULL when is_async=1 and pool exhausted.
#include <linux/module.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

struct ffi_alloc {
	void *buffer;
	u64 data_size;
	u32 free_async;
	u32 flags;
};

int ffi_alloc_buf(struct ffi_alloc *alloc, u64 data_size,
		  u64 offsets_size, int is_async);

noinline int ffi_alloc_buf(struct ffi_alloc *alloc, u64 data_size,
			   u64 offsets_size, int is_async)
{
	if (!is_async) {
		alloc->buffer = kmalloc(data_size, GFP_KERNEL);
		if (!alloc->buffer)
			return -ENOMEM;
		return 0;
	}
	// BUG: async path returns 0 (success) but doesn't set buffer when pool empty
	if (alloc->free_async == 0) {
		// Should return -ENOSPC here, but falls through to return 0
		alloc->buffer = NULL;  // left as NULL!
		return 0;  // CONTRACT VIOLATION: success but buffer is NULL
	}
	alloc->buffer = kmalloc(data_size, GFP_KERNEL);
	alloc->free_async--;
	return 0;
}
EXPORT_SYMBOL(ffi_alloc_buf);
