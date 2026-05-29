// SPDX-License-Identifier: GPL-2.0
// poc2_iouring.c - Simulates silent in-bounds corruption of a flag field.
// Models io_kiocb where io_req_set_rsrc_node() writes to wrong adjacent field.
// Write to /proc/poc2_iouring to trigger.
#include <linux/module.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");

#define REQ_F_FIXED_FILE  0x0040
#define REQ_F_RSRC_NODE   0x0200

struct sim_io_kiocb {
	u32 opcode;
	u32 flags;       // should be invariant after prep
	u32 rsrc_flags;  // intended target
	u64 user_data;
};

// Simulates io_read_prep: sets initial flags
noinline int sim_io_read_prep(struct sim_io_kiocb *req, u32 opcode, u64 user_data);
noinline int sim_io_read_prep(struct sim_io_kiocb *req, u32 opcode, u64 user_data)
{
	req->opcode = opcode;
	req->flags = REQ_F_FIXED_FILE;
	req->rsrc_flags = 0;
	req->user_data = user_data;
	return 0;
}
EXPORT_SYMBOL(sim_io_read_prep);

// BUG: writes to req->flags instead of req->rsrc_flags
noinline void sim_io_req_set_rsrc_node(struct sim_io_kiocb *req, u32 node_id);
noinline void sim_io_req_set_rsrc_node(struct sim_io_kiocb *req, u32 node_id)
{
	// INTENDED: req->rsrc_flags |= REQ_F_RSRC_NODE;
	// BUG: writes to adjacent field
	req->flags |= REQ_F_RSRC_NODE;  // WRONG FIELD!
	(void)node_id;
}
EXPORT_SYMBOL(sim_io_req_set_rsrc_node);

// Outer function that calls both
noinline int sim_io_submit(struct sim_io_kiocb *req, u32 opcode, u64 user_data);
noinline int sim_io_submit(struct sim_io_kiocb *req, u32 opcode, u64 user_data)
{
	int ret = sim_io_read_prep(req, opcode, user_data);
	if (ret)
		return ret;
	sim_io_req_set_rsrc_node(req, 42);
	pr_info("sim_io_submit: flags=0x%x rsrc_flags=0x%x\n",
		req->flags, req->rsrc_flags);
	return 0;
}
EXPORT_SYMBOL(sim_io_submit);

static ssize_t trigger_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct sim_io_kiocb req = {};
	sim_io_submit(&req, 22 /* IORING_OP_READ_FIXED */, 0xdeadbeef);
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };
static int __init init_mod(void) { proc_create("poc2_iouring", 0222, NULL, &ops); return 0; }
static void __exit exit_mod(void) { remove_proc_entry("poc2_iouring", NULL); }
module_init(init_mod);
module_exit(exit_mod);
