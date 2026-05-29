// SPDX-License-Identifier: GPL-2.0
// binder_audit.c - Exercises binder ioctl paths from kernel context
// Write to /proc/binder_audit to trigger with kcov_dataflow recording
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/file.h>

MODULE_LICENSE("GPL");

struct binder_write_read {
	s64 write_size, write_consumed;
	u64 write_buffer;
	s64 read_size, read_consumed;
	u64 read_buffer;
};

#define BINDER_VERSION         _IOWR('b', 9, s32)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, u32)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)
#define BC_ENTER_LOOPER        0x630d

static ssize_t trigger_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct file *bf;
	s32 version = 0;
	u32 max_threads;
	u32 cmd;
	struct binder_write_read bwr = {};

	bf = filp_open("/dev/binderfs/binder", O_RDWR, 0);
	if (IS_ERR(bf)) {
		pr_err("binder_audit: open failed %ld\n", PTR_ERR(bf));
		return count;
	}

	// BINDER_VERSION
	if (bf->f_op && bf->f_op->unlocked_ioctl)
		bf->f_op->unlocked_ioctl(bf, BINDER_VERSION, (unsigned long)&version);
	pr_info("binder_audit: version=%d\n", version);

	// SET_MAX_THREADS(0xdeadbeef) - absurd value, binder accepts it unchecked
	max_threads = 0xdeadbeef;
	if (bf->f_op && bf->f_op->unlocked_ioctl)
		bf->f_op->unlocked_ioctl(bf, BINDER_SET_MAX_THREADS, (unsigned long)&max_threads);
	pr_info("binder_audit: set_max_threads(0xdeadbeef) done\n");

	// BC_ENTER_LOOPER
	cmd = BC_ENTER_LOOPER;
	bwr.write_size = sizeof(cmd);
	bwr.write_buffer = (u64)(unsigned long)&cmd;
	if (bf->f_op && bf->f_op->unlocked_ioctl)
		bf->f_op->unlocked_ioctl(bf, BINDER_WRITE_READ, (unsigned long)&bwr);
	pr_info("binder_audit: enter_looper done\n");

	// BC_ENTER_LOOPER again (duplicate)
	bwr.write_size = sizeof(cmd);
	bwr.write_consumed = 0;
	if (bf->f_op && bf->f_op->unlocked_ioctl)
		bf->f_op->unlocked_ioctl(bf, BINDER_WRITE_READ, (unsigned long)&bwr);
	pr_info("binder_audit: enter_looper(dup) done\n");

	filp_close(bf, NULL);
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };
static int __init init_mod(void)
{
	proc_create("binder_audit", 0222, NULL, &ops);
	return 0;
}
static void __exit exit_mod(void) { remove_proc_entry("binder_audit", NULL); }
module_init(init_mod);
module_exit(exit_mod);
