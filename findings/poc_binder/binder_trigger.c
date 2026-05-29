// binder_trigger.c - Opens binder, does operations, triggered via procfs for kcov_dataflow capture
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

// We call binder's internal functions by opening /dev/binderfs/binder from kernel
// Actually simpler: just open the binder file and call its ioctl from kernel context

struct binder_write_read {
	s64 write_size;
	s64 write_consumed;
	u64 write_buffer;
	s64 read_size;
	s64 read_consumed;
	u64 read_buffer;
};

#define BINDER_VERSION         _IOWR('b', 9, s32)
#define BINDER_SET_MAX_THREADS _IOW('b', 5, u32)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)
#define BC_ENTER_LOOPER        0x630d

static ssize_t trigger_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct file *binder_file;
	s32 version = 0;
	u32 max_threads;
	u32 cmd;
	struct binder_write_read bwr;
	int ret;

	binder_file = filp_open("/dev/binderfs/binder", O_RDWR, 0);
	if (IS_ERR(binder_file)) {
		pr_err("binder_trigger: cannot open binder: %ld\n", PTR_ERR(binder_file));
		return count;
	}

	pr_info("binder_trigger: === BINDER_VERSION ===\n");
	ret = vfs_ioctl(binder_file, BINDER_VERSION, (unsigned long)&version);
	pr_info("binder_trigger: version=%d ret=%d\n", version, ret);

	pr_info("binder_trigger: === SET_MAX_THREADS(0) ===\n");
	max_threads = 0;
	ret = vfs_ioctl(binder_file, BINDER_SET_MAX_THREADS, (unsigned long)&max_threads);
	pr_info("binder_trigger: ret=%d\n", ret);

	pr_info("binder_trigger: === BC_ENTER_LOOPER ===\n");
	cmd = BC_ENTER_LOOPER;
	memset(&bwr, 0, sizeof(bwr));
	bwr.write_size = sizeof(cmd);
	bwr.write_buffer = (u64)(unsigned long)&cmd;
	ret = vfs_ioctl(binder_file, BINDER_WRITE_READ, (unsigned long)&bwr);
	pr_info("binder_trigger: enter_looper ret=%d\n", ret);

	pr_info("binder_trigger: === BC_ENTER_LOOPER (duplicate!) ===\n");
	bwr.write_size = sizeof(cmd);
	bwr.write_consumed = 0;
	ret = vfs_ioctl(binder_file, BINDER_WRITE_READ, (unsigned long)&bwr);
	pr_info("binder_trigger: duplicate ret=%d\n", ret);

	pr_info("binder_trigger: === SET_MAX_THREADS(0xffffffff) ===\n");
	max_threads = 0xffffffff;
	ret = vfs_ioctl(binder_file, BINDER_SET_MAX_THREADS, (unsigned long)&max_threads);
	pr_info("binder_trigger: ret=%d\n", ret);

	filp_close(binder_file, NULL);
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };
static int __init init_mod(void) { proc_create("binder_trigger", 0222, NULL, &ops); return 0; }
static void __exit exit_mod(void) { remove_proc_entry("binder_trigger", NULL); }
module_init(init_mod);
module_exit(exit_mod);
