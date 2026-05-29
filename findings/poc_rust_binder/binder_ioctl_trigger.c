// binder_ioctl_trigger.c - Does specific binder ioctls, triggered by write to procfs
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

struct binder_write_read {
	s64 write_size, write_consumed;
	u64 write_buffer;
	s64 read_size, read_consumed;
	u64 read_buffer;
};

#define BINDER_SET_MAX_THREADS _IOW('b', 5, u32)
#define BINDER_WRITE_READ      _IOWR('b', 1, struct binder_write_read)
#define BC_ENTER_LOOPER        0x630d
#define BC_FREE_BUFFER         0x630c

static struct file *binder_file;

static ssize_t trigger_write(struct file *f, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	u32 max_threads;
	u32 cmd;
	u64 ptr;
	struct binder_write_read bwr = {};
	char buf[16] = {};
	int test;

	if (!binder_file) return -ENODEV;
	if (count > 15) count = 15;
	if (copy_from_user(buf, ubuf, count)) return -EFAULT;
	test = simple_strtol(buf, NULL, 10);

	switch (test) {
	case 1: // SET_MAX_THREADS(0xffffffff)
		max_threads = 0xffffffff;
		binder_file->f_op->unlocked_ioctl(binder_file,
			BINDER_SET_MAX_THREADS, (unsigned long)&max_threads);
		break;
	case 2: // BC_ENTER_LOOPER
		cmd = BC_ENTER_LOOPER;
		bwr.write_size = sizeof(cmd);
		bwr.write_buffer = (u64)(unsigned long)&cmd;
		binder_file->f_op->unlocked_ioctl(binder_file,
			BINDER_WRITE_READ, (unsigned long)&bwr);
		break;
	case 3: // BC_FREE_BUFFER(0xdeadbeef)
		cmd = BC_FREE_BUFFER;
		ptr = 0xdeadbeefULL;
		bwr.write_size = sizeof(cmd) + sizeof(ptr);
		{
			u8 wbuf[12];
			memcpy(wbuf, &cmd, 4);
			memcpy(wbuf+4, &ptr, 8);
			bwr.write_buffer = (u64)(unsigned long)wbuf;
			binder_file->f_op->unlocked_ioctl(binder_file,
				BINDER_WRITE_READ, (unsigned long)&bwr);
		}
		break;
	default: // SET_MAX_THREADS(0)
		max_threads = 0;
		binder_file->f_op->unlocked_ioctl(binder_file,
			BINDER_SET_MAX_THREADS, (unsigned long)&max_threads);
	}
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };

static int __init init_mod(void)
{
	binder_file = filp_open("/dev/binderfs/binder", O_RDWR, 0);
	if (IS_ERR(binder_file)) {
		binder_file = NULL;
		pr_err("binder_ioctl_trigger: cannot open binder\n");
		return -ENODEV;
	}
	proc_create("binder_ioctl", 0222, NULL, &ops);
	pr_info("binder_ioctl_trigger: ready\n");
	return 0;
}

static void __exit exit_mod(void)
{
	remove_proc_entry("binder_ioctl", NULL);
	if (binder_file) filp_close(binder_file, NULL);
}

module_init(init_mod);
module_exit(exit_mod);
