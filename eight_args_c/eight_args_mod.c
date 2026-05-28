// SPDX-License-Identifier: GPL-2.0
// Verify kcov_dataflow captures 1-arg through 8-arg functions.
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/export.h>

MODULE_LICENSE("GPL");

u64 func1(u64 a1);
u64 func2(u64 a1, u64 a2);
u64 func3(u64 a1, u64 a2, u64 a3);
u64 func4(u64 a1, u64 a2, u64 a3, u64 a4);
u64 func5(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5);
u64 func6(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6);
u64 func7(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7);
u64 func8(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8);

noinline u64 func1(u64 a1) { return a1; }
noinline u64 func2(u64 a1, u64 a2) { return a1+a2; }
noinline u64 func3(u64 a1, u64 a2, u64 a3) { return a1+a2+a3; }
noinline u64 func4(u64 a1, u64 a2, u64 a3, u64 a4) { return a1+a2+a3+a4; }
noinline u64 func5(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5) { return a1+a2+a3+a4+a5; }
noinline u64 func6(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6) { return a1+a2+a3+a4+a5+a6; }
noinline u64 func7(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7) { return a1+a2+a3+a4+a5+a6+a7; }
noinline u64 func8(u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7, u64 a8) { return a1+a2+a3+a4+a5+a6+a7+a8; }
EXPORT_SYMBOL(func1); EXPORT_SYMBOL(func2); EXPORT_SYMBOL(func3); EXPORT_SYMBOL(func4);
EXPORT_SYMBOL(func5); EXPORT_SYMBOL(func6); EXPORT_SYMBOL(func7); EXPORT_SYMBOL(func8);

static ssize_t trigger_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	pr_info("func1(0x11)=0x%llx\n", func1(0x11));
	pr_info("func2(0x11,0x22)=0x%llx\n", func2(0x11, 0x22));
	pr_info("func3(0x11,0x22,0x33)=0x%llx\n", func3(0x11, 0x22, 0x33));
	pr_info("func4(0x11,..,0x44)=0x%llx\n", func4(0x11, 0x22, 0x33, 0x44));
	pr_info("func5(0x11,..,0x55)=0x%llx\n", func5(0x11, 0x22, 0x33, 0x44, 0x55));
	pr_info("func6(0x11,..,0x66)=0x%llx\n", func6(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
	pr_info("func7(0x11,..,0x77)=0x%llx\n", func7(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77));
	pr_info("func8(0x11,..,0x88)=0x%llx\n", func8(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88));
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };
static int __init init_mod(void) { proc_create("test_args", 0222, NULL, &ops); return 0; }
static void __exit exit_mod(void) { remove_proc_entry("test_args", NULL); }
module_init(init_mod);
module_exit(exit_mod);
