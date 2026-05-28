// SPDX-License-Identifier: GPL-2.0
/*
 * simple_vuln_mod.c - Demonstrates KCOV data flow tracing.
 * The trace-args/trace-ret callbacks in kcov.c will printk when
 * the PC is in module address space.
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>

struct simple_data {
	int id;
	char buf[16];
	int size;
};

static struct proc_dir_entry *proc_entry;
static struct proc_dir_entry *proc_entry_uaf;
static struct proc_dir_entry *proc_entry_df;
static struct proc_dir_entry *proc_entry_many;

/*
 * Many-argument function: x86_64 passes first 6 integer args in registers
 * (rdi, rsi, rdx, rcx, r8, r9), rest on stack. This tests all of them.
 */
static noinline long many_args(struct simple_data *sd, int a, long b,
			       unsigned int c, char d, long e,
			       int stack1, long stack2)
{
	/* Modify struct via multiple args */
	sd->id = a + (int)b;
	sd->size = c + (unsigned int)d + (int)e + stack1;
	memset(sd->buf, (char)stack2, 16);
	return sd->id + sd->size;
}

static ssize_t many_trigger_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	struct simple_data *sd;
	long ret;

	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->id = 0xAA;
	memcpy(sd->buf, "before_manyargs", 16);
	sd->size = 7;

	pr_info("--- MANY_ARGS TRIGGER: 8 arguments (6 regs + 2 stack) ---\n");
	ret = many_args(sd, 0x11, 0x2222, 0x33, 'X', 0x5555, 0x66, 0x77);
	pr_info("--- MANY_ARGS TRIGGER: returned %ld ---\n", ret);

	kfree(sd);
	return count;
}

static noinline struct simple_data *vuln_process(struct simple_data *data,
						 int user_size)
{
	/* BUG: user_size not bounds-checked, causes OOB write */
	memset(data->buf, 'A', user_size);
	data->size = user_size;
	return data;
}

/* UAF write: writes to freed memory */
static noinline struct simple_data *uaf_write(struct simple_data *data,
					      int new_id)
{
	/* BUG: data is already freed, writing to dangling pointer */
	data->id = new_id;
	data->size = 0xDEAD;
	memcpy(data->buf, "UAF_CORRUPTED!!", 16);
	return data;
}

static ssize_t vuln_write(struct file *file, const char __user *buf,
			  size_t count, loff_t *ppos)
{
	struct simple_data *sd;
	int trigger_size = 32; /* > 16, causes OOB */

	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->id = 0x1337;
	memcpy(sd->buf, "initial_data!!", 15);
	sd->buf[15] = '\0';
	sd->size = 15;

	pr_info("--- OOB TRIGGER: calling vuln_process(sd=%px, size=%d) ---\n",
		sd, trigger_size);

	vuln_process(sd, trigger_size);

	pr_info("--- OOB TRIGGER: vuln_process returned ---\n");

	kfree(sd);
	return count;
}

static ssize_t uaf_trigger_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
	struct simple_data *sd;

	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->id = 0xBEEF;
	memcpy(sd->buf, "valid_data_here", 16);
	sd->size = 16;

	pr_info("--- UAF TRIGGER: allocated sd=%px, freeing it... ---\n", sd);
	kfree(sd);

	pr_info("--- UAF TRIGGER: calling uaf_write(sd=%px, 0x41414141) on FREED ptr ---\n", sd);
	uaf_write(sd, 0x41414141);

	pr_info("--- UAF TRIGGER: uaf_write returned ---\n");
	return count;
}

/* Double-free + write: free twice, then write to the corrupted slab */
static noinline struct simple_data *df_write(struct simple_data *data,
					     int poison_val)
{
	/* BUG: data was double-freed, slab metadata is corrupted */
	data->id = poison_val;
	data->size = 0xDF;
	memcpy(data->buf, "DOUBLEFREE_WR!!", 16);
	return data;
}

static ssize_t df_trigger_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	struct simple_data *sd;

	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->id = 0xCAFE;
	memcpy(sd->buf, "before_dfree!!!", 16);
	sd->size = 99;

	pr_info("--- DF TRIGGER: allocated sd=%px, first kfree... ---\n", sd);
	kfree(sd);

	pr_info("--- DF TRIGGER: second kfree (DOUBLE FREE!) ---\n");
	kfree(sd);

	pr_info("--- DF TRIGGER: calling df_write(sd=%px, 0xDF00DF00) on double-freed ptr ---\n", sd);
	df_write(sd, 0xDF00DF00);

	pr_info("--- DF TRIGGER: df_write returned ---\n");
	return count;
}

static const struct proc_ops vuln_proc_ops = {
	.proc_write = vuln_write,
};

static const struct proc_ops uaf_proc_ops = {
	.proc_write = uaf_trigger_write,
};

static const struct proc_ops df_proc_ops = {
	.proc_write = df_trigger_write,
};

static const struct proc_ops many_proc_ops = {
	.proc_write = many_trigger_write,
};

/*
 * Verification function: takes known args, then sleeps so drgn can
 * inspect the stack and verify kcov_dataflow captured the same values.
 */
static noinline int sleep_verify(struct simple_data *sd, int magic,
				 long cookie)
{
	/* These values should be visible in drgn stack inspection */
	sd->id = magic;
	sd->size = (int)cookie;

	pr_info("sleep_verify: sd=%px magic=0x%x cookie=0x%lx — sleeping 30s\n",
		sd, magic, cookie);

	/* Sleep so drgn can inspect this task's stack */
	msleep(30000);

	pr_info("sleep_verify: woke up, returning\n");
	return magic + (int)cookie;
}

static ssize_t verify_trigger_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	struct simple_data *sd;

	sd = kmalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd)
		return -ENOMEM;

	sd->id = 0xAAAA;
	memcpy(sd->buf, "drgn_verify_dat", 16);
	sd->size = 42;

	sleep_verify(sd, 0xDEADBEEF, 0x1234567890ABCDEFLL);

	kfree(sd);
	return count;
}

static const struct proc_ops verify_proc_ops = {
	.proc_write = verify_trigger_write,
};

static struct proc_dir_entry *proc_entry_verify;

static int __init vuln_mod_init(void)
{
	proc_entry = proc_create("vuln_trigger", 0222, NULL, &vuln_proc_ops);
	proc_entry_uaf = proc_create("uaf_trigger", 0222, NULL, &uaf_proc_ops);
	proc_entry_df = proc_create("df_trigger", 0222, NULL, &df_proc_ops);
	proc_entry_many = proc_create("many_trigger", 0222, NULL, &many_proc_ops);
	proc_entry_verify = proc_create("verify_trigger", 0222, NULL, &verify_proc_ops);
	if (!proc_entry || !proc_entry_uaf || !proc_entry_df ||
	    !proc_entry_many || !proc_entry_verify)
		return -ENOMEM;
	pr_info("simple_vuln_mod: loaded. /proc/{vuln,uaf,df,many,verify}_trigger\n");
	return 0;
}

static void __exit vuln_mod_exit(void)
{
	proc_remove(proc_entry);
	proc_remove(proc_entry_uaf);
	proc_remove(proc_entry_df);
	proc_remove(proc_entry_many);
	proc_remove(proc_entry_verify);
}

module_init(vuln_mod_init);
module_exit(vuln_mod_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KCOV data flow demo - shows args/ret for module functions");
