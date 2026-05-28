// SPDX-License-Identifier: GPL-2.0
// poc3_kvm.c - Simulates KVM MMU 10-deep taint propagation from user CR3 to OOB.
// Write to /proc/poc3_kvm to trigger.
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

#define PAGE_TABLE_SIZE 8  // only 8 valid entries

static u64 *page_table;

noinline u64 kvm_vcpu_ioctl(u64 cmd, u64 cr3);
noinline u64 kvm_arch_vcpu_run(u64 cr3);
noinline u64 vcpu_run(u64 cr3);
noinline u64 kvm_mmu_reload(u64 cr3);
noinline u64 kvm_mmu_load(u64 cr3);
noinline u64 mmu_alloc_root(u64 gfn);
noinline u64 kvm_mmu_get_page(u64 gfn, u32 level);
noinline u64 mmu_get_spte(u64 gfn, u32 level);
noinline u64 mmu_set_spte(u64 *spte_ptr, u64 new_spte);
noinline u64 kvm_mmu_page_fault(u64 addr);

noinline u64 kvm_vcpu_ioctl(u64 cmd, u64 cr3)
{
	return kvm_arch_vcpu_run(cr3);
}

noinline u64 kvm_arch_vcpu_run(u64 cr3)
{
	return vcpu_run(cr3);
}

noinline u64 vcpu_run(u64 cr3)
{
	return kvm_mmu_reload(cr3);
}

noinline u64 kvm_mmu_reload(u64 cr3)
{
	return kvm_mmu_load(cr3);
}

noinline u64 kvm_mmu_load(u64 cr3)
{
	u64 gfn = cr3 >> 12;  // page frame number
	return mmu_alloc_root(gfn);
}

noinline u64 mmu_alloc_root(u64 gfn)
{
	// BUG: no bounds check on gfn!
	return kvm_mmu_get_page(gfn, 4);
}

noinline u64 kvm_mmu_get_page(u64 gfn, u32 level)
{
	return mmu_get_spte(gfn, level);
}

noinline u64 mmu_get_spte(u64 gfn, u32 level)
{
	u64 *spte_ptr = &page_table[gfn];  // OOB if gfn >= PAGE_TABLE_SIZE
	u64 new_spte = (gfn << 12) | 0x67;
	return mmu_set_spte(spte_ptr, new_spte);
}

noinline u64 mmu_set_spte(u64 *spte_ptr, u64 new_spte)
{
	// Would write OOB here - but we just report for PoC
	pr_info("mmu_set_spte: ptr=%px val=0x%llx (OOB=%s)\n",
		spte_ptr, new_spte,
		(spte_ptr < page_table || spte_ptr >= page_table + PAGE_TABLE_SIZE) ? "YES" : "no");
	return kvm_mmu_page_fault((u64)(unsigned long)spte_ptr);
}

noinline u64 kvm_mmu_page_fault(u64 addr)
{
	pr_info("kvm_mmu_page_fault: fault_addr=0x%llx\n", addr);
	return addr;
}

static ssize_t trigger_write(struct file *f, const char __user *buf,
			     size_t count, loff_t *ppos)
{
	// Simulate: user sets guest CR3 = 0xdeadb000 (gfn=0xdeadb, way OOB)
	kvm_vcpu_ioctl(0xae80 /* KVM_RUN */, 0xdeadb000ULL);
	return count;
}

static const struct proc_ops ops = { .proc_write = trigger_write };

static int __init init_mod(void)
{
	page_table = kcalloc(PAGE_TABLE_SIZE, sizeof(u64), GFP_KERNEL);
	proc_create("poc3_kvm", 0222, NULL, &ops);
	pr_info("poc3_kvm: loaded (page_table=%px, size=%d)\n", page_table, PAGE_TABLE_SIZE);
	return 0;
}

static void __exit exit_mod(void)
{
	remove_proc_entry("poc3_kvm", NULL);
	kfree(page_table);
}

module_init(init_mod);
module_exit(exit_mod);
