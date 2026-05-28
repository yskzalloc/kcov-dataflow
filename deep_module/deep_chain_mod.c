// SPDX-License-Identifier: GPL-2.0
/*
 * deep_chain_mod.c - Demonstrates kcov_dataflow tracing through 10 nested
 * function calls. An attacker-controlled "offset" value propagates from
 * the entry point through transformations until it causes an OOB write
 * in the deepest function.
 *
 * Call chain:
 *   entry_handler → parse_request → validate_header → extract_payload →
 *   transform_data → apply_filter → compute_index → lookup_slot →
 *   write_slot → commit_write (BUG: OOB here)
 */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/delay.h>

/* Simulated protocol structures */
struct request_header {
	u32 magic;
	u32 version;
	u32 payload_offset;  /* ← attacker controls this */
	u32 payload_size;
};

struct payload {
	u64 session_id;
	u32 transform_key;
	u32 filter_mask;
	u8  data[32];
};

struct slot_table {
	u32 num_slots;
	u64 slots[8];  /* only 8 slots! */
};

static struct proc_dir_entry *proc_deep;

/* === 10 nested functions: deepest first === */

/* Function 10 (DEEPEST): The vulnerable write */
static noinline int commit_write(struct slot_table *table, u32 index, u64 value)
{
	/* BUG: no bounds check on index — if index >= 8, OOB write */
	table->slots[index] = value;
	return 0;
}

/* Function 9 */
static noinline int write_slot(struct slot_table *table, u32 slot_idx,
			       u64 session_id)
{
	u64 combined = session_id ^ (u64)slot_idx;
	return commit_write(table, slot_idx, combined);
}

/* Function 8 */
static noinline u32 lookup_slot(struct slot_table *table, u32 computed_idx)
{
	/* Pass through — in real code this might do hash lookup */
	u32 final_idx = computed_idx % 16;  /* BUG: should be % 8 */
	write_slot(table, final_idx, 0xDEADC0DE00000000ULL | final_idx);
	return final_idx;
}

/* Function 7 */
static noinline u32 compute_index(u32 transform_result, u32 filter_output)
{
	/* Combines two values into an index */
	return (transform_result + filter_output) & 0xF;  /* 0-15, but table has 8 */
}

/* Function 6 */
static noinline u32 apply_filter(struct payload *pl, u32 transformed_val)
{
	u32 filtered = transformed_val & pl->filter_mask;
	return filtered >> 1;
}

/* Function 5 */
static noinline u32 transform_data(struct payload *pl, u32 raw_offset)
{
	/* Transforms the offset using the payload's key */
	return raw_offset * pl->transform_key;
}

/* Function 4 */
static noinline struct payload *extract_payload(void *buf, u32 offset, u32 size)
{
	/* In real code: validates and extracts payload from buffer */
	return (struct payload *)((u8 *)buf + offset);
}

/* Function 3 */
static noinline int validate_header(struct request_header *hdr)
{
	if (hdr->magic != 0x50524F54)  /* "PROT" */
		return -1;
	if (hdr->version > 2)
		return -1;
	/* BUG: doesn't validate payload_offset bounds! */
	return 0;
}

/* Function 2 */
static noinline int parse_request(void *buf, u32 buf_size,
				  struct request_header **out_hdr,
				  struct payload **out_payload)
{
	struct request_header *hdr = (struct request_header *)buf;

	if (validate_header(hdr) < 0)
		return -1;

	*out_hdr = hdr;
	*out_payload = extract_payload(buf, hdr->payload_offset, hdr->payload_size);
	return 0;
}

/* Function 1 (ENTRY): The syscall handler */
static noinline int entry_handler(void *user_buf, u32 user_size)
{
	struct request_header *hdr;
	struct payload *pl;
	struct slot_table *table;
	u32 transformed, filtered, index, slot;

	if (parse_request(user_buf, user_size, &hdr, &pl) < 0)
		return -1;

	table = kzalloc(sizeof(*table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;
	table->num_slots = 8;

	/* The tainted data flow:
	 * hdr->payload_offset → extract_payload → pl
	 * pl->transform_key + payload_offset → transform_data → transformed
	 * transformed + pl->filter_mask → apply_filter → filtered
	 * transformed + filtered → compute_index → index
	 * index → lookup_slot → slot (% 16, should be % 8)
	 * slot → write_slot → commit_write (OOB if slot >= 8)
	 */
	transformed = transform_data(pl, hdr->payload_offset);
	filtered = apply_filter(pl, transformed);
	index = compute_index(transformed, filtered);
	slot = lookup_slot(table, index);

	pr_info("deep_chain: slot=%u (OOB if >= 8)\n", slot);

	kfree(table);
	return 0;
}

/* Trigger: constructs a malicious request that causes index=12 (OOB) */
static ssize_t deep_trigger_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	u8 *buf;
	struct request_header *hdr;
	struct payload *pl;

	buf = kzalloc(256, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Craft malicious request */
	hdr = (struct request_header *)buf;
	hdr->magic = 0x50524F54;       /* valid magic */
	hdr->version = 1;              /* valid version */
	hdr->payload_offset = 16;      /* offset to payload (valid position) */
	hdr->payload_size = sizeof(struct payload);

	/* Craft payload that will produce OOB index */
	pl = (struct payload *)(buf + 16);
	pl->session_id = 0xAAAABBBBCCCCDDDDULL;
	pl->transform_key = 3;         /* multiplier */
	pl->filter_mask = 0xFFFFFFFF;  /* no filtering */
	memcpy(pl->data, "ATTACKER_PAYLOAD_DATA!!!", 24);

	/*
	 * Trace: payload_offset=16, transform_key=3
	 * transformed = 16 * 3 = 48
	 * filtered = (48 & 0xFFFFFFFF) >> 1 = 24
	 * index = (48 + 24) & 0xF = 72 & 0xF = 8
	 * lookup_slot: final_idx = 8 % 16 = 8  ← OOB! (table has slots[0..7])
	 */

	pr_info("deep_chain: triggering 10-deep call chain with offset=%u\n",
		hdr->payload_offset);

	entry_handler(buf, 256);

	kfree(buf);
	return count;
}

static const struct proc_ops deep_proc_ops = {
	.proc_write = deep_trigger_write,
};

static int __init deep_chain_init(void)
{
	proc_deep = proc_create("deep_trigger", 0222, NULL, &deep_proc_ops);
	if (!proc_deep)
		return -ENOMEM;
	pr_info("deep_chain_mod: loaded. echo x > /proc/deep_trigger\n");
	return 0;
}

static void __exit deep_chain_exit(void)
{
	proc_remove(proc_deep);
}

module_init(deep_chain_init);
module_exit(deep_chain_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("10-deep call chain for kcov_dataflow visualization");
