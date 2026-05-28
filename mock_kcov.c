#include <stdio.h>
#include <stdint.h>
#include <string.h>

void __sanitizer_cov_trace_args(uint64_t pc, uint32_t arg_idx,
                                uint32_t arg_size, void *arg_ptr,
                                uint64_t *offsets, uint32_t num_fields) {
    if (num_fields > 0) {
        printf("[ENTRY] pc=0x%lx arg[%u] ptr=%p (struct, %u fields)\n",
               pc, arg_idx, arg_ptr, num_fields);
        for (uint32_t i = 0; i < num_fields; i++) {
            uint64_t off = offsets[i * 2];
            uint64_t sz = offsets[i * 2 + 1];
            printf("  field[%u]: offset=%lu size=%lu val=0x", i, off, sz);
            unsigned char *base = (unsigned char *)arg_ptr + off;
            uint64_t to_print = sz > 8 ? 8 : sz;
            for (uint64_t b = 0; b < to_print; b++)
                printf("%02x", base[b]);
            printf("\n");
        }
    } else {
        uint64_t val = 0;
        memcpy(&val, arg_ptr, arg_size > 8 ? 8 : arg_size);
        printf("[ENTRY] pc=0x%lx arg[%u] scalar(%u bytes) = 0x%lx\n",
               pc, arg_idx, arg_size, val);
    }
}

void __sanitizer_cov_trace_ret(uint64_t pc, uint32_t ret_size, void *ret_val,
                               uint64_t *offsets, uint32_t num_fields) {
    if (num_fields > 0 && ret_val) {
        printf("[RET] pc=0x%lx ptr=%p (struct, %u fields)\n",
               pc, ret_val, num_fields);
        for (uint32_t i = 0; i < num_fields; i++) {
            uint64_t off = offsets[i * 2];
            uint64_t sz = offsets[i * 2 + 1];
            printf("  field[%u]: offset=%lu size=%lu val=0x", i, off, sz);
            unsigned char *base = (unsigned char *)ret_val + off;
            uint64_t to_print = sz > 8 ? 8 : sz;
            for (uint64_t b = 0; b < to_print; b++)
                printf("%02x", base[b]);
            printf("\n");
        }
    } else if (ret_val && ret_size > 0) {
        uint64_t val = 0;
        memcpy(&val, ret_val, ret_size > 8 ? 8 : ret_size);
        printf("[RET] pc=0x%lx scalar(%u bytes) = 0x%lx\n",
               pc, ret_size, val);
    }
}

void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {}
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {}
