/*
 * trace-args/trace-ret callbacks for demo.c. Build this file WITHOUT
 * -fsanitize-coverage, so the callbacks do not instrument themselves.
 *
 * TLV contract:
 *   tag = (arg_idx << 32) | size
 *   offsets == NULL: val is the value itself, zero-extended to 64 bits
 *   offsets != NULL: val is an address; offsets[0] = N, followed by N
 *                    {byte offset, byte size} pairs
 * The call site, __builtin_return_address(0) - 1, identifies the observation.
 */
#include <stdint.h>
#include <stdio.h>

static void dump(const char *k, uint64_t tag, uint64_t val,
		 const uint64_t *off, void *pc)
{
	fprintf(stderr, "%-5s pc=%p", k, pc);
	if (k[0] == 'E')
		fprintf(stderr, " arg[%u]", (unsigned)(tag >> 32));
	fprintf(stderr, " size=%u", (unsigned)tag);
	if (!off) {
		fprintf(stderr, " val=%#llx\n", (unsigned long long)val);
		return;
	}
	/* Every field of struct req is a long; a general consumer would read
	 * off[2 + 2 * i] bytes per field. */
	fprintf(stderr, " @%#llx {", (unsigned long long)val);
	for (uint64_t i = 0; i < off[0]; i++)
		fprintf(stderr, "%s%#llx", i ? ", " : "",
			(unsigned long long)*(const uint64_t *)(val + off[1 + 2 * i]));
	fprintf(stderr, "}\n");
}

void __sanitizer_cov_trace_args(uint64_t tag, uint64_t val, const uint64_t *off)
{
	dump("ENTRY", tag, val, off, __builtin_return_address(0));
}

void __sanitizer_cov_trace_ret(uint64_t size, uint64_t val, const uint64_t *off)
{
	dump("RET", size, val, off, __builtin_return_address(0));
}
