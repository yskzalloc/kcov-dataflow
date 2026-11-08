struct req { long op, len, flags; };          /* 24 bytes: passed in memory */

__attribute__((noinline)) void sink(long v) { __asm__ volatile("" :: "r"(v) : "memory"); }

/* 1. last use of `mode` is the first line: later it is <optimized out> */
__attribute__((noinline)) int process(int mode, int len)
{
	sink(mode * 3);
	sink(len);                                /* gdb breakpoint here */
	return len;
}

/* 2. ten arguments: a7..a10 are on the stack on x86-64, a9..a10 on arm64 */
__attribute__((noinline)) long many(long a1, long a2, long a3, long a4, long a5,
				    long a6, long a7, long a8, long a9, long a10)
{
	return a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9 + a10;
}

/* 3. struct by value, ABI passes it in memory: fields are reported */
__attribute__((noinline)) long submit(struct req r) { return r.op + r.len + r.flags; }

int main(int argc, char **argv)
{
	sink(process(argc * 0x8201, 16));
	sink(many(argc, 2, 3, 4, 5, 6, 7, 8, 9, 10));
	struct req r = { .op = argc + 1, .len = 4096, .flags = 0x41 };
	sink(submit(r));
	return 0;
}
