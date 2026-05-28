/*
 * trigger.c - Uses /sys/kernel/debug/kcov_dataflow to capture
 * function args/ret TLV records. Completely independent from legacy kcov.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#define KCOV_DF_INIT_TRACE	_IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE		_IO('d', 100)
#define KCOV_DF_DISABLE		_IO('d', 101)

#define COVER_SIZE (64 * 1024)  /* 64K u64 words = 512KB */

static void dump_buffer(uint64_t *cover, uint64_t n)
{
	uint64_t i = 1;

	printf("=== KCOV Dataflow TLV Dump (%lu words) ===\n", n);
	while (i <= n && i < COVER_SIZE) {
		uint64_t hdr = cover[i];
		uint64_t type = hdr & 0xF0000000ULL;
		uint64_t seq = hdr & 0x00FFFFFFULL;
		uint64_t pc = cover[i + 1];
		uint64_t meta = cover[i + 2];

		if (type == 0xE0000000ULL) {
			uint32_t arg_idx = (meta >> 56) & 0xFF;
			uint32_t arg_sz = (meta >> 48) & 0xFF;
			uint64_t ptr = meta & 0xFFFFFFFFFFFFULL;
			printf("[ENTRY] seq=%lu pc=0x%lx arg[%u](%u) ptr=0x%lx\n",
			       seq, pc, arg_idx, arg_sz, ptr);
		} else if (type == 0xF0000000ULL) {
			uint32_t ret_sz = (meta >> 48) & 0xFF;
			uint64_t ptr = meta & 0xFFFFFFFFFFFFULL;
			printf("[RET]   seq=%lu pc=0x%lx ret(%u) ptr=0x%lx\n",
			       seq, pc, ret_sz, ptr);
		} else {
			i++;
			continue;
		}

		/* Print field values */
		i += 3;
		while (i <= n && i < COVER_SIZE) {
			uint64_t next = cover[i];
			uint64_t next_type = next & 0xF0000000ULL;
			if (next_type == 0xE0000000ULL || next_type == 0xF0000000ULL)
				break;
			if (next == 0xBADADD85ULL)
				printf("  val = FAULT\n");
			else
				printf("  val = 0x%lx\n", next);
			i++;
		}
	}
	printf("=== Done ===\n");
}

int main(int argc, char **argv)
{
	const char *trigger_path = "/proc/uaf_trigger";
	int fd;
	uint64_t *cover;
	uint64_t n;

	if (argc > 1)
		trigger_path = argv[1];

	fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
	if (fd < 0) {
		perror("open kcov_dataflow");
		return 1;
	}

	if (ioctl(fd, KCOV_DF_INIT_TRACE, COVER_SIZE)) {
		perror("KCOV_DF_INIT_TRACE");
		close(fd);
		return 1;
	}

	cover = mmap(NULL, COVER_SIZE * sizeof(uint64_t),
		     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (cover == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	if (ioctl(fd, KCOV_DF_ENABLE, 0)) {
		perror("KCOV_DF_ENABLE");
		munmap(cover, COVER_SIZE * sizeof(uint64_t));
		close(fd);
		return 1;
	}

	/* Reset */
	__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);

	/* Trigger */
	int tfd = open(trigger_path, O_WRONLY);
	if (tfd >= 0) {
		write(tfd, "x", 1);
		close(tfd);
	}

	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);

	ioctl(fd, KCOV_DF_DISABLE, 0);

	dump_buffer(cover, n);

	munmap(cover, COVER_SIZE * sizeof(uint64_t));
	close(fd);
	return 0;
}
