/*
 * sniper_common.h — Shared authenticated SMB2 socket + kcov_df feedback.
 * Provides NTLMv2 auth with fuzz:fuzz credentials + reconnect + connection pooling.
 */
#ifndef SNIPER_COMMON_H
#define SNIPER_COMMON_H

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/xattr.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <time.h>

#define KCOV_DF_INIT 0x80086401
#define KCOV_DF_REMOTE_ENABLE 0x00006466
#define BUF_WORDS (1<<16)

__attribute__((section("__libfuzzer_extra_counters")))
static uint8_t ctr[4096];

static int df_fd;
static volatile uint64_t *df_buf;
static int raw_sock = -1;
static uint64_t sid = 0, mid = 0;
static uint32_t tid = 0;
static uint8_t file_id[16];
static int has_file = 0;

static void fb(void) {
    uint64_t n = df_buf[0], pos = 1;
    while (pos + 3 <= 1 + n && pos < BUF_WORDS) {
        uint64_t pc = df_buf[pos+1], val = df_buf[pos+3];
        uint32_t nf = (df_buf[pos]>>24)&0xF; if (!nf) nf = 1;
        uint32_t rt = (df_buf[pos]>>28)&0xF;
        uint64_t h = pc * 0x517cc1b727220a95ULL;
        if (rt == 0xF && val == 0) ctr[(h>>12)%4096] += 3;
        else { h ^= val; ctr[h%4096]++; }
        pos += 3 + nf;
    }
}

static void df_init(void) {
    df_fd = open("/sys/kernel/debug/kcov_dataflow", O_RDWR);
    if (df_fd < 0) _exit(1);
    ioctl(df_fd, KCOV_DF_INIT, (unsigned long)BUF_WORDS);
    df_buf = mmap(0, BUF_WORDS*8, PROT_READ|PROT_WRITE, MAP_SHARED, df_fd, 0);
    ioctl(df_fd, KCOV_DF_REMOTE_ENABLE, 0);
}

static void smb2_hdr(uint8_t *h, uint16_t cmd) {
    memset(h, 0, 64);
    memcpy(h, "\xfeSMB", 4);
    *(uint16_t*)(h+4) = 64;
    *(uint16_t*)(h+6) = 1;
    *(uint16_t*)(h+12) = cmd;
    *(uint16_t*)(h+14) = 31;
    *(uint64_t*)(h+24) = mid++;
    *(uint32_t*)(h+36) = tid;
    *(uint64_t*)(h+40) = sid;
}

static int xact(uint8_t *pdu, size_t len, uint8_t *resp, size_t rmax) {
    uint8_t frame[4];
    uint32_t fl = len;
    frame[0]=fl>>24; frame[1]=(fl>>16)&0xff; frame[2]=(fl>>8)&0xff; frame[3]=fl&0xff;
    if (send(raw_sock, frame, 4, MSG_NOSIGNAL) < 0) return -1;
    if (send(raw_sock, pdu, len, MSG_NOSIGNAL) < 0) return -1;
    if (recv(raw_sock, frame, 4, MSG_WAITALL) != 4) return -1;
    uint32_t rlen = (frame[0]<<24)|(frame[1]<<16)|(frame[2]<<8)|frame[3];
    if (rlen > rmax) rlen = rmax;
    int got = 0;
    while ((size_t)got < rlen) {
        int r = recv(raw_sock, resp+got, rlen-got, 0);
        if (r <= 0) break;
        got += r;
    }
    return got;
}

static void send_only(uint8_t *pdu, size_t len) {
    uint8_t frame[4];
    uint32_t fl = len;
    frame[0]=fl>>24; frame[1]=(fl>>16)&0xff; frame[2]=(fl>>8)&0xff; frame[3]=fl&0xff;
    send(raw_sock, frame, 4, MSG_NOSIGNAL);
    send(raw_sock, pdu, len, MSG_NOSIGNAL);
}

#ifdef USE_NTLMV2
#include "ntlmv2.h"
#endif

static int smb_connect(void) {
    raw_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (raw_sock < 0) return -1;
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(445)};
    inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (connect(raw_sock, (void*)&addr, sizeof(addr)) < 0) return -1;
    struct timeval tv = {.tv_sec=2};
    setsockopt(raw_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    return 0;
}

/*
 * NTLMv2 auth with fuzz:fuzz credentials.
 *
 * Since ksmbd's [share] has "guest ok = yes" + "force user = root",
 * even a minimal NTLMSSP negotiate → authenticate with username "fuzz"
 * will get session established. The key is sending the username in the
 * AUTHENTICATE_MESSAGE so ksmbd maps to the right user.
 *
 * For the [aclshare] (guest ok = no), we need valid NTLMv2. However,
 * since ksmbd with "restrict anonymous = 0" + our config accepts the
 * user if ksmbd.adduser was done, we send a proper NTLMSSP flow with
 * the username set. If NTLMv2 computation fails, guest fallback works
 * for [share].
 */
static uint8_t server_challenge[8];

static int smb_auth(const char *share) {
    uint8_t pdu[1024], resp[2048];
    int r;

    /* NEGOTIATE */
    smb2_hdr(pdu, 0);
    uint8_t *nb = pdu+64;
    *(uint16_t*)(nb+0) = 36;      /* StructureSize */
    *(uint16_t*)(nb+2) = 1;       /* DialectCount */
    *(uint16_t*)(nb+4) = 1;       /* SecurityMode */
    *(uint16_t*)(nb+6) = 0;       /* Reserved */
    *(uint32_t*)(nb+8) = 0;       /* Capabilities */
    memset(nb+12, 0, 16);         /* ClientGuid */
    memset(nb+28, 0, 8);          /* NegContextOffset/Count/Reserved2 */
    *(uint16_t*)(nb+36) = 0x0300; /* Dialect SMB 3.0 */
    r = xact(pdu, 64+38, resp, sizeof(resp));
    if (r < 64) return -1;

    /* Extract server challenge from NEGOTIATE response's security buffer */
    uint16_t sec_off = *(uint16_t*)(resp+56);
    uint16_t sec_len = *(uint16_t*)(resp+58);
    /* The challenge is inside NTLMSSP_CHALLENGE at offset +24 in the token */
    if (sec_off + sec_len <= (unsigned)r && sec_len > 32) {
        /* Find "NTLMSSP\0\x02" in the security buffer */
        for (int i = sec_off; i + 32 < sec_off + sec_len && i + 32 < r; i++) {
            if (memcmp(resp+i, "NTLMSSP\x00\x02", 9) == 0) {
                memcpy(server_challenge, resp+i+24, 8);
                break;
            }
        }
    }

    /* SESSION_SETUP 1: NTLMSSP_NEGOTIATE */
    smb2_hdr(pdu, 1);
    nb = pdu+64;
    memset(nb, 0, 24); /* zero entire body */
    *(uint16_t*)(nb+0) = 25;   /* StructureSize */
    nb[2] = 0;                  /* Flags */
    nb[3] = 1;                  /* SecurityMode */
    /* Capabilities(4) + Channel(4) already zeroed */
    /* SPNEGO wrapping the NTLMSSP_NEGOTIATE */
    uint8_t ntlm_neg[] = {
        /* NTLMSSP header */
        'N','T','L','M','S','S','P',0, 0x01,0,0,0,
        /* NegotiateFlags: NTLM|Unicode|RequestTarget|NTLMv2|128|56 */
        0x97,0x82,0x08,0xe2,
        /* DomainNameFields (0,0,0) */
        0,0, 0,0, 0x28,0,0,0,
        /* WorkstationFields (0,0,0) */
        0,0, 0,0, 0x28,0,0,0,
    };
    uint16_t sec_buf_off = 88;
    *(uint16_t*)(nb+12) = sec_buf_off;
    *(uint16_t*)(nb+14) = sizeof(ntlm_neg);
    memcpy(pdu+sec_buf_off, ntlm_neg, sizeof(ntlm_neg));
    r = xact(pdu, sec_buf_off + sizeof(ntlm_neg), resp, sizeof(resp));
    if (r >= 48) sid = *(uint64_t*)(resp+40);

    /* SESSION_SETUP 2: NTLMSSP_AUTHENTICATE (unknown user → guest) */
    smb2_hdr(pdu, 1);
    nb = pdu+64;
    memset(nb, 0, 24);
    *(uint16_t*)(nb+0) = 25; nb[3] = 1;

    /* Build NTLMSSP_AUTHENTICATE message with user="fuzz" */
    uint8_t auth[512];
    memset(auth, 0, sizeof(auth));
    memcpy(auth, "NTLMSSP\x00\x03\x00\x00\x00", 12);
    /* NegotiateFlags */
    *(uint32_t*)(auth+60) = 0xe2088215;

    int payload_off = 72;

#ifdef USE_NTLMV2
    /* Real NTLMv2 auth (requires -lcrypto) */
    uint8_t lm_buf[24], nt_buf[64];
    int lm_len = 0, nt_len = 0;
    ntlmv2_response(server_challenge, nt_buf, &nt_len, lm_buf, &lm_len);

    /* LmChallengeResponse */
    *(uint16_t*)(auth+12) = lm_len;
    *(uint16_t*)(auth+14) = lm_len;
    *(uint32_t*)(auth+16) = payload_off;
    memcpy(auth+payload_off, lm_buf, lm_len);
    payload_off += lm_len;

    /* NtChallengeResponse */
    *(uint16_t*)(auth+20) = nt_len;
    *(uint16_t*)(auth+22) = nt_len;
    *(uint32_t*)(auth+24) = payload_off;
    memcpy(auth+payload_off, nt_buf, nt_len);
    payload_off += nt_len;
#else
    /* Guest/anonymous fallback (works for shares with guest ok = yes) */
    *(uint16_t*)(auth+12) = 24;
    *(uint16_t*)(auth+14) = 24;
    *(uint32_t*)(auth+16) = payload_off;
    memset(auth+payload_off, 0, 24);
    payload_off += 24;

    *(uint16_t*)(auth+20) = 24;
    *(uint16_t*)(auth+22) = 24;
    *(uint32_t*)(auth+24) = payload_off;
    memset(auth+payload_off, 0, 24);
    payload_off += 24;
#endif

    /* DomainName: empty */
    *(uint16_t*)(auth+28) = 0;
    *(uint16_t*)(auth+30) = 0;
    *(uint32_t*)(auth+32) = payload_off;

    /* UserName: "fuzz" for NTLMv2 auth, "guest" for guest fallback */
#ifdef USE_NTLMV2
    uint8_t user_utf16[] = {'f',0,'u',0,'z',0,'z',0};
#else
    uint8_t user_utf16[] = {'g',0,'u',0,'e',0,'s',0,'t',0};
#endif
    *(uint16_t*)(auth+36) = sizeof(user_utf16);
    *(uint16_t*)(auth+38) = sizeof(user_utf16);
    *(uint32_t*)(auth+40) = payload_off;
    memcpy(auth+payload_off, user_utf16, sizeof(user_utf16));
    payload_off += sizeof(user_utf16);

    /* Workstation: empty */
    *(uint16_t*)(auth+44) = 0;
    *(uint16_t*)(auth+46) = 0;
    *(uint32_t*)(auth+48) = payload_off;

    /* EncryptedRandomSessionKey: empty */
    *(uint16_t*)(auth+52) = 0;
    *(uint16_t*)(auth+54) = 0;
    *(uint32_t*)(auth+56) = payload_off;

    *(uint16_t*)(nb+12) = sec_buf_off;
    *(uint16_t*)(nb+14) = payload_off;
    memcpy(pdu+sec_buf_off, auth, payload_off);
    r = xact(pdu, sec_buf_off + payload_off, resp, sizeof(resp));
    if (r >= 48) {
        sid = *(uint64_t*)(resp+40);
        /* Check NT_STATUS — 0 = success, 0xC000006D = bad password */
        uint32_t status = *(uint32_t*)(resp+8);
        if (status != 0 && status != 0x00000016) {
            /* Auth failed — try with empty user (guest fallback) */
            /* Already have sid from MORE_PROCESSING status */
        }
    }

    /* TREE_CONNECT */
    smb2_hdr(pdu, 3);
    nb = pdu+64;
    *(uint16_t*)(nb) = 9;
    uint16_t pathlen = 0;
    for (int i = 0; share[i]; i++) { pdu[72+i*2]=share[i]; pdu[73+i*2]=0; pathlen+=2; }
    *(uint16_t*)(nb+4) = 72; *(uint16_t*)(nb+6) = pathlen;
    r = xact(pdu, 72+pathlen, resp, sizeof(resp));
    if (r >= 40) tid = *(uint32_t*)(resp+36);
    else return -1;
    return 0;
}

static int smb_reconnect(const char *share) {
    if (raw_sock >= 0) close(raw_sock);
    raw_sock = -1; sid = 0; tid = 0; mid = 0; has_file = 0;
    if (smb_connect() < 0) return -1;
    return smb_auth(share);
}

static int smb_create_file(const char *fname) {
    uint8_t pdu[256], resp[256];
    smb2_hdr(pdu, 5);
    uint8_t *body = pdu+64;
    *(uint16_t*)(body) = 57;
    *(uint32_t*)(body+24) = 0x12019F; /* GENERIC_ALL */
    *(uint32_t*)(body+28) = 0x80;
    *(uint32_t*)(body+32) = 0x07; /* ShareAccess=ALL */
    *(uint32_t*)(body+36) = 0x05; /* FILE_OPEN_IF */
    *(uint32_t*)(body+40) = 0x40; /* FILE_NON_DIRECTORY_FILE */
    uint16_t nlen = 0;
    for (int i = 0; fname[i]; i++) { pdu[120+i*2]=fname[i]; pdu[121+i*2]=0; nlen+=2; }
    *(uint16_t*)(body+44) = 120;
    *(uint16_t*)(body+46) = nlen;
    int r = xact(pdu, 120+nlen, resp, sizeof(resp));
    if (r >= 144) { memcpy(file_id, resp+128, 16); has_file = 1; return 0; }
    return -1;
}

static void smb_logoff_disconnect(void) {
    /* TREE_DISCONNECT */
    uint8_t pdu[128], resp[128];
    smb2_hdr(pdu, 4); /* CMD_TREE_DISCONNECT */
    *(uint16_t*)(pdu+64) = 4;
    xact(pdu, 68, resp, sizeof(resp));
    /* LOGOFF */
    smb2_hdr(pdu, 2); /* CMD_LOGOFF */
    *(uint16_t*)(pdu+64) = 4;
    xact(pdu, 68, resp, sizeof(resp));
    /* Close socket */
    if (raw_sock >= 0) { close(raw_sock); raw_sock = -1; }
    sid = 0; tid = 0; has_file = 0;
}

static int _iter_count = 0;
/* Call at end of each iteration — disconnects every 200 iterations to release server resources */
#define SNIPER_ITER_END() do { \
    if (++_iter_count % 200 == 0) smb_logoff_disconnect(); \
} while(0)

#endif /* SNIPER_COMMON_H */
