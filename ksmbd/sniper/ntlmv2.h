/*
 * sniper_ntlmv2.h — NTLMv2 computation for snipers (requires -lcrypto).
 * Call ntlmv2_auth_response() to get valid LM + NT response for fuzz:fuzz.
 */
#ifndef SNIPER_NTLMV2_H
#define SNIPER_NTLMV2_H

#include <openssl/md4.h>
#include <openssl/hmac.h>
#include <string.h>
#include <time.h>

/* NT hash of password "fuzz" — precomputed MD4(UTF16LE("fuzz")) */
static void nt_hash(const char *password, uint8_t out[16]) {
    /* Convert to UTF-16LE */
    uint8_t utf16[256];
    int len = 0;
    for (int i = 0; password[i] && len < 250; i++) {
        utf16[len++] = password[i]; utf16[len++] = 0;
    }
    MD4(utf16, len, out);
}

/* NTLMv2 hash = HMAC-MD5(NT_hash, UPPER(user) + domain in UTF16LE) */
static void ntlmv2_hash(const char *user, const char *domain,
                         const uint8_t nt[16], uint8_t out[16]) {
    uint8_t buf[512];
    int blen = 0;
    /* Username in uppercase UTF-16LE */
    for (int i = 0; user[i] && blen < 250; i++) {
        char c = user[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        buf[blen++] = c; buf[blen++] = 0;
    }
    /* Domain in UTF-16LE (can be empty) */
    for (int i = 0; domain[i] && blen < 500; i++) {
        buf[blen++] = domain[i]; buf[blen++] = 0;
    }
    unsigned int olen = 16;
    HMAC(EVP_md5(), nt, 16, buf, blen, out, &olen);
}

/* Compute NTLMv2 response */
static int ntlmv2_response(const uint8_t server_chal[8],
                            uint8_t *nt_resp, int *nt_resp_len,
                            uint8_t *lm_resp, int *lm_resp_len) {
    uint8_t nt_h[16], v2_h[16];
    nt_hash("fuzz", nt_h);
    ntlmv2_hash("fuzz", "", nt_h, v2_h);

    /* Client challenge (random) */
    uint8_t client_chal[8];
    uint32_t t = time(NULL);
    for (int i = 0; i < 8; i++) client_chal[i] = (t >> (i*3)) ^ (i*37);

    /* LM response: HMAC-MD5(v2_hash, server_challenge + client_challenge) + client_challenge */
    uint8_t lm_input[16];
    memcpy(lm_input, server_chal, 8);
    memcpy(lm_input+8, client_chal, 8);
    unsigned int olen = 16;
    HMAC(EVP_md5(), v2_h, 16, lm_input, 16, lm_resp, &olen);
    memcpy(lm_resp+16, client_chal, 8);
    *lm_resp_len = 24;

    /* NT response: HMAC-MD5(v2_hash, server_challenge + blob) + blob */
    /* Minimal blob: signature(4) + reserved(4) + timestamp(8) + client_chal(8) + reserved(4) */
    uint8_t blob[32];
    memset(blob, 0, sizeof(blob));
    *(uint32_t*)(blob) = 0x00000101; /* blob signature */
    /* timestamp: Windows filetime (100ns since 1601) — use current */
    uint64_t ft = ((uint64_t)t + 11644473600ULL) * 10000000ULL;
    memcpy(blob+8, &ft, 8);
    memcpy(blob+16, client_chal, 8);

    uint8_t nt_input[8 + sizeof(blob)];
    memcpy(nt_input, server_chal, 8);
    memcpy(nt_input+8, blob, sizeof(blob));
    HMAC(EVP_md5(), v2_h, 16, nt_input, 8+sizeof(blob), nt_resp, &olen);
    memcpy(nt_resp+16, blob, sizeof(blob));
    *nt_resp_len = 16 + sizeof(blob);

    return 0;
}

#endif /* SNIPER_NTLMV2_H */
