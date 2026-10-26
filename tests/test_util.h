/*
 * test_util.h - Tiny test framework + packet/PCAP builders shared by tests.
 */
#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

static int g_fail = 0, g_checks = 0, g_tests_failed = 0, g_tests = 0;

#define CHECK(c) do { g_checks++; if (!(c)) { g_fail++; \
    fprintf(stderr, "    FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)

#define RUN(fn) do { int f0 = g_fail; g_tests++; fn(); \
    if (g_fail != f0) g_tests_failed++; \
    printf("  [%s] %s\n", g_fail == f0 ? "PASS" : "FAIL", #fn); } while (0)

#define SUMMARY(name) (printf("%s: %d/%d tests passed (%d checks)\n", name, \
    g_tests - g_tests_failed, g_tests, g_checks), g_tests_failed ? 1 : 0)

static inline void wr16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)(v >> 8); p[1] = (uint8_t)v; }
static inline void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
}

#define IP4(a,b,c,d) (((uint32_t)(a) << 24) | ((uint32_t)(b) << 16) | ((uint32_t)(c) << 8) | (uint32_t)(d))

/* Build an Ethernet+IPv4+TCP frame. ihl/doff are in 32-bit words (5 = no options).
 * Returns total frame length. buf must be large enough. */
__attribute__((unused)) static size_t build_tcp_frame(uint8_t *b, uint32_t sip, uint32_t dip,
                              uint16_t sp, uint16_t dp, uint32_t seq, uint8_t flags,
                              const uint8_t *pl, uint32_t plen, int ihl, int doff)
{
    uint32_t total = (uint32_t)(ihl * 4 + doff * 4) + plen;
    memset(b, 0, 14 + total);
    b[12] = 0x08; b[13] = 0x00;
    uint8_t *ip = b + 14;
    ip[0] = (uint8_t)(0x40 | ihl);
    wr16(ip + 2, (uint16_t)total);
    ip[8] = 64; ip[9] = 6;
    wr32(ip + 12, sip); wr32(ip + 16, dip);
    uint8_t *t = ip + ihl * 4;
    wr16(t, sp); wr16(t + 2, dp); wr32(t + 4, seq);
    t[12] = (uint8_t)(doff << 4); t[13] = flags;
    if (plen) memcpy(t + doff * 4, pl, plen);
    return 14 + total;
}

/* Write a classic PCAP file. frames[i] has lens[i] bytes. */
__attribute__((unused)) static int write_pcap(const char *path, uint32_t linktype,
                      const uint8_t *const *frames, const size_t *lens, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    /* Global header: magic, version 2.4, thiszone, sigfigs, snaplen, linktype */
    uint32_t magic = 0xa1b2c3d4u;
    uint16_t ver[2] = { 2, 4 };
    uint32_t rest[4] = { 0, 0, 65535, linktype };
    fwrite(&magic, 4, 1, f);
    fwrite(ver, 2, 2, f);
    fwrite(rest, 4, 4, f);
    for (size_t i = 0; i < n; i++) {
        uint32_t rh[4] = { (uint32_t)i, 0, (uint32_t)lens[i], (uint32_t)lens[i] };
        fwrite(rh, 4, 4, f);
        fwrite(frames[i], 1, lens[i], f);
    }
    fclose(f);
    return 0;
}

#endif /* TEST_UTIL_H */
