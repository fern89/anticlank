#ifndef JUNK_H
#define JUNK_H
#include <stdint.h>

static inline __attribute__((always_inline)) uint64_t junk_0(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int r=0; r<3; r++) {
        for(int i=0; i<8; i++) {
            u.bytes[i] = (u.bytes[i] ^ 0x3F) + (u.bytes[(i+1)%8] ^ i);
            u.bytes[i] = (u.bytes[i] << 3) | (u.bytes[i] >> 5);
        }
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_1(uint64_t state) {
    union { uint64_t val; uint32_t w[2]; } u = { .val = state };
    uint32_t L = u.w[0];
    uint32_t R = u.w[1];
    for(int i=0; i<4; i++) {
        uint32_t temp = L;
        L = R ^ (((L << 9) | (L >> 23)) + 0x9E3779B9 + i);
        R = temp;
    }
    u.w[0] = L;
    u.w[1] = R;
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_2(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i++) {
        int target = (u.bytes[i] + i) % 8;
        uint8_t tmp = u.bytes[i];
        u.bytes[i] = u.bytes[target] ^ 0x5A;
        u.bytes[target] = tmp + i;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_3(uint64_t state) {
    union { uint64_t val; uint16_t w[4]; } u = { .val = state };
    uint16_t carry = 0x1234;
    for(int i=0; i<4; i++) {
        uint32_t sum = (uint32_t)u.w[i] + carry + 0x5A82;
        u.w[i] = (uint16_t)(sum ^ (sum >> 16));
        carry = u.w[i] ^ 0x7070;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_4(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i+=2) {
        uint8_t x = u.bytes[i];
        uint8_t y = u.bytes[i+1];
        u.bytes[i]   = (uint8_t)((3 * x + 2 * y) & 0xFF);
        u.bytes[i+1] = (uint8_t)((5 * x + 7 * y) & 0xFF);
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_5(uint64_t state) {
    uint64_t x = state;
    x = ((x & 0x5555555555555555ULL) << 1) | ((x & 0xAAAAAAAAAAAAAAAAULL) >> 1);
    x ^= 0x0F0F0F0F0F0F0F0FULL;
    x = (x << 17) | (x >> 47);
    x += 0xD125193902130311ULL;
    return x;
}

static inline __attribute__((always_inline)) uint64_t junk_6(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint8_t acc = 0xAA;
    for(int i=0; i<8; i++) {
        u.bytes[i] ^= acc;
        acc = (acc + u.bytes[i]) ^ 0x1F;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_7(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i++) {
        uint8_t high = u.bytes[i] >> 4;
        uint8_t low = u.bytes[i] & 0x0F;
        high = (high * 5 + 3) & 0x0F;
        low = (low * 7 + 11) & 0x0F;
        u.bytes[i] = (low << 4) | high;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_8(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint8_t prev2 = u.bytes[0];
    uint8_t prev1 = u.bytes[1];
    for(int i=2; i<8; i++) {
        uint8_t next = prev1 + prev2 + i;
        u.bytes[i] ^= next;
        prev2 = prev1;
        prev1 = u.bytes[i];
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_9(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<4; i++) {
        uint8_t b1 = u.bytes[i];
        uint8_t b2 = u.bytes[7-i];
        b1 = (b1 << 4) | (b1 >> 4);
        b2 = ~b2;
        u.bytes[i] = b2;
        u.bytes[7-i] = b1;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_10(uint64_t state) {
    union { uint64_t val; uint16_t w[4]; } u = { .val = state };
    u.w[0] = (u.w[0] * 31) - u.w[1];
    u.w[1] = (u.w[1] * 17) + u.w[2];
    u.w[2] = (u.w[2] * 13) - u.w[3];
    u.w[3] = (u.w[3] * 7) + u.w[0];
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_11(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<4; i++) {
        u.bytes[i*2] ^= u.bytes[i*2+1];
        u.bytes[i*2+1] = (u.bytes[i*2+1] << 2) | (u.bytes[i*2+1] >> 6);
    }
    u.bytes[0] += u.bytes[2];
    u.bytes[4] += u.bytes[6];
    u.bytes[0] ^= u.bytes[4];
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_12(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i++) {
        if (u.bytes[i] & 0x01) {
            u.bytes[i] = (u.bytes[i] ^ 0xAA) + 5;
        } else {
            u.bytes[i] = (u.bytes[i] ^ 0x55) - 3;
        }
        u.bytes[i] = ~u.bytes[i];
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_13(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint16_t multiplier = 109;
    uint16_t increment = 89;
    uint16_t accum = 0xCD;
    for(int i=0; i<8; i++) {
        accum = (u.bytes[i] * multiplier + increment + accum) & 0xFF;
        u.bytes[i] = (uint8_t)accum;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_14(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint8_t odd = 0;
    uint8_t even = 0;
    for(int i=0; i<8; i++) {
        if (i % 2 == 0) even ^= u.bytes[i];
        else odd ^= u.bytes[i];
    }
    for(int i=0; i<8; i++) {
        u.bytes[i] = (u.bytes[i] + (i % 2 == 0 ? odd : even)) ^ 0x33;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_15(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i++) {
        int shift = (i + 1) % 8;
        u.bytes[i] = (u.bytes[i] << shift) | (u.bytes[i] >> (8 - shift));
        u.bytes[i] ^= 0xC3;
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_16(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint8_t lookup[4] = { 0x45, 0xF2, 0x1A, 0x7E };
    for(int i=0; i<8; i++) {
        uint8_t key = lookup[u.bytes[i] & 0x03];
        u.bytes[i] = (u.bytes[i] ^ key) + lookup[(i + 1) & 0x03];
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_17(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    uint8_t r1 = u.bytes[0];
    uint8_t r2 = u.bytes[7];
    for(int i=1; i<7; i++) {
        r1 = (r1 + u.bytes[i]) ^ 0x66;
        r2 = (r2 ^ u.bytes[i]) + 0x22;
        u.bytes[i] = r1 ^ r2;
    }
    u.bytes[0] = r1;
    u.bytes[7] = r2;
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_18(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int i=0; i<8; i++) {
        uint8_t denom = (u.bytes[(i+1)%8] | 1);
        u.bytes[i] = (uint8_t)((u.bytes[i] * denom) + 0x7F);
    }
    return u.val;
}

static inline __attribute__((always_inline)) uint64_t junk_19(uint64_t state) {
    union { uint64_t val; uint8_t bytes[8]; } u = { .val = state };
    for(int round=0; round<2; round++) {
        uint8_t checksum = 0;
        for(int i=0; i<8; i++) {
            checksum ^= u.bytes[i];
        }
        for(int i=0; i<8; i++) {
            u.bytes[i] = (u.bytes[i] + checksum) ^ (0x99 * (i + 1));
            u.bytes[i] = (u.bytes[i] >> 2) | (u.bytes[i] << 6);
        }
    }
    return u.val;
}

#endif
