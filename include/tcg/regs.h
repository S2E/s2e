#ifndef _TCG_REGS_H_

#define _TCG_REGS_H_

#include <inttypes.h>

// XXX: this is in softfloat.
typedef uint32_t float32;
typedef uint64_t float64;

typedef union {
    uint8_t _b[8];
    uint16_t _w[4];
    uint32_t _l[2];
    float32 _s[2];
    uint64_t q;
} MMXReg;

typedef union {
    uint8_t _b[16];
    uint16_t _w[8];
    uint32_t _l[4];
    uint64_t _q[2];
    float32 _s[4];
    float64 _d[2];
} XMMReg;

#endif
