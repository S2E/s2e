// Unions for reinterpreting between floats and integers.
//
// Upstream QEMU keeps these in include/qemu/cpu-float.h rather than in
// bswap.h: they are the only part that needs softfloat types, and leaving
// them in bswap.h creates an include cycle now that softfloat-types.h pulls
// in registerfields.h -> bitops.h -> host-utils.h -> bswap.h.

#ifndef TCG_CPU_FLOAT_H
#define TCG_CPU_FLOAT_H

#include <inttypes.h>

#include <fpu/softfloat-types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
    float32 f;
    uint32_t l;
} CPU_FloatU;

typedef union {
    float64 d;
#if defined(HOST_WORDS_BIGENDIAN)
    struct {
        uint32_t upper;
        uint32_t lower;
    } l;
#else
    struct {
        uint32_t lower;
        uint32_t upper;
    } l;
#endif
    uint64_t ll;
} CPU_DoubleU;

typedef union {
    floatx80 d;
    struct {
        uint64_t lower;
        uint16_t upper;
    } l;
} CPU_LDoubleU;

typedef union {
    float128 q;
#if defined(HOST_WORDS_BIGENDIAN)
    struct {
        uint32_t upmost;
        uint32_t upper;
        uint32_t lower;
        uint32_t lowest;
    } l;
    struct {
        uint64_t upper;
        uint64_t lower;
    } ll;
#else
    struct {
        uint32_t lowest;
        uint32_t lower;
        uint32_t upper;
        uint32_t upmost;
    } l;
    struct {
        uint64_t lower;
        uint64_t upper;
    } ll;
#endif
} CPU_QuadU;

static inline float32 ldfl_le_p(const void *ptr) {
    return *(float32 *) ptr;
}

static inline float64 ldfq_le_p(const void *ptr) {
    return *(float64 *) ptr;
}

static inline void stfl_le_p(void *ptr, float32 v) {
    *(float32 *) ptr = v;
}

static inline void stfq_le_p(void *ptr, float64 v) {
    *(float64 *) ptr = v;
}

#ifdef __cplusplus
}
#endif

#endif
