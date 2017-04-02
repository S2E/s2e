/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#ifndef BSWAP_H
#define BSWAP_H

#include <cpu/config-host.h>

#include <inttypes.h>
#include "softfloat.h"

#ifdef CONFIG_MACHINE_BSWAP_H
#include <machine/bswap.h>
#include <sys/endian.h>
#include <sys/types.h>
#else

#ifdef CONFIG_BYTESWAP_H
#include <byteswap.h>
#else

#define bswap_16(x)                                                                                                  \
    ({                                                                                                               \
        uint16_t __x = (x);                                                                                          \
        ((uint16_t)((((uint16_t)(__x) & (uint16_t) 0x00ffU) << 8) | (((uint16_t)(__x) & (uint16_t) 0xff00U) >> 8))); \
    })

#define bswap_32(x)                                                        \
    ({                                                                     \
        uint32_t __x = (x);                                                \
        ((uint32_t)((((uint32_t)(__x) & (uint32_t) 0x000000ffUL) << 24) |  \
                    (((uint32_t)(__x) & (uint32_t) 0x0000ff00UL) << 8) |   \
                    (((uint32_t)(__x) & (uint32_t) 0x00ff0000UL) >> 8) |   \
                    (((uint32_t)(__x) & (uint32_t) 0xff000000UL) >> 24))); \
    })

#define bswap_64(x)                                                                           \
    ({                                                                                        \
        uint64_t __x = (x);                                                                   \
        ((uint64_t)((uint64_t)(((uint64_t)(__x) & (uint64_t) 0x00000000000000ffULL) << 56) |  \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x000000000000ff00ULL) << 40) |  \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x0000000000ff0000ULL) << 24) |  \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x00000000ff000000ULL) << 8) |   \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x000000ff00000000ULL) >> 8) |   \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x0000ff0000000000ULL) >> 24) |  \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0x00ff000000000000ULL) >> 40) |  \
                    (uint64_t)(((uint64_t)(__x) & (uint64_t) 0xff00000000000000ULL) >> 56))); \
    })

#endif /* !CONFIG_BYTESWAP_H */

static inline uint16_t bswap16(uint16_t x) {
    return bswap_16(x);
}

static inline uint32_t bswap32(uint32_t x) {
    return bswap_32(x);
}

static inline uint64_t bswap64(uint64_t x) {
    return bswap_64(x);
}

#endif /* ! CONFIG_MACHINE_BSWAP_H */

static inline void bswap16s(uint16_t *s) {
    *s = bswap16(*s);
}

static inline void bswap32s(uint32_t *s) {
    *s = bswap32(*s);
}

static inline void bswap64s(uint64_t *s) {
    *s = bswap64(*s);
}

#if defined(HOST_WORDS_BIGENDIAN)
#define be_bswap(v, size) (v)
#define le_bswap(v, size) bswap##size(v)
#define be_bswaps(v, size)
#define le_bswaps(p, size) *p = bswap##size(*p);
#else
#define le_bswap(v, size) (v)
#define be_bswap(v, size) bswap##size(v)
#define le_bswaps(v, size)
#define be_bswaps(p, size) *p = bswap##size(*p);
#endif

#define CPU_CONVERT(endian, size, type)                            \
    static inline type endian##size##_to_cpu(type v) {             \
        return endian##_bswap(v, size);                            \
    }                                                              \
                                                                   \
    static inline type cpu_to_##endian##size(type v) {             \
        return endian##_bswap(v, size);                            \
    }                                                              \
                                                                   \
    static inline void endian##size##_to_cpus(type *p) {           \
        endian##_bswaps(p, size)                                   \
    }                                                              \
                                                                   \
    static inline void cpu_to_##endian##size##s(type *p) {         \
        endian##_bswaps(p, size)                                   \
    }                                                              \
                                                                   \
    static inline type endian##size##_to_cpup(const type *p) {     \
        return endian##size##_to_cpu(*p);                          \
    }                                                              \
                                                                   \
    static inline void cpu_to_##endian##size##w(type *p, type v) { \
        *p = cpu_to_##endian##size(v);                             \
    }

CPU_CONVERT(be, 16, uint16_t)
CPU_CONVERT(be, 32, uint32_t)
CPU_CONVERT(be, 64, uint64_t)

CPU_CONVERT(le, 16, uint16_t)
CPU_CONVERT(le, 32, uint32_t)
CPU_CONVERT(le, 64, uint64_t)

/* unaligned versions (optimized for frequent unaligned accesses)*/

#if defined(__i386__) || defined(_ARCH_PPC)

#define cpu_to_le16wu(p, v) cpu_to_le16w(p, v)
#define cpu_to_le32wu(p, v) cpu_to_le32w(p, v)
#define le16_to_cpupu(p) le16_to_cpup(p)
#define le32_to_cpupu(p) le32_to_cpup(p)
#define be32_to_cpupu(p) be32_to_cpup(p)

#define cpu_to_be16wu(p, v) cpu_to_be16w(p, v)
#define cpu_to_be32wu(p, v) cpu_to_be32w(p, v)

#else

static inline void cpu_to_le16wu(uint16_t *p, uint16_t v) {
    uint8_t *p1 = (uint8_t *) p;

    p1[0] = v & 0xff;
    p1[1] = v >> 8;
}

static inline void cpu_to_le32wu(uint32_t *p, uint32_t v) {
    uint8_t *p1 = (uint8_t *) p;

    p1[0] = v & 0xff;
    p1[1] = v >> 8;
    p1[2] = v >> 16;
    p1[3] = v >> 24;
}

static inline uint16_t le16_to_cpupu(const uint16_t *p) {
    const uint8_t *p1 = (const uint8_t *) p;
    return p1[0] | (p1[1] << 8);
}

static inline uint32_t le32_to_cpupu(const uint32_t *p) {
    const uint8_t *p1 = (const uint8_t *) p;
    return p1[0] | (p1[1] << 8) | (p1[2] << 16) | (p1[3] << 24);
}

static inline uint32_t be32_to_cpupu(const uint32_t *p) {
    const uint8_t *p1 = (const uint8_t *) p;
    return p1[3] | (p1[2] << 8) | (p1[1] << 16) | (p1[0] << 24);
}

static inline void cpu_to_be16wu(uint16_t *p, uint16_t v) {
    uint8_t *p1 = (uint8_t *) p;

    p1[0] = v >> 8;
    p1[1] = v & 0xff;
}

static inline void cpu_to_be32wu(uint32_t *p, uint32_t v) {
    uint8_t *p1 = (uint8_t *) p;

    p1[0] = v >> 24;
    p1[1] = v >> 16;
    p1[2] = v >> 8;
    p1[3] = v & 0xff;
}

#endif

#ifdef HOST_WORDS_BIGENDIAN
#define cpu_to_32wu cpu_to_be32wu
#else
#define cpu_to_32wu cpu_to_le32wu
#endif

#undef le_bswap
#undef be_bswap
#undef le_bswaps
#undef be_bswaps

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

static inline int ldub_p(const void *ptr) {
    return *(uint8_t *) ptr;
}

static inline int ldsb_p(const void *ptr) {
    return *(int8_t *) ptr;
}

static inline void stb_p(void *ptr, int v) {
    *(uint8_t *) ptr = v;
}

static inline int lduw_le_p(const void *ptr) {
    return *(uint16_t *) ptr;
}

static inline int ldsw_le_p(const void *ptr) {
    return *(int16_t *) ptr;
}

static inline int ldl_le_p(const void *ptr) {
    return *(uint32_t *) ptr;
}

static inline uint64_t ldq_le_p(const void *ptr) {
    return *(uint64_t *) ptr;
}

static inline void stw_le_p(void *ptr, int v) {
    *(uint16_t *) ptr = v;
}

static inline void stl_le_p(void *ptr, int v) {
    *(uint32_t *) ptr = v;
}

static inline void stq_le_p(void *ptr, uint64_t v) {
    *(uint64_t *) ptr = v;
}

/* float access */

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

/* some important defines:
 *
 * WORDS_ALIGNED : if defined, the host cpu can only make word aligned
 * memory accesses.
 *
 * HOST_WORDS_BIGENDIAN : if defined, the host cpu is big endian and
 * otherwise little endian.
 *
 * (TARGET_WORDS_ALIGNED : same for target cpu (not supported yet))
 *
 * TARGET_WORDS_BIGENDIAN : same for target cpu
 */

#if defined(HOST_WORDS_BIGENDIAN) != defined(TARGET_WORDS_BIGENDIAN)
#define BSWAP_NEEDED
#endif

#ifdef BSWAP_NEEDED

static inline uint16_t tswap16(uint16_t s) {
    return bswap16(s);
}

static inline uint32_t tswap32(uint32_t s) {
    return bswap32(s);
}

static inline uint64_t tswap64(uint64_t s) {
    return bswap64(s);
}

static inline void tswap16s(uint16_t *s) {
    *s = bswap16(*s);
}

static inline void tswap32s(uint32_t *s) {
    *s = bswap32(*s);
}

static inline void tswap64s(uint64_t *s) {
    *s = bswap64(*s);
}

#else

static inline uint16_t tswap16(uint16_t s) {
    return s;
}

static inline uint32_t tswap32(uint32_t s) {
    return s;
}

static inline uint64_t tswap64(uint64_t s) {
    return s;
}

static inline void tswap16s(uint16_t *s) {
}

static inline void tswap32s(uint32_t *s) {
}

static inline void tswap64s(uint64_t *s) {
}

#endif

#if TARGET_LONG_SIZE == 4
#define tswapl(s) tswap32(s)
#define tswapls(s) tswap32s((uint32_t *) (s))
#define bswaptls(s) bswap32s(s)
#else
#define tswapl(s) tswap64(s)
#define tswapls(s) tswap64s((uint64_t *) (s))
#define bswaptls(s) bswap64s(s)
#endif

#endif /* BSWAP_H */
