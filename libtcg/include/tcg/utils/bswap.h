/*
 * The target-dependent half of QEMU's include/qemu/bswap.h: MemOp and
 * target-endian accessors. The host-only half is in utils/bswap.h (libutils).
 */
#ifndef TCG_BSWAP_H
#define TCG_BSWAP_H

#include <tcg/tcg-memop.h>
#include <tcg/utils/target-info.h>
#include <utils/bswap.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ldm_p: Load value from host memory (byteswapping if necessary)
 *
 * @ptr: the host pointer to be accessed
 * @mop: #MemOp mask containing access size and optional byteswapping
 *
 * Convert the value stored at @ptr in host memory and byteswap if necessary.
 *
 * Returns: the converted value.
 */
static inline uint64_t ldm_p(const void *ptr, MemOp mop) {
    switch (mop & (MO_SIZE | MO_BSWAP)) {
        case MO_8:
            return ldub_p(ptr);
        case MO_16 | MO_LE:
            return lduw_le_p(ptr);
        case MO_16 | MO_BE:
            return lduw_be_p(ptr);
        case MO_32 | MO_LE:
            return ldl_le_p(ptr);
        case MO_32 | MO_BE:
            return ldl_be_p(ptr);
        case MO_64 | MO_LE:
            return ldq_le_p(ptr);
        case MO_64 | MO_BE:
            return ldq_be_p(ptr);
        default:
            g_assert_not_reached();
    }
}

/**
 * stm_p: Store value to host memory (byteswapping if necessary)
 *
 * @ptr: the host pointer to be accessed
 * @mop: #MemOp mask containing access size and optional byteswapping
 * @val: the value to store
 *
 * Convert the value (byteswap if necessary) and store at @ptr in host memory.
 */
static inline void stm_p(void *ptr, MemOp mop, uint64_t val) {
    switch (mop & (MO_SIZE | MO_BSWAP)) {
        case MO_8:
            stb_p(ptr, val);
            break;
        case MO_16 | MO_LE:
            stw_le_p(ptr, val);
            break;
        case MO_16 | MO_BE:
            stw_be_p(ptr, val);
            break;
        case MO_32 | MO_LE:
            stl_le_p(ptr, val);
            break;
        case MO_32 | MO_BE:
            stl_be_p(ptr, val);
            break;
        case MO_64 | MO_LE:
            stq_le_p(ptr, val);
            break;
        case MO_64 | MO_BE:
            stq_be_p(ptr, val);
            break;
        default:
            g_assert_not_reached();
    }
}

/* Return ld{word}_{le,be}_p following target endianness. */
#define LOAD_IMPL(word, args...)                      \
    do {                                              \
        if (target_big_endian()) {                    \
            return glue(glue(ld, word), _be_p)(args); \
        } else {                                      \
            return glue(glue(ld, word), _le_p)(args); \
        }                                             \
    } while (0)

static inline int lduw_p(const void *ptr) {
    LOAD_IMPL(uw, ptr);
}

static inline int ldsw_p(const void *ptr) {
    LOAD_IMPL(sw, ptr);
}

static inline int ldl_p(const void *ptr) {
    LOAD_IMPL(l, ptr);
}

static inline uint64_t ldq_p(const void *ptr) {
    LOAD_IMPL(q, ptr);
}

static inline uint64_t ldn_p(const void *ptr, int sz) {
    LOAD_IMPL(n, ptr, sz);
}

#undef LOAD_IMPL

/* Call st{word}_{le,be}_p following target endianness. */
#define STORE_IMPL(word, args...)              \
    do {                                       \
        if (target_big_endian()) {             \
            glue(glue(st, word), _be_p)(args); \
        } else {                               \
            glue(glue(st, word), _le_p)(args); \
        }                                      \
    } while (0)

static inline void stw_p(void *ptr, uint16_t v) {
    STORE_IMPL(w, ptr, v);
}

static inline void stl_p(void *ptr, uint32_t v) {
    STORE_IMPL(l, ptr, v);
}

static inline void stq_p(void *ptr, uint64_t v) {
    STORE_IMPL(q, ptr, v);
}

static inline void stn_p(void *ptr, int sz, uint64_t v) {
    STORE_IMPL(n, ptr, sz, v);
}

#undef STORE_IMPL

#ifdef __cplusplus
}
#endif

#endif /* TCG_BSWAP_H */
