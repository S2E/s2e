#define CMPXCHG_HELPER(OP, TYPE)                                                                         \
    TYPE HELPER(atomic_##OP)(CPUArchState * env, target_ulong addr, TYPE oldv, TYPE newv, uint32_t oi) { \
        abort();                                                                                         \
    }

CMPXCHG_HELPER(cmpxchgb, uint32_t)
CMPXCHG_HELPER(cmpxchgw_be, uint32_t)
CMPXCHG_HELPER(cmpxchgw_le, uint32_t)
CMPXCHG_HELPER(cmpxchgl_be, uint32_t)
CMPXCHG_HELPER(cmpxchgl_le, uint32_t)

#ifdef CONFIG_ATOMIC64
CMPXCHG_HELPER(cmpxchgq_be, uint64_t)
CMPXCHG_HELPER(cmpxchgq_le, uint64_t)
#endif

#undef CMPXCHG_HELPER

Int128 HELPER(nonatomic_cmpxchgo)(CPUArchState *env, uint64_t addr, Int128 cmpv, Int128 newv, uint32_t oi) {
    abort();
}

#define ATOMIC_HELPER(OP, TYPE)                                                                    \
    TYPE HELPER(glue(atomic_, OP))(CPUArchState * env, target_ulong addr, TYPE val, uint32_t oi) { \
        abort();                                                                                   \
    }

#ifdef CONFIG_ATOMIC64
#define GEN_ATOMIC_HELPERS(OP)              \
    ATOMIC_HELPER(glue(OP, b), uint32_t)    \
    ATOMIC_HELPER(glue(OP, w_be), uint32_t) \
    ATOMIC_HELPER(glue(OP, w_le), uint32_t) \
    ATOMIC_HELPER(glue(OP, l_be), uint32_t) \
    ATOMIC_HELPER(glue(OP, l_le), uint32_t) \
    ATOMIC_HELPER(glue(OP, q_be), uint64_t) \
    ATOMIC_HELPER(glue(OP, q_le), uint64_t)
#else
#define GEN_ATOMIC_HELPERS(OP)              \
    ATOMIC_HELPER(glue(OP, b), uint32_t)    \
    ATOMIC_HELPER(glue(OP, w_be), uint32_t) \
    ATOMIC_HELPER(glue(OP, w_le), uint32_t) \
    ATOMIC_HELPER(glue(OP, l_be), uint32_t) \
    ATOMIC_HELPER(glue(OP, l_le), uint32_t)
#endif

GEN_ATOMIC_HELPERS(fetch_add)
GEN_ATOMIC_HELPERS(fetch_and)
GEN_ATOMIC_HELPERS(fetch_or)
GEN_ATOMIC_HELPERS(fetch_xor)
GEN_ATOMIC_HELPERS(fetch_smin)
GEN_ATOMIC_HELPERS(fetch_umin)
GEN_ATOMIC_HELPERS(fetch_smax)
GEN_ATOMIC_HELPERS(fetch_umax)

GEN_ATOMIC_HELPERS(add_fetch)
GEN_ATOMIC_HELPERS(and_fetch)
GEN_ATOMIC_HELPERS(or_fetch)
GEN_ATOMIC_HELPERS(xor_fetch)
GEN_ATOMIC_HELPERS(smin_fetch)
GEN_ATOMIC_HELPERS(umin_fetch)
GEN_ATOMIC_HELPERS(smax_fetch)
GEN_ATOMIC_HELPERS(umax_fetch)

GEN_ATOMIC_HELPERS(xchg)

#undef ATOMIC_HELPER
#undef GEN_ATOMIC_HELPERS
