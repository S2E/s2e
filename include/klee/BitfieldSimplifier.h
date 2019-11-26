/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef KLEE_BITFIELDSIMPLIFIER_H
#define KLEE_BITFIELDSIMPLIFIER_H

#include <inttypes.h>
#include "klee/Expr.h"
#include "klee/util/ExprHashMap.h"

namespace klee {

class BitfieldSimplifier {
protected:
    struct BitsInfo {
        __uint128_t ignoredBits;   ///< Bits that can be ignored because they
                                   ///< are not used by higher-level expressions
                                   ///< (passed top-down)
        __uint128_t knownOneBits;  ///< Bits known to be one (passed bottom-up)
        __uint128_t knownZeroBits; ///< Bits known to be zero (passed bottom-up)
    };
    typedef std::pair<ref<Expr>, BitsInfo> ExprBitsInfo;

    /// XXX: this cache will probably grow too large with time
    ExprHashMap<BitsInfo> m_bitsInfoCache;

    ExprHashMap<ExprBitsInfo> m_simplifiedExpressions;

    ref<Expr> replaceWithConstant(const ref<Expr> &e, __uint128_t value);

    ExprBitsInfo doSimplifyBits(const ref<Expr> &e, __uint128_t ignoredBits);

public:
    uint64_t m_cacheHits, m_cacheMisses;

    ref<Expr> simplify(const ref<Expr> &e, uint64_t *knownZeroBits = NULL);

    // If e = base + offset, where base is concrete and offset is
    // symbolic of size 1 byte, return true.
    bool getBaseOffset(const ref<Expr> &e, uint64_t &base, ref<Expr> &offset, unsigned &offsetSize);

    // This is a faster version that uses pattern matching. It may have false negatives.
    bool getBaseOffsetFast(const ref<Expr> &e, uint64_t &base, ref<Expr> &offset, unsigned &offsetSize);

    BitfieldSimplifier() {
        m_cacheHits = 0;
        m_cacheMisses = 0;
    }
};

} // namespace klee

#endif // BITFIELDSIMPLIFIER_H
