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

///
/// \brief The BitfieldSimplifier class implements bitfield-based expression simplification.
///
/// Conversion from x86 to LLVM gives rise to complex symbolic expressions. S2E "sees" a lower
/// level representation of the programs than what would be obtained by compiling source code
/// to LLVM (as done in KLEE): it actually sees the code that simulates the execution of the
/// original program on the target CPU architecture. Such code typically contains many bitfield
/// operations (such as and/or, shift) that manipulate bits in the eflags register.
///
/// To optimize these expressions, we built a bitfield expression simplifier that, if parts of a
/// symbolic variable are masked away by bit operations, removes those bits from the corresponding
/// expressions. First, the simplifier starts from the bottom of the expression’s tree
/// representation and propagates information about individual bits whose value is known.
/// If all bits in an expression are known, S2E replaces the expression with the corresponding
/// constant. Second, the simplifier propagates top-down information about bits that are ignored by
/// the upper parts of the expression—when an operator only modifies bits that upper parts ignore,
/// the simplifier removes that entire operation.
///
/// We say a bit in an expression is known to be one (respectively zero), when that bit is not
/// symbolic and has the value one (respectively zero). For example, if x is a 4-bit symbolic value,
/// the expression x | 1000 has its most significant bit (MSb) known to be one, because the result of
/// an or of a concrete bit set to one and of a symbolic bit is always one. Moreover, this expression
/// has no bits known to be zero, because the MSb is always one and symbolic bits or-ed with a zero
/// remain symbolic. Finally, the ignore mask specifies which bits are ignored by the upper part of an
/// expression. For example, in 1000 & (x | 1010), the ignore mask at the top-level expression is 0111
/// because the and operator cancels the three lower bits of the entire expression.
///
/// To illustrate, consider the 4-bit wide expression 0001 & (x | 0010). The simplifier starts from
/// the bottom (i.e., x | 0010) and propagates up the expression tree the value k11 = 0010 for the
/// known-one bits as well as k10 = 0000 for the known-zero bits. This means that the simplifier
/// knows that bit 1 is set but none of the bits are zero for sure (because x is symbolic). At the top
/// level, the and operation produces k21 = 0000 for the known-one bits (k11 & 0001) and k20 = 1110
/// for the known-zero bits (k10 | 1110). The simplifier now knows that only the least significant bit
/// matters and propagates the ignore mask m = 1110 top down. There, the simplifier notices that
/// 0010 is redundant and removes it, because 1101 | m yields 1111, meaning that all bits are ignored.
/// The final result is thus 1 & x.
///
/// We implemented this simplification in the early stage of expression creation rather than in the
/// constraint solver. This way, we do not have to re-simplify the same expressions again when they
/// are sent to the constraint solver several times (for example, as part of path constraints). This is
/// an example of applying domain-specific logic to reduce constraint solving time; we expect our
/// simplifier to be directly useful for KLEE as well, when testing programs that use bitfields heavily.
class BitfieldSimplifier {
protected:
    struct BitsInfo {
        llvm::APInt ignoredBits;   ///< Bits that can be ignored because they
                                   ///< are not used by higher-level expressions
                                   ///< (passed top-down)
        llvm::APInt knownOneBits;  ///< Bits known to be one (passed bottom-up)
        llvm::APInt knownZeroBits; ///< Bits known to be zero (passed bottom-up)
    };
    typedef std::pair<ref<Expr>, BitsInfo> ExprBitsInfo;

    /// XXX: this cache will probably grow too large with time
    ExprHashMap<BitsInfo> m_bitsInfoCache;

    ExprHashMap<ExprBitsInfo> m_simplifiedExpressions;

    ref<Expr> replaceWithConstant(const ref<Expr> &e, const llvm::APInt &value);

    ExprBitsInfo doSimplifyBits(const ref<Expr> &e, const llvm::APInt &ignoredBits);

public:
    uint64_t m_cacheHits, m_cacheMisses;

    ref<Expr> simplify(const ref<Expr> &e, llvm::APInt *knownZeroBits = nullptr);

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
