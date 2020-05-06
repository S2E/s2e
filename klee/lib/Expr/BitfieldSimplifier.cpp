/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2016, Cyberhaven
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 *
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

#include <inttypes.h>

#include "klee/BitfieldSimplifier.h"

#include <klee/Common.h>
#include "llvm/Support/CommandLine.h"

using namespace klee;
using namespace llvm;

namespace {

bool maskToBits(uint64_t mask, unsigned &bits) {
    switch (mask) {
        case 0x1:
            bits = 1;
            break;
        case 0x3:
            bits = 4;
            break;
        case 0x7:
            bits = 8;
            break;
        case 0xf:
            bits = 16;
            break;
        case 0x1f:
            bits = 32;
            break;
        case 0x3f:
            bits = 64;
            break;
        case 0x7f:
            bits = 128;
            break;
        case 0xff:
            bits = 256;
            break;
        default:
            return false;
    }
    return true;
}

cl::opt<bool> DebugSimplifier("debug-expr-simplifier", cl::init(false));

cl::opt<bool> PrintSimplifier("print-expr-simplifier", cl::init(false));
} // namespace

ref<Expr> BitfieldSimplifier::replaceWithConstant(const ref<Expr> &e, const llvm::APInt &value) {
    ConstantExpr *ce = dyn_cast<ConstantExpr>(e);
    if (ce && ce->getAPValue() == value) {
        return e;
    }

    // Remove kids from cache
    unsigned numKids = e->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
        m_bitsInfoCache.erase(e->getKid(i));
    }

    // Remove e from cache
    m_bitsInfoCache.erase(e);

    return ConstantExpr::alloc(value);
}

BitfieldSimplifier::ExprBitsInfo BitfieldSimplifier::doSimplifyBits(const ref<Expr> &e,
                                                                    const llvm::APInt &ignoredBits) {
    // Fast path for the constant case
    if (isa<ConstantExpr>(e)) {
        BitsInfo rbits;
        rbits.ignoredBits = ignoredBits;
        rbits.knownOneBits = cast<ConstantExpr>(e)->getAPValue();
        rbits.knownZeroBits = ~rbits.knownOneBits;
        return std::make_pair(e, rbits);
    }

    ExprHashMap<BitsInfo>::iterator it = m_bitsInfoCache.find(e);
    if (it != m_bitsInfoCache.end()) {
        return *it;
    }

    ref<Expr> kids[8];
    BitsInfo bits[8];
    APInt oldIgnoredBits[8];

    BitsInfo rbits;
    rbits.ignoredBits = ignoredBits;

    // Call doSimplifyBits recursively to obtain knownBits for each kid
    unsigned numKids = e->getNumKids();
    for (unsigned i = 0; i < numKids; ++i) {
        // By setting ignoredBits to zero we disable any ignoredBits-related
        // optimization. Only optimizations based on knownBits will be done.
        ExprBitsInfo r = doSimplifyBits(e->getKid(i), APInt::getNullValue(e->getKid(i)->getWidth()));
        kids[i] = r.first;
        bits[i] = r.second;

        // Save current value of ignoredBits. If we find more bits that are
        // ignored we rerun doSimplifyBits for this kid.
        oldIgnoredBits[i] = bits[i].ignoredBits;
    }

    if (DebugSimplifier) {
        *klee_message_stream << "Considering " << e << '\n';
    }

    // Apply kind-specific knowledge to obtain knownBits for e and
    // ignoredBits for kids of e, then to optimize e.
    switch (e->getKind()) {
            // TODO: Concat, Read, AShr

        case Expr::And:
            rbits.knownOneBits = bits[0].knownOneBits & bits[1].knownOneBits;
            rbits.knownZeroBits = bits[0].knownZeroBits | bits[1].knownZeroBits;

            bits[0].ignoredBits = ignoredBits | bits[1].knownZeroBits;
            bits[1].ignoredBits = ignoredBits | (bits[0].knownZeroBits & ~bits[1].knownZeroBits);

            // Check if we can replace some kids by 1
            for (unsigned i = 0; i < 2; ++i) {
                if (~(bits[i].knownOneBits | bits[i].ignoredBits) == 0) {
                    // All bits of this kid is either one or ignored
                    bits[i].knownOneBits = APInt::getAllOnesValue(e->getWidth());
                    bits[i].knownZeroBits = APInt::getNullValue(e->getWidth());
                }
            }

            break;

        case Expr::Or:
            rbits.knownOneBits = bits[0].knownOneBits | bits[1].knownOneBits;
            rbits.knownZeroBits = bits[0].knownZeroBits & bits[1].knownZeroBits;

            bits[0].ignoredBits = ignoredBits | bits[1].knownOneBits;
            bits[1].ignoredBits = ignoredBits | (bits[0].knownOneBits & ~bits[1].knownOneBits);

            // Check if we can replace some kids by 0
            for (unsigned i = 0; i < 2; ++i) {
                if (~(bits[i].knownZeroBits | bits[i].ignoredBits) == 0) {
                    // All bits of this kid is either zero or ignored
                    bits[i].knownOneBits = APInt::getNullValue(e->getWidth());
                    bits[i].knownZeroBits = APInt::getAllOnesValue(e->getWidth());
                }
            }

            break;

        case Expr::Xor:
            rbits.knownOneBits =
                (bits[0].knownZeroBits & bits[1].knownOneBits) | (bits[0].knownOneBits & bits[1].knownZeroBits);
            rbits.knownZeroBits =
                (bits[0].knownOneBits & bits[1].knownOneBits) | (bits[0].knownZeroBits & bits[1].knownZeroBits);

            bits[0].ignoredBits = ignoredBits;
            bits[1].ignoredBits = ignoredBits;

            break;

        case Expr::Not:
            rbits.knownOneBits = bits[0].knownZeroBits;
            rbits.knownZeroBits = bits[0].knownOneBits;

            bits[0].ignoredBits = ignoredBits;

            break;

        case Expr::Shl: {
            unsigned width = e->getWidth();
            assert(width == kids[0]->getWidth());

            if (ConstantExpr *c1 = dyn_cast<ConstantExpr>(kids[1])) {
                // We can simplify only if the shift is known

                // We need getLimitedValue because shift amounts must be unsigned
                unsigned shift = c1->getLimitedValue(width);

                if (shift < width) {
                    rbits.knownOneBits = bits[0].knownOneBits << shift;
                    // The low bits are zero after shifting
                    rbits.knownZeroBits = (bits[0].knownZeroBits << shift) | APInt::getLowBitsSet(width, shift);

                    // The high bits of kid 0 are ignored because they got shifted out
                    bits[0].ignoredBits = ignoredBits.lshr(shift) | APInt::getHighBitsSet(width, shift);
                } else {
                    // When the shift amount is >= the expression's width, the result is always 0
                    rbits.knownOneBits = APInt::getNullValue(width);
                    rbits.knownZeroBits = APInt::getAllOnesValue(width);
                    bits[0].ignoredBits = APInt::getAllOnesValue(width);
                }
            } else {
                // This is the most general assumption
                rbits.knownOneBits = APInt::getNullValue(width);
                rbits.knownZeroBits = APInt::getNullValue(width);
            }
        } break;

        case Expr::LShr: {
            unsigned width = e->getWidth();
            assert(width == kids[0]->getWidth());

            if (ConstantExpr *c1 = dyn_cast<ConstantExpr>(kids[1])) {
                // We can simplify only if the shift is known

                // We need getLimitedValue because shift amounts must be unsigned
                unsigned shift = c1->getLimitedValue(width);

                if (shift < width) {
                    rbits.knownOneBits = bits[0].knownOneBits.lshr(shift);
                    // The high bits are zero after shifting
                    rbits.knownZeroBits = bits[0].knownZeroBits.lshr(shift) | APInt::getHighBitsSet(width, shift);

                    // The low bits of kid 0 are ignored because they got shifted out
                    bits[0].ignoredBits = (ignoredBits << shift) | APInt::getLowBitsSet(width, shift);
                } else {
                    // When the shift amout is >= the expression's width, the result is always 0
                    rbits.knownOneBits = APInt::getNullValue(width);
                    rbits.knownZeroBits = APInt::getAllOnesValue(width);
                    bits[0].ignoredBits = APInt::getAllOnesValue(width);
                }
            } else {
                // This is the most general assumption
                rbits.knownOneBits = APInt::getNullValue(width);
                rbits.knownZeroBits = APInt::getNullValue(width);
            }
        } break;

        case Expr::Extract: {
            ExtractExpr *ee = cast<ExtractExpr>(e);

            unsigned offset = ee->getOffset();
            unsigned width = ee->getWidth();
            unsigned kidWidth = kids[0]->getWidth();

            // KnownOne(Extract(K, off, width)) == Extract(KnownOne(K), off, width), same thing for KnownZero
            // Since we always want the masks to be as wide as the corresponding expression, we also have to
            // truncate them
            rbits.knownOneBits = bits[0].knownOneBits.lshr(offset).trunc(width);
            rbits.knownZeroBits = bits[0].knownZeroBits.lshr(offset).trunc(width);

            // Bits from the lsb until offset are ignored because they're discarded by extract
            // Bits from (offset + width) to the msb are also ignored for the same reason
            // The parent's ignored bits mask has to be zero-extended for the same reason why we're truncating the kid's
            // masks above
            bits[0].ignoredBits = APInt::getLowBitsSet(kidWidth, offset) |
                                  APInt::getHighBitsSet(kidWidth, kidWidth - width - offset) |
                                  (ignoredBits.zext(kidWidth) << offset);
        } break;

        case Expr::Concat: {
            // Shifting by more than the width of the expression is not allowed
            unsigned shift = kids[1]->getWidth();
            unsigned width = e->getWidth();

            // Since we always want the masks to be as wide as the corresponding expression, we have to zero-extend
            // the two kids' masks before combining them
            rbits.knownOneBits = (bits[0].knownOneBits.zext(width) << shift) | bits[1].knownOneBits.zext(width);
            rbits.knownZeroBits = (bits[0].knownZeroBits.zext(width) << shift) | bits[1].knownZeroBits.zext(width);

            // The parent's ignored bits mask has to be truncated for the same reason as above.
            bits[0].ignoredBits = (ignoredBits.lshr(shift)).trunc(kids[0]->getWidth());
            bits[1].ignoredBits = ignoredBits.trunc(shift);
        } break;

        case Expr::Select:
            rbits.knownOneBits = bits[1].knownOneBits & bits[2].knownOneBits;
            rbits.knownZeroBits = bits[1].knownZeroBits & bits[2].knownZeroBits;

            bits[1].ignoredBits = ignoredBits;
            bits[2].ignoredBits = ignoredBits;
            break;

        case Expr::ZExt: {
            unsigned width = e->getWidth();
            unsigned kidWidth = kids[0]->getWidth();

            // The bits in the zero-extended region are all zero so they should be set them in the known zero mask
            rbits.knownOneBits = bits[0].knownOneBits.zext(width);
            rbits.knownZeroBits = bits[0].knownZeroBits.zext(width) | APInt::getHighBitsSet(width, width - kidWidth);

            bits[0].ignoredBits = ignoredBits.trunc(kidWidth);

        } break;

        case Expr::SExt: {
            unsigned width = e->getWidth();
            unsigned kidWidth = kids[0]->getWidth();

            // If the msb of one of the masks is set then the high bits of this
            // expression are known and they should be set in the corresponding mask
            rbits.knownOneBits = bits[0].knownOneBits.sext(width);
            rbits.knownZeroBits = bits[0].knownZeroBits.sext(width);

            bits[0].ignoredBits = ignoredBits.trunc(kidWidth);

            // If any of the bits in the region that got sign-extended are not ignored
            // then the msb of kid 0 cannot be ignored
            if (ignoredBits.countLeadingOnes() < width - kidWidth) {
                bits[0].ignoredBits.clearBit(bits[0].ignoredBits.getBitWidth() - 1);
            }
        } break;

        case Expr::Constant:
            // This case is treated at the beginning of this function
            rbits.knownOneBits = cast<ConstantExpr>(e)->getAPValue();
            rbits.knownZeroBits = ~rbits.knownOneBits;
            break;

        default:
            // This is the most general assumption
            rbits.knownOneBits = APInt::getNullValue(e->getWidth());
            rbits.knownZeroBits = APInt::getNullValue(e->getWidth());
            break;
    }

    assert((rbits.knownOneBits & rbits.knownZeroBits) == 0);
    // The masks should be exactly as wide as the value itself
    assert((rbits.knownOneBits.getBitWidth() == e->getWidth()) && (rbits.knownZeroBits.getBitWidth() == e->getWidth()));

    auto rebuilt = e;

    if (!isa<ConstantExpr>(e) && (~(rbits.knownOneBits | rbits.knownZeroBits | ignoredBits)) == 0) {
        if (DebugSimplifier) {
            *klee_message_stream << "CS Replacing " << e << " with constant " << hexval(rbits.knownOneBits) << '\n';
        }

        rebuilt = replaceWithConstant(e, rbits.knownOneBits);
    } else {
        // Check wether we want to reoptimize or replace kids
        for (unsigned i = 0; i < e->getNumKids(); ++i) {
            if ((~(bits[i].knownOneBits | bits[i].knownZeroBits | bits[i].ignoredBits)) == 0) {
                // All bits are known or ignored, replace expression by const
                // NOTE: we do it here on order to take into account
                //       kind-specific adjustements to knownBits
                if (!isa<ConstantExpr>(kids[i])) {
                    if (DebugSimplifier) {
                        *klee_message_stream << "NC Replacing " << kids[i] << " with constant "
                                             << hexval(bits[i].knownOneBits) << '\n';
                    }

                    kids[i] = replaceWithConstant(kids[i], bits[i].knownOneBits);
                }

            } else if ((bits[i].ignoredBits & ~oldIgnoredBits[i]) != 0) {
                /* We have new information about ignoredBits */
                kids[i] = doSimplifyBits(kids[i], bits[i].ignoredBits).first;
            }
        }

        // Check wheter any kid was changed
        for (unsigned i = 0; i < e->getNumKids(); ++i) {
            if (kids[i] != e->getKid(i)) {
                // Kid was changed, we must rebuild the expression
                rebuilt = e->rebuild(kids);
                break;
            }
        }
    }

    /* Cache knownBits information, but only for complex expressions */
    if (rebuilt->getNumKids() > 1) {
        m_bitsInfoCache.insert(std::make_pair(rebuilt, rbits));
    }

    return std::make_pair(rebuilt, rbits);
}

ref<Expr> BitfieldSimplifier::simplify(const ref<Expr> &e, APInt *knownZeroBits) {
    bool cste = isa<ConstantExpr>(e);
    if (PrintSimplifier && !cste && klee_message_stream)
        *klee_message_stream << "BEFORE SIMPL: " << e << '\n';

    if (cste) {
        return e;
    }

    ExprHashMap<ExprBitsInfo>::iterator it = m_simplifiedExpressions.find(e);
    if (it != m_simplifiedExpressions.end()) {
        ++m_cacheHits;
        if (knownZeroBits) {
            *knownZeroBits = (*it).second.second.knownZeroBits;
        }
        return (*it).second.first;
    }

    ++m_cacheMisses;

    ExprBitsInfo ret = doSimplifyBits(e, APInt::getNullValue(e->getWidth()));

    m_simplifiedExpressions[e] = ret;

    if (PrintSimplifier && !cste && klee_message_stream) {
        if (ret.first != e) {
            *klee_message_stream << "AFTER  SIMPL: " << ret.first << '\n';
        }
    }

    if (knownZeroBits) {
        *knownZeroBits = ret.second.knownZeroBits;
    }

    return ret.first;
}

bool BitfieldSimplifier::getBaseOffset(const ref<Expr> &e, uint64_t &base, ref<Expr> &offset, unsigned &offsetSize) {
    auto add = dyn_cast<AddExpr>(e);
    if (!add) {
        return false;
    }

    auto baseExpr = dyn_cast<ConstantExpr>(add->getLeft());
    if (!baseExpr) {
        return false;
    }

    auto offsetExpr = add->getRight();
    APInt knownZeroBits;
    simplify(offsetExpr, &knownZeroBits);

    // Only handle 8-bits sized objects for now.
    // TODO: make it work for arbitrary consecutive numbers of 1s.
    if ((knownZeroBits & ~(uint64_t) 0xff) == ~(uint64_t) 0xff) {
        offsetSize = 1 << 8;
    } else {
        return false;
    }

    base = baseExpr->getZExtValue();
    offset = offsetExpr;
    return true;
}

bool BitfieldSimplifier::getBaseOffsetFast(const ref<Expr> &e, uint64_t &base, ref<Expr> &offset,
                                           unsigned &offsetSize) {
    auto add = dyn_cast<AddExpr>(e);
    if (!add || add->getWidth() > Expr::Int64) {
        return false;
    }

    auto baseExpr = dyn_cast<ConstantExpr>(add->getLeft());
    if (!baseExpr) {
        return false;
    }

    auto offsetExpr = add->getRight();

    auto andExpr = dyn_cast<AndExpr>(offsetExpr);
    if (!andExpr) {
        return false;
    }

    auto maskExpr = dyn_cast<ConstantExpr>(andExpr->getRight());
    if (!maskExpr) {
        return false;
    }

    auto mask = maskExpr->getZExtValue();
    if (!maskToBits(mask, offsetSize)) {
        return false;
    }

    base = baseExpr->getZExtValue();
    offset = offsetExpr;
    return true;
}
