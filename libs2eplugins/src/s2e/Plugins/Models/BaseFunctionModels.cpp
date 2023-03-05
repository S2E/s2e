///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <s2e/cpu.h>
#include <s2e/function_models/commands.h>

#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include <klee/Expr.h>
#include <klee/util/ExprTemplates.h>

#include "BaseFunctionModels.h"

namespace s2e {
namespace plugins {
namespace models {

bool BaseFunctionModels::readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg) {
    target_ulong ret;

    uint64_t addr = state->regs()->getSp() + (param + 1) * state->getPointerSize();

    // First check if argument is symbolic
    ref<Expr> readArg = state->mem()->read(addr, state->getPointerWidth());
    if (!isa<ConstantExpr>(readArg)) {
        getDebugStream(state) << "Argument " << param << " at " << hexval(addr) << " is symbolic\n";
        return false;
    }

    // If not, read concrete value
    bool ok = state->readPointer(addr, ret);

    if (!ok) {
        getDebugStream(state) << "Failed to read argument " << param << " at " << hexval(addr) << "\n";
        return false;
    }

    arg = ret;
    return true;
}

bool BaseFunctionModels::findNullChar(S2EExecutionState *state, uint64_t stringAddr, size_t &len) {
    assert(stringAddr);

    getDebugStream(state) << "Searching for nullptr at " << hexval(stringAddr) << "\n";

    auto solver = state->solver();
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    for (len = 0; len < MAX_STRLEN; len++) {
        assert(stringAddr <= UINT64_MAX - len);
        ref<Expr> charExpr = m_memutils->read(state, stringAddr + len);
        if (!charExpr) {
            getDebugStream(state) << "Failed to read char " << len << " of string " << hexval(stringAddr) << "\n";
            return false;
        }

        ref<Expr> isNullByteExpr = E_EQ(charExpr, nullByteExpr);
        Query query(state->constraints(), isNullByteExpr);

        bool truth;
        bool res = solver->mustBeTrue(query, truth);
        if (res && truth) {
            break;
        }
    }

    if (len == MAX_STRLEN) {
        getDebugStream(state) << "Could not find nullptr char\n";
        return false;
    }

    getDebugStream(state) << "Max length " << len << "\n";

    return true;
}

///
/// \brief A helper function for functions that need to obtain the length of a string.
///
/// Obtaining the length of a string can be achieved by the following logic:
/// \code
/// if (str[0] == '\0')
///     len = 0;
/// else {
///     if (str[1] == '\0')
///         len = 1;
///     else {
///         ... {
///                 if (str[i] == '\0')
///                      len = i;
///                  else {
///                       ...
///                 }
///          ... }
///      }
/// }
/// \endcode
///
bool BaseFunctionModels::strlenHelper(S2EExecutionState *state, uint64_t stringAddr, size_t &len, ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling strlen(" << hexval(stringAddr) << ")\n";

    if (!stringAddr) {
        getDebugStream(state) << "Got nullptr input\n";
        return false;
    }

    // Calculate the string length
    if (!findNullChar(state, stringAddr, len)) {
        getDebugStream(state) << "Failed to find nullptr char in string " << hexval(stringAddr) << "\n";
        return false;
    }

    //
    // Assemble the expression
    //

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    retExpr = E_CONST(len, width);

    for (int nr = len - 1; nr >= 0; nr--) {
        ref<Expr> charExpr = m_memutils->read(state, stringAddr + nr);
        if (!charExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(stringAddr) << "\n";
            return false;
        }

        retExpr = E_ITE(E_EQ(charExpr, nullByteExpr), E_CONST(nr, width), retExpr);
    }

    return true;
}

bool BaseFunctionModels::strcmpHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling strcmp(" << hexval(strAddrs[0]) << ", " << hexval(strAddrs[1]) << ")\n";

    // Calculate the string lengths to determine the maximum
    size_t strLens[2];
    for (int i = 0; i < 2; i++) {
        if (!findNullChar(state, strAddrs[i], strLens[i])) {
            getDebugStream(state) << "Failed to find nullptr char in string " << hexval(strAddrs[i]) << "\n";
            return false;
        }
    }
    size_t memSize = std::min(strLens[0], strLens[1]) + 1;

    return strcmpHelperCommon(state, strAddrs, memSize, retExpr);
}

bool BaseFunctionModels::strncmpHelper(S2EExecutionState *state, const uint64_t strAddrs[2], size_t size,
                                       ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling strncmp(" << hexval(strAddrs[0]) << ", " << hexval(strAddrs[1]) << ", " << size
                          << ")\n";

    // Calculate the string lengths to determine the maximum
    size_t strLens[2];
    for (unsigned i = 0; i < 2; i++) {
        if (!findNullChar(state, strAddrs[i], strLens[i])) {
            getDebugStream(state) << "Failed to find nullptr char in string " << hexval(strAddrs[i]) << "\n";
            return false;
        }
    }
    size_t memSize = std::min(std::min(strLens[0], strLens[1]) + 1, size);

    return strcmpHelperCommon(state, strAddrs, memSize, retExpr);
}

///
/// \brief A helper function for functions that need to compare two strings str1 and str2
///
/// The comparison result can be calculated by examining each byte of the two strings as follows:
/// If str1[0] is lower than str2[0], then the result is -1.
/// If str1[0] is larger than str2[0], then the result is +1.
/// If str1[0] equals to str2[0], then we have to check whether str1[1] is '\0'. If yes, the result will be 0,
/// otherwise we should perform the same check on (str1[1], str2[1]), (str1[2], str2[2]), ..., (str1[memSize],
/// str2[memSize]).
///
bool BaseFunctionModels::strcmpHelperCommon(S2EExecutionState *state, const uint64_t strAddrs[2], uint64_t memSize,
                                            ref<Expr> &retExpr) {
    getDebugStream(state) << "Comparing " << memSize << " chars\n";

    if (!strAddrs[0] || !strAddrs[1]) {
        getDebugStream(state) << "Got nullptr input\n";
        return false;
    }

    if (memSize == 0) {
        retExpr = E_CONST(0, Expr::Int8);
        return true;
    }

    //
    // Assemble expression
    //

    // Return value of the C library functions is a 32-bit int.
    const Expr::Width width = Expr::Int32;
    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    assert(width == Expr::Int32 && "-1 representation becomes wrong");
    const ref<Expr> retZeroExpr = E_CONST(0, width);

    for (int nr = memSize - 1; nr >= 0; nr--) { // also compare null char
        ref<Expr> charExpr[2];
        charExpr[0] = m_memutils->read(state, strAddrs[0] + nr);
        if (!charExpr[0]) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[0]) << "\n";
            return false;
        }

        charExpr[1] = m_memutils->read(state, strAddrs[1] + nr);
        if (!charExpr[1]) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[1]) << "\n";
            return false;
        }

        ref<Expr> subRes = E_SUB(E_ZE(charExpr[0], width), E_ZE(charExpr[1], width));
        if ((unsigned) nr == memSize - 1) {
            retExpr = E_ITE(E_GT(charExpr[0], charExpr[1]), subRes, retZeroExpr);
            retExpr = E_ITE(E_LT(charExpr[0], charExpr[1]), subRes, retExpr);
        } else {
            retExpr =
                E_ITE(E_AND(E_EQ(charExpr[0], nullByteExpr), E_EQ(charExpr[1], nullByteExpr)), retZeroExpr, retExpr);
            retExpr = E_ITE(E_GT(charExpr[0], charExpr[1]), subRes, retExpr);
            retExpr = E_ITE(E_LT(charExpr[0], charExpr[1]), subRes, retExpr);
        }
    }

    return true;
}

///
/// \brief A function model for char* strcpy(char *dest, const char *src)
///
/// Function Model:
///     For each memory index, i, from 0 to strlen(src) - 1, byte located at
///     src[i] will be written to dest[i] only if there is no terminating null
///     byte before src[i]. The address of the destination string is returned.
///
///     I.e.
///     \code
///     dest[i] = (src[0] != '\0' && src[1] != '\0' && ... && src[i-1] != '\0') ? src[i] : dest[i]
///     \endcode
///     For i = 0, we just perform:
///     \code
///     dest[0] = src[0]
///     \endcode
///
bool BaseFunctionModels::strcpyHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling strcpy(" << hexval(strAddrs[0]) << ", " << hexval(strAddrs[1]) << ")\n";

    // Calculate the length of the source string
    size_t strLen;
    if (!findNullChar(state, strAddrs[1], strLen)) {
        getDebugStream(state) << "Failed to find nullptr char in string " << hexval(strAddrs[1]) << "\n";
        return false;
    }

    //
    // Perform the string copy. The address of the destination string is returned
    //

    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);
    ref<Expr> accuExpr = E_CONST(1, Expr::Bool);

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(strAddrs[0], width);

    for (unsigned nr = 0; nr < strLen; nr++) {
        ref<Expr> dstCharExpr = m_memutils->read(state, strAddrs[0] + nr);
        ref<Expr> srcCharExpr = m_memutils->read(state, strAddrs[1] + nr);
        if (!dstCharExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[0]) << "\n";
            return false;
        }
        if (!srcCharExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[1]) << "\n";
            return false;
        }

        ref<Expr> writeExpr = E_ITE(accuExpr, srcCharExpr, dstCharExpr);
        if (!state->mem()->write(strAddrs[0] + nr, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string.\n";
            return false;
        }
        accuExpr = E_AND(E_NOT(E_EQ(srcCharExpr, nullByteExpr)), accuExpr);
    }
    if (!state->mem()->write(strAddrs[0] + strLen, nullByteExpr)) {
        getDebugStream(state) << "Failed to write to terminate byte.\n";
        return false;
    }

    return true;
}

///
/// \brief A function model for char* strncpy(char *dest, const char *src, size_t n)
///
/// Function Model:
///     For each memory index i, from 0 to min(n-1, strlen(src) - 1), byte
///     located at src[i] will be written to dest[i] only if there is no
///     terminating null byte before src[i]. If strlen(src) is less than n,
///     then pad with null bytes. The address of the destination string is returned
///
///     I.e.
///     \code
///     dest[i] = (src[0] != '\0' && src[1] != '\0' && ... && src[i-1] != '\0') ? src[i] : '\0'
///     \endcode
///     For i = 0, we just perform:
///     \code
///     dest[0] = src[0]
///     \endcode
///
bool BaseFunctionModels::strncpyHelper(S2EExecutionState *state, const uint64_t strAddrs[2], uint64_t numBytes,
                                       ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling strncpy(" << hexval(strAddrs[0]) << ", " << hexval(strAddrs[1]) << ", "
                          << numBytes << ")\n";

    //
    // Perform the string copy. The address of the destination string is returned
    //

    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);
    ref<Expr> AccuExpr = E_CONST(1, Expr::Bool);

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(strAddrs[0], width);

    for (unsigned nr = 0; nr < numBytes; nr++) {
        ref<Expr> srcCharExpr = m_memutils->read(state, strAddrs[1] + nr);
        if (!srcCharExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[1]) << "\n";
            return false;
        }

        ref<Expr> writeExpr = E_ITE(AccuExpr, srcCharExpr, nullByteExpr); // null padding

        if (!state->mem()->write(strAddrs[0] + nr, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string.\n";
            return false;
        }
        AccuExpr = E_AND(E_NOT(E_EQ(srcCharExpr, nullByteExpr)), AccuExpr);
    }

    return true;
}

///
/// \brief A function model for int memcmp(const void *s1, const void *s2, size_t n);
///
/// Function Model:
///     Memcmp has similar logic to strcmp except that we don't need to check the terminating null byte.
///
bool BaseFunctionModels::memcmpHelper(S2EExecutionState *state, const uint64_t memAddrs[2], uint64_t numBytes,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling memcmp(" << hexval(memAddrs[0]) << ", " << hexval(memAddrs[1]) << ", "
                          << numBytes << ")\n";

    if (!memAddrs[0] || !memAddrs[1] || !numBytes) {
        getDebugStream(state) << "Got nullptr input\n";
        return false;
    }

    if (numBytes > MAX_STRLEN) {
        getDebugStream(state) << "memcmp input is too large\n";
        return false;
    }

    //
    // Assemble the expression
    //

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(0, width);

    for (int nr = numBytes - 1; nr >= 0; nr--) {
        ref<Expr> charExpr[2];
        for (unsigned i = 0; i < 2; i++) {
            charExpr[i] = m_memutils->read(state, memAddrs[i] + nr);
            if (!charExpr[i]) {
                getDebugStream(state) << "Failed to read byte " << nr << " of memory " << hexval(memAddrs[i]) << "\n";
                return false;
            }
        }

        retExpr = E_ITE(E_NEQ(charExpr[0], charExpr[1]), E_SUBZE(charExpr[0], charExpr[1], width), retExpr);
    }

    return true;
}

///
/// \brief A function model for void* memcpy(void *dest, const void *src, size_t n);
///
/// Function Model:
///     Memcpy has similar logic to strcpy except that we don't need to check the terminating null byte.
///
bool BaseFunctionModels::memcpyHelper(S2EExecutionState *state, const uint64_t memAddrs[2], uint64_t numBytes,
                                      ref<Expr> &retExpr) {
    getDebugStream(state) << "Handling memcpy(" << hexval(memAddrs[0]) << ", " << hexval(memAddrs[1]) << ", "
                          << numBytes << ")\n";

    //
    // Perform the memory copy. The address of the destination buffer is returned
    //

    const Expr::Width width = state->getPointerSize() * CHAR_BIT;
    retExpr = E_CONST(memAddrs[0], width);

    for (unsigned nr = 0; nr < numBytes; nr++) {
        ref<Expr> srcCharExpr = m_memutils->read(state, memAddrs[1] + nr);
        if (!srcCharExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(memAddrs[1]) << "\n";
            return false;
        }

        if (!state->mem()->write(memAddrs[0] + nr, srcCharExpr)) {
            getDebugStream(state) << "Failed to write to destination string.\n";
            return false;
        }
    }

    return true;
}

///
/// \brief A helper function for functions that need to concatenate two strings
///
///      ----------------------------------------------
/// dest | A | B | C | D | E | F | G | H | I | J |'\0'|
///      ----------------------------------------------
///
///      ----------------------------------------------
/// src  | a | b | c | d | e | f | g | h | i | j |'\0'|
///      ----------------------------------------------
///
/// As the two strings could both be symbolic, the lengths of these two strings cannot be determined.
/// Therefore the final concatenated string will could have multiple length.
/// For example, if the length of dest and src are 3 and 4 respectively:
///
///      ------------------------------------
/// dest | A | B | C |'\0'|  |  |  |  |  |  |
///      ------------------------------------
///
///      -------------------------------------
/// src  | a | b | c | d |'\0'|  |  |  |  |  |
///      -------------------------------------
///
/// The result would be:
///
///      ------------------------------------------
/// dest | A | B | C | a | b | c | d |'\0'| I | J |
///      ------------------------------------------
///
/// Therefore, when given a byte of dest string, for example, for dest[4],
/// if symlen_dest can exceed 4, then we just keep dest[4] unmodified.
/// otherwise it should be overwritten by src[position] (or '\0' when using 'strncat'),
/// which can be illustrated as follows (note that symlen refers to the symbolic length
/// and conlen refers to the concrete length):
///
/// \code
///     if (symlen_dest + 0 == 4) {
///        if (symlen_src == 0), then: dest[4] = '\0';
///        if (symlen_src > 0),  then: dest[4] = dest[4]; // dest[4] == '\0'
///        return;
///     }
///     if (symlen_dest + 1 == 4) {
///        if (symlen_src == 1), then: dest[4] = '\0';
///        if (symlen_src > 1),  then: dest[4] = dest[4];
///        if (symlen_src < 1),  then: dest[4] = src[1];
///        return;
///     }
///     .
///     .
///     .
///     if (symlen_dest + 4 == 4) {
///        if (symlen_src == 4), then: dest[4] = '\0';
///        if (symlen_src > 4),  then: dest[4] = dest[4];
///        if (symlen_src < 4),  then: dest[4] = src[4];
///        return;
///     }
/// \endcode
///
/// This can be formulated as:
///
/// \code
/// for nr in range[0, conlen_dest + conlen_src)
///    for i in range[0, nr]
///      if (nr - i == symlen_dest), then
///          if   (symlen_src == i), then: dst[nr] = '\0';
///          elif (symlen_src < i),  then: dst[nr] = dst[nr];
///          else (symlen_src > i),  then: dst[nr] = Ncat; // Ncat = (srclen > numBytes) ? src[i] : null; or Ncat =
///          srcCharExpr;
///          fi
///      fi
///     done
/// done
/// \endcode
///
bool BaseFunctionModels::strcatHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr,
                                      uint64_t numBytes, bool isNcat) {
    getDebugStream(state) << "Handling str" << (isNcat ? "n" : "") << "cat(" << hexval(strAddrs[0]) << ", "
                          << hexval(strAddrs[1]);
    if (isNcat) {
        getDebugStream(state) << ", " << numBytes << ")\n";
    } else {
        getDebugStream(state) << ")\n";
    }

    size_t srcStrLen, destStrLen;
    ref<Expr> srcExprLen, dstExprLen;

    if (!strlenHelper(state, strAddrs[0], destStrLen, dstExprLen) ||
        !strlenHelper(state, strAddrs[1], srcStrLen, srcExprLen)) {
        return false;
    }

    const ref<Expr> nullByteExpr = E_CONST('\0', Expr::Int8);

    const Expr::Width width = dstExprLen.get()->getWidth();
    retExpr = E_CONST(strAddrs[0], width);

    if (isNcat) {
        assert(numBytes && "Strncat of size 0 should be go through the original strncat in libc!");
    }

    int extra_cat = isNcat ? (int) numBytes : srcStrLen;

    // FIXME: O(n2)
    for (int nr = destStrLen + extra_cat; nr >= 0; nr--) {
        ref<Expr> dstCharExpr = m_memutils->read(state, strAddrs[0] + nr);
        if (!dstCharExpr) {
            getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[0]) << "\n";
            return false;
        }

        ref<Expr> firstOrderCond = E_GT(dstExprLen, E_CONST(nr, width));
        ref<Expr> writeExpr, subWrite = nullByteExpr;

        for (int i = 0; i <= nr; i++) { // construct subWrite expression
            ref<Expr> dstlenConds = E_EQ(dstExprLen, E_CONST(nr - i, width));
            ref<Expr> srclenConds_eq = E_EQ(srcExprLen, E_CONST(i, width));
            ref<Expr> srclenConds_lower = E_LT(srcExprLen, E_CONST(i, width));

            ref<Expr> srcCharExpr = m_memutils->read(state, strAddrs[1] + i);
            if (!srcCharExpr) {
                getDebugStream(state) << "Failed to read char " << nr << " of string " << hexval(strAddrs[1]) << "\n";
                return false;
            }

            ref<Expr> NCat = isNcat ? E_ITE(E_LT(srcExprLen, E_CONST((int) numBytes, width)), nullByteExpr, srcCharExpr)
                                    : srcCharExpr;
            ref<Expr> SecondOrder = E_ITE(srclenConds_eq, nullByteExpr, E_ITE(srclenConds_lower, dstCharExpr, NCat));

            subWrite = E_ITE(dstlenConds, SecondOrder, subWrite);
        }
        writeExpr = E_ITE(firstOrderCond, dstCharExpr, subWrite);

        if (!state->mem()->write(strAddrs[0] + nr, writeExpr)) {
            getDebugStream(state) << "Failed to write to destination string.\n";
            return false;
        }
    }

    if (!state->mem()->write(strAddrs[0] + destStrLen + extra_cat, nullByteExpr)) {
        getDebugStream(state) << "Failed to write to terminate byte.\n";
        return false;
    }

    return true;
}

} // namespace models
} // namespace plugins
} // namespace s2e
