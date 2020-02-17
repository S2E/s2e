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

#ifndef S2E_PLUGINS_BASE_FUNCTION_MODELS_H
#define S2E_PLUGINS_BASE_FUNCTION_MODELS_H

#include <klee/Expr.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>

using namespace klee;

namespace s2e {

class S2E;
class S2EExecutionState;

namespace plugins {
namespace models {

///
/// \brief Abstract base class for modelling functions that commonly result in
/// state explosion
///
class BaseFunctionModels : public Plugin {
public:
    BaseFunctionModels(S2E *s2e) : Plugin(s2e) {
        initCRCModels();
    }

    virtual ~BaseFunctionModels() {
    }

private:
    void initCRCModels();

protected:
    MemUtils *m_memutils;

    klee::UpdateListPtr m_crc16_ul;
    klee::UpdateListPtr m_crc32_ul;

    ref<Expr> crc32(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input, bool xorResult);
    ref<Expr> crc16(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input);

    bool readArgument(S2EExecutionState *state, unsigned param, uint64_t &arg);
    bool findNullChar(S2EExecutionState *state, uint64_t stringAddr, size_t &len);

    bool strlenHelper(S2EExecutionState *state, uint64_t stringAddr, size_t &len, ref<Expr> &retExpr);
    bool strcmpHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr);
    bool strncmpHelper(S2EExecutionState *state, const uint64_t strAddrs[2], size_t size, ref<Expr> &retExpr);
    bool strcmpHelperCommon(S2EExecutionState *state, const uint64_t strAddrs[2], uint64_t memSize, ref<Expr> &retExpr);
    bool strcpyHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr);
    bool strncpyHelper(S2EExecutionState *state, const uint64_t strAddrs[2], uint64_t numBytes, ref<Expr> &retExpr);
    bool memcmpHelper(S2EExecutionState *state, const uint64_t memAddrs[2], uint64_t numBytes, ref<Expr> &retExpr);
    bool memcpyHelper(S2EExecutionState *state, const uint64_t memAddrs[2], uint64_t numBytes, ref<Expr> &retExpr);
    bool strcatHelper(S2EExecutionState *state, const uint64_t strAddrs[2], ref<Expr> &retExpr, uint64_t numBytes = 0,
                      bool isNcat = false);
};

} // namespace models
} // namespace plugins
} // namespace s2e

#endif
