///
/// Copyright (C) 2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BASE_FUNCTION_MODELS_H
#define S2E_PLUGINS_BASE_FUNCTION_MODELS_H

#include <klee/Expr.h>
#include <s2e/Plugin.h>

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
    klee::UpdateList *m_crc16_ul;
    klee::UpdateList *m_crc32_ul;

    ref<Expr> crc32(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input, bool xorResult);
    ref<Expr> crc16(const ref<Expr> &initialCrc, const std::vector<ref<Expr>> &input);

    bool readMemory(S2EExecutionState *state, std::vector<ref<Expr>> &output, uint64_t address, unsigned length);
    virtual klee::ref<klee::Expr> readMemory8(S2EExecutionState *state, uint64_t addr) = 0;

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
