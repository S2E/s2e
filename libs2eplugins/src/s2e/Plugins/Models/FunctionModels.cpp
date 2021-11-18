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

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <algorithm>

#include "FunctionModels.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

S2E_DEFINE_PLUGIN(FunctionModels, "Plugin that implements models for libraries", "", "MemUtils");

void FunctionModels::initialize() {
    m_memutils = s2e()->getPlugin<MemUtils>();
}

void FunctionModels::handleStrlen(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddr = (uint64_t) cmd.Strlen.str;

    // Assemble the string length expression
    size_t len;
    if (strlenHelper(state, stringAddr, len, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrcmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcmp.str1;
    stringAddrs[1] = (uint64_t) cmd.Strcmp.str2;

    // Assemble the string compare expression
    if (strcmpHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrncmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncmp.str1;
    stringAddrs[1] = (uint64_t) cmd.Strncmp.str2;
    size_t nSize = cmd.Strncmp.n;

    // Assemble the string compare expression
    if (strncmpHelper(state, stringAddrs, nSize, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrcpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcpy.dst;
    stringAddrs[1] = (uint64_t) cmd.Strcpy.src;

    // Perform the string copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (strcpyHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrncpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncpy.dst;
    stringAddrs[1] = (uint64_t) cmd.Strncpy.src;
    uint64_t numBytes = cmd.Strncpy.n;

    // Perform the string copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (strncpyHelper(state, stringAddrs, numBytes, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleMemcpy(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t memAddrs[2];
    memAddrs[0] = (uint64_t) cmd.Memcpy.dst;
    memAddrs[1] = (uint64_t) cmd.Memcpy.src;
    uint64_t numBytes = (int) cmd.Memcpy.n;

    // Perform the memory copy. We don't use the return expression here because it is just a concrete address
    ref<Expr> retExpr;
    if (memcpyHelper(state, memAddrs, numBytes, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleMemcmp(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &retExpr) {
    // Read function arguments
    uint64_t memAddrs[2];
    memAddrs[0] = (uint64_t) cmd.Memcmp.str1;
    memAddrs[1] = (uint64_t) cmd.Memcmp.str2;
    uint64_t numBytes = (int) cmd.Memcmp.n;

    // Assemble the memory compare expression
    if (memcmpHelper(state, memAddrs, numBytes, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrcat(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strcat.dst;
    stringAddrs[1] = (uint64_t) cmd.Strcat.src;

    // Assemble the string concatenation expression. We don't use the return expression here because it is just a
    // concrete address
    ref<Expr> retExpr;
    if (strcatHelper(state, stringAddrs, retExpr)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleStrncat(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd) {
    // Read function arguments
    uint64_t stringAddrs[2];
    stringAddrs[0] = (uint64_t) cmd.Strncat.dst;
    stringAddrs[1] = (uint64_t) cmd.Strncat.src;
    uint64_t numBytes = (int) cmd.Strncat.n;

    // Assemble the string concatenation expression. We don't use the return expression here because it is just a
    // concrete address
    ref<Expr> retExpr;
    if (strcatHelper(state, stringAddrs, retExpr, true, numBytes)) {
        cmd.needOrigFunc = 0;
    } else {
        cmd.needOrigFunc = 1;
    }
}

void FunctionModels::handleCrc(S2EExecutionState *state, S2E_LIBCWRAPPER_COMMAND &cmd, ref<Expr> &ret) {

    std::vector<ref<Expr>> buffer;
    cmd.needOrigFunc = 1;
    if (!m_memutils->read(state, buffer, cmd.Crc.buffer, cmd.Crc.size)) {
        return;
    }

    ref<Expr> initialCrc;

    switch (cmd.Crc.type) {
        case S2E_WRAPPER_CRC16:
            initialCrc = state->mem()->read(cmd.Crc.initial_value_ptr, Expr::Int16);
            getDebugStream(state) << "Handling crc16(" << initialCrc << ", " << hexval(cmd.Crc.buffer) << ", "
                                  << cmd.Crc.size << ")\n";
            if (!initialCrc) {
                return;
            }

            ret = crc16(initialCrc, buffer);
            break;

        case S2E_WRAPPER_CRC32:
            initialCrc = state->mem()->read(cmd.Crc.initial_value_ptr, Expr::Int32);
            getDebugStream(state) << "Handling crc32(" << initialCrc << ", " << hexval(cmd.Crc.buffer) << ", "
                                  << cmd.Crc.size << ")\n";
            if (!initialCrc) {
                return;
            }

            ret = crc32(initialCrc, buffer, cmd.Crc.xor_result);
            break;

        default:
            s2e()->getWarningsStream(state) << "Invalid crc type " << hexval(cmd.Crc.type) << "\n";
            return;
    }

    cmd.needOrigFunc = 0;
}

// TODO: use template
#define UPDATE_RET_VAL(CmdType, cmd)                                         \
    do {                                                                     \
        uint32_t offRet = offsetof(S2E_LIBCWRAPPER_COMMAND, CmdType.ret);    \
                                                                             \
        if (!state->mem()->write(guestDataPtr, &cmd, sizeof(cmd))) {         \
            getWarningsStream(state) << "Could not write to guest memory\n"; \
        }                                                                    \
                                                                             \
        if (!state->mem()->write(guestDataPtr + offRet, retExpr)) {          \
            getWarningsStream(state) << "Could not write to guest memory\n"; \
        }                                                                    \
    } while (0)

void FunctionModels::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_LIBCWRAPPER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "S2E_LIBCWRAPPER_COMMAND: "
                                 << "mismatched command structure size " << guestDataSize << "\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "S2E_LIBCWRAPPER_COMMAND: could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case LIBCWRAPPER_STRCPY: {
            handleStrcpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case LIBCWRAPPER_STRNCPY: {
            handleStrncpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case LIBCWRAPPER_STRLEN: {
            ref<Expr> retExpr;
            handleStrlen(state, command, retExpr);
            UPDATE_RET_VAL(Strlen, command);
        } break;

        case LIBCWRAPPER_STRCMP: {
            ref<Expr> retExpr;
            handleStrcmp(state, command, retExpr);
            UPDATE_RET_VAL(Strcmp, command);
        } break;

        case LIBCWRAPPER_STRNCMP: {
            ref<Expr> retExpr;
            handleStrncmp(state, command, retExpr);
            UPDATE_RET_VAL(Strncmp, command);
        } break;

        case LIBCWRAPPER_MEMCPY: {
            handleMemcpy(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case LIBCWRAPPER_MEMCMP: {
            ref<Expr> retExpr;
            handleMemcmp(state, command, retExpr);
            UPDATE_RET_VAL(Memcmp, command);
        } break;

        case LIBCWRAPPER_STRCAT: {
            handleStrcat(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case LIBCWRAPPER_STRNCAT: {
            handleStrncat(state, command);
            if (!state->mem()->write(guestDataPtr, &command, sizeof(command))) {
                getWarningsStream(state) << "Could not write to guest memory\n";
            }
        } break;

        case WRAPPER_CRC: {
            ref<Expr> retExpr;
            handleCrc(state, command, retExpr);
            UPDATE_RET_VAL(Crc, command);
        } break;

        default: {
            getWarningsStream(state) << "Invalid command " << hexval(command.Command) << "\n";
            exit(-1);
        }
    }
}

} // namespace models
} // namespace plugins
} // namespace s2e
