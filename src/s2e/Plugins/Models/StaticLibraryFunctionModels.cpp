///
/// Copyright (C) 2015-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/cpu.h>

#include <klee/util/ExprTemplates.h>
#include <llvm/Support/CommandLine.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <algorithm>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

#include "StaticLibraryFunctionModels.h"

using namespace klee;

namespace s2e {
namespace plugins {
namespace models {

S2E_DEFINE_PLUGIN(StaticLibraryFunctionModels, "Plugin that implements models for statically-linked libraries", "",
                  "ModuleExecutionDetector");

ref<Expr> StaticLibraryFunctionModels::readMemory8(S2EExecutionState *state, uint64_t address) {
    return m_detector->readMemory8(state, address);
}

/*
 * Sample s2e-config.lua to use this plugin:
 *
 * pluginsConfig.StaticLibraryFunctionModels = {
 *   modules = {}
 * }
 *
 * g_function_models = {}
 *
 * g_function_models["TNETS_00002_patched"] = {}
 * g_function_models["TNETS_00002_patched"][0x8049b20] = {
 *   type="strlen",
 *   accepts_null_input = true,
 * }
 *
 * pluginsConfig.StaticLibraryFunctionModels.modules = g_function_models
*/
void StaticLibraryFunctionModels::initialize() {
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    m_detector->onModuleTranslateBlockEnd.connect(
        sigc::mem_fun(*this, &StaticLibraryFunctionModels::onModuleTranslateBlockEnd));

    m_handlers["strlen"] = &StaticLibraryFunctionModels::handleStrlen;
    m_handlers["strcmp"] = &StaticLibraryFunctionModels::handleStrcmp;
    m_handlers["strncmp"] = &StaticLibraryFunctionModels::handleStrncmp;
    m_handlers["memcmp"] = &StaticLibraryFunctionModels::handleMemcmp;

    getInfoStream() << "Model count: " << getFunctionModelCount() << "\n";
}

unsigned StaticLibraryFunctionModels::getFunctionModelCount() const {
    ConfigFile *cfg = s2e()->getConfig();

    return cfg->getInt(getConfigKey() + ".count");
}

bool StaticLibraryFunctionModels::getBool(S2EExecutionState *state, const std::string &property) {
    std::stringstream ss;
    const ModuleDescriptor *module = m_detector->getModule(state, state->getPc());
    assert(module);

    ss << getConfigKey() << ".modules[\"" << module->Name << "\"][" << hexval(state->getPc()) << "]." << property;

    return s2e()->getConfig()->getBool(ss.str());
}

void StaticLibraryFunctionModels::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                            const ModuleDescriptor &module, TranslationBlock *tb,
                                                            uint64_t endPc, bool staticTarget, uint64_t targetPc) {
    // Only instrument direct calls
    if (!staticTarget || tb->se_tb_type != TB_CALL) {
        return;
    }

    // Check if we call a known string function
    uint64_t pc = module.ToNativeBase(targetPc);

    std::stringstream ss;
    ss << getConfigKey() << ".modules[\"" << module.Name << "\"]"
       << "[" << hexval(pc) << "]";

    ConfigFile *cfg = s2e()->getConfig();
    bool origSilent = cfg->isSilent();
    cfg->setSilent(true);

    bool ok;
    std::string type = cfg->getString(ss.str() + ".type", "", &ok);
    if (!ok) {
        return;
    }

    getDebugStream(state) << "Found function type " << type << "\n";
    HandlerMap::const_iterator it = m_handlers.find(type);
    if (it == m_handlers.end()) {
        return;
    }

    getDebugStream(state) << "Found handler for function type " << type << "\n";
    signal->connect(sigc::bind(sigc::mem_fun(*this, &StaticLibraryFunctionModels::onCall), (*it).second));

    cfg->setSilent(origSilent);
}

void StaticLibraryFunctionModels::onCall(S2EExecutionState *state, uint64_t pc,
                                         StaticLibraryFunctionModels::OpHandler handler) {
    state->undoCallAndJumpToSymbolic();

    bool handled = ((*this).*handler)(state, pc);
    if (handled) {
        state->bypassFunction(0);
    } else {
        getDebugStream(state) << "Handling function at PC " << hexval(pc) << " failed, falling back to original code\n";
    }
}

bool StaticLibraryFunctionModels::handleStrlen(S2EExecutionState *state, uint64_t pc) {
    // Read function arguments
    uint64_t stringAddr;
    if (!readArgument(state, 0, stringAddr)) {
        getDebugStream(state) << "Failed to read stringAddr argument\n";
        return false;
    }

    // Assemble the string length expression
    size_t len;
    ref<Expr> retExpr;
    if (strlenHelper(state, stringAddr, len, retExpr)) {
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticLibraryFunctionModels::handleStrcmp(S2EExecutionState *state, uint64_t pc) {
    // Read function arguments
    uint64_t stringAddrs[2];
    for (int i = 0; i < 2; i++) {
        if (!readArgument(state, i, stringAddrs[i])) {
            getDebugStream(state) << "Failed to read stringAddr argument\n";
            return false;
        }
    }

    // Assemble the string compare expression
    ref<Expr> retExpr;
    if (strcmpHelper(state, stringAddrs, retExpr)) {
        // Invert the result if required
        if (getBool(state, "inverted")) {
            getDebugStream(state) << "strcmp returns inverted result\n";
            retExpr = E_SUB(E_CONST(0, state->getPointerSize() * CHAR_BIT), retExpr);
        }

        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticLibraryFunctionModels::handleStrncmp(S2EExecutionState *state, uint64_t pc) {
    // Read function arguments
    uint64_t stringAddrs[2];
    for (int i = 0; i < 2; i++) {
        if (!readArgument(state, i, stringAddrs[i])) {
            getDebugStream(state) << "Failed to read stringAddr argument\n";
            return false;
        }
    }

    uint64_t maxSize;
    if (!readArgument(state, 2, maxSize)) {
        getDebugStream(state) << "Failed to read maxSize argument\n";
        return false;
    }

    // Assemble the string compare expression
    ref<Expr> retExpr;
    if (strncmpHelper(state, stringAddrs, maxSize, retExpr)) {
        // Invert the result if required
        if (getBool(state, "inverted")) {
            getDebugStream(state) << "strncmp returns inverted result\n";
            retExpr = E_SUB(E_CONST(0, state->getPointerSize() * CHAR_BIT), retExpr);
        }

        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

bool StaticLibraryFunctionModels::handleMemcmp(S2EExecutionState *state, uint64_t pc) {
    // Read function arguments
    uint64_t memAddrs[2];
    uint64_t memSize;

    for (int i = 0; i < 2; i++) {
        if (!readArgument(state, i, memAddrs[i])) {
            getDebugStream(state) << "Failed to read memory address argument\n";
            return false;
        }
    }

    if (!readArgument(state, 2, memSize)) {
        getDebugStream(state) << "Failed to read memSize argument\n";
        return false;
    }

    // Assemble the memory compare expression
    ref<Expr> retExpr;
    if (memcmpHelper(state, memAddrs, memSize, retExpr)) {
        state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), retExpr);

        return true;
    } else {
        return false;
    }
}

} // namespace models
} // namespace plugins
} // namespace s2e
