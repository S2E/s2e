///
/// Copyright (C) 2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

#include "LuaInstructionInstrumentation.h"
#include "LuaInstructionInstrumentationState.h"
#include "LuaS2EExecutionState.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(LuaInstructionInstrumentation, "Execute Lua code on an instruction", "LuaInstructionInstrumentation",
                  "LuaBindings", "ProcessExecutionDetector", "ModuleMap");

// XXX: don't duplicate with LuaFunctionInstrumentation, move to ConfigFile?
static std::string readStringOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    std::string ret = cfg->getString(key, "", &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionInstrumentation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

static uint64_t readIntOrFail(S2E *s2e, const std::string &key) {
    bool ok;
    ConfigFile *cfg = s2e->getConfig();
    uint64_t ret = cfg->getInt(key, 0, &ok);

    if (!ok) {
        s2e->getWarningsStream() << "LuaFunctionInstrumentation: " << key << " is missing\n";
        exit(-1);
    }

    return ret;
}

// TODO: share some code with LuaFunctionInstrumentation
void LuaInstructionInstrumentation::initialize() {
    m_detector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_modules = s2e()->getPlugin<ModuleMap>();

    bool ok;
    ConfigFile *cfg = s2e()->getConfig();
    ConfigFile::string_list keys = cfg->getListKeys(getConfigKey() + ".instrumentation", &ok);
    if (!ok) {
        getWarningsStream() << "must have an .instrumentation section\n";
        exit(-1);
    }

    for (auto const &key : keys) {
        std::stringstream ss;
        ss << getConfigKey() << ".instrumentation." << key;

        std::string moduleId = readStringOrFail(s2e(), ss.str() + ".module_name");
        std::string instrumentationName = readStringOrFail(s2e(), ss.str() + ".name");
        uint64_t pc = readIntOrFail(s2e(), ss.str() + ".pc");

        if (!registerInstrumentation(moduleId, Instrumentation(instrumentationName, pc))) {
            exit(-1);
        }
    }

    m_detector->onMonitorLoad.connect(sigc::mem_fun(*this, &LuaInstructionInstrumentation::onMonitorLoad));
}

bool LuaInstructionInstrumentation::registerInstrumentation(const std::string &moduleId,
                                                            const Instrumentation &instrumentation) {
    if (m_instrumentation[moduleId] == nullptr) {
        m_instrumentation[moduleId] = new Moduleinstrumentation();
    }

    if (m_instrumentation[moduleId]->find(instrumentation) != m_instrumentation[moduleId]->end()) {
        getWarningsStream() << "attempting to register existing instrumentation\n";
        return false;
    }

    m_instrumentation[moduleId]->insert(instrumentation);

    getDebugStream() << "loaded " << moduleId << " " << instrumentation.instrumentationName << " "
                     << hexval(instrumentation.pc) << "\n";

    return true;
}

void LuaInstructionInstrumentation::onMonitorLoad(S2EExecutionState *state) {
    s2e()->getCorePlugin()->onTranslateBlockStart.connect(
        sigc::mem_fun(*this, &LuaInstructionInstrumentation::onTranslateBlockStart));

    s2e()->getCorePlugin()->onTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &LuaInstructionInstrumentation::onTranslateBlockComplete));
}

// XXX: what if TB is interrupt in the middle?
void LuaInstructionInstrumentation::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                          TranslationBlock *tb, uint64_t pc) {
    // TODO: decide here whether there might be an instruction
    // that can be hooked (probably will need the use of the static CFG)
    CorePlugin *plg = s2e()->getCorePlugin();
    m_instructionStart.disconnect();

    auto module = m_modules->getModule(state, pc);
    if (!module) {
        return;
    }

    auto it = m_instrumentation.find(module->Name);
    if (it == m_instrumentation.end()) {
        return;
    }

    uint64_t addend;
    if (!module->ToNativeBase(pc, addend)) {
        getWarningsStream(state) << "Could not convert pc to native base\n";
        return;
    }

    m_instructionStart = plg->onTranslateInstructionStart.connect(sigc::bind(
        sigc::mem_fun(*this, &LuaInstructionInstrumentation::onTranslateInstructionStart), it->second, addend));
}

void LuaInstructionInstrumentation::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                                TranslationBlock *tb, uint64_t pc,
                                                                const Moduleinstrumentation *instrumentation,
                                                                uint64_t addend) {
    uint64_t offset = pc - tb->pc;
    uint64_t modulePc = offset + addend;
    Instrumentation tofind(modulePc);

    if (instrumentation->find(tofind) == instrumentation->end()) {
        return;
    }

    signal->connect(
        sigc::bind(sigc::mem_fun(*this, &LuaInstructionInstrumentation::onInstruction), instrumentation, modulePc));
}

void LuaInstructionInstrumentation::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb,
                                                             uint64_t ending_pc) {
    m_instructionStart.disconnect();
}

void LuaInstructionInstrumentation::onInstruction(S2EExecutionState *state, uint64_t pc,
                                                  const Moduleinstrumentation *instrumentation, uint64_t modulePc) {
    if (!m_detector->isTracked(state)) {
        return;
    }

    Instrumentation tofind(modulePc);
    Moduleinstrumentation::const_iterator it = instrumentation->find(tofind);
    if (it == instrumentation->end()) {
        return;
    }

    getDebugStream(state) << "instruction " << hexval(modulePc) << " triggered instrumentation "
                          << it->instrumentationName << "\n";

    lua_State *L = s2e()->getConfig()->getState();

    LuaS2EExecutionState luaS2EState(state);
    LuaInstructionInstrumentationState luaInstrumentation;

    lua_getglobal(L, it->instrumentationName.c_str());
    Lunar<LuaS2EExecutionState>::push(L, &luaS2EState);
    Lunar<LuaInstructionInstrumentationState>::push(L, &luaInstrumentation);

    lua_call(L, 2, 0);

    if (luaInstrumentation.exitCpuLoop()) {
        throw CpuExitException();
    }

    if (luaInstrumentation.doSkip()) {
        TranslationBlock *tb = state->getTb();

        getDebugStream(state) << "Instrumentation " << it->instrumentationName << " asked to skip instruction at "
                              << hexval(it->pc) << '\n';

        uint64_t next_pc = pc + tb_get_instruction_size(tb, pc);

        assert(next_pc != pc);

        getDebugStream(state) << "PC of next instruction: " << hexval(next_pc) << '\n';

        state->regs()->setPc(next_pc);
        throw CpuExitException();
    }
}

} // namespace plugins
} // namespace s2e
