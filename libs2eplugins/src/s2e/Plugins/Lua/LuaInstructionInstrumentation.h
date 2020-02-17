///
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

#ifndef S2E_PLUGINS_LuaInstructionInstrumentation_H
#define S2E_PLUGINS_LuaInstructionInstrumentation_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>

namespace s2e {

class S2EExecutionState;

namespace plugins {

class ModuleMap;
class ProcessExecutionDetector;

class LuaInstructionInstrumentation : public Plugin {
    S2E_PLUGIN

public:
    LuaInstructionInstrumentation(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    struct Instrumentation {
        const std::string instrumentationName;
        const uint64_t pc;

        Instrumentation(std::string name, uint64_t pc_) : instrumentationName(name), pc(pc_) {
        }

        Instrumentation(uint64_t pc_) : Instrumentation("", pc_) {
        }

        bool operator==(const Instrumentation &a1) const {
            return pc == a1.pc && instrumentationName == a1.instrumentationName;
        }

        bool operator<(const Instrumentation &a1) const {
            return pc < a1.pc;
        }
    };

    typedef std::set<Instrumentation> Moduleinstrumentation;
    typedef std::map<std::string, Moduleinstrumentation *> InstrumentationMap;
    InstrumentationMap m_instrumentation;

    ProcessExecutionDetector *m_detector;
    ModuleMap *m_modules;
    sigc::connection m_instructionStart;

    bool registerInstrumentation(const std::string &moduleId, const Instrumentation &instrumentation);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc, const Moduleinstrumentation *instrumentation, uint64_t addend);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t ending_pc);

    void onInstruction(S2EExecutionState *state, uint64_t pc, const Moduleinstrumentation *instrumentation,
                       uint64_t modulePc);

    void onMonitorLoad(S2EExecutionState *state);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_LuaInstructionInstrumentation_H
