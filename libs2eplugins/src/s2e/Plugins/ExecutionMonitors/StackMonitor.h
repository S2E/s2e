///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_PLUGINS_STACKMONITOR_H
#define S2E_PLUGINS_STACKMONITOR_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {

struct ThreadDescriptor;

namespace plugins {

class OSMonitor;

struct StackFrameInfo {
    uint64_t StackBound;
    uint64_t FrameTop;
    uint64_t FrameSize;

    /**
     * Program counter that opened the frame.
     * This is usually the return address.
     */
    uint64_t FramePc;

    /**
     * Function to which this frame belongs.
     * Points to the first instruction of the function.
     */
    uint64_t FrameFunction;
};

class StackMonitorState;

class StackMonitor : public Plugin {
    S2E_PLUGIN
public:
    typedef std::vector<StackFrameInfo> CallStack;
    typedef std::vector<CallStack> CallStacks;

    friend class StackMonitorState;
    StackMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    void registerNoframeFunction(S2EExecutionState *state, uint64_t pid, uint64_t callAddr);

    bool getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack, StackFrameInfo &info) const;
    bool getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid, CallStack &callStack) const;
    bool getCallStacks(S2EExecutionState *state, CallStacks &callStacks) const;

    void dump(S2EExecutionState *state);

    void update(S2EExecutionState *state, uint64_t sp, uint64_t pc, bool createNewFrame);

    /**
     * Emitted when a new stack frame is setup (e.g., when execution enters a module of interest).
     */
    sigc::signal<void, S2EExecutionState *> onStackCreation;

    /**
     * Emitted when there are no more stack frames anymore.
     */
    sigc::signal<void, S2EExecutionState *> onStackDeletion;

    /**
     * Emitted when stack is modified.
     */
    sigc::signal<void, S2EExecutionState *, uint64_t /* newBottom */, uint64_t /* newTop */> onStackFrameCreate;
    sigc::signal<void, S2EExecutionState *, uint64_t /* oldBottom */, uint64_t /* newBottom */, uint64_t /* top */>
        onStackFrameGrow;
    sigc::signal<void, S2EExecutionState *, uint64_t /* oldBottom */, uint64_t /* newBottom */, uint64_t /* top */>
        onStackFrameShrink;
    sigc::signal<void, S2EExecutionState *, uint64_t /* oldBottom */, uint64_t /* oldTop */, uint64_t /* newBottom */,
                 uint64_t /* newTop */>
        onStackFrameDelete;

private:
    OSMonitor *m_monitor;
    ProcessExecutionDetector *m_processDetector;

    typedef enum { DEBUGLEVEL_PRINT_MESSAGES = 1, DEBUGLEVEL_DUMP_STACK = 2 } DebugLevel;
    DebugLevel m_debugLevel;

    sigc::connection m_onTranslateRegisterAccessConnection;

    void onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread);
    void onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode);

    void onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);

    void onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc);

    void onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                                   uint64_t rmask, uint64_t wmask, bool accessesMemory);

    void onStackPointerModification(S2EExecutionState *state, uint64_t pc, bool isCall, uint64_t callEip);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_STACKMONITOR_H
