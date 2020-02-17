///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>

#include <iostream>

#include "StackMonitor.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(StackMonitor, "Tracks stack usage by modules", "StackMonitor", "OSMonitor",
                  "ProcessExecutionDetector");

class StackMonitorState : public PluginState {
public:
    struct StackFrame {
        uint64_t pc; // Program counter that opened the frame
        uint64_t top;
        uint64_t size;

        bool operator<(const StackFrame &f1) {
            return top + size <= f1.size;
        }

        friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const StackFrame &frame);
    };

    // The frames are sorted by decreasing stack pointer
    typedef std::vector<StackFrame> StackFrames;

    class Stack {
        uint64_t m_stackBound;
        StackFrames m_frames;

    public:
        Stack(StackMonitorState *plgState, S2EExecutionState *state, uint64_t stackBound, uint64_t sp, uint64_t pc) {

            m_stackBound = stackBound;

            StackFrame frame;
            frame.pc = pc;
            frame.top = stackBound;
            frame.size = stackBound - sp + state->getPointerSize();
            m_frames.push_back(frame);

            plgState->m_stackMonitor->onStackFrameCreate.emit(state, frame.top - frame.size, frame.top);
        }

        uint64_t getStackBound() const {
            return m_stackBound;
        }

        /** Used for call instructions */
        void newFrame(StackMonitorState *plgState, S2EExecutionState *state, uint64_t pc, uint64_t stackPointer,
                      unsigned initialFrameSize) {
            if (m_frames.size() > 0) {
                const StackFrame &last = m_frames.back();
                s2e_assert(state, stackPointer < last.top + last.size,
                           "New frame " << hexval(stackPointer) << "is not below the last one "
                                        << hexval(last.top + last.size));
            }

            StackFrame frame;
            frame.pc = pc;
            frame.top = stackPointer;
            frame.size = initialFrameSize;
            m_frames.push_back(frame);

            plgState->m_stackMonitor->onStackFrameCreate.emit(state, frame.top - frame.size, frame.top);
        }

        void update(StackMonitorState *plgState, S2EExecutionState *state, uint64_t pc, uint64_t stackPointer) {
            s2e_assert(state, !m_frames.empty(), "No frames to update");

            if (stackPointer >= m_stackBound) {
                // This may happen if SP becomes symbolic, let the binary crash itself
                // Current stack will be unwinded and deleted
                plgState->m_stackMonitor->getWarningsStream(state)
                    << "Stack pointer " << hexval(stackPointer) << " goes above stack bound " << hexval(m_stackBound)
                    << "\n";
                m_stackBound = stackPointer;
            }

            StackFrame *last = &m_frames.back();

            // Unwind stack frames
            while (stackPointer > last->top) {
                uint64_t oldBottom = last->top - last->size;
                uint64_t oldTop = last->top;

                last = nullptr;
                m_frames.pop_back();

                if (m_frames.empty()) {
                    plgState->m_stackMonitor->onStackFrameDelete.emit(state, oldBottom, oldTop, 0, 0);
                    return; // Stack is empty
                }

                last = &m_frames.back();
                plgState->m_stackMonitor->onStackFrameDelete.emit(state, oldBottom, oldTop, last->top - last->size,
                                                                  last->top);
            }

            // Resize current stack frame
            uint64_t oldSize = last->size;
            uint64_t newSize = last->top - stackPointer + state->getPointerSize();
            if (oldSize != newSize) {
                last->size = newSize;

                if (newSize > oldSize)
                    plgState->m_stackMonitor->onStackFrameGrow.emit(state, last->top - oldSize, last->top - newSize,
                                                                    last->top);
                else
                    plgState->m_stackMonitor->onStackFrameShrink.emit(state, last->top - oldSize, last->top - newSize,
                                                                      last->top);
            }
        }

        bool empty() const {
            return m_frames.empty();
        }

        bool getFrame(uint64_t sp, bool &frameValid, StackFrame &frameInfo) const {
            if (sp >= m_stackBound) {
                return false;
            }

            frameValid = false;

            // Look for the right frame
            // XXX: Use binary search?
            foreach2 (it, m_frames.begin(), m_frames.end()) {
                const StackFrame &frame = *it;
                if (sp > frame.top || (sp < frame.top - frame.size)) {
                    continue;
                }

                frameValid = true;
                frameInfo = frame;
                break;
            }

            return true;
        }

        void getCallStack(StackMonitor::CallStack &cs) const {
            foreach2 (it, m_frames.begin(), m_frames.end()) {
                StackFrameInfo info;

                info.FramePc = (*it).pc;
                info.FrameSize = (*it).size;
                info.FrameTop = (*it).top;
                info.StackBound = getStackBound();

                cs.push_back(info);
            }
        }

        friend llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const Stack &stack);
    };

private:
    // Maps Pid and Tid to a stack representation
    typedef std::pair<uint64_t, uint64_t> PidTid;
    typedef std::map<PidTid, Stack> Stacks;

    StackMonitor::DebugLevel m_debugLevel;
    OSMonitor *m_monitor;
    StackMonitor *m_stackMonitor;
    Stacks m_stacks;

    std::map<uint64_t /* pid */, std::set<uint64_t /* callAddr */>> m_noframeFunctions;

public:
    void update(S2EExecutionState *state, uint64_t sp, uint64_t pc, bool createNewFrame);
    void deleteStack(S2EExecutionState *state, uint64_t pid, uint64_t tid);
    void onProcessUnload(S2EExecutionState *state, uint64_t pid);

    void registerNoframeFunction(uint64_t pid, uint64_t callAddr);
    bool isNoframeFunction(uint64_t pid, uint64_t addr);

    bool getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack, StackFrameInfo &info) const;
    bool getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid, StackMonitor::CallStack &callStack) const;
    bool getCallStacks(S2EExecutionState *state, StackMonitor::CallStacks &callStacks) const;

    void dump(S2EExecutionState *state) const;

    StackMonitorState(StackMonitor::DebugLevel debugLevel);
    virtual ~StackMonitorState();
    virtual StackMonitorState *clone() const;
    static PluginState *factory(Plugin *p, S2EExecutionState *s);

    friend class StackMonitor;
};

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const StackMonitorState::StackFrame &frame) {
    os << "  Frame pc=" << hexval(frame.pc) << " top=" << hexval(frame.top) << " size=" << hexval(frame.size);
    return os;
}

llvm::raw_ostream &operator<<(llvm::raw_ostream &os, const StackMonitorState::Stack &stack) {
    os << "Stack bound=" << hexval(stack.m_stackBound) << "\n";
    foreach2 (it, stack.m_frames.begin(), stack.m_frames.end()) { os << *it << "\n"; }

    return os;
}

void StackMonitor::initialize() {
    CorePlugin *core = s2e()->getCorePlugin();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_processDetector = s2e()->getPlugin<ProcessExecutionDetector>();

    m_debugLevel = (DebugLevel) s2e()->getConfig()->getInt(getConfigKey() + ".debugLevel", 0);

    m_monitor->onThreadExit.connect(sigc::mem_fun(*this, &StackMonitor::onThreadExit));
    m_monitor->onProcessUnload.connect(sigc::mem_fun(*this, &StackMonitor::onProcessUnload));

    core->onTranslateBlockStart.connect(sigc::mem_fun(*this, &StackMonitor::onTranslateBlockStart));
    core->onTranslateBlockComplete.connect(sigc::mem_fun(*this, &StackMonitor::onTranslateBlockComplete));
}

void StackMonitor::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                         uint64_t pc) {
    if (!m_processDetector->isTrackedPc(state, pc, true)) {
        return;
    }

    m_onTranslateRegisterAccessConnection.disconnect();

    m_onTranslateRegisterAccessConnection = s2e()->getCorePlugin()->onTranslateRegisterAccessEnd.connect(
        sigc::mem_fun(*this, &StackMonitor::onTranslateRegisterAccess));
}

void StackMonitor::onTranslateBlockComplete(S2EExecutionState *state, TranslationBlock *tb, uint64_t endPc) {
    m_onTranslateRegisterAccessConnection.disconnect();
}

void StackMonitor::onTranslateRegisterAccess(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc, uint64_t rmask, uint64_t wmask, bool accessesMemory) {
    if ((wmask & (1 << R_ESP))) {
        if (tb->se_tb_type == TB_SYSENTER) {
            // Ignore sysenter (last instruction in this TB)
            return;
        }

        bool isCall = false;
        uint64_t callEip = 0;
        if (tb->se_tb_type == TB_CALL || tb->se_tb_type == TB_CALL_IND) {
            isCall = true;
            callEip = tb->se_tb_call_eip;
        }

        signal->connect(sigc::bind(sigc::mem_fun(*this, &StackMonitor::onStackPointerModification), isCall, callEip));
    }
}

void StackMonitor::onStackPointerModification(S2EExecutionState *state, uint64_t pc, bool isCall, uint64_t callEip) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);

    bool createNewFrame = false;

    if (isCall) {
        if (!plgState->isNoframeFunction(m_monitor->getPid(state), callEip)) {
            createNewFrame = true;
        } else if (m_debugLevel >= DEBUGLEVEL_PRINT_MESSAGES) {
            // TODO: convert pc to native base
            uint64_t pid = m_monitor->getPid(state);
            uint64_t tid = m_monitor->getTid(state);
            getDebugStream(state) << "ignoring call"        //
                                  << " pid=" << hexval(pid) //
                                  << " tid=" << hexval(tid) //
                                  << " pc=" << hexval(pc)   //
                                  << "\n";
        }
    }

    plgState->update(state, state->regs()->getSp(), pc, createNewFrame);
}

void StackMonitor::update(S2EExecutionState *state, uint64_t sp, uint64_t pc, bool createNewFrame) {
    if (!m_processDetector->isTracked(state)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->update(state, sp, pc, createNewFrame);
}

void StackMonitor::onThreadExit(S2EExecutionState *state, const ThreadDescriptor &thread) {
    if (!m_processDetector->isTracked(state, thread.Pid)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->deleteStack(state, thread.Pid, thread.Tid);
}

void StackMonitor::onProcessUnload(S2EExecutionState *state, uint64_t pageDir, uint64_t pid, uint64_t returnCode) {
    if (!m_processDetector->isTracked(state, pid)) {
        return;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->onProcessUnload(state, pid);
}

void StackMonitor::registerNoframeFunction(S2EExecutionState *state, uint64_t pid, uint64_t callAddr) {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->registerNoframeFunction(pid, callAddr);
}

bool StackMonitor::getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack, StackFrameInfo &info) const {
    if (!m_processDetector->isTracked(state)) {
        return false;
    }

    DECLARE_PLUGINSTATE(StackMonitorState, state);
    return plgState->getFrameInfo(state, sp, onTheStack, info);
}

bool StackMonitor::getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid, CallStack &callStack) const {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    return plgState->getCallStack(state, pid, tid, callStack);
}

bool StackMonitor::getCallStacks(S2EExecutionState *state, CallStacks &callStacks) const {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    return plgState->getCallStacks(state, callStacks);
}

void StackMonitor::dump(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(StackMonitorState, state);
    plgState->dump(state);
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

StackMonitorState::StackMonitorState(StackMonitor::DebugLevel debugLevel) {
    m_debugLevel = debugLevel;
    m_monitor = static_cast<OSMonitor *>(g_s2e->getPlugin("OSMonitor"));
    m_stackMonitor = g_s2e->getPlugin<StackMonitor>();
}

StackMonitorState::~StackMonitorState() {
}

StackMonitorState *StackMonitorState::clone() const {
    return new StackMonitorState(*this);
}

PluginState *StackMonitorState::factory(Plugin *p, S2EExecutionState *s) {
    StackMonitor *sm = g_s2e->getPlugin<StackMonitor>();
    return new StackMonitorState(sm->m_debugLevel);
}

void StackMonitorState::update(S2EExecutionState *state, uint64_t sp, uint64_t pc, bool createNewFrame) {
    uint64_t pid = m_monitor->getPid(state);
    uint64_t tid = m_monitor->getTid(state);

    if (m_debugLevel >= StackMonitor::DEBUGLEVEL_PRINT_MESSAGES) {
        // TODO: convert pc to native base
        m_stackMonitor->getDebugStream(state)
            << "update"
            << " pid=" << hexval(pid) << " tid=" << hexval(tid) << " pc=" << hexval(pc) << " sp=" << hexval(sp)
            << " newFrame=" << createNewFrame << "\n";
    }

    PidTid p = std::make_pair(pid, tid);

    Stacks::iterator stackit = m_stacks.find(p);
    if (stackit == m_stacks.end()) {
        uint64_t stackBase, stackSize;
        if (!m_monitor->getCurrentStack(state, &stackBase, &stackSize)) {
            if (m_debugLevel >= StackMonitor::DEBUGLEVEL_PRINT_MESSAGES) {
                m_stackMonitor->getDebugStream(state) << "could not get current stack\n";
            }
            return;
        }

        Stack stack(this, state, stackBase + stackSize, sp, pc);

        m_stacks.insert(std::make_pair(p, stack));
        stackit = m_stacks.find(p);

        m_stackMonitor->onStackCreation.emit(state);
    }

    Stack &stack = (*stackit).second;

    if (createNewFrame) {
        stack.newFrame(this, state, pc, sp, state->getPointerSize());
    } else {
        stack.update(this, state, pc, sp);
    }

    if (m_debugLevel >= StackMonitor::DEBUGLEVEL_DUMP_STACK) {
        m_stackMonitor->getDebugStream(state) << (*stackit).second << "\n";
    }

    if (stack.empty()) {
        m_stacks.erase(stackit);
        m_stackMonitor->onStackDeletion.emit(state);
    }
}

void StackMonitorState::deleteStack(S2EExecutionState *state, uint64_t pid, uint64_t tid) {
    PidTid p = std::make_pair(pid, tid);
    Stacks::iterator it = m_stacks.find(p);
    if (it == m_stacks.end()) {
        g_s2e->getWarningsStream(state) << "No stack for pid " << hexval(pid) << " tid " << hexval(tid) << '\n';
        return;
    }

    m_stacks.erase(it);
}

void StackMonitorState::onProcessUnload(S2EExecutionState *state, uint64_t pid) {
    m_noframeFunctions.erase(pid);

    foreach2 (it, m_stacks.begin(), m_stacks.end()) {
        const PidTid &p = it->first;
        s2e_assert(state, p.first != pid,
                   "Stack was not deleted for pid " << hexval(p.first) << " tid " << hexval(p.second));
    }
}

void StackMonitorState::registerNoframeFunction(uint64_t pid, uint64_t callAddr) {
    m_noframeFunctions[pid].insert(callAddr);
}

bool StackMonitorState::isNoframeFunction(uint64_t pid, uint64_t addr) {
    const std::set<uint64_t> &addrSet = m_noframeFunctions[pid];
    return addrSet.find(addr) != addrSet.end();
}

// onTheStack == true && result == true ==> found a valid frame
// onTheStack == true && result == false ==> on the stack but not in any know frame
// onTheStack == false ==> does not fall in any know stack
bool StackMonitorState::getFrameInfo(S2EExecutionState *state, uint64_t sp, bool &onTheStack,
                                     StackFrameInfo &info) const {
    uint64_t pid = m_monitor->getPid(state);
    onTheStack = false;

    // XXX: Assume here that there are very few stacks, so simple iteration is fast enough
    foreach2 (it, m_stacks.begin(), m_stacks.end()) {
        if ((*it).first.first != pid) {
            continue;
        }

        const Stack &stack = (*it).second;
        StackFrame frameInfo;
        bool frameValid = false;
        if (!stack.getFrame(sp, frameValid, frameInfo)) {
            continue;
        }

        onTheStack = true;

        if (frameValid) {
            info.FramePc = frameInfo.pc;
            info.FrameSize = frameInfo.size;
            info.FrameTop = frameInfo.top;
            info.StackBound = stack.getStackBound();
            return true;
        }

        return false;
    }

    return false;
}

void StackMonitorState::dump(S2EExecutionState *state) const {
    m_stackMonitor->getDebugStream() << "Dumping stacks\n";
    foreach2 (it, m_stacks.begin(), m_stacks.end()) { m_stackMonitor->getDebugStream() << (*it).second << "\n"; }
}

bool StackMonitorState::getCallStack(S2EExecutionState *state, uint64_t pid, uint64_t tid,
                                     StackMonitor::CallStack &callStack) const {
    Stacks::const_iterator it = m_stacks.find(std::make_pair(pid, tid));
    if (it == m_stacks.end()) {
        return false;
    }

    it->second.getCallStack(callStack);

    return true;
}

bool StackMonitorState::getCallStacks(S2EExecutionState *state, StackMonitor::CallStacks &callStacks) const {
    foreach2 (it, m_stacks.begin(), m_stacks.end()) {
        callStacks.push_back(StackMonitor::CallStack());
        StackMonitor::CallStack &cs = callStacks.back();

        const Stack &stack = (*it).second;
        stack.getCallStack(cs);
    }

    return true;
}

} // namespace plugins
} // namespace s2e
