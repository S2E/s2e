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

#ifndef S2E_PLUGINS_ResourceMonitor_H
#define S2E_PLUGINS_ResourceMonitor_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Synchronization.h>

#include <memory>

namespace s2e {
namespace plugins {

class ResourceMonitor : public Plugin {
    S2E_PLUGIN
public:
    ResourceMonitor(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    uint64_t m_timerCount;
    uint64_t m_rss;
    uint64_t m_cgroupMemLimit;
    std::string m_memStatFileName;
    S2ESynchronizedObject<bool> m_notifiedQMP;

    void onStateForkDecide(S2EExecutionState *state, const klee::ref<klee::Expr> &condition, bool &allowForking);
    void onTimer(void);
    void updateMemoryUsage();
    bool memoryLimitExceeded();
    void dropStates();
    void emitQMPNofitication();
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ResourceMonitor_H
