///
/// Copyright (C) 2023, Vitaly Chipounov
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

#ifndef _ITRACKER_H_

#define _ITRACKER_H_

namespace s2e {

class S2EExecutionState;
class S2E;
class Plugin;

namespace plugins {

///
/// @brief Interface that plugins can use to implement tracking policies.
///
/// Execution tracing is very expensive when recording everything.
/// We need users a flexible way to configure what guest code needs to be traced (the policy).
/// Execution tracers should only focus on recording the trace data (the mechanism).
/// It should be possible to mix and match tracers with tracking policies.
/// For example, InstructionCounter should be configurable to count instructions in
/// a specific, process, thread, or small piece of code. Same for TranslationBlockTracer.
///
class ITracker {
public:
    ///
    /// @brief Signal that is triggered when a tracker's configuration changes.
    ///
    /// Guest code could, e.g., configure new threads to trace.
    /// A tracing plugin may want to update its state as a result of that.
    ///
    sigc::signal<void, S2EExecutionState *> onConfigChange;

    ///
    /// @brief Indicates whether the guest code currently executing is being tracked.
    ///
    /// Execution tracers should call this API to determine whether to instrument
    /// the code or not.
    ///
    /// TODO: the tracker should indicate the instrumentation granualarity:
    /// - All translation blocks in the system.
    /// - All translation blocks of a module.
    /// Actual filtering is done on execution, so it would help to avoid instrumenting
    /// codes unnecessarily.
    ///
    virtual bool isTrackedPc(S2EExecutionState *state, uint64_t pc) = 0;

    bool isTracked(S2EExecutionState *state);

    ///
    /// @brief Indicates whether the tracker plugin is currently tracking something.
    ///
    /// This is useful to avoid instrumenting anything if there is nothing to be traced.
    ///
    virtual bool isTrackingConfigured(S2EExecutionState *state) = 0;

    ///
    /// @brief Plugins can use this to allow generic configuration of a tracker.
    ///
    static ITracker *getTracker(S2E *s2e, Plugin *plugin);
};

} // namespace plugins
} // namespace s2e

#endif