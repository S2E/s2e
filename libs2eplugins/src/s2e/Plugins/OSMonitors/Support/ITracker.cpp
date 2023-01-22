
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

#include <s2e/ConfigFile.h>
#include <s2e/Plugin.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>

#include "ITracker.h"

namespace s2e {
namespace plugins {

bool ITracker::isTracked(S2EExecutionState *state) {
    return isTrackedPc(state, state->regs()->getPc());
}

ITracker *ITracker::getTracker(S2E *s2e, Plugin *plugin) {
    auto filterPluginName = s2e->getConfig()->getString(plugin->getConfigKey() + ".filterPlugin");
    if (filterPluginName.size() == 0) {
        s2e->getWarningsStream() << "could not find .filterPlugin config key\n";
        return nullptr;
    }

    auto filterPlugin = s2e->getPlugin(filterPluginName);
    if (!filterPlugin) {
        s2e->getWarningsStream() << "could not find filter plugin " << filterPluginName << "\n";
        return nullptr;
    }

    ITracker *tracker = dynamic_cast<ITracker *>(filterPlugin);
    if (!tracker) {
        plugin->getWarningsStream() << filterPluginName << " must implement the ITracker interface\n";
        return nullptr;
    }

    return tracker;
}

} // namespace plugins
} // namespace s2e
