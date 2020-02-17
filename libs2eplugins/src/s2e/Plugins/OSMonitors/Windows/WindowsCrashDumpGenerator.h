///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_PLUGINS_WINDOWSCRASHDUMPGENERATOR_H
#define S2E_PLUGINS_WINDOWSCRASHDUMPGENERATOR_H

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Lua/Lua.h>
#include <s2e/S2EExecutionState.h>

#include "WindowsMonitor.h"

#include <vmi/WindowsCrashDumpGenerator.h>

namespace s2e {
namespace plugins {

class WindowsCrashDumpGenerator;

class WindowsCrashDumpInvoker {
private:
    WindowsCrashDumpGenerator *m_plugin;

public:
    static const char className[];
    static Lunar<WindowsCrashDumpInvoker>::RegType methods[];

    WindowsCrashDumpInvoker(WindowsCrashDumpGenerator *plg);
    WindowsCrashDumpInvoker(lua_State *lua);
    ~WindowsCrashDumpInvoker();

public:
    int generateCrashDump(lua_State *L);
};

///
/// \brief The WindowsCrashDumpGenerator plugins provides mechanisms to generate
/// WinDbg-compatible crash dumps.
///
/// Remarks:
///  - This class has no configurable options and does not generate dumps by itself
///  - Other plugins may use WindowsCrashDumpGenerator to request crash dumps
///    when they detect guest bugs. BugCollector is one such plugin.
///
class WindowsCrashDumpGenerator : public Plugin {
    S2E_PLUGIN
public:
    WindowsCrashDumpGenerator(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool generateDump(S2EExecutionState *state, const std::string &filename,
                      const vmi::windows::BugCheckDescription *info);

    bool generateManualDump(S2EExecutionState *state, const std::string &filename,
                            const vmi::windows::BugCheckDescription *info);

    std::string getPathForDump(S2EExecutionState *state, const std::string &prefix = "dump");

private:
    WindowsMonitor *m_monitor;

    // TODO: put these somewhere else. In principe getContext functions are generic,
    // but for now, only WindowsCrashDumpGenerator uses them.
    template <typename T> static void getContext(S2EExecutionState *state, T &context);
    static void getContext32(S2EExecutionState *state, vmi::windows::CONTEXT32 &context);
    static void getContext64(S2EExecutionState *state, vmi::windows::CONTEXT64 &context);

    bool generateCrashDump(S2EExecutionState *state, const std::string &filename,
                           const vmi::windows::BugCheckDescription *bugDesc, const vmi::windows::CONTEXT32 &context);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
