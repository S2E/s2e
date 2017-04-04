///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_WINDOWSCRASHDUMPGENERATOR_H
#define S2E_PLUGINS_WINDOWSCRASHDUMPGENERATOR_H

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Lua/Lua.h>
#include <s2e/S2EExecutionState.h>

#include "WindowsInterceptor.h"

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
    WindowsInterceptor *m_monitor;
    bool m_generateCrashDump;

    bool generateCrashDump(S2EExecutionState *state, const std::string &filename,
                           const vmi::windows::BugCheckDescription *bugDesc, const vmi::windows::CONTEXT32 &context);

    void onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_EXAMPLE_H
