///
/// Copyright (C) 2014-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

extern "C" {
#include <qint.h>
#include <qlist.h>
#include <qstring.h>
}

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>

#include <klee/util/Assignment.h>
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EStatsTracker.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <iostream>
#include <sstream>
#include <unistd.h>

#include <signal.h>

#include <s2e/Plugins/Core/Events.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/BlueScreenInterceptor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashDumpGenerator.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsMonitor.h>

#include "BugCollector.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(
    BugCollector,
    "This plugin centralizes all the bugs found by various plugins and makes them available in a standard format", "");

void BugCollector::initialize() {
    m_linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
    m_windowsMonitor = s2e()->getPlugin<WindowsMonitor>();

    m_bsodInterceptor = s2e()->getPlugin<BlueScreenInterceptor>();
    m_bsodGenerator = s2e()->getPlugin<WindowsCrashDumpGenerator>();

    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    m_vmiPlugin = s2e()->getPlugin<Vmi>();
    m_tc = s2e()->getPlugin<testcases::TestCaseGenerator>();
    if (m_tc) {
        m_tc->disable();
    }

    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    if (m_bsodInterceptor) {
        m_bsodInterceptor->onBlueScreen.connect(sigc::mem_fun(*this, &BugCollector::onBlueScreen));
    }

    m_compressDumps = s2e()->getConfig()->getBool(getConfigKey() + ".compressDumps", true);

    s2e()->getCorePlugin()->onTimer.connect(sigc::mem_fun(*this, &BugCollector::onTimer));

    if (m_detector) {
        s2e()->getCorePlugin()->onTranslateSoftInterruptStart.connect(
            sigc::mem_fun(*this, &BugCollector::onTranslateSoftInterruptStart));
    }
}

/*****************************************************************/
QObject *BugCollectorBug::serialize() const {
    QDict *dict = qdict_new();

    qdict_put_obj(dict, "code", QOBJECT(qint_from_int(code)));
    qdict_put_obj(dict, "count", QOBJECT(qint_from_int(count)));
    qdict_put_obj(dict, "state", QOBJECT(qint_from_int(state)));
    qdict_put_obj(dict, "crash_dump", QOBJECT(qstring_from_str(crashDumpFile.c_str())));

    QDict *concrete = qdict_new();
    foreach2 (it, concreteInputs.begin(), concreteInputs.end()) {
        /* Encode the concrete values as a list of integers */
        QList *data = qlist_new();
        foreach2 (lit, (*it).second.begin(), (*it).second.end()) { qlist_append(data, qint_from_int(*lit)); }
        qdict_put_obj(concrete, (*it).first.c_str(), QOBJECT(data));
    }

    qdict_put_obj(dict, "concrete_input", QOBJECT(concrete));
    return QOBJECT(dict);
}

// XXX: This may crash in case of malformed inputs
void BugCollectorBug::deserialize(BugCollectorBug &ret, QDict *dict) {
    ret.code = qint_get_int(qobject_to_qint(qdict_get(dict, "code")));

    // The received count indicates how many bsods where seen globally.
    // However, it is the #of bsods seen locally, so discard what we've got.
    // ret.count = qint_get_int(qobject_to_qint(qdict_get(dict, "count")));
    ret.count = 0;
    ret.updated = false;
    ret.state = qint_get_int(qobject_to_qint(qdict_get(dict, "state")));

    // Also discard the bugs
}

BugCollectorBug *BugCollectorBug::deserialize(QDict *dict) {
    std::string type = qstring_get_str(qobject_to_qstring(qdict_get(dict, "bug_type")));
    if (type == "bsod") {
        BugBlueScreen *bug = new BugBlueScreen();
        BugBlueScreen::deserialize(*bug, dict);
        return bug;
    } else if (type == "custom") {
        BugCustom *bug = new BugCustom();
        BugCustom::deserialize(*bug, dict);
        return bug;
    } else if (type == "win_user_mode_crash") {
        BugWindowsUserModeCrash *bug = new BugWindowsUserModeCrash();
        BugWindowsUserModeCrash::deserialize(*bug, dict);
        return bug;
    } else if (type == "resource_leak") {
        BugCollectorResourceLeak *bug = new BugCollectorResourceLeak();
        BugCollectorResourceLeak::deserialize(*bug, dict);
        return bug;
    }
    return NULL;
}

/*****************************************************************/
QObject *BugBlueScreen::serialize() const {
    QDict *dict = qobject_to_qdict(BugCollectorBug::serialize());
    qdict_put_obj(dict, "bug_type", QOBJECT(qstring_from_str("bsod")));
    QList *list = qlist_new();
    for (unsigned i = 0; i < PARAM_COUNT; ++i) {
        qlist_append(list, qint_from_int(parameters[i]));
    }

    qdict_put_obj(dict, "parameters", QOBJECT(list));

    return QOBJECT(dict);
}

// XXX: This may crash in case of malformed inputs
void BugBlueScreen::deserialize(BugBlueScreen &ret, QDict *dict) {
    BugCollectorBug::deserialize(ret, dict);

    QList *list = qobject_to_qlist(qdict_get(dict, "parameters"));
    QListEntry *le;
    unsigned index = 0;
    QLIST_FOREACH_ENTRY(list, le) {
        if (index >= PARAM_COUNT) {
            break;
        }
        ret.parameters[index++] = qint_get_int(qobject_to_qint(qlist_entry_obj(le)));
    }
}

/*****************************************************************/
QObject *BugCustom::serialize() const {
    QDict *dict = qobject_to_qdict(BugCollectorBug::serialize());
    qdict_put_obj(dict, "bug_type", QOBJECT(qstring_from_str("custom")));
    qdict_put_obj(dict, "description", QOBJECT(qstring_from_str(description.c_str())));
    return QOBJECT(dict);
}

// XXX: This may crash in case of malformed inputs
void BugCustom::deserialize(BugCustom &ret, QDict *dict) {
    BugCollectorBug::deserialize(ret, dict);
    ret.description = qstring_get_str(qobject_to_qstring(qdict_get(dict, "description")));
}

/*****************************************************************/
QObject *BugWindowsUserModeCrash::serialize() const {
    QDict *dict = qobject_to_qdict(BugCollectorBug::serialize());
    qdict_put_obj(dict, "bug_type", QOBJECT(qstring_from_str("win_user_mode_crash")));
    qdict_put_obj(dict, "program_name", QOBJECT(qstring_from_str(programName.c_str())));
    qdict_put_obj(dict, "pid", QOBJECT(qint_from_int(pid)));
    qdict_put_obj(dict, "exception_address", QOBJECT(qint_from_int(exceptionAddress)));
    qdict_put_obj(dict, "exception_flags", QOBJECT(qint_from_int(exceptionFlags)));

    return QOBJECT(dict);
}

void BugWindowsUserModeCrash::deserialize(BugWindowsUserModeCrash &ret, QDict *dict) {
    BugCollectorBug::deserialize(ret, dict);
    ret.programName = qstring_get_str(qobject_to_qstring(qdict_get(dict, "program_name")));
    ret.pid = qint_get_int(qobject_to_qint(qdict_get(dict, "pid")));
    ret.exceptionAddress = qint_get_int(qobject_to_qint(qdict_get(dict, "exception_address")));
    ret.exceptionFlags = qint_get_int(qobject_to_qint(qdict_get(dict, "exception_flags")));
}

/*****************************************************************/
QObject *BugCollectorResourceLeak::serialize() const {
    QDict *dict = qobject_to_qdict(BugCollectorBug::serialize());
    qdict_put_obj(dict, "bug_type", QOBJECT(qstring_from_str("resource_leak")));
    qdict_put_obj(dict, "resource_id", QOBJECT(qint_from_int(resourceId)));
    qdict_put_obj(dict, "call_site", QOBJECT(qint_from_int(callSite)));
    qdict_put_obj(dict, "module_name", QOBJECT(qstring_from_str(moduleName.c_str())));
    qdict_put_obj(dict, "library_name", QOBJECT(qstring_from_str(libraryName.c_str())));
    qdict_put_obj(dict, "library_function_name", QOBJECT(qstring_from_str(libraryFunctionName.c_str())));

    return QOBJECT(dict);
}

void BugCollectorResourceLeak::deserialize(BugCollectorResourceLeak &ret, QDict *dict) {
    BugCollectorBug::deserialize(ret, dict);
    ret.resourceId = qint_get_int(qobject_to_qint(qdict_get(dict, "resource_id")));
    ret.callSite = qint_get_int(qobject_to_qint(qdict_get(dict, "call_site")));
    ret.moduleName = qstring_get_str(qobject_to_qstring(qdict_get(dict, "module_name")));
    ret.libraryName = qstring_get_str(qobject_to_qstring(qdict_get(dict, "library_name")));
    ret.libraryFunctionName = qstring_get_str(qobject_to_qstring(qdict_get(dict, "library_function_name")));
}

/*****************************************************************/
void BugCollector::getConcreteInputs(S2EExecutionState *state, BugCollectorBug *bug) {
    foreach2 (it, state->concolics->bindings.begin(), state->concolics->bindings.end()) {
        const klee::Array *var = (*it).first;
        const std::vector<unsigned char> &data = (*it).second;

        std::string realName = (*state->variableNameMapping.find(var->getName())).second;
        bug->concreteInputs.push_back(std::make_pair(realName, data));
    }
}

QObject *BugCollector::getUpdatedBugs() {
    if (m_bugs.size() == 0) {
        return NULL;
    }

    QList *list = qlist_new();

    foreach2 (it, m_bugs.begin(), m_bugs.end()) {
        const BugCollectorBug &bs = *(*it);
        if (bs.updated) {
            qlist_append_obj(list, bs.serialize());
            bs.updated = 0;
            bs.count = 0;
        }
    }

    return QOBJECT(list);
}

std::string BugCollector::compressFile(const std::string &path) {
    // Simply call the system's gzip.
    std::stringstream ss;
    ss << "gzip \"" << path << "\"";
    int sret = system(ss.str().c_str());
    if (sret == -1) {
        return path;
    }

    // Check that the file was compressed
    llvm::SmallString<128> compressed(path);
    llvm::sys::path::replace_extension(compressed, "gz");

    if (llvm::sys::fs::exists(compressed)) {
        unlink(path.c_str());
        return compressed.c_str();
    }

    return path;
}

void BugCollector::addCrashDump(S2EExecutionState *state, BugCollectorBug *bug, S2E_BUG_CRASH_OPAQUE crashOpaque) {
    if (!m_bsodGenerator) {
        getWarningsStream(state) << "WindowsCrashDump generator not enabled\n";
        return;
    }

    std::string path = m_bsodGenerator->getPathForDump(state);

    bool ret;
    vmi::windows::BugCheckDescription bugCheckDesc;
    bugCheckDesc.guestHeader = crashOpaque.CrashOpaque;
    bugCheckDesc.headerSize = crashOpaque.CrashOpaqueSize;

    if (bug->type == BUG_TYPE_BSOD) {
        BugBlueScreen *bsod = static_cast<BugBlueScreen *>(bug);

        bugCheckDesc.code = bsod->code;
        bugCheckDesc.parameters[0] = bsod->parameters[0];
        bugCheckDesc.parameters[1] = bsod->parameters[1];
        bugCheckDesc.parameters[2] = bsod->parameters[2];
        bugCheckDesc.parameters[3] = bsod->parameters[3];
        ret = m_bsodGenerator->generateDump(state, path, &bugCheckDesc);
    } else {
        ret = m_bsodGenerator->generateManualDump(state, path, &bugCheckDesc);
    }

    if (!ret) {
        return;
    }

    if (m_compressDumps) {
        bug->crashDumpFile = compressFile(path);
    } else {
        bug->crashDumpFile = path;
    }
}

bool BugCollector::isNewBug(BugCollectorBug *bug) {
    bool b = m_bugs.find(bug) == m_bugs.end();
    getDebugStream() << (b ? "new bug" : "repeated bug") << "\n";
    return b;
}

void BugCollector::addOrUpdateBug(S2EExecutionState *state, BugCollectorBug *bug, S2E_BUG_CRASH_OPAQUE crashOpaque) {
    Bugs::iterator it = m_bugs.find(bug);
    if (it != m_bugs.end()) {
        // Skip already-existing bugs
        (*it)->count++;
        (*it)->updated = true;
        delete bug;
    } else {
        bug->updated = true;
        addCrashDump(state, bug, crashOpaque);
        m_bugs.insert(bug);
        ++klee::stats::bugs;
    }
}

void BugCollector::onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info) {
    BugBlueScreen *bug = new BugBlueScreen();
    bug->code = info->code;
    bug->state = state->getID();

    for (unsigned i = 0; i < 4; ++i) {
        bug->parameters[i] = info->parameters[i];
    }

    if (isNewBug(bug)) {
        getConcreteInputs(state, bug);
        onBug.emit(state, KERNEL_CRASH);
    }

    S2E_BUG_CRASH_OPAQUE opaque;
    opaque.CrashOpaque = info->guestHeader;
    opaque.CrashOpaqueSize = info->headerSize;
    addOrUpdateBug(state, bug, opaque);
}

void BugCollector::onTranslateSoftInterruptStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                 struct TranslationBlock *tb, uint64_t pc, unsigned vector) {
    if (vector != 3) {
        /* Only track int3 traps to debugger */
        return;
    }

    const ModuleDescriptor *module = m_detector->getModule(state, pc);
    if (!module) {
        return;
    }

    signal->connect(sigc::mem_fun(*this, &BugCollector::onSoftInterrupt));
}

void BugCollector::onSoftInterrupt(S2EExecutionState *state, uint64_t pc) {
    if (m_tracer) {
        m_tracer->flushCircularBufferToFile();
    }

    s2e()->getExecutor()->terminateStateEarly(*state, "trap to debugger");
}

void BugCollector::onTimer() {
    Events::PluginData data;

    if (!monitor_ready()) {
        return;
    }

    QObject *bsods = getUpdatedBugs();
    if (bsods) {
        data.push_back(std::make_pair("bugs", bsods));
        Events::emitQMPEvent(this, data);
    }
}

/*****************************************************************/
void BugCollector::opcodeCustomBug(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_BUG_COMMAND &command) {
    BugCustom *bug = new BugCustom();
    bug->code = command.CustomBug.CustomCode;
    bug->state = state->getID();

    bool ret = true;
    ret &= state->mem()->readString(command.CustomBug.DescriptionStr, bug->description);
    if (!ret) {
        getWarningsStream(state) << "could not read custom bug description\n";
        return;
    }

    if (isNewBug(bug)) {
        getConcreteInputs(state, bug);
        onBug.emit(state, USER_TRIGGERED_CRASH);
    }

    addOrUpdateBug(state, bug, command.CrashOpaque);

    if (m_tracer) {
        m_tracer->flushCircularBufferToFile();
    }

    s2e()->getExecutor()->terminateStateEarly(*state, "BugCollector: opcodeCustomBug");
}

void BugCollector::opcodeWindowsUserModeBug(S2EExecutionState *state, uint64_t guestDataPtr,
                                            const S2E_BUG_COMMAND &command) {
    BugWindowsUserModeCrash *bug = new BugWindowsUserModeCrash();
    bug->code = command.WindowsUserModeBug.ExceptionCode;
    bug->state = state->getID();
    bug->exceptionAddress = command.WindowsUserModeBug.ExceptionAddress;
    bug->exceptionFlags = command.WindowsUserModeBug.ExceptionFlags;
    bug->pid = command.WindowsUserModeBug.Pid;

    bool ret = true;
    ret &= state->mem()->readString(command.WindowsUserModeBug.ProgramName, bug->programName);
    if (!ret) {
        getWarningsStream(state) << "could not read custom program name\n";
        return;
    }

    if (isNewBug(bug)) {
        getConcreteInputs(state, bug);
        onBug.emit(state, USER_MODE_CRASH);
    }

    addOrUpdateBug(state, bug, command.CrashOpaque);

    if (m_tracer) {
        m_tracer->flushCircularBufferToFile();
    }

    s2e()->getExecutor()->terminateStateEarly(*state, "opcodeWindowsUserModeBug");
}

void BugCollector::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_BUG_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_BUG_COMMAND size\n";
        return;
    }

    if (!state->mem()->readMemoryConcrete(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case CUSTOM_BUG: {
            opcodeCustomBug(state, guestDataPtr, command);
        } break;

        case WINDOWS_USERMODE_BUG: {
            opcodeWindowsUserModeBug(state, guestDataPtr, command);
        } break;
    }
}

} // namespace plugins
} // namespace s2e
