///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BugCollector_H
#define S2E_PLUGINS_BugCollector_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/S2EExecutionState.h>

#include <s2e/Plugins/Core/Vmi.h>

#include <llvm/ADT/StringMap.h>

#include <map>
#include <set>

namespace vmi {
namespace windows {
struct BugCheckDescription;
} // namespace windows
} // namespace vmi

namespace s2e {
namespace plugins {

class LinuxMonitor;
class WindowsMonitor;
class BlueScreenInterceptor;
class WindowsCrashDumpGenerator;

/// \c si_code values for SIGCHLD signal
enum LinuxSIGCHLDCodes {
    CLD_EXITED = 1, ///< Child has exited
    CLD_KILLED,     ///< Child was killed
    CLD_DUMPED,     ///< Child terminated abnormally
    CLD_TRAPPED,    ///< Traced child has trapped
    CLD_STOPPED,    ///< Child has stopped
    CLD_CONTINUED   ///< Stopped child has continued
};

enum BugType {
    SEGFAULT,
    ILLEGAL_INSTRUCTION,
    ABORT,
    STACK_OVERFLOW,
    ARITHMETIC_ERROR,
    KERNEL_CRASH,
    USER_MODE_CRASH,
    USER_TRIGGERED_CRASH,
    RESOURCE_LEAK,
    OTHER,
    NONFATAL
};

enum BugCollectorType { BUG_TYPE_BSOD, BUG_TYPE_CUSTOM, BUG_TYPE_WIN_UM_CRASH, BUG_TYPE_RESOURCE_LEAK };

typedef std::pair<std::string, std::vector<uint8_t>> BugInput;
typedef std::vector<BugInput> BugInputs;

struct BugCollectorBug {
    BugCollectorType type;

    /// Bug code, depends on the context
    uint64_t code;

    /// This bug was updated since the last time it was sent to s2e-lb
    mutable bool updated;

    /// State in which this bug check has been initially found
    unsigned state;

    /// How many times did this bug occur?
    mutable unsigned count;

    /// Crash dump associated with the bug
    mutable std::string crashDumpFile;

    BugInputs concreteInputs;

    BugCollectorBug() {
        count = 1;
    }

    virtual ~BugCollectorBug() {
    }

    virtual QObject *serialize() const;
    static void deserialize(BugCollectorBug &ret, QDict *dict);
    static BugCollectorBug *deserialize(QDict *dict);

    virtual bool operator<(const BugCollectorBug *b1) const = 0;
};

struct BugCollectorBugLt {
    bool operator()(const BugCollectorBug *b1, const BugCollectorBug *b2) {
        return b1->operator<(b2);
    }
};

struct BugBlueScreen : public BugCollectorBug {
    static const unsigned PARAM_COUNT = 4;
    uint64_t parameters[PARAM_COUNT];

    BugBlueScreen() : BugCollectorBug() {
        type = BUG_TYPE_BSOD;
        for (unsigned i = 0; i < PARAM_COUNT; ++i) {
            parameters[i] = 0;
        }
    }

    virtual bool operator<(const BugCollectorBug *b) const {
        if (b->type != type)
            return b->type < type;

        const BugBlueScreen &b1 = *static_cast<const BugBlueScreen *>(b);
        if (b1.code != code)
            return b1.code < code;

        for (unsigned i = 0; i < PARAM_COUNT; ++i) {
            if (b1.code == 0xa) { /* IRQL_NOT_LESS_OR_EQUAL */
                /* Skip the data address to avoid many duplicates */
                continue;
            }
            if (b1.parameters[i] != parameters[i]) {
                return b1.parameters[i] < parameters[i];
            }
        }

        return false;
    }

    virtual QObject *serialize() const;
    static void deserialize(BugBlueScreen &ret, QDict *dict);
};

struct BugCustom : public BugCollectorBug {
    /// Custom user description
    std::string description;

    BugCustom() : BugCollectorBug() {
        type = BUG_TYPE_CUSTOM;
    }

    virtual bool operator<(const BugCollectorBug *b) const {
        if (b->type != type)
            return b->type < type;

        const BugCustom &b1 = *static_cast<const BugCustom *>(b);
        if (b1.code != code)
            return b1.code < code;
        return b1.description < description;
    }

    virtual QObject *serialize() const;
    static void deserialize(BugCustom &ret, QDict *dict);
};

struct BugWindowsUserModeCrash : public BugCollectorBug {
    std::string programName;
    uint64_t pid;
    uint64_t exceptionAddress;
    uint64_t exceptionFlags;

    BugWindowsUserModeCrash() : BugCollectorBug() {
        type = BUG_TYPE_WIN_UM_CRASH;
    }

    virtual bool operator<(const BugCollectorBug *b) const {
        if (b->type != type)
            return b->type < type;

        const BugWindowsUserModeCrash &b1 = *static_cast<const BugWindowsUserModeCrash *>(b);
        if (b1.programName != programName)
            return b1.programName < programName;
        if (b1.code != code)
            return b1.code < code;
        if (b1.pid != pid)
            return b1.pid < pid;
        if (b1.exceptionAddress != exceptionAddress)
            return b1.exceptionAddress < exceptionAddress;
        return b1.exceptionFlags < exceptionFlags;
    }

    virtual QObject *serialize() const;
    static void deserialize(BugWindowsUserModeCrash &ret, QDict *dict);
};

struct BugCollectorResourceLeak : public BugCollectorBug {
    uint64_t resourceId;
    uint64_t callSite;
    std::string moduleName;
    std::string libraryName;
    std::string libraryFunctionName;

    BugCollectorResourceLeak() : BugCollectorBug() {
        type = BUG_TYPE_RESOURCE_LEAK;
    }

    virtual bool operator<(const BugCollectorBug *b) const {
        if (b->type != type)
            return b->type < type;

        const BugCollectorResourceLeak &b1 = *static_cast<const BugCollectorResourceLeak *>(b);
        if (b1.resourceId != resourceId)
            return b1.resourceId < resourceId;
        if (b1.callSite != callSite)
            return b1.callSite < callSite;
        if (b1.moduleName != moduleName)
            return b1.moduleName < moduleName;
        if (b1.libraryName != libraryName)
            return b1.libraryName < libraryName;
        return b1.libraryFunctionName < libraryFunctionName;
    }

    virtual QObject *serialize() const;
    static void deserialize(BugCollectorResourceLeak &ret, QDict *dict);
};

struct S2E_BUG_CUSTOM {
    uint64_t CustomCode;
    uint64_t DescriptionStr;
};

struct S2E_BUG_WINDOWS_USERMODE_BUG {
    uint64_t ProgramName;
    uint64_t Pid;
    uint64_t ExceptionCode;
    uint64_t ExceptionAddress;
    uint64_t ExceptionFlags;
};

enum S2E_BUG_COMMANDS { CUSTOM_BUG, WINDOWS_USERMODE_BUG };

struct S2E_BUG_CRASH_OPAQUE {
    uint64_t CrashOpaque;
    uint64_t CrashOpaqueSize;
};

struct S2E_BUG_COMMAND {
    S2E_BUG_COMMANDS Command;
    union {
        S2E_BUG_CUSTOM CustomBug;
        S2E_BUG_WINDOWS_USERMODE_BUG WindowsUserModeBug;
    };
    /* Optional, used by the crash dump plugin. */
    S2E_BUG_CRASH_OPAQUE CrashOpaque;
};

class BugCollector : public Plugin, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN
public:
    BugCollector(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    // Triggered whenever a bug occurs
    sigc::signal<void, S2EExecutionState *, BugType> onBug;

    void addOrUpdateBug(S2EExecutionState *state, BugCollectorBug *bug, S2E_BUG_CRASH_OPAQUE crashOpaque);
    void getConcreteInputs(S2EExecutionState *state, BugCollectorBug *bug);

private:
    std::set<uint64_t> m_buggyPaths;
    std::set<uint64_t> m_buggyPathsToNotify;

    LinuxMonitor *m_linuxMonitor;
    WindowsMonitor *m_windowsMonitor;
    BlueScreenInterceptor *m_bsodInterceptor;
    WindowsCrashDumpGenerator *m_bsodGenerator;
    ModuleExecutionDetector *m_detector;

    Vmi *m_vmiPlugin;
    ExecutionTracer *m_tracer;
    testcases::TestCaseGenerator *m_tc;

    void onTimer();

    std::string compressFile(const std::string &path);

    void onTranslateSoftInterruptStart(ExecutionSignal *signal, S2EExecutionState *state, struct TranslationBlock *tb,
                                       uint64_t pc, unsigned vector);
    void onSoftInterrupt(S2EExecutionState *state, uint64_t pc);
    bool isNewBug(BugCollectorBug *bug);

    /*************************************************/
    /* Windows stuff                                 */
    /*************************************************/
    typedef std::set<BugCollectorBug *, BugCollectorBugLt> Bugs;
    Bugs m_bugs;
    bool m_compressDumps;

    void onBlueScreen(S2EExecutionState *state, vmi::windows::BugCheckDescription *info);

    QObject *getUpdatedBugs();
    void addCrashDump(S2EExecutionState *state, BugCollectorBug *bug, S2E_BUG_CRASH_OPAQUE crashOpaque);

    /*************************************************/
    /* Custom opcodes                                */
    /*************************************************/
    void opcodeCustomBug(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_BUG_COMMAND &command);

    void opcodeWindowsUserModeBug(S2EExecutionState *state, uint64_t guestDataPtr, const S2E_BUG_COMMAND &command);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_BugCollector_H
