///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_H
#define S2E_H

#undef NDEBUG

#include <fstream>
#include <string>
#include <vector>
//#include <tr1/unordered_map>
#include <llvm/Support/raw_ostream.h>
#include <map>

// Undefine cat from "compiler.h"
#undef cat

#include "Logging.h"
#include "PluginManager.h"
#include "S2EExecutor.h"
#include "Synchronization.h"
#include "s2e_config.h"

namespace klee {
class Interpreter;
class InterpreterHandler;
}

struct TCGLLVMContext;

namespace s2e {

class Plugin;
class CorePlugin;
class ConfigFile;
class PluginsFactory;

class S2EHandler;
class S2EExecutor;
class S2EExecutionState;

class Database;

// Structure used for synchronization among multiple instances of S2E
struct S2EShared {
    unsigned currentProcessCount;
    unsigned lastFileId;
    // We must have unique state ids across all processes
    // otherwise offline tools will be extremely confused when
    // aggregating different execution trace files.
    unsigned lastStateId;

    // Array of currently running instances.
    // Each entry either contains -1 (no instance running) or
    // the instance index.
    unsigned processIds[S2E_MAX_PROCESSES];
    unsigned processPids[S2E_MAX_PROCESSES];
    S2EShared() {
        for (unsigned i = 0; i < S2E_MAX_PROCESSES; ++i) {
            processIds[i] = (unsigned) -1;
            processPids[i] = (unsigned) -1;
        }
    }
};

class S2E {
protected:
    S2ESynchronizedObject<S2EShared> m_sync;
    ConfigFile *m_configFile;

    PluginManager m_pluginManager;
    std::string m_outputDirectory;

    LogLevel m_globalLogLevel;
    bool m_hasGlobalLogLevel;
    LogLevel m_consoleLevel;

    llvm::raw_ostream *m_infoFileRaw;
    llvm::raw_ostream *m_debugFileRaw;
    llvm::raw_ostream *m_warningsFileRaw;

    llvm::raw_ostream *m_warningStream;
    llvm::raw_ostream *m_infoStream;
    llvm::raw_ostream *m_debugStream;

    bool m_setupUnbufferedStream;

    TCGLLVMContext *m_tcgLLVMContext;

    uint64_t m_startTimeSeconds;

    /* How many processes can S2E fork */
    unsigned m_maxProcesses;
    unsigned m_currentProcessIndex;
    unsigned m_currentProcessId;

    std::string m_outputDirectoryBase;

    S2EHandler *m_s2eHandler;
    S2EExecutor *m_s2eExecutor;

    /* forked indicates whether the current S2E process was forked from a parent S2E process */
    void initOutputDirectory(const std::string &outputDirectory, int verbose, bool forked);

    void initKleeOptions();
    void initExecutor();
    void initLogging();
    void initPlugins();

    void setupStreams(bool forked, bool reopen);

    llvm::raw_ostream &getStream(llvm::raw_ostream &stream, const S2EExecutionState *state) const;

public:
    S2E();
    ~S2E();

    /** Construct S2E */
    bool initialize(int argc, char **argv, TCGLLVMContext *tcgLLVMContext, const std::string &configFileName,
                    const std::string &outputDirectory, bool setupUnbufferedStream, int verbose,
                    unsigned s2e_max_processes);

    /*****************************/
    /* Configuration and plugins */

    /** Get configuration file */
    ConfigFile *getConfig() const {
        return m_configFile;
    }

    /** Get plugin by name of functionName */
    Plugin *getPlugin(const std::string &name) const {
        return m_pluginManager.getPlugin(name);
    }

    template <class PluginClass> PluginClass *getPlugin() const;

    /** Get Core plugin */
    inline CorePlugin *getCorePlugin() const {
        return m_pluginManager.getCorePlugin();
    }

    /*************************/
    /* Directories and files */

    /** Get output directory name */
    const std::string &getOutputDirectory() const {
        return m_outputDirectory;
    }

    /** Get output directory base name */
    const std::string &getOutputDirectoryBase() const {
        return m_outputDirectoryBase;
    }

    /** Get a filename inside an output directory */
    std::string getOutputFilename(const std::string &fileName);

    /** Create output file in an output directory */
    llvm::raw_ostream *openOutputFile(const std::string &filename);

    /** Get info stream (used only by KLEE internals) */
    llvm::raw_ostream &getInfoStream(const S2EExecutionState *state = 0) const {
        return getStream(*m_infoStream, state);
    }

    /** Get debug stream (used for non-important debug info) */
    llvm::raw_ostream &getDebugStream(const S2EExecutionState *state = 0) const {
        return getStream(*m_debugStream, state);
    }

    /** Get warnings stream (used for warnings, duplicated on the screen) */
    llvm::raw_ostream &getWarningsStream(const S2EExecutionState *state = 0) const {
        return getStream(*m_warningStream, state);
    }

    void flushOutputStreams() {
        m_infoStream->flush();
        m_debugStream->flush();
        m_warningStream->flush();

        m_warningsFileRaw->flush();
        m_debugFileRaw->flush();
        m_infoFileRaw->flush();

        fflush(stdout);
        fflush(stderr);
    }

    LogLevel getGlobalLogLevel() {
        return m_globalLogLevel;
    }

    bool hasGlobalLogLevel() {
        return m_hasGlobalLogLevel;
    }

    static void printf(llvm::raw_ostream &os, const char *fmt, ...);

    /***********************/
    /* Runtime information */
    S2EExecutor *getExecutor() {
        return m_s2eExecutor;
    }

    // XXX: A plugin can hold cached state information. When a state is deleted,
    // remove all the cached info from all plugins.
    void refreshPlugins() {
        m_pluginManager.refreshPlugins();
    }

    void writeBitCodeToFile();

    int fork();

    unsigned fetchAndIncrementStateId();
    unsigned fetchNextStateId();
    unsigned getMaxProcesses() const {
        return m_maxProcesses;
    }
    unsigned getCurrentProcessId() const {
        return m_currentProcessId;
    }

    unsigned getCurrentProcessIndex() const {
        return m_currentProcessIndex;
    }

    unsigned getProcessIndexForId(unsigned id);

    unsigned getCurrentProcessCount();

    inline uint64_t getStartTime() const {
        return m_startTimeSeconds;
    }
};

template <class PluginClass> PluginClass *S2E::getPlugin() const {
    return static_cast<PluginClass *>(getPlugin(PluginClass::getPluginInfoStatic()->name));
}

/// \brief Terminate state if assertion fails
///
/// *Soft* assertion, it will only terminate state on failure.
///
/// The \p message parameter may contain stream operators:
/// `s2e_assert(state, a == b, a << " does not equal " << b)`.
///
/// It is possible to avoid passing current state pointer to the function where
/// assertion is needed. In this case, you can use NULL for the
/// \p state parameter, and g_s2e_state will be used as current state.
///
/// \note Unreachable code assertion will fail if you use a different (not
/// the current one) state for the \p state parameter.
///
/// \param state current state
/// \param condition asserted value
/// \param message message to be printed
#define s2e_assert(state, condition, message)                                                                     \
    do {                                                                                                          \
        if (!(condition)) {                                                                                       \
            S2EExecutionState *currentState = (state) != NULL ? (state) : g_s2e_state;                            \
            int currentStateId = currentState ? currentState->getID() : -1;                                       \
            g_s2e->getWarningsStream() << __FILE__ << ":" << __LINE__ << ": " << __PRETTY_FUNCTION__              \
                                       << ": Assertion `" << #condition << "' failed in state " << currentStateId \
                                       << ": " << message << "\n";                                                \
            print_stacktrace(s2e_warning_print, "state assertion failed");                                        \
            assert(currentState != NULL && "state assertion failed, no current state to terminate");              \
            g_s2e->getExecutor()->terminateStateEarly(*currentState, "state assertion failed");                   \
            assert(false && "Unreachable code - current state must be terminated");                               \
        }                                                                                                         \
    } while (0)

/// \brief Print message if assertion fails
///
/// *Extra Soft* assertion, it will only print assert-like message on failure.
///
/// The \p message parameter may contain stream operators:
/// `s2e_warn_assert(state, a == b, a << " does not equal " << b)`.
///
/// It is possible to avoid passing current state pointer to the function where
/// assertion is needed. In this case, you can use NULL for the
/// \p state parameter, and g_s2e_state will be used as current state.
///
/// \param state current state
/// \param condition asserted value
/// \param message message to be printed
#define s2e_warn_assert(state, condition, message)                                                                \
    do {                                                                                                          \
        if (!(condition)) {                                                                                       \
            S2EExecutionState *currentState = (state) != NULL ? (state) : g_s2e_state;                            \
            int currentStateId = currentState ? currentState->getID() : -1;                                       \
            g_s2e->getWarningsStream() << __FILE__ << ":" << __LINE__ << ": " << __PRETTY_FUNCTION__              \
                                       << ": Assertion `" << #condition << "' failed in state " << currentStateId \
                                       << ": " << message << "\n";                                                \
            print_stacktrace(s2e_warning_print, "state assertion failed");                                        \
        }                                                                                                         \
    } while (0)

} // namespace s2e

extern "C" {
extern s2e::S2E *g_s2e;
}

#endif // S2E_H
