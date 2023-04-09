///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
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

#include <tcg/tcg-llvm.h>

#include <s2e/S2E.h>

#include <s2e/ConfigFile.h>
#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Support/raw_ostream.h>
#include <s2e/s2e_libcpu.h>

#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/ExecutionEngine/ExecutionEngine.h>
#include <llvm/IR/Module.h>

#include <klee/Common.h>

#include <assert.h>
#include <deque>
#include <errno.h>
#include <iostream>
#include <sstream>
#include <stdlib.h>

#include <stdarg.h>
#include <stdio.h>

#include <sys/stat.h>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>
#include <boost/graph/adjacency_list.hpp>
#include <boost/graph/labeled_graph.hpp>
#include <boost/graph/topological_sort.hpp>

using namespace boost;

#ifndef _WIN32
#include <sys/types.h>
#include <unistd.h>
#endif

namespace s2e {

using namespace std;

S2E::S2E(const std::string &bitcodeLibraryDir) {
    m_bitcodeLibraryDir = bitcodeLibraryDir;
}

bool S2E::initialize(int argc, char **argv, TCGLLVMTranslator *translator, const std::string &configFileName,
                     const std::string &outputDirectory, bool setupUnbufferedStream, int verbose,
                     unsigned s2e_max_processes) {
    m_TCGLLVMTranslator = translator;

    if (s2e_max_processes < 1) {
        std::cerr << "You must at least allow one process for S2E." << '\n';
        return false;
    }

    if (s2e_max_processes > S2E_MAX_PROCESSES) {
        std::cerr << "S2E can handle at most " << S2E_MAX_PROCESSES << " processes." << '\n';
        std::cerr << "Please increase the S2E_MAX_PROCESSES constant." << '\n';
        return false;
    }

#ifdef CONFIG_WIN32
    if (s2e_max_processes > 1) {
        std::cerr << "S2E for Windows does not support more than one process" << '\n';
        return false;
    }
#endif

    auto tp = std::chrono::steady_clock::now();
    m_startTime = std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch());

    // We are the master process of our group
    setpgid(0, 0);

    m_setupUnbufferedStream = setupUnbufferedStream;
    m_maxInstances = s2e_max_processes;
    m_currentInstanceIndex = 0;
    m_currentInstanceId = 0;
    S2EShared *shared = m_sync.acquire();
    shared->currentInstanceCount = 1;
    shared->lastStateId = 0;
    shared->lastFileId = 1;
    shared->instanceIds[m_currentInstanceIndex] = m_currentInstanceId;
    shared->instancePids[m_currentInstanceIndex] = getpid();
    m_sync.release();

    /* Open output directory. Do it at the very beginning so that
       other init* functions can use it. */
    initOutputDirectory(outputDirectory, verbose, false);

    /* Parse configuration file */
    m_configFile = new s2e::ConfigFile(configFileName);

    /* Initialize KLEE command line options */
    initKleeOptions();

    /* Initialize S2EExecutor */
    initExecutor();

    initLogging();

    /* Load and initialize plugins */
    initPlugins();

    // Save all configuration files so that users can restore them if needed.
    // This is useful to reproduce runs.
    return backupConfigFiles(configFileName);
}

///
/// \brief Backup all the *.lua, *.sh, and *.bat files in the directory where the
/// main S2E config file resides. This is useful in case one needs to retrieve
/// the configuration of older experiments.
///
/// TODO: It really should be the caller's responsibility to do that. The S2E launch
/// script shall compute the s2e-last folder and make a backup of all the configuration.
/// For a fully-reproducible run, all binary files should be copied too.
///
/// \param configFileName the name of the config file (e.g., s2e-config.lua)
/// \return false is a file could not be copied, true otherwise
///
bool S2E::backupConfigFiles(const std::string &configFileName) {
    auto configFileDir = llvm::sys::path::parent_path(configFileName);
    if (configFileDir == "") {
        configFileDir = ".";
    }

    std::error_code error;

    auto outputDir = getOutputFilename("config-backup");
    error = llvm::sys::fs::create_directory(outputDir);
    if (error) {
        getWarningsStream() << "Could not create " << outputDir << '\n';
        return false;
    }

    for (llvm::sys::fs::directory_iterator i(configFileDir, error), e; i != e; i.increment(error)) {
        std::string entry = i->path();
        auto status = i->status();
        if (!status) {
            getWarningsStream() << "Error when querying " << entry << " - " << status.getError().message() << '\n';
            continue;
        }

        if (status->type() != llvm::sys::fs::file_type::regular_file) {
            continue;
        }

        const char *extensions[] = {".lua", ".sh", ".bat", nullptr};
        for (unsigned i = 0; extensions[i]; ++i) {
            if (!boost::algorithm::ends_with(entry, extensions[i])) {
                continue;
            }
            auto fileName = llvm::sys::path::filename(entry);
            std::stringstream destination;
            destination << outputDir << "/" << fileName.str();
            error = llvm::sys::fs::copy_file(entry, destination.str());
            if (error) {
                getWarningsStream() << "Could not backup " << entry << " to " << destination.str() << "\n";
                return false;
            }
        }
    }

    return true;
}

void S2E::writeBitCodeToFile() {
    std::string fileName = getOutputFilename("module.bc");

    std::error_code error;
    llvm::raw_fd_ostream o(fileName, error, llvm::sys::fs::OF_None);

    llvm::Module *module = m_TCGLLVMTranslator->getModule();

    // Output the bitcode file to stdout
    llvm::WriteBitcodeToFile(*module, o);
}

S2E::~S2E() {
    getWarningsStream() << "Terminating node id " << m_currentInstanceId << " (instance slot " << m_currentInstanceIndex
                        << ")\n";

    // Delete all the stuff used by the instance
    m_pluginManager.destroy();

    // Tell other instances we are dead so they can fork more
    S2EShared *shared = m_sync.acquire();

    assert(shared->instanceIds[m_currentInstanceIndex] == m_currentInstanceId);
    shared->instanceIds[m_currentInstanceIndex] = (unsigned) -1;
    shared->instancePids[m_currentInstanceIndex] = (unsigned) -1;
    assert(shared->currentInstanceCount > 0);
    --shared->currentInstanceCount;

    m_sync.release();

    writeBitCodeToFile();

    // KModule wants to delete the llvm::Module in destroyer.
    // llvm::ModuleProvider wants to delete it too. We have to arbitrate.

    // Make sure everything is clean
    m_s2eExecutor->flushTb();

    delete m_s2eExecutor;

    delete m_configFile;

    // This is the last thing that will show in the debug log,
    // it helps making sure that shutdown went fine.
    getDebugStream() << "Engine terminated.\n";
    flushOutputStreams();

    delete m_warningStream;
    delete m_infoStream;
    delete m_debugStream;

    delete m_infoFileRaw;
    delete m_warningsFileRaw;
    delete m_debugFileRaw;
}

std::string S2E::getOutputFilename(const std::string &fileName) {
    llvm::SmallString<128> filePath(m_outputDirectory);
    llvm::sys::path::append(filePath, fileName);

    return std::string(filePath.str());
}

llvm::raw_ostream *S2E::openOutputFile(const std::string &fileName) {
    std::string path = getOutputFilename(fileName);
    std::error_code error;
    llvm::raw_fd_ostream *f = new llvm::raw_fd_ostream(path, error, llvm::sys::fs::OF_None);

    if (!f || error) {
        llvm::errs() << "Error opening " << path << ": " << error.message() << "\n";
        exit(-1);
    }

    return f;
}

void S2E::initOutputDirectory(const string &outputDirectory, int verbose, bool forked) {
    if (!forked) {
        // In case we create the first S2E process
        if (outputDirectory.empty()) {
            for (int i = 0;; i++) {
                ostringstream dirName;
                dirName << "s2e-out-" << i;

                llvm::SmallString<128> dirPath(".");
                llvm::sys::path::append(dirPath, dirName.str());

                if (!llvm::sys::fs::exists(dirPath)) {
                    m_outputDirectory = dirPath.str();
                    break;
                }
            }

        } else {
            m_outputDirectory = outputDirectory;
        }
        m_outputDirectoryBase = m_outputDirectory;
    } else {
        m_outputDirectory = m_outputDirectoryBase;
    }

#ifndef _WIN32
    if (m_maxInstances > 1) {
        // Create one output directory per child process.
        // This prevents child processes from clobbering each other's output.
        llvm::SmallString<128> dirPath(m_outputDirectory);

        ostringstream oss;
        oss << m_currentInstanceId;

        llvm::sys::path::append(dirPath, oss.str());

        assert(!llvm::sys::fs::exists(dirPath));
        m_outputDirectory = dirPath.str();
    }
#endif

    std::cout << "S2E: output directory = \"" << m_outputDirectory << "\"\n";

    std::error_code mkdirError = llvm::sys::fs::create_directories(m_outputDirectory);
    if (mkdirError) {
        std::cerr << "Could not create output directory " << m_outputDirectory << " error: " << mkdirError.message()
                  << '\n';
        exit(-1);
    }

#ifndef _WIN32
    // Fix directory permissions (createDirectoryOnDisk narrows umask)
    mode_t m = umask(0);
    umask(m);
    chmod(m_outputDirectory.c_str(), 0775 & ~m);

    if (!forked) {
        llvm::SmallString<128> s2eLast(".");
        llvm::sys::path::append(s2eLast, "s2e-last");

        if ((unlink(s2eLast.c_str()) < 0) && (errno != ENOENT)) {
            perror("ERROR: Cannot unlink s2e-last");
            exit(1);
        }

        if (symlink(m_outputDirectoryBase.c_str(), s2eLast.c_str()) < 0) {
            perror("ERROR: Cannot make symlink s2e-last");
            exit(1);
        }
    }
#endif

    setupStreams(forked, true);

    getDebugStream(nullptr) << "Revision: " << LIBCPU_REVISION << "\n";
    getDebugStream(nullptr) << "Config date: " << CONFIG_DATE << "\n\n";
}

void S2E::setupStreams(bool forked, bool reopen) {
    ios_base::sync_with_stdio(true);
    cout.setf(ios_base::unitbuf);
    cerr.setf(ios_base::unitbuf);

    if (forked) {
        /* Close old file descriptors */
        delete m_infoFileRaw;
        delete m_debugFileRaw;
        delete m_warningsFileRaw;
    }

    if (reopen) {
        m_infoFileRaw = openOutputFile("info.txt");
        m_debugFileRaw = openOutputFile("debug.txt");
        m_warningsFileRaw = openOutputFile("warnings.txt");
    }

    // Debug writes to debug.txt
    raw_tee_ostream *debugStream = new raw_tee_ostream(m_debugFileRaw);

    // Info writes to info.txt and debug.txt
    raw_tee_ostream *infoStream = new raw_tee_ostream(m_infoFileRaw);
    infoStream->addParentBuf(m_debugFileRaw);

    // Warnings appear in debug.txt, warnings.txt and on stderr in red color
    raw_tee_ostream *warningsStream = new raw_tee_ostream(m_warningsFileRaw);
    warningsStream->addParentBuf(m_debugFileRaw);
    warningsStream->addParentBuf(new raw_highlight_ostream(&llvm::errs()));

    // Select which streams also write to the terminal
    switch (m_consoleLevel) {
        case LOG_ALL:
        case LOG_DEBUG:
            debugStream->addParentBuf(&llvm::outs());
        case LOG_INFO:
            infoStream->addParentBuf(&llvm::outs());
        case LOG_WARN:
            /* Warning stream already prints to stderr */
            break;
        case LOG_NONE:
            /* Don't log anything to terminal */
            break;
    }

    m_debugStream = debugStream;
    m_infoStream = infoStream;
    m_warningStream = warningsStream;

    if (m_setupUnbufferedStream) {
        // Make contents valid when assertion fails
        m_infoFileRaw->SetUnbuffered();
        m_infoStream->SetUnbuffered();
        m_debugFileRaw->SetUnbuffered();
        m_debugStream->SetUnbuffered();
        m_warningsFileRaw->SetUnbuffered();
        m_warningStream->SetUnbuffered();
    }

    klee::klee_message_stream = m_infoStream;
    klee::klee_warning_stream = m_warningStream;
}

void S2E::initKleeOptions() {
    std::vector<std::string> kleeOptions = getConfig()->getStringList("s2e.kleeArgs");
    if (!kleeOptions.empty()) {
        int numArgs = kleeOptions.size() + 1;
        const char **kleeArgv = new const char *[numArgs + 1];

        kleeArgv[0] = "s2e.kleeArgs";
        kleeArgv[numArgs] = 0;

        for (unsigned int i = 0; i < kleeOptions.size(); ++i)
            kleeArgv[i + 1] = kleeOptions[i].c_str();

        llvm::cl::ParseCommandLineOptions(numArgs, (char **) kleeArgv);

        delete[] kleeArgv;
    }
}

void S2E::initLogging() {
    bool ok;
    std::string logLevel = getConfig()->getString("s2e.logging.logLevel", "", &ok);

    if (ok) {
        m_hasGlobalLogLevel = true;
        ok = parseLogLevel(logLevel, &m_globalLogLevel);
        if (ok) {
            std::cout << "Using log level override '" << logLevel << "'\n";
        } else {
            std::cerr << "Invalid global log level override '" << logLevel << "'\n";
        }
    }

    std::string consoleOutput = getConfig()->getString("s2e.logging.console", "", &ok);

    if (ok) {
        ok = parseLogLevel(consoleOutput, &m_consoleLevel);
        if (ok) {
            std::cout << "Setting console level to '" << consoleOutput << "'\n";
        } else {
            std::cerr << "Invalid log level '" << consoleOutput << "' for console output, defaulting to '"
                      << DEFAULT_CONSOLE_OUTPUT << "'\n";
            parseLogLevel(DEFAULT_CONSOLE_OUTPUT, &m_consoleLevel);
        }
        /* Setup streams according to configuration. Don't reopen files */
        setupStreams(false, false);
    }
}

void S2E::initPlugins() {
    if (!m_pluginManager.initialize(this, m_configFile)) {
        exit(-1);
    }
}

void S2E::initExecutor() {
    m_s2eExecutor = new S2EExecutor(this, m_TCGLLVMTranslator);
}

llvm::raw_ostream &S2E::getStream(llvm::raw_ostream &stream, const S2EExecutionState *state) const {
    fflush(stdout);
    fflush(stderr);

    stream.flush();

    if (state) {
        using namespace std::chrono;
        auto elapsed = steady_clock::now() - m_startTime;
        auto elapsedSeconds = duration_cast<seconds>(elapsed.time_since_epoch()).count();
        stream << elapsedSeconds << ' ';

        if (m_maxInstances > 1) {
            stream << "[Node " << m_currentInstanceId << "/" << m_currentInstanceIndex << " - State " << state->getID()
                   << "] ";
        } else {
            stream << "[State " << state->getID() << "] ";
        }
    }
    return stream;
}

void S2E::printf(llvm::raw_ostream &os, const char *fmt, ...) {
    va_list vl;
    va_start(vl, fmt);

    char str[512];
    vsnprintf(str, sizeof(str), fmt, vl);
    os << str;
}

int S2E::fork() {
#if defined(CONFIG_WIN32)
    return -1;
#else

    S2EShared *shared = m_sync.acquire();

    assert(shared->currentInstanceCount > 0);
    if (shared->currentInstanceCount == m_maxInstances) {
        m_sync.release();
        return -1;
    }

    unsigned newProcessId = shared->lastFileId;
    ++shared->lastFileId;
    ++shared->currentInstanceCount;

    m_sync.release();

    s2e_kvm_flush_disk();

    pid_t pid = ::fork();
    if (pid < 0) {
        // Fork failed

        shared = m_sync.acquire();

        // Do not decrement lastFileId, as other fork may have
        // succeeded while we were handling the failure.

        assert(shared->currentInstanceCount > 1);
        --shared->currentInstanceCount;

        m_sync.release();
        return -1;
    }

    if (pid == 0) {
        // Find a free slot in the instance map
        shared = m_sync.acquire();
        unsigned i = 0;
        for (i = 0; i < m_maxInstances; ++i) {
            if (shared->instanceIds[i] == (unsigned) -1) {
                shared->instanceIds[i] = newProcessId;
                shared->instancePids[i] = getpid();
                m_currentInstanceIndex = i;
                break;
            }
        }
        assert(i < m_maxInstances && "Failed to find a free slot");
        m_sync.release();

        unsigned oldInstanceId = m_currentInstanceId;
        m_currentInstanceId = newProcessId;
        // We are the child process, set up the log files again
        initOutputDirectory(m_outputDirectoryBase, 0, true);

        getWarningsStream() << "Started new node id=" << newProcessId << " index=" << m_currentInstanceIndex
                            << " pid=" << getpid() << " parent_id=" << oldInstanceId << "\n";

        s2e_kvm_clone_process();
    }

    return pid == 0 ? 1 : 0;
#endif
}

unsigned S2E::fetchAndIncrementStateId() {
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->lastStateId;
    ++shared->lastStateId;
    m_sync.release();
    return ret;
}
unsigned S2E::fetchNextStateId() {
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->lastStateId;
    m_sync.release();
    return ret;
}

unsigned S2E::getCurrentInstanceCount() {
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->currentInstanceCount;
    m_sync.release();
    return ret;
}

unsigned S2E::getInstanceId(unsigned index) {
    assert(index < m_maxInstances);
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->instanceIds[index];
    m_sync.release();
    return ret;
}

unsigned S2E::getInstanceIndexWithLowestId() {
    S2EShared *shared = m_sync.acquire();
    unsigned ret = shared->getInstanceIndexWithLowestId();
    m_sync.release();
    return ret;
}

} // namespace s2e

/******************************/

extern "C" {

s2e::S2E *g_s2e = nullptr;

void *get_s2e(void) {
    return g_s2e;
}

void s2e_initialize(int argc, char **argv, void *translator, const char *s2e_config_file, const char *s2e_output_dir,
                    int setup_unbuffered_stream, int verbose, unsigned s2e_max_processes, const char *bitcode_lib_dir) {
    auto ctx = reinterpret_cast<TCGLLVMTranslator *>(translator);
    g_s2e = new s2e::S2E(bitcode_lib_dir);
    if (!g_s2e->initialize(argc, argv, ctx, s2e_config_file ? s2e_config_file : "",
                           s2e_output_dir ? s2e_output_dir : "", setup_unbuffered_stream, verbose, s2e_max_processes)) {
        exit(-1);
    }
}

void s2e_close(void) {
    delete g_s2e;
    tcg_llvm_close(tcg_llvm_translator);
    tcg_llvm_translator = nullptr;
    g_s2e = nullptr;
}

void s2e_flush_output_streams(void) {
    g_s2e->flushOutputStreams();
}

int s2e_vprintf(const char *fmtstr, int warn, va_list args) {
    if (!g_s2e) {
        return 0;
    }

    char str[4096];
    int ret = vsnprintf(str, sizeof(str), fmtstr, args);

    if (warn) {
        g_s2e->getWarningsStream() << str;
    } else {
        g_s2e->getDebugStream() << str;
    }

    return ret;
}

void s2e_debug_print(const char *fmtstr, ...) {
    va_list vl;
    va_start(vl, fmtstr);
    s2e_vprintf(fmtstr, 0, vl);
    va_end(vl);
}

void s2e_warning_print(const char *fmtstr, ...) {
    va_list vl;
    va_start(vl, fmtstr);
    s2e_vprintf(fmtstr, 1, vl);
    va_end(vl);
}

void s2e_debug_print_hex(void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *) addr;
    char tempbuff[512] = {0};
    char line[512] = {0};

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                sprintf(tempbuff, "  %s\n", buff);
                strcat(line, tempbuff);
                g_s2e->getDebugStream() << line;
                line[0] = 0;
            }

            // Output the offset.
            sprintf(tempbuff, "  %04x ", i);
            strcat(line, tempbuff);
        }

        // Now the hex code for the specific character.
        sprintf(tempbuff, " %02x", pc[i]);
        strcat(line, tempbuff);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        sprintf(tempbuff, "   ");
        strcat(line, tempbuff);
        i++;
    }

    // And print the final ASCII bit.
    sprintf(tempbuff, "  %s\n", buff);
    strcat(line, tempbuff);
    g_s2e->getDebugStream() << line;
}

void s2e_print_constraints(void);
void s2e_print_constraints(void) {
    g_s2e->getDebugStream() << "===== Constraints =====\n";
    for (auto c : g_s2e_state->constraints()) {
        g_s2e->getDebugStream() << c << '\n';
    }
    g_s2e->getDebugStream() << "\n";
}

// Print a klee expression.
// Useful for invocations from GDB
void s2e_print_expr(void *expr);
void s2e_print_expr(void *expr) {
    klee::ref<klee::Expr> e = *(klee::ref<klee::Expr> *) expr;
    std::stringstream ss;
    ss << e;
    g_s2e->getDebugStream() << ss.str() << '\n';
}

void s2e_print_value(void *value);
void s2e_print_value(void *value) {
    llvm::Value *v = (llvm::Value *) value;
    g_s2e->getDebugStream() << *v << '\n';
}

extern "C" {
void s2e_execute_cmd(const char *cmd) {
    g_s2e->getConfig()->invokeLuaCommand(cmd);
}

// Non-S2E modules can redeclare this variable with __attribute__((weak))
// to check whether they run in S2E or not.
int g_s2e_linked = 1;
}

} // extern "C"
