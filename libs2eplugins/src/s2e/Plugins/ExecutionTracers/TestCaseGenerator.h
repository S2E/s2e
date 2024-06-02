///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2018, Cyberhaven
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

#ifndef S2E_PLUGINS_TCGEN_H
#define S2E_PLUGINS_TCGEN_H

#include <string>
#include <unordered_map>
#include <vector>

#include <llvm/Support/raw_ostream.h>

#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.h>
#include <s2e/test_case_generator/commands.h>

namespace s2e {
namespace plugins {
namespace testcases {

///
/// \brief Stores information about file chunks encoded in symbolic variable names
///
struct TestCaseFile {
    // Maps a chunk id to the size
    std::map<unsigned, unsigned> chunks;

    // Maps a chunk id to the data
    std::map<unsigned, const uint8_t *> chunksData;

    unsigned totalParts;
};

///
/// \brief Maps a test case file name to a test case file descriptor
///
typedef std::unordered_map<std::string, TestCaseFile> TestCaseFiles;

///
/// \brief Represents any byte-sized data
///
typedef std::vector<uint8_t> Data;

///
/// \brief Maps a test case file name to its concrete data
///
typedef std::unordered_map<std::string, Data> TestCaseData;

///
/// \brief Specifies the type of the test case to generate
///
enum TestCaseType : unsigned {
    TC_NONE = 0,

    // The test case will be written to the S2E's debug log
    TC_LOG = 1,

    // The test case is to be written to the execution trace file
    TC_TRACE = 2,

    // The test case is a concrete file written to to the output
    // folder on the host. Symbolic variable names must have a proper
    // encoding for such test cases to be generated.
    TC_FILE = 4
};

///
/// \brief Maps a sanitized file name to concrete data.
///
/// This map will be stored in each execution state and copied
/// on state fork, because each state may have different sets
/// of concrete input files.
///
/// We use an immutable map in order to avoid needless duplication,
/// as in general every state will have the exact same copy of the
/// concrete data.
///
typedef klee::ImmutableMap<std::string, Data> ConcreteFileTemplates;

///
/// \brief Generate test cases when states are killed and provides APIs to generate
/// test cases on-demand.
///
/// This plugin supports two types of test cases:
/// - Basic concrete input assignments. This is the simplest form, where each
///   symbolic variable will have its concrete value printed when the state terminates.
/// - Concrete files. This reconstructs complete concrete input files from
///   the symbolic variable names. The names must have a special encoding in order to be
///   reconstructed into files by this plugin.
///
/// Concrete file test cases
/// ========================
///
/// In order to make a file symbolic, the guest must create one or more symbolic
/// variables and write them over the original concrete data present in the file.
/// The symbolic variables must cover all the file without overlaps so that the
/// test case generator plugin can reassemble these variables and write back the concrete
/// data computed by the constraint solver to the right file locations.
///
/// In order for the concrete files to be assembled properly, the symbolic variable
/// names must follow this pattern:
///
/// .*?__symfile___(.+?)___(\\d+)_(\\d+)_symfile__.*
///
///                  ^--1    ^--2    ^--3
///
/// Group 1: this is the sanitized name of the symbolic file. Symbolic variable names
/// cannot have any special characters, so tools that create symbolic files (e.g., s2ecmd)
/// must first strip all non-alphanumerical characters and replace them with underscores.
///
/// Group 2: this is the chunk identifier of the data encoded by the symbolic variable.
/// The plugin sorts chunks by increasing indentifiers and writes them consecutively to the
/// concrete file. For performance reasons, the guest would  typically split a large file
/// into chunks of equal-sized symbolic variables (e.g., 4KB). When chunk size is 1, the
/// chunk identifier is the offset of the byte in the test case file.
///
/// Group 3: this is the total number of chunks. The test case generator plugin uses
/// this as a sanity check to make sure all variable names are present and no chunk is
/// missing. When chunk size is 1, this value is equal to the concrete file size.
///
/// The following symbolic variable name of size 1 encodes a chunk for the x__image_iso file name
/// (which was stripped from the original x:\image.iso), starting at offset 47105. The
/// expected total file size is 368640.
///
/// v1___symfile___x__image_iso___47105_368640_symfile___1
///
/// Partial symbolic files
/// ======================
///
/// Simetimes input files are large and making them entirely symbolic is impractial.
/// The test case generator plugin provides a mechanism to make only a subset of bytes
/// symbolic, while keeping the rest concrete. Here is how it works:
///
/// 1. The guest sends the original concrete input file and its sanitized name to the plugin.
///    This is the concrete file template.
/// 2. The guest creates symbolic variable names only for those bytes that must be
///    symbolic.
/// 3. When generating the test case, the plugin first writes the original concrete
///    input file template and then overwrites the parts that where made symbolic with concrete
///    bytes computed by the constraint solver.
///
/// For example, if a user has a file whose size is 16 bytes and wants to make
/// bytes 1 and 6 symbolic, the user will proceed as follows:
///
/// 1. Send "01 43 44 30 30 31 01 00  4c 49 4e 55 58 20 20 20" to the plugin
///    together with its sanitized name, e.g., "input_txt".
///
/// 2. Create the following symbolic variables of 1 byte each with the following names:
///    __symfile___input_txt___1_16_symfile__
///    __symfile___input_txt___6_16_symfile__
///
/// 3. Suppose the constraint solver assigns 0x12 and 0x77 for the 2nd and 7th bytes
///    respectively. The test case will look as follows:
///
///    "01 12 44 30 30 31 77 00  4c 49 4e 55 58 20 20 20"
///        ^^--           ^^--modified bytes
///
/// Notes:
///
/// - When using partial symbolic files, the chunk size must be one.
///
class TestCaseGenerator : public Plugin, public IPluginInvoker {
    S2E_PLUGIN

private:
    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

public:
    TestCaseGenerator(S2E *s2e);

    void initialize();

    void enable();
    void disable();

    ///
    /// \brief Generate a test case for the given execution state
    ///
    /// \param state the execution state
    /// \param prefix the prefix to use for the file name if the test case is a concrete file
    /// \param type the type of the test case to generate
    ///
    void generateTestCases(S2EExecutionState *state, const std::string &prefix, TestCaseType type);

    ///
    /// \brief Compute and write concrete test case files to disk
    ///
    /// \param inputs the concrete inputs that must contain symbolic file chunks
    /// \param prefix the prefix to add to the generated test case file
    /// \param fileNames returns the location of the written file names
    /// \param templates concrete file templates returned by getTemplates()
    ///
    void assembleTestCaseToFiles(const ConcreteInputs &inputs, const ConcreteFileTemplates &templates,
                                 const std::string &prefix, std::vector<std::string> &fileNames);

    ///
    /// \brief Compute the content of concrete test case files
    /// \param inputs the concrete inputs that must contain symbolic file chunks
    /// \param data the computed test case files
    /// \param templates concrete file templates returned by getTemplates()
    ///
    void assembleTestCaseToFiles(const ConcreteInputs &inputs, const ConcreteFileTemplates &templates,
                                 TestCaseData &data);

    ///
    /// \brief Compute the content of concrete test case files
    /// \param assignment the assignment of symbolic variables to concrete values
    /// \param data the computed test case files
    /// \param templates concrete file templates returned by getTemplates()
    ///
    void assembleTestCaseToFiles(const klee::Assignment &assignment, const ConcreteFileTemplates &templates,
                                 TestCaseData &data);

    ///
    /// \brief Get concrete file templates, if any
    ///
    /// Concrete file templates are present when part of input files have
    /// been made symbolic.
    ///
    /// \param state the state whose concrete file templates to get
    /// \return a mapping of a sanitized file name to the actual file content
    ///
    const ConcreteFileTemplates &getTemplates(S2EExecutionState *state) const;

private:
    sigc::connection m_stateForkConnection;
    sigc::connection m_stateKillConnection;
    sigc::connection m_linuxSegFaultConnection;
    sigc::connection m_windowsUserCrashConnection;
    sigc::connection m_windowsKernelCrashConnection;

    ExecutionTracer *m_tracer;

    void onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                     const std::vector<klee::ref<klee::Expr>> &newConditions);
    void onStateKill(S2EExecutionState *state);
    void onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data);
    void onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc);
    void onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc);

    void writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs);
    void writeSimpleTestCase(llvm::raw_ostream &os, const ConcreteInputs &inputs);

    bool getFilePart(const std::string &variableName, std::string &filePath, unsigned *part, unsigned *total) const;
    void getFiles(const ConcreteInputs &inputs, TestCaseFiles &files);
    bool assembleChunks(const std::string &name, const TestCaseFile &file, const ConcreteFileTemplates &templates,
                        std::vector<uint8_t> &out);

    void handleAddConcreteFileChunk(S2EExecutionState *state, const S2E_TCGEN_CONCRETE_FILE_CHUNK &chunk);
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};
} // namespace testcases
} // namespace plugins
} // namespace s2e

#endif
