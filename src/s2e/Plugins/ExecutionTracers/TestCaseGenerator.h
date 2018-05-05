///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_TCGEN_H
#define S2E_PLUGINS_TCGEN_H

#include <llvm/Support/raw_ostream.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/ExecutionTracers/ExecutionTracer.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.h>
#include <string>
#include <unordered_map>
#include <vector>

namespace s2e {
namespace plugins {
namespace testcases {

struct TestCaseFile {
    /* Maps a chunk id to the size */
    std::map<unsigned, unsigned> chunks;
    /* Maps a chunk id to the data */
    std::map<unsigned, const uint8_t *> chunksData;
    unsigned totalParts;
};

typedef std::map<std::string, TestCaseFile> TestCaseFiles;

typedef std::vector<uint8_t> Data;
typedef std::unordered_map<std::string, Data> TestCaseData;

enum TestCaseType : unsigned { TC_NONE = 0, TC_LOG = 1, TC_TRACE = 2, TC_FILE = 4 };

/** Handler required for KLEE interpreter */
class TestCaseGenerator : public Plugin {
    S2E_PLUGIN

private:
    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

public:
    TestCaseGenerator(S2E *s2e);

    void initialize();

    void enable();
    void disable();

    void generateTestCases(S2EExecutionState *state, const std::string &prefix, TestCaseType type);

    void assembleTestCaseToFiles(const ConcreteInputs &inputs, const std::string &prefix,
                                 std::vector<std::string> &fileNames);
    void assembleTestCaseToFiles(const ConcreteInputs &inputs, TestCaseData &data);
    void assembleTestCaseToFiles(const klee::Assignment &assignment, TestCaseData &data);

private:
    sigc::connection m_connection;
    ExecutionTracer *m_tracer;

    void onStateKill(S2EExecutionState *state);
    void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc);
    void onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc);
    void onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc);

    void writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs);
    void writeSimpleTestCase(llvm::raw_ostream &os, const ConcreteInputs &inputs);

    bool getFilePart(const std::string &variableName, std::string &filePath, unsigned *part, unsigned *total) const;
    void getFiles(const ConcreteInputs &inputs, TestCaseFiles &files);
    bool assembleChunks(const TestCaseFile &file, std::vector<uint8_t> &out);
};
}
}
}

#endif
