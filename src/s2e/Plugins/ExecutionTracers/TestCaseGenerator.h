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
#include <string>

namespace s2e {
namespace plugins {

struct TestCaseFile {
    /* Maps a chunk id to the size */
    std::map<unsigned, unsigned> chunks;
    /* Maps a chunk id to the data */
    std::map<unsigned, const uint8_t *> chunksData;
    unsigned totalParts;
};

typedef std::map<std::string, TestCaseFile> TestCaseFiles;

/** Handler required for KLEE interpreter */
class TestCaseGenerator : public Plugin {
    S2E_PLUGIN

private:
    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

    unsigned m_testIndex;     // number of tests written so far
    unsigned m_pathsExplored; // number of paths explored so far

public:
    TestCaseGenerator(S2E *s2e);

    void initialize();

    void enable();
    void disable();

    void writeTestCase(S2EExecutionState *state, llvm::raw_ostream *out);
    llvm::raw_ostream *getTestCaseFile(S2EExecutionState *state);

private:
    sigc::connection m_connection;

    void onStateKill(S2EExecutionState *state);

    bool isFilePart(const std::string &variableName);
    bool getFilePart(const std::string &variableName, std::string &filePath, unsigned *part, unsigned *total) const;
    void getFiles(const ConcreteInputs &inputs, TestCaseFiles &files);
    bool generateFile(S2EExecutionState *state, const std::string &filePath, TestCaseFile &file);
    void generateFiles(S2EExecutionState *state, TestCaseFiles &files);
};
}
}

#endif
