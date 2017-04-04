///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cctype>
#include <fstream>
#include <iomanip>

#include <llvm/Support/Path.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include "ExecutionTracer.h"
#include "TestCaseGenerator.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(TestCaseGenerator, "TestCaseGenerator plugin", "TestCaseGenerator", "ExecutionTracer");

TestCaseGenerator::TestCaseGenerator(S2E *s2e) : Plugin(s2e) {
    m_testIndex = 0;
    m_pathsExplored = 0;
}

void TestCaseGenerator::initialize() {
    m_connection = s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateKill));
}

void TestCaseGenerator::enable() {
    if (m_connection.connected() == false) {
        m_connection =
            s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateKill));
    }
}

void TestCaseGenerator::disable() {
    m_connection.disconnect();
}

void TestCaseGenerator::onStateKill(S2EExecutionState *state) {
    getInfoStream() << "TestCaseGenerator: processTestCase of state " << state->getID() << " at address "
                    << hexval(state->getPc()) << '\n';

    ConcreteInputs out;
    bool success = s2e()->getExecutor()->getSymbolicSolution(*state, out);

    if (!success) {
        getWarningsStream() << "Could not get symbolic solutions" << '\n';
        return;
    }

    getInfoStream() << '\n';

    ExecutionTracer *tracer = (ExecutionTracer *) s2e()->getPlugin("ExecutionTracer");
    assert(tracer);

    std::stringstream ss;
    ConcreteInputs::iterator it;
    for (it = out.begin(); it != out.end(); ++it) {
        const VarValuePair &vp = *it;
        ss << std::setw(20) << vp.first << " = {";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            if (i != 0)
                ss << ", ";
            ss << std::setw(2) << std::setfill('0') << "0x" << std::hex << (unsigned) vp.second[i] << std::dec;
        }
        ss << "}" << std::setfill(' ') << "; ";

        if (vp.second.size() == sizeof(int32_t)) {
            int32_t valueAsInt = vp.second[0] | ((int32_t) vp.second[1] << 8) | ((int32_t) vp.second[2] << 16) |
                                 ((int32_t) vp.second[3] << 24);
            ss << "(int32_t) " << valueAsInt << ", ";
        }
        if (vp.second.size() == sizeof(int64_t)) {
            int64_t valueAsInt = vp.second[0] | ((int64_t) vp.second[1] << 8) | ((int64_t) vp.second[2] << 16) |
                                 ((int64_t) vp.second[3] << 24) | ((int64_t) vp.second[4] << 32) |
                                 ((int64_t) vp.second[5] << 40) | ((int64_t) vp.second[6] << 48) |
                                 ((int64_t) vp.second[7] << 56);
            ss << "(int64_t) " << valueAsInt << ", ";
        }

        ss << "(string) \"";
        for (unsigned i = 0; i < vp.second.size(); ++i) {
            ss << (char) (std::isprint(vp.second[i]) ? vp.second[i] : '.');
        }
        ss << "\"\n";
    }

    getInfoStream() << ss.str();

    unsigned bufsize;
    ExecutionTraceTestCase *tc = ExecutionTraceTestCase::serialize(&bufsize, out);
    tracer->writeData(state, tc, bufsize, TRACE_TESTCASE);
    ExecutionTraceTestCase::deallocate(tc);
}

llvm::raw_ostream *TestCaseGenerator::getTestCaseFile(S2EExecutionState *state) {
    std::stringstream testCaseName;
    testCaseName << "testcase" << state->getID() << ".txt";
    llvm::raw_ostream *out = s2e()->openOutputFile(testCaseName.str());

    if (!out) {
        getWarningsStream(state) << "TestCaseGenerator: could not open file " << testCaseName.str() << '\n';
        return NULL;
    }

    return out;
}

bool TestCaseGenerator::isFilePart(const std::string &variableName) {
    const std::string startMarker = "__symfile$$$";
    return variableName.find(startMarker) != std::string::npos;
}

/* The format of the variable is __symfile$$$/path/to/file$$$chunkid$chunkcount$symfile__ */
bool TestCaseGenerator::getFilePart(const std::string &variableName, std::string &filePath, unsigned *part,
                                    unsigned *numberOfParts) const {
    /** Find the file name */
    const std::string startMarker = "__symfile$$$";
    size_t fileNameStart = variableName.find(startMarker);
    if (fileNameStart == std::string::npos) {
        return false;
    }
    fileNameStart += startMarker.size();

    size_t fileNameEnd = variableName.find("$$$", fileNameStart);
    if (fileNameEnd == std::string::npos) {
        return false;
    }

    filePath = variableName.substr(fileNameStart, fileNameEnd - fileNameStart);

    /** Extract the chunk id and count */
    size_t chunkCountStart = fileNameEnd += 3;

    const std::string endMarker = "$symfile__";
    size_t endMarkerStart = variableName.find(endMarker);
    if (endMarkerStart == std::string::npos) {
        return false;
    }

    std::string counts = variableName.substr(chunkCountStart, endMarkerStart);
    sscanf(counts.c_str(), "%d$%d", part, numberOfParts);
    return true;
}

void TestCaseGenerator::getFiles(const ConcreteInputs &inputs, TestCaseFiles &files) {
    ConcreteInputs::const_iterator it;
    for (it = inputs.begin(); it != inputs.end(); ++it) {
        const VarValuePair &vp = *it;
        const std::string &varName = vp.first;
        unsigned chunkSize = vp.second.size();

        std::string filePath;
        unsigned part, total;

        if (!getFilePart(varName, filePath, &part, &total)) {
            continue;
        }

        files[filePath].chunks[part] = chunkSize;
        files[filePath].chunksData[part] = &vp.second[0];
        files[filePath].totalParts = total;
    }
}

bool TestCaseGenerator::generateFile(S2EExecutionState *state, const std::string &filePath, TestCaseFile &file) {
    if (file.totalParts != file.chunks.size()) {
        getWarningsStream() << "Test case for " << filePath << " has incorrect number of parts\n";
        return false;
    }

    if (file.chunksData.size() != file.chunks.size()) {
        getWarningsStream() << "Test case for " << filePath << " has not enough data chunks\n";
        return false;
    }

    // Get the total size
    // The loop supposes the chunks are traversed in increasing order
    unsigned size = 0;
    std::vector<unsigned> offsets;
    foreach2 (it, file.chunks.begin(), file.chunks.end()) {
        offsets.push_back(size);
        size += (*it).second;
    }

    char *data = new char[size];

    foreach2 (it, file.chunksData.begin(), file.chunksData.end()) {
        unsigned id = (*it).first;
        const uint8_t *chunkData = (*it).second;
        memcpy(data + offsets[id], chunkData, file.chunks[id]);
    }

    std::string fileName = llvm::sys::path::filename(filePath);
    std::stringstream ss;
    ss << "testcase" << state->getID() << "-file-" << fileName;

    std::string outputFileName = s2e()->getOutputFilename(ss.str());

    getDebugStream() << "TestCaseGenerator: generating concrete file for " << filePath << " in " << outputFileName
                     << "\n";
    std::ofstream ofs(outputFileName.c_str(), std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
    ofs.write(data, size);
    ofs.close();
    delete[] data;
    return true;
}

void TestCaseGenerator::generateFiles(S2EExecutionState *state, TestCaseFiles &files) {
    foreach2 (it, files.begin(), files.end()) {
        TestCaseFile &file = (*it).second;
        if (!generateFile(state, (*it).first, file)) {
            getWarningsStream(state) << "Could not generate concrete test file for " << (*it).first << "\n";
        }
    }
}

void TestCaseGenerator::writeTestCase(S2EExecutionState *state, llvm::raw_ostream *out) {
    getInfoStream() << "TestCaseGenerator: writing test case of state " << state->getID() << '\n';

    ConcreteInputs inputs;
    bool success = s2e()->getExecutor()->getSymbolicSolution(*state, inputs);

    if (!success) {
        getWarningsStream() << "TestCaseGenerator: Could not get symbolic solutions for state " << state->getID()
                            << '\n';
        return;
    }

    TestCaseFiles files;
    getFiles(inputs, files);
    generateFiles(state, files);

    *out << "//////////////////\n";
    *out << "//Program inputs//\n";
    *out << "//////////////////\n\n";

    ConcreteInputs::iterator it;
    for (it = inputs.begin(); it != inputs.end(); ++it) {
        const VarValuePair &vp = *it;

        if (isFilePart(vp.first)) {
            continue;
        }

        *out << "char " << vp.first << "[] = {";

        for (unsigned i = 0; i < vp.second.size(); ++i) {
            uint8_t byte = vp.second[i];
            if (isalnum(byte)) {
                *out << "'" << (char) byte << "'";
            } else {
                *out << hexval(byte);
            }

            if (i < vp.second.size() - 1) {
                *out << ", ";
            }
        }

        *out << "};\n";
    }
}
}
}
