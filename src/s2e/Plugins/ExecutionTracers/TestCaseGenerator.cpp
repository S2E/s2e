///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cctype>
#include <fstream>
#include <iomanip>

#include <boost/regex.hpp>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include "TestCaseGenerator.h"

namespace s2e {
namespace plugins {
namespace testcases {

// TODO: this must be in sync with s2ecmd
static const boost::regex SymbolicFileRegEx(".*?__symfile___(.+?)___(\\d+)_(\\d+)_symfile__.*", boost::regex::perl);

TestCaseType operator|(TestCaseType a, TestCaseType b) {
    return static_cast<TestCaseType>(static_cast<unsigned>(a) | static_cast<unsigned>(b));
}

bool operator&(TestCaseType a, TestCaseType b) {
    return static_cast<bool>(static_cast<unsigned>(a) & static_cast<unsigned>(b));
}

S2E_DEFINE_PLUGIN(TestCaseGenerator, "TestCaseGenerator plugin", "TestCaseGenerator");

TestCaseGenerator::TestCaseGenerator(S2E *s2e) : Plugin(s2e) {
}

void TestCaseGenerator::initialize() {
    ConfigFile *cfg = s2e()->getConfig();
    bool tcOnKill = cfg->getBool(getConfigKey() + ".generateOnStateKill", true);
    bool tcOnSegfault = cfg->getBool(getConfigKey() + ".generateOnSegfault", true);

    if (tcOnKill) {
        m_connection =
            s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateKill));
    }

    m_tracer = s2e()->getPlugin<ExecutionTracer>();

    // TODO: add support for Windows
    // TODO: refactor POV generation, which is another type of test case
    if (tcOnSegfault) {
        LinuxMonitor *linux = s2e()->getPlugin<LinuxMonitor>();
        if (linux) {
            linux->onSegFault.connect(sigc::mem_fun(*this, &TestCaseGenerator::onSegFault));
        } else {
            getWarningsStream() << "LinuxMonitor not enabled, cannot produce test cases on crashes\n";
            exit(-1);
        }
    }
}

void TestCaseGenerator::enable() {
    if (!m_connection.connected()) {
        m_connection =
            s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateKill));
    }
}

void TestCaseGenerator::disable() {
    m_connection.disconnect();
}

void TestCaseGenerator::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
    std::stringstream ss;
    ss << "crash:" << hexval(pid) << ":" << hexval(pc);
    generateTestCases(state, ss.str(), TC_FILE);
}

void TestCaseGenerator::onStateKill(S2EExecutionState *state) {
    generateTestCases(state, "kill", TC_LOG | TC_TRACE | TC_FILE);
}

void TestCaseGenerator::generateTestCases(S2EExecutionState *state, const std::string &prefix, TestCaseType type) {
    getInfoStream(state) << "generating test case at address " << hexval(state->getPc()) << '\n';

    ConcreteInputs inputs;
    bool success = s2e()->getExecutor()->getSymbolicSolution(*state, inputs);

    if (!success) {
        getWarningsStream(state) << "Could not get symbolic solutions" << '\n';
        return;
    }

    if (type & TC_LOG) {
        writeSimpleTestCase(getDebugStream(state), inputs);
    }

    if (type & TC_TRACE) {
        writeTestCaseToTrace(state, inputs);
    }

    if (type & TC_FILE) {
        std::stringstream ss;
        ss << "testcase-" << prefix << "-" << state->getID();
        std::vector<std::string> fileNames;
        assembleTestCaseToFiles(inputs, ss.str(), fileNames);
        for (const auto &it : fileNames) {
            getDebugStream(state) << "Generated " << it << "\n";
        }
    }
}

void TestCaseGenerator::writeSimpleTestCase(llvm::raw_ostream &os, const ConcreteInputs &inputs) {
    std::stringstream ss;
    ConcreteInputs::const_iterator it;
    for (it = inputs.begin(); it != inputs.end(); ++it) {
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

    os << ss.str();
}

void TestCaseGenerator::writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs) {
    if (!m_tracer) {
        getWarningsStream(state) << "ExecutionTracer not enabled, cannot write concrete inputs to trace file\n";
        return;
    }

    unsigned bufsize;
    ExecutionTraceTestCase *tc = ExecutionTraceTestCase::serialize(&bufsize, inputs);
    m_tracer->writeData(state, tc, bufsize, TRACE_TESTCASE);
    ExecutionTraceTestCase::deallocate(tc);
}

///
/// \brief Splits a variable name into chunk information
///
/// \param variableName the name of the variable
/// \param filePath the file path encoded in the variable name
/// \param part the part of the chunk encoded in the variable name
/// \param numberOfParts the total number of chunks encoded in the variable name
/// \return
///
bool TestCaseGenerator::getFilePart(const std::string &variableName, std::string &filePath, unsigned *part,
                                    unsigned *numberOfParts) const {

    boost::smatch what;
    if (!boost::regex_match(variableName, what, SymbolicFileRegEx)) {
        return false;
    }

    if (what.size() != 4) {
        return false;
    }

    filePath = what[1];

    std::string partStr = what[2];
    std::string numberOfPartsStr = what[3];

    *part = atoi(partStr.c_str());
    *numberOfParts = atoi(numberOfPartsStr.c_str());

    if (*part >= *numberOfParts) {
        return false;
    }

    return true;
}

///
/// \brief Decodes file information encoded in symbolic variable names
///
/// \param inputs Concrete inputs whose variable names may contain file chunk data
/// \param files The decoded information
///
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

///
/// \brief Assembles the given list of concrete file chunks
///
/// \param file the chunked representation of the concrete file
/// \param out the assembled file content
/// \return true if assembling was successful
///
bool TestCaseGenerator::assembleChunks(const TestCaseFile &file, std::vector<uint8_t> &out) {
    if (file.totalParts != file.chunks.size()) {
        getWarningsStream() << "Test case has incorrect number of parts\n";
        return false;
    }

    if (file.chunksData.size() != file.chunks.size()) {
        getWarningsStream() << "Test case has not enough data chunks\n";
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

    out.resize(size);

    foreach2 (it, file.chunksData.begin(), file.chunksData.end()) {
        unsigned id = (*it).first;
        const uint8_t *chunkData = (*it).second;
        unsigned chunkSize = (*file.chunks.find(id)).second;
        memcpy(&out[offsets[id]], chunkData, chunkSize);
    }

    return true;
}

///
/// \brief Decodes concrete file chunks encoded in concrete inputs and assembles them into actual files.
///
/// Symbolic files may be large, it is more efficient to represent them as several
/// symbolic arrays, each identified by a special name. Each symbolic array represents a chunk of the
/// symbolic file. The name of the array encodes the position of the chunk in the file.
///
/// A chunk name looks like this:
/// v0___symfile____(guest_file_name)___(chunk_id)_(number_of_chunks)_symfile___0
///
/// - (guest_file_name) is any name chosen by the guest to identify the file.
///   It is usually the guest file path with special characters replaced with underscores.
/// - (chunk_id) is the position of the chunk in the file.
/// - (number_of_chunks) is the total number of chunks for the file.
///
/// For small files, there is often only one chunk:
/// v0___symfile____tmp_input___0_1_symfile___0 = {0x0, .... }
/// This is the first (0) chunk of a file that has only one (1) chunk. That file was called /tmp/input.
///
///
/// \param inputs the concrete inputs that must contain symbolic file chunks
/// \param prefix the prefix to add to the generated test case file
/// \param fileNames returns the location of the written file names
///
void TestCaseGenerator::assembleTestCaseToFiles(const ConcreteInputs &inputs, const std::string &prefix,
                                                std::vector<std::string> &fileNames) {
    TestCaseFiles files;
    getFiles(inputs, files);

    foreach2 (it, files.begin(), files.end()) {
        const std::string &name = (*it).first;
        TestCaseFile &file = (*it).second;
        std::vector<uint8_t> out;
        if (!assembleChunks(file, out)) {
            getWarningsStream() << "Could not generate concrete test file for " << (*it).first << "\n";
            continue;
        }

        std::stringstream ss;
        ss << prefix << "-" << name;
        std::string outputFileName = s2e()->getOutputFilename(ss.str());
        fileNames.push_back(outputFileName);
        std::ofstream ofs(outputFileName.c_str(), std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
        ofs.write((const char *) &out[0], out.size());
        ofs.close();
    }
}
}
}
}
