///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2017-2018, Cyberhaven
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

#include <cctype>
#include <fstream>
#include <iomanip>

#include <boost/regex.hpp>
#include <klee/Internal/ADT/ImmutableMap.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <s2e/Plugins/OSMonitors/Windows/WindowsCrashMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <TraceEntries.pb.h>

#include "TestCaseGenerator.h"

namespace s2e {
namespace plugins {
namespace testcases {

namespace {

class TestCaseGeneratorState : public PluginState {
private:
    ConcreteFileTemplates m_concreteFiles;

public:
    virtual TestCaseGeneratorState *clone() const {
        return new TestCaseGeneratorState(*this);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new TestCaseGeneratorState();
    }

    Data getChunk(const std::string &name) {
        auto dataPtr = m_concreteFiles.lookup(name);
        if (dataPtr == nullptr) {
            return Data();
        } else {
            return dataPtr->second;
        }
    }

    void addChunk(const std::string &name, unsigned offset, const Data &chunk) {
        auto data = getChunk(name);

        if (data.size() < (offset + chunk.size())) {
            data.resize(offset + chunk.size());
        }

        for (unsigned i = 0; i < chunk.size(); ++i) {
            data[offset + i] = chunk[i];
        }

        m_concreteFiles = m_concreteFiles.replace(std::make_pair(name, data));
    }

    const ConcreteFileTemplates &getTemplates() const {
        return m_concreteFiles;
    }
};
} // namespace

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
    m_tracer = s2e()->getPlugin<ExecutionTracer>();
    enable();
}

void TestCaseGenerator::enable() {
    ConfigFile *cfg = s2e()->getConfig();

    bool tcOnFork = cfg->getBool(getConfigKey() + ".generateOnStateFork", false);
    bool tcOnKill = cfg->getBool(getConfigKey() + ".generateOnStateKill", true);
    bool tcOnSegfault = cfg->getBool(getConfigKey() + ".generateOnSegfault", true);

    if (tcOnFork) {
        m_stateForkConnection.disconnect();
        m_stateForkConnection =
            s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateFork));
    }

    if (tcOnKill) {
        m_stateKillConnection.disconnect();
        m_stateKillConnection =
            s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &TestCaseGenerator::onStateKill));
    }

    // TODO: refactor POV generation, which is another type of test case
    if (tcOnSegfault) {
        WindowsCrashMonitor *windows = s2e()->getPlugin<WindowsCrashMonitor>();
        LinuxMonitor *linux = s2e()->getPlugin<LinuxMonitor>();
        if (linux) {
            m_linuxSegFaultConnection.disconnect();
            m_linuxSegFaultConnection = linux->onSegFault.connect(sigc::mem_fun(*this, &TestCaseGenerator::onSegFault));
        } else if (windows) {
            m_windowsKernelCrashConnection.disconnect();
            m_windowsKernelCrashConnection.disconnect();

            m_windowsUserCrashConnection =
                windows->onUserModeCrash.connect(sigc::mem_fun(*this, &TestCaseGenerator::onWindowsUserCrash));
            m_windowsKernelCrashConnection =
                windows->onKernelModeCrash.connect(sigc::mem_fun(*this, &TestCaseGenerator::onWindowsKernelCrash));
        } else {
            getWarningsStream() << "No suitable crash sources enabled, cannot produce test cases on crashes\n";
            exit(-1);
        }
    }
}

void TestCaseGenerator::disable() {
    m_stateForkConnection.disconnect();
    m_stateKillConnection.disconnect();
    m_linuxSegFaultConnection.disconnect();
    m_windowsKernelCrashConnection.disconnect();
    m_windowsUserCrashConnection.disconnect();
}

void TestCaseGenerator::onWindowsUserCrash(S2EExecutionState *state, const WindowsUserModeCrash &desc) {
    S2E_LINUXMON_COMMAND_SEG_FAULT data = {0};
    data.pc = desc.ExceptionAddress;

    onSegFault(state, desc.Pid, data);
}

void TestCaseGenerator::onWindowsKernelCrash(S2EExecutionState *state, const vmi::windows::BugCheckDescription &desc) {
    S2E_LINUXMON_COMMAND_SEG_FAULT data = {0};
    data.pc = state->pc;

    onSegFault(state, 0, data);
}

void TestCaseGenerator::onSegFault(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_SEG_FAULT &data) {
    std::stringstream ss;
    ss << "crash:" << hexval(pid) << ":" << hexval(data.pc);
    generateTestCases(state, ss.str(), TC_FILE);
}

void TestCaseGenerator::onStateFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                                    const std::vector<klee::ref<klee::Expr>> &newConditions) {
    for (auto *newState : newStates) {
        if (newState != state)
            generateTestCases(newState, "fork", TC_FILE);
    }
}

void TestCaseGenerator::onStateKill(S2EExecutionState *state) {
    generateTestCases(state, "kill", TC_LOG | TC_TRACE | TC_FILE);
}

const ConcreteFileTemplates &TestCaseGenerator::getTemplates(S2EExecutionState *state) const {
    DECLARE_PLUGINSTATE_CONST(TestCaseGeneratorState, state);
    return plgState->getTemplates();
}

void TestCaseGenerator::generateTestCases(S2EExecutionState *state, const std::string &prefix, TestCaseType type) {
    getInfoStream(state) << "generating test case at address " << hexval(state->regs()->getPc()) << '\n';

    ConcreteInputs inputs;
    bool success = state->getSymbolicSolution(inputs);

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
        assembleTestCaseToFiles(inputs, getTemplates(state), ss.str(), fileNames);
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

    s2e_trace::PbTraceTestCase item;

    for (const auto &it : inputs) {
        const auto &name = it.first;
        const auto &value = it.second;

        auto tc_item = item.add_items();
        tc_item->set_key(name);
        tc_item->set_value(reinterpret_cast<const char *>(value.data()), value.size());
    }

    m_tracer->writeData(state, item, s2e_trace::TRACE_TESTCASE);
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
/// \param file the chunked representation of the concrete file
/// \param out the assembled file content
/// \return true if assembling was successful
///
bool TestCaseGenerator::assembleChunks(const std::string &name, const TestCaseFile &file,
                                       const ConcreteFileTemplates &templates, std::vector<uint8_t> &out) {
    const auto tpl = templates.lookup_previous(name);

    if (tpl == nullptr) {
        // The file has no concrete template, so all its data must be contained
        // in symbolic variables.
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
            unsigned offset = offsets[id];

            memcpy(&out[offset], chunkData, chunkSize);
        }
    } else {
        // We have a concrete template for the file. We use it as the base, and overwrite
        // parts that were made symbolic.
        out = tpl->second;

        foreach2 (it, file.chunksData.begin(), file.chunksData.end()) {
            unsigned id = (*it).first;
            const uint8_t *chunkData = (*it).second;
            unsigned chunkSize = (*file.chunks.find(id)).second;

            if (chunkSize != 1) {
                getWarningsStream() << "symbolic chunk sizes must be of size 1\n";
                return false;
            }

            if (id >= out.size()) {
                getWarningsStream() << "symbolic chunk id is greater than concrete file template\n";
                return false;
            }

            out[id] = *chunkData;
        }
    }

    return true;
}

void TestCaseGenerator::assembleTestCaseToFiles(const ConcreteInputs &inputs, const ConcreteFileTemplates &templates,
                                                const std::string &prefix, std::vector<std::string> &fileNames) {
    TestCaseData data;
    assembleTestCaseToFiles(inputs, templates, data);

    for (const auto &it : data) {
        const std::string &name = it.first;
        const auto &tcData = it.second;

        std::stringstream ss;
        ss << prefix << "-" << name;
        std::string outputFileName = s2e()->getOutputFilename(ss.str());
        fileNames.push_back(outputFileName);
        std::ofstream ofs(outputFileName.c_str(), std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
        ofs.write((const char *) &tcData[0], tcData.size());
        ofs.close();
    }
}

void TestCaseGenerator::assembleTestCaseToFiles(const ConcreteInputs &inputs, const ConcreteFileTemplates &templates,
                                                TestCaseData &data) {
    TestCaseFiles files;
    getFiles(inputs, files);

    for (const auto &it : files) {
        const std::string &name = it.first;
        const TestCaseFile &file = it.second;
        std::vector<uint8_t> &out = data[name];
        if (!assembleChunks(name, file, templates, out)) {
            getWarningsStream() << "Could not generate concrete test file for " << name << "\n";
            continue;
        }
    }
}

void TestCaseGenerator::assembleTestCaseToFiles(const klee::Assignment &assignment,
                                                const ConcreteFileTemplates &templates, TestCaseData &data) {
    ConcreteInputs inputs;
    for (const auto &it : assignment.bindings) {
        auto &array = it.first;
        const std::vector<unsigned char> &varData = it.second;
        inputs.push_back(std::make_pair(array->getName(), varData));
    }

    assembleTestCaseToFiles(inputs, templates, data);
}

void TestCaseGenerator::handleAddConcreteFileChunk(S2EExecutionState *state,
                                                   const S2E_TCGEN_CONCRETE_FILE_CHUNK &chunk) {
    std::string name;
    if (!state->mem()->readString(chunk.name, name)) {
        getWarningsStream() << "could not read file name at address " << hexval(chunk.name) << "\n";
        s2e()->getExecutor()->terminateState(*state, "TestCaseGenerator call failed");
    }

    std::vector<uint8_t> data;
    data.resize(chunk.size);

    if (!state->mem()->read(chunk.data, data.data(), chunk.size)) {
        getWarningsStream() << "could not read chunk data from guest at address " << hexval(chunk.data) << "\n";
        s2e()->getExecutor()->terminateState(*state, "TestCaseGenerator call failed");
    }

    DECLARE_PLUGINSTATE(TestCaseGeneratorState, state);
    plgState->addChunk(name, chunk.offset, data);
}

void TestCaseGenerator::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
                                               uint64_t guestDataSize) {
    S2E_TCGEN_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_TCGEN_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        case TCGEN_ADD_CONCRETE_FILE_CHUNK: {
            handleAddConcreteFileChunk(state, command.Chunk);
        } break;
    }
}
} // namespace testcases
} // namespace plugins
} // namespace s2e
