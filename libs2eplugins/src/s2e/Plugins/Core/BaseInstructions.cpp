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
#include <s2e/opcodes.h>

#ifdef CONFIG_WIN32
#include <windows.h>
#endif

#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

#include <chrono>
#include <iostream>
#include <sstream>

#include <klee/Searcher.h>
#include <klee/Solver.h>
#include <klee/SolverManager.h>
#include <llvm/ADT/DenseSet.h>

#include <llvm/Support/CommandLine.h>

#include "BaseInstructions.h"

extern "C" {
/**
 * In some cases, it may be useful to forbid guest apps to use
 * s2e instructions, e.g., when doing malware analysis.
 */
int g_s2e_allow_custom_instructions = 0;
}

namespace s2e {
namespace plugins {

using namespace std;
using namespace klee;

S2E_DEFINE_PLUGIN(BaseInstructions, "Default set of custom instructions plugin", "", );

namespace {
class BaseInstructionsState : public PluginState {
    llvm::DenseSet<uint64_t> m_allowedPids;

public:
    bool allowed(uint64_t pid) {
        return m_allowedPids.count(pid);
    }

    inline bool empty() {
        return m_allowedPids.empty();
    }

    inline void allow(uint64_t pid) {
        m_allowedPids.insert(pid);
    }

    inline void disallow(uint64_t pid) {
        m_allowedPids.erase(pid);
    }

    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new BaseInstructionsState();
    }

    virtual ~BaseInstructionsState() {
    }
    virtual BaseInstructionsState *clone() const {
        return new BaseInstructionsState(*this);
    }
};
} // namespace

void BaseInstructions::initialize() {
    ConfigFile *cfg = s2e()->getConfig();

    m_monitor = nullptr;
    if (cfg->getBool(getConfigKey() + ".restrict", false)) {
        m_monitor = dynamic_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
        if (!m_monitor) {
            getWarningsStream() << "You must enable an os monitoring plugin to use restricted mode\n";
            exit(-1);
        }

        getWarningsStream() << "Restriction enabled\n";
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
            sigc::mem_fun(*this, &BaseInstructions::onTranslateBlockStart));
    }

    s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &BaseInstructions::onCustomInstruction));

    g_s2e_allow_custom_instructions = 1;
}

void BaseInstructions::onTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                             uint64_t pc) {
    if ((tb->flags >> VM_SHIFT) & 1) {
        g_s2e_allow_custom_instructions = 1;
        return;
    }

    if (m_monitor->isKernelAddress(pc)) { // XXX make it configurable
        g_s2e_allow_custom_instructions = 1;
        return;
    }

    DECLARE_PLUGINSTATE(BaseInstructionsState, state);
    if (plgState->empty()) {
        /**
         * The first process will have to register itself
         */
        g_s2e_allow_custom_instructions = 1;
        return;
    }

    uint64_t pid = m_monitor->getPid(state);
    g_s2e_allow_custom_instructions = plgState->allowed(pid);
}

void BaseInstructions::allowCurrentPid(S2EExecutionState *state) {
    if (!m_monitor) {
        getWarningsStream(state) << "Please enable the restrict option to control access to custom instructions\n";
        exit(-1);
        return;
    }

    DECLARE_PLUGINSTATE(BaseInstructionsState, state);
    uint64_t pid = m_monitor->getPid(state);
    plgState->allow(pid);

    getDebugStream(state) << "Allowing custom instructions for pid " << hexval(pid) << "\n";

    se_tb_safe_flush();
}

void BaseInstructions::makeSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
                                    const std::string &nameStr, std::vector<klee::ref<Expr>> *varData,
                                    std::string *varName) {
    std::vector<klee::ref<Expr>> symb;
    std::stringstream valueSs;

    std::vector<uint8_t> concreteData;

    valueSs << "='";
    for (unsigned i = 0; i < size; ++i) {
        uint8_t byte = 0;
        if (!state->mem()->read<uint8_t>(address + i, &byte, VirtualAddress, false)) {
            getWarningsStream(state) << "Can not concretize/read symbolic value at " << hexval(address + i)
                                     << ". System state not modified\n";
            return;
        }
        concreteData.push_back(byte);
        valueSs << charval(byte);
    }
    valueSs << "'";
    symb = state->createSymbolicArray(nameStr, size, concreteData, varName);

    getInfoStream(state) << "Inserted symbolic data @" << hexval(address) << " of size " << hexval(size) << ": "
                         << (varName ? *varName : nameStr) << valueSs.str() << " pc=" << hexval(state->regs()->getPc())
                         << "\n";

    for (unsigned i = 0; i < size; ++i) {
        if (!state->mem()->write(address + i, symb[i])) {
            getWarningsStream(state) << "Can not insert symbolic value at " << hexval(address + i)
                                     << ": can not write to memory\n";
        }
    }

    if (varData) {
        *varData = symb;
    }
}

void BaseInstructions::makeSymbolic(S2EExecutionState *state) {
    target_ulong address, size, name;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &address, sizeof address, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &size, sizeof size, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &name, sizeof name, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    " insert_symbolic opcode\n";
        return;
    }

    std::string nameStr = "unnamed";
    if (name && !state->mem()->readString(name, nameStr)) {
        getWarningsStream(state) << "Error reading string from the guest\n";
    }

    makeSymbolic(state, address, size, nameStr);
}

void BaseInstructions::isSymbolic(S2EExecutionState *state) {
    target_ulong address;
    target_ulong size;
    target_ulong result;

    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &address, sizeof(address), false);

    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &size, sizeof(size), false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op is_symbolic\n";
        return;
    }

    // readMemoryConcrete fails if the value is symbolic
    result = 0;
    for (unsigned i = 0; i < size; ++i) {
        klee::ref<klee::Expr> ret = state->mem()->read(address + i);
        if (ret.isNull()) {
            getWarningsStream() << "Could not read address " << hexval(address + i) << "\n";
            continue;
        }

        if (!isa<ConstantExpr>(ret)) {
            result = 1;
        }
    }

    getDebugStream(state) << "Testing whether data at " << hexval(address) << " and size " << size
                          << " is symbolic: " << (result ? " true" : " false") << '\n';

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result));
}

void BaseInstructions::killState(S2EExecutionState *state) {
    std::string message;
    target_ulong messagePtr;

#ifdef TARGET_X86_64
    const klee::Expr::Width width = klee::Expr::Int64;
#else
    const klee::Expr::Width width = klee::Expr::Int32;
#endif

    bool ok = true;
    klee::ref<klee::Expr> status = state->regs()->read(CPU_OFFSET(regs[R_EAX]), width);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &messagePtr, sizeof messagePtr, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_kill_state \n";
    } else {
        message = "<NO MESSAGE>";
        if (messagePtr && !state->mem()->readString(messagePtr, message)) {
            getWarningsStream(state) << "Error reading message string from the guest\n";
        }
    }

    // Kill the current state
    getInfoStream(state) << "Killing state " << state->getID() << '\n';
    std::ostringstream os;
    os << "State was terminated by opcode\n"
       << "            message: \"" << message << "\"\n"
       << "            status: " << status;
    s2e()->getExecutor()->terminateState(*state, os.str());
}

void BaseInstructions::printExpression(S2EExecutionState *state) {
// Print the expression
#ifdef TARGET_X86_64
    const klee::Expr::Width width = klee::Expr::Int64;
#else
    const klee::Expr::Width width = klee::Expr::Int32;
#endif

    target_ulong name;
    bool ok = true;
    klee::ref<Expr> val = state->regs()->read(offsetof(CPUX86State, regs[R_EAX]), width);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &name, sizeof name, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    "print_expression opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if (name && !state->mem()->readString(name, nameStr)) {
        getWarningsStream(state) << "Error reading string from the guest\n";
    }

    getInfoStream() << "SymbExpression " << nameStr << " - " << val << '\n';

    if (!isa<klee::ConstantExpr>(val)) {
        klee::ref<klee::Expr> concrete = state->concolics->evaluate(val);
        getInfoStream() << "SymbExpression " << nameStr << " - Value: " << concrete << '\n';
    }
}

void BaseInstructions::printMemory(S2EExecutionState *state) {
    target_ulong address, size, name;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &address, sizeof address, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &size, sizeof size, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &name, sizeof name, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    "print_expression opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if (name && !state->mem()->readString(name, nameStr)) {
        getWarningsStream(state) << "Error reading string from the guest\n";
    }

    getInfoStream() << "Symbolic memory dump of " << nameStr << '\n';

    for (uint32_t i = 0; i < size; ++i) {
        getInfoStream() << hexval(address + i) << ": ";
        klee::ref<Expr> res = state->mem()->read(address + i);
        if (res.isNull()) {
            getInfoStream() << "Invalid pointer\n";
        } else {
            getInfoStream() << res << '\n';
        }
    }
}

void BaseInstructions::hexDump(S2EExecutionState *state) {
    target_ulong address, size, name;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &address, sizeof address, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EBX]), &size, sizeof size, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &name, sizeof name, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    "hexDump opcode\n";
        return;
    }

    std::string nameStr = "<NO NAME>";
    if (name && !state->mem()->readString(name, nameStr)) {
        getWarningsStream(state) << "Error reading string from the guest\n";
    }

    llvm::raw_ostream &os = getDebugStream(state);

    os << "Hexdump of " << nameStr << '\n';

    unsigned i;
    char buff[17];

    // Process every byte in the data.
    for (i = 0; i < size; i++) {
        uint8_t data = 0;
        state->mem()->read<uint8_t>(address + i, &data);

        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                os << "  " << buff << "\n";
            }
            // Output the offset.
            os << hexval(address + i, 8);
        }

        // Now the hex code for the specific character.
        os << " " << hexval(data, 2);

        // And store a printable ASCII character for later.
        if ((data < 0x20) || (data > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = data;
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        os << "   ";
        i++;
    }

    // And print the final ASCII bit.
    os << "  " << buff << "\n";
}

void BaseInstructions::concretize(S2EExecutionState *state, bool addConstraint) {
    target_ulong address, size;

    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &address, sizeof address, false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &size, sizeof size, false);

    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    " get_example opcode\n";
        return;
    }

    for (unsigned i = 0; i < size; ++i) {
        uint8_t b = 0;
        if (!state->mem()->read<uint8_t>(address + i, &b, VirtualAddress, addConstraint)) {
            getWarningsStream(state) << "Can not concretize memory"
                                     << " at " << hexval(address + i) << '\n';
        } else {
            // read memory does not automatically overwrite the destination
            // address if we choose not to add the constraint, so we do it here
            if (!addConstraint) {
                if (!state->mem()->write(address + i, &b, sizeof(b))) {
                    getWarningsStream(state) << "Can not write memory"
                                             << " at " << hexval(address + i) << '\n';
                }
            }
        }
    }
}

void BaseInstructions::sleep(S2EExecutionState *state) {
    long duration = 0;
    state->regs()->read(CPU_OFFSET(regs[R_EAX]), &duration, sizeof(duration), false);
    getDebugStream() << "Sleeping " << duration << " seconds\n";

    using namespace std::chrono;

    auto t1 = steady_clock::now();
    auto d1 = seconds(duration);

    while (steady_clock::now() - t1 < d1) {
#ifdef _WIN32
        Sleep(1000);
#else
        ::sleep(1);
#endif
    }
}

void BaseInstructions::printMessage(S2EExecutionState *state, bool isWarning) {
    target_ulong address = 0;
    bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &address, sizeof address, false);
    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic argument was passed to s2e_op "
                                    " message opcode\n";
        return;
    }

    std::string str = "";
    if (!address || !state->mem()->readString(address, str)) {
        getWarningsStream(state) << "Error reading string message from the guest at address " << hexval(address)
                                 << '\n';
    } else {
        llvm::raw_ostream *stream;
        if (isWarning)
            stream = &getWarningsStream(state);
        else
            stream = &getInfoStream(state);
        (*stream) << "Message from guest (" << hexval(address) << "): " << str;

        /* Avoid doubling end of lines */
        if (str[str.length() - 1] != '\n') {
            *stream << "\n";
        }
    }
}

void BaseInstructions::checkPlugin(S2EExecutionState *state) const {
    std::string pluginName;
    target_ulong pluginNamePointer = 0;
    target_ulong loaded = 0;
    bool ok = true;

    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &pluginNamePointer, sizeof(pluginNamePointer), false);
    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic arguments were passed to s2e_op checkPlugin opcode\n";
        loaded = 0;
        goto fail;
    }

    if (!state->mem()->readString(pluginNamePointer, pluginName)) {
        getWarningsStream(state) << "ERROR: checkPlugin could not read name of plugin to invoke\n";
        loaded = 0;
        goto fail;
    }

    loaded = s2e()->getPlugin(pluginName) == nullptr ? 0 : 1;

fail:
    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &loaded, sizeof(loaded));
}

void BaseInstructions::invokePlugin(S2EExecutionState *state) {
    IPluginInvoker *iface = nullptr;
    Plugin *plugin;
    std::string pluginName;
    target_ulong pluginNamePointer = 0;
    target_ulong dataPointer = 0;
    target_ulong dataSize = 0;
    target_ulong result = 0;
    bool ok = true;

    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &pluginNamePointer, sizeof(pluginNamePointer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &dataPointer, sizeof(dataPointer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &dataSize, sizeof(dataSize), false);
    if (!ok) {
        getWarningsStream(state) << "ERROR: symbolic arguments were passed to s2e_op invokePlugin opcode\n";
        result = 1;
        goto fail;
    }

    if (!state->mem()->readString(pluginNamePointer, pluginName)) {
        getWarningsStream(state) << "ERROR: invokePlugin could not read name of plugin to invoke\n";
        result = 2;
        goto fail;
    }

    plugin = s2e()->getPlugin(pluginName);
    if (!plugin) {
        getWarningsStream(state) << "ERROR: invokePlugin could not find plugin " << pluginName << "\n";
        result = 3;
        goto fail;
    }

    iface = dynamic_cast<IPluginInvoker *>(plugin);

    if (!iface) {
        getWarningsStream(state) << "ERROR: " << pluginName << " is not an instance of IPluginInvoker\n";
        result = 4;
        goto fail;
    }

    iface->handleOpcodeInvocation(state, dataPointer, dataSize);

fail:
    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result));
}

void BaseInstructions::assume(S2EExecutionState *state) {
    klee::ref<klee::Expr> expr = state->regs()->read(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
    assumeInternal(state, expr);
}

void BaseInstructions::assumeRange(S2EExecutionState *state) {
    klee::ref<klee::Expr> value;
    klee::ref<klee::Expr> lower;
    klee::ref<klee::Expr> upper;

    value = state->regs()->read(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int32);
    lower = state->regs()->read(CPU_OFFSET(regs[R_ECX]), klee::Expr::Int32);
    upper = state->regs()->read(CPU_OFFSET(regs[R_EDX]), klee::Expr::Int32);

    klee::ref<klee::Expr> condition =
        klee::AndExpr::create(klee::UgeExpr::create(value, lower), klee::UleExpr::create(value, upper));

    assumeInternal(state, condition);
}

void BaseInstructions::assumeDisjunction(S2EExecutionState *state) {
    uint64_t sp = state->regs()->getSp();
    uint32_t count;
    bool ok = true;

    static unsigned STACK_ELEMENT_SIZE = state->getPointerSize();

    target_ulong currentParam = sp + STACK_ELEMENT_SIZE * 2;

    klee::ref<klee::Expr> variable = state->mem()->read(currentParam, STACK_ELEMENT_SIZE * 8);
    if (variable.isNull()) {
        getWarningsStream(state) << "BaseInstructions: assumeDisjunction could not read the variable\n";
        return;
    }

    currentParam += STACK_ELEMENT_SIZE;
    ok &= state->mem()->read(currentParam, &count, sizeof(count));
    if (!ok) {
        getWarningsStream(state) << "BaseInstructions: assumeDisjunction could not read number of disjunctions\n";
        return;
    }

    if (count == 0) {
        getDebugStream(state) << "BaseInstructions: assumeDisjunction got 0 disjunctions\n";
        return;
    }

    currentParam += STACK_ELEMENT_SIZE;

    klee::ref<klee::Expr> expr;
    for (unsigned i = 0; i < count; ++i) {
        // XXX: 64-bits mode!!!
        klee::ref<klee::Expr> value = state->mem()->read(currentParam, STACK_ELEMENT_SIZE * 8);
        if (i == 0) {
            expr = klee::EqExpr::create(variable, value);
        } else {
            expr = klee::OrExpr::create(expr, klee::EqExpr::create(variable, value));
        }
        currentParam += STACK_ELEMENT_SIZE;
    }

    getDebugStream(state) << "BaseInstructions: assuming expression " << expr << "\n";
    assumeInternal(state, expr);
}

void BaseInstructions::assumeInternal(S2EExecutionState *state, klee::ref<klee::Expr> expr) {

    klee::ref<klee::Expr> zero = klee::ConstantExpr::create(0, expr.get()->getWidth());
    klee::ref<klee::Expr> boolExpr = klee::NeExpr::create(expr, zero);

    getDebugStream(state) << "Assuming " << boolExpr << "\n";

    if (!state->addConstraint(boolExpr, true)) {
        s2e()->getExecutor()->terminateState(*state, "Tried to add an invalid constraint");
    }
}

/**
 * Copies a guest memory buffer from one place to another, disregarding
 * any page protections. Can be used to hack kernel memory from user apps.
 * Use with caution.
 */
void BaseInstructions::writeBuffer(S2EExecutionState *state) {
    target_ulong source, destination, size;
    bool ok = true;

    ok &= state->regs()->read(CPU_OFFSET(regs[R_ESI]), &source, sizeof(source), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDI]), &destination, sizeof(destination), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &size, sizeof(size), false);

    getDebugStream(state) << "BaseInstructions: copying " << size << " bytes from " << hexval(source) << " to "
                          << hexval(destination) << "\n";

    uint32_t remaining = (uint32_t) size;

    while (remaining > 0) {
        uint8_t byte;
        if (!state->mem()->read(source, &byte, sizeof(byte))) {
            getDebugStream(state) << "BaseInstructions: could not read byte at " << hexval(source) << "\n";
            break;
        }

        if (!state->mem()->write(destination, &byte, sizeof(byte))) {
            getDebugStream(state) << "BaseInstructions: could not write byte to " << hexval(destination) << "\n";
            break;
        }

        source++;
        destination++;
        remaining--;
    }

    target_ulong written = size - remaining;
    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &written, sizeof(written));
}

void BaseInstructions::getRange(S2EExecutionState *state) {
    klee::ref<klee::Expr> value;
    std::pair<klee::ref<klee::Expr>, klee::ref<klee::Expr>> range;
    target_ulong low = 0, high = 0;

    unsigned size = state->getPointerSize();
    value = state->regs()->read(CPU_OFFSET(regs[R_EAX]), size * 8);
    state->regs()->read(CPU_OFFSET(regs[R_ECX]), &low, size);
    state->regs()->read(CPU_OFFSET(regs[R_EDX]), &high, size);

    if (!low || !high) {
        getDebugStream(state) << "BaseInstructions: invalid arguments for range\n";
        return;
    }

    Solver *solver = state->solver()->solver;

    Query query(state->constraints(), value);
    range = solver->getRange(query);

    getDebugStream(state) << "BaseInstructions: range " << range.first << " to " << range.second << "\n";

    state->mem()->write(low, range.first);
    state->mem()->write(high, range.second);
}

void BaseInstructions::getConstraintsCountForExpression(S2EExecutionState *state) {
    klee::ref<klee::Expr> value;

    unsigned size = state->getPointerSize();
    value = state->regs()->read(CPU_OFFSET(regs[R_EAX]), size * 8);

    Query query(state->constraints(), value);
    std::vector<klee::ref<klee::Expr>> requiredConstraints;
    klee::getIndependentConstraintsForQuery(query, requiredConstraints);

    target_ulong result = requiredConstraints.size();
    state->regs()->write(CPU_OFFSET(regs[R_EAX]), &result, sizeof(result));
}

/**
 * Forks count times without adding constraints.
 */
void BaseInstructions::forkCount(S2EExecutionState *state) {
    target_ulong count;
    target_ulong nameptr;

    state->jumpToSymbolicCpp();

    state->regs()->read(CPU_OFFSET(regs[R_EAX]), &count, sizeof count);
    state->regs()->read(CPU_OFFSET(regs[R_ECX]), &nameptr, sizeof nameptr);

    std::string name;

    if (!state->mem()->readString(nameptr, name)) {
        getWarningsStream(state) << "Could not read string at address " << hexval(nameptr) << "\n";

        state->regs()->write<target_ulong>(CPU_OFFSET(regs[R_EAX]), -1);
        return;
    }

    klee::ref<klee::Expr> var = state->createSymbolicValue<uint32_t>(name, 0);

    state->regs()->write(CPU_OFFSET(regs[R_EAX]), var);
    state->regs()->write<target_ulong>(CPU_OFFSET(eip), state->regs()->getPc() + 10);

    getDebugStream(state) << "s2e_fork: will fork " << count << " times with variable " << var << "\n";

    for (unsigned i = 1; i < count; ++i) {
        klee::ref<klee::Expr> val = klee::ConstantExpr::create(i, var->getWidth());
        klee::ref<klee::Expr> cond = klee::NeExpr::create(var, val);

        klee::Executor::StatePair sp = s2e()->getExecutor()->forkCondition(state, cond, true);
        assert(sp.first == state);
        assert(sp.second && sp.second != sp.first);
    }

    klee::ref<klee::Expr> cond = klee::EqExpr::create(var, klee::ConstantExpr::create(0, var->getWidth()));
    if (!state->addConstraint(cond)) {
        s2e()->getExecutor()->terminateState(*state, "Could not add condition");
    }
}

/** Handle s2e_op instruction. Instructions:
    0f 3f XX XX XX XX XX XX XX XX
    XX: opcode
 */
void BaseInstructions::handleBuiltInOps(S2EExecutionState *state, uint64_t opcode) {
    switch ((opcode >> 8) & 0xFF) {
        case BASE_S2E_CHECK: { /* s2e_check */
            target_ulong v = 1;
            state->regs()->write(CPU_OFFSET(regs[R_EAX]), &v, sizeof v);
        } break;

        case BASE_S2E_MAKE_CONCOLIC:
            getWarningsStream(state) << "s2e_make_concolic is deprecated. Use s2e_make_symbolic instead.\n";
        case BASE_S2E_MAKE_SYMBOLIC: { /* s2e_make_symbolic */
            makeSymbolic(state);
            break;
        }

        case BASE_S2E_IS_SYMBOLIC: { /* s2e_is_symbolic */
            isSymbolic(state);
            break;
        }

        case BASE_S2E_GET_PATH_ID: { /* s2e_get_path_id */
            const klee::Expr::Width width = sizeof(target_ulong) << 3;
            state->regs()->write(offsetof(CPUX86State, regs[R_EAX]), klee::ConstantExpr::create(state->getID(), width));
            break;
        }

        case BASE_S2E_KILL_STATE: { /* s2e_kill_state */
            killState(state);
            break;
        }

        case BASE_S2E_PRINT_EXPR: { /* s2e_print_expression */
            printExpression(state);
            break;
        }

        case BASE_S2E_PRINT_MEM: { // Print memory contents
            printMemory(state);
            break;
        }

        case BASE_S2E_ENABLE_FORK: { /* s2e_enable_forking */
            state->enableForking();
            break;
        }

        case BASE_S2E_DISABLE_FORK: { /* s2e_disable_forking */
            state->disableForking();
            break;
        }

        case BASE_S2E_CHECK_PLUGIN: { /* s2e_plugin_loaded */
            checkPlugin(state);
            break;
        }

        case BASE_S2E_INVOKE_PLUGIN: { /* s2e_invoke_plugin */
            invokePlugin(state);
            break;
        }

        case BASE_S2E_ASSUME: { /* s2e_assume */
            assume(state);
            break;
        }

        case BASE_S2E_ASSUME_DISJ: {
            assumeDisjunction(state);
            break;
        }

        case BASE_S2E_ASSUME_RANGE: { /* s2e_assume_range */
            assumeRange(state);
            break;
        }

        case BASE_S2E_YIELD: { /* s2e_yield */
            state->yield();
            break;
        }

        case BASE_S2E_PRINT_MSG: { /* s2e_message */
            printMessage(state, opcode >> 16);
            break;
        }

        case BASE_S2E_BEGIN_ATOMIC: { /* s2e_begin_atomic */
            getDebugStream(state) << "BaseInstructions: s2e_begin_atomic\n";
            state->setStateSwitchForbidden(true);
            break;
        }

        case BASE_S2E_END_ATOMIC: { /* s2e_end_atomic */
            state->setStateSwitchForbidden(false);
            getDebugStream(state) << "BaseInstructions: s2e_end_atomic\n";
            break;
        }

        case BASE_S2E_CONCRETIZE: /* s2e_concretize */
            concretize(state, true);
            break;

        case BASE_S2E_EXAMPLE: { /* s2e_get_example */
            concretize(state, false);
            break;
        }

        case BASE_S2E_STATE_COUNT: { /* Get number of active states */
            target_ulong count = s2e()->getExecutor()->getStatesCount();
            state->regs()->write(CPU_OFFSET(regs[R_EAX]), &count, sizeof(count));
            break;
        }

        case BASE_S2E_INSTANCE_COUNT: { /* Get number of active S2E instances */
            target_ulong count = s2e()->getCurrentInstanceCount();
            state->regs()->write(CPU_OFFSET(regs[R_EAX]), &count, sizeof(count));
            break;
        }

        case BASE_S2E_SLEEP: { /* Sleep for a given number of seconds */
            sleep(state);
            break;
        }

        case BASE_S2E_WRITE_BUFFER: { /* Write the given buffer to some guest memory location */
            writeBuffer(state);
            break;
        }

        case BASE_S2E_GET_RANGE: { /* s2e_get_range */
            getRange(state);
            break;
        }

        case BASE_S2E_CONSTR_CNT: { /* s2e_get_constraint_count */
            getConstraintsCountForExpression(state);
            break;
        }

        case BASE_S2E_HEX_DUMP: { /* s2e_hex_dump */
            hexDump(state);
            break;
        }

        case BASE_S2E_SET_TIMER_INT: { /* s2e_enable_timer_interrupt / s2e_disable_timer_interrupt */
            uint8_t disabled = opcode >> 16;
            if (disabled)
                getDebugStream(state) << "Disabling timer interrupt\n";
            else
                getDebugStream(state) << "Enabling timer interrupt\n";
            state->regs()->write(CPU_OFFSET(timer_interrupt_disabled), disabled);
            break;
        }
        case BASE_S2E_SET_APIC_INT: { /* s2e_enable_all_apic_interrupts / s2e_disable_all_apic_interrupts */
            uint8_t disabled = opcode >> 16;
            if (disabled)
                getDebugStream(state) << "Disabling all apic interrupt\n";
            else
                getDebugStream(state) << "Enabling all apic interrupt\n";
            state->regs()->write(CPU_OFFSET(all_apic_interrupts_disabled), disabled);
            break;
        }

        case BASE_S2E_GET_OBJ_SZ: { /* s2e_get_ram_objects_bits */
            target_ulong size = SE_RAM_OBJECT_BITS;
            state->regs()->write(CPU_OFFSET(regs[R_EAX]), &size, sizeof size);
            break;
        }

        case BASE_S2E_CLEAR_TEMPS: { /* s2e_invoke_plugin_concrete */
            /**
             * Clear all temporary flags.
             * Useful to force concrete mode from guest code.
             */
            target_ulong val = 0;
            state->regs()->write(CPU_OFFSET(cc_op), val);
            state->regs()->write(CPU_OFFSET(cc_src), val);
            state->regs()->write(CPU_OFFSET(cc_dst), val);
            state->regs()->write(CPU_OFFSET(cc_tmp), val);
        } break;

        case BASE_S2E_FORK_COUNT: { /* s2e_fork */
            forkCount(state);
        } break;

        // This may be useful for properly measuring kernel coverage
        case BASE_S2E_FLUSH_TBS: { /* s2e_flush_tbs */
            se_tb_safe_flush();
        } break;

        default:
            getWarningsStream(state) << "BaseInstructions: Invalid built-in opcode " << hexval(opcode) << '\n';
            break;
    }
}

void BaseInstructions::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    uint8_t opc = (opcode >> 8) & 0xFF;

    if (opc <= BASE_S2E_MAX_OPCODE) {
        handleBuiltInOps(state, opcode);
    }
}

void BaseInstructions::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
    S2E_BASEINSTRUCTION_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_BASEINSTRUCTION_COMMAND size\n";
        exit(-1);
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
    }

    switch (command.Command) {
        case ALLOW_CURRENT_PID: {
            allowCurrentPid(state);
        } break;

        case GET_HOST_CLOCK_MS: {
            auto t = std::chrono::steady_clock::now();
            command.Milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
            state->mem()->write(guestDataPtr, &command, guestDataSize);
        } break;
    }
}
} // namespace plugins
} // namespace s2e
