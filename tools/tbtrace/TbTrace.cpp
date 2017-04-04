///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#define __STDC_FORMAT_MACROS 1

#include <fstream>
#include <inttypes.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include "llvm/Support/CommandLine.h"

#include "lib/ExecutionTracer/InstructionCounter.h"
#include "lib/ExecutionTracer/ModuleParser.h"
#include "lib/ExecutionTracer/PageFault.h"
#include "lib/ExecutionTracer/Path.h"
#include "lib/ExecutionTracer/TestCase.h"

#include <llvm/Support/Path.h>

#include "TbTrace.h"

using namespace llvm;
using namespace s2etools;
using namespace s2e::plugins;

namespace {

cl::list<std::string> TraceFiles("trace", llvm::cl::value_desc("Input trace"), llvm::cl::Prefix,
                                 llvm::cl::desc("Specify an execution trace file"));

cl::opt<std::string> LogDir("outputdir", cl::desc("Store the list of translation blocks into the given folder"),
                            cl::init("."));

cl::list<std::string> ModDir("moddir", cl::desc("Directory containing the binary modules"));

cl::list<unsigned> PathList("pathId", cl::desc("Path id to output, repeat for more. Empty=all paths"), cl::ZeroOrMore);

cl::opt<bool> PrintRegisters("printRegisters",
                             cl::desc("Print register contents for each block. Requires TranslationBlockTracer."),
                             cl::init(false));

#ifdef ENABLE_TRACE_STACK
cl::opt<bool> PrintStack("printStack",
                         cl::desc("Print stack contents for each block. Requires TranslationBlockTracer."),
                         cl::init(false));
#endif

cl::opt<bool> PrintMemory("printMemory", cl::desc("Print memory trace. Requires plugins that generate a memory trace."),
                          cl::init(false));

cl::opt<bool> PrintDisassembly(
    "printDisassembly",
    cl::desc("Print disassembly in the trace. Requires an *.lst disassembly listing from IDApro in moddir."),
    cl::init(false));

cl::opt<bool> PrintMemoryChecker("printMemoryChecker",
                                 cl::desc("Print memory checker events. Requires the MemoryChecker plugin."),
                                 cl::init(false));

cl::opt<bool> PrintMemoryCheckerStack("printMemoryCheckerStack",
                                      cl::desc("Print stack grants/revocations. Requires the MemoryChecker plugin."),
                                      cl::init(false));
}

namespace s2etools {

struct hexval {
    uint64_t value;
    int width;
    bool prefix;

    hexval(uint64_t _value, int _width = 0, bool _prefix = true) : value(_value), width(_width), prefix(_prefix) {
    }
    hexval(const void *_value, int _width = 0, bool _prefix = true)
        : value((uint64_t) _value), width(_width), prefix(_prefix) {
    }

    std::string str() const {
        std::stringstream ss;

        if (prefix) {
            ss << "0x";
        }
        ss << std::hex;
        if (width) {
            ss << std::setfill('0') << std::setw(width);
        }
        ss << value;

        return ss.str();
    }
};

inline std::ostream &operator<<(std::ostream &out, const hexval &h) {
    out << h.str();
    return out;
}

TbTrace::TbTrace(Library *lib, ModuleCache *cache, LogEvents *events, std::ofstream &of) : m_output(of) {
    m_events = events;
    m_connection = events->onEachItem.connect(sigc::mem_fun(*this, &TbTrace::onItem));
    m_cache = cache;
    m_library = lib;
    m_hasItems = false;
    m_hasDebugInfo = false;
    m_hasModuleInfo = false;
}

TbTrace::~TbTrace() {
    m_connection.disconnect();
}

bool TbTrace::parseDisassembly(const std::string &listingFile, Disassembly &out) {
    // Get the module name
    std::string moduleName = llvm::sys::path::stem(listingFile);

    bool added = false;

    char line[1024];
    std::filebuf file;
    if (!file.open(listingFile.c_str(), std::ios::in)) {
        return false;
    }

    std::istream is(&file);

    while (is.getline(line, sizeof(line))) {
        std::string ln = line;
        // Skip the start
        unsigned i = 0;
        while (line[i] && (line[i] != ':'))
            ++i;
        if (line[i] != ':')
            continue;

        ++i;
        // Grab the address
        std::string strpc;
        while (isxdigit(line[i])) {
            strpc = strpc + line[i];
            ++i;
        }

        uint64_t pc = 0;
        sscanf(strpc.c_str(), "%" PRIx64, &pc);
        if (pc) {
            out[moduleName][pc].push_back(ln);
            added = true;
        }
    }

    return added;
}

void TbTrace::printDisassembly(const std::string &module, uint64_t relPc, unsigned tbSize) {
    static std::set<std::string> moduleWarnOnce;
    Disassembly::iterator it = m_disassembly.find(module);
    if (it == m_disassembly.end()) {
        std::string disassemblyListing;
        if (!m_library->findDisassemblyListing(module, disassemblyListing)) {
            if (moduleWarnOnce.find(module) == moduleWarnOnce.end()) {
                std::cerr << "Could not find disassembly listing for module " << module << std::endl;
                moduleWarnOnce.insert(module);
            }
            return;
        }

        if (!parseDisassembly(disassemblyListing, m_disassembly)) {
            return;
        }
        it = m_disassembly.find(module);
        assert(it != m_disassembly.end());
    }

    // Fetch the basic blocks for our module
    ModuleBasicBlocks::iterator bbit = m_basicBlocks.find(module);
    if (bbit == m_basicBlocks.end()) {
        std::string basicBlockList;

        if (!m_library->findBasicBlockList(module, basicBlockList)) {
            std::cerr << "TbTrace: could not find basic block list for  " << module << std::endl;
            exit(-1);
        }

        TbTraceBbs moduleBbs;

        if (!BasicBlockListParser::parseListing(basicBlockList, moduleBbs)) {
            std::cerr << "TbTrace: could not parse basic block list in file " << basicBlockList << std::endl;
            exit(-1);
        }

        m_basicBlocks[module] = moduleBbs;
        bbit = m_basicBlocks.find(module);
        assert(bbit != m_basicBlocks.end());
    }

    while ((int) tbSize > 0) {
        // Fetch the right basic block
        BasicBlock bbToFetch(relPc, 1);
        TbTraceBbs::iterator mybb = (*bbit).second.find(bbToFetch);
        if (mybb == (*bbit).second.end()) {
            m_output << "Could not find basic block 0x" << std::hex << relPc << " in the list" << std::endl;
            return;
        }

        // Found the basic block, compute the range of program counters
        // whose disassembly we are going to print.
        const BasicBlock &bb = *mybb;
        uint64_t asmStartPc = relPc;
        uint64_t asmEndPc;

        if (relPc + tbSize >= bb.start + bb.size) {
            asmEndPc = bb.start + bb.size;
        } else {
            asmEndPc = relPc + tbSize;
        }

        assert(relPc >= bb.start && relPc < bb.start + bb.size);

        // Grab the vector of strings for the program counter
        ModuleDisassembly::iterator modIt = (*it).second.find(asmStartPc);
        if (modIt == (*it).second.end()) {
            return;
        }

        // Fetch the range of program counters from the disassembly file
        ModuleDisassembly::iterator modItEnd = (*it).second.lower_bound(asmEndPc);

        for (ModuleDisassembly::iterator it = modIt; it != modItEnd; ++it) {
            // Print the vector we've got
            for (DisassemblyEntry::const_iterator asmIt = (*it).second.begin(); asmIt != (*it).second.end(); ++asmIt) {
                m_output << "\033[1;33m" << *asmIt << "\033[0m" << std::endl;
            }
        }

        tbSize -= asmEndPc - asmStartPc;
        relPc += asmEndPc - asmStartPc;

        if ((int) tbSize < 0) {
            assert(false && "Cannot be negative");
        }
    }
}

void TbTrace::printDebugInfo(uint64_t pid, uint64_t pc, unsigned tbSize, bool printListing) {
    ModuleCacheState *mcs = static_cast<ModuleCacheState *>(m_events->getState(m_cache, &ModuleCacheState::factory));
    const ModuleInstance *mi = mcs->getInstance(pid, pc);
    if (!mi) {
        return;
    }
    uint64_t relPc = pc - mi->LoadBase + mi->ImageBase;
    m_output << std::hex << "(" << mi->Name;
    if (relPc != pc) {
        m_output << " 0x" << relPc;
    }
    m_output << ")";

    m_hasModuleInfo = true;

    std::string file = "?", function = "?";
    uint64_t line = 0;
    if (m_library->getInfo(mi, pc, file, line, function)) {
        size_t pos = file.find_last_of('/');
        if (pos != std::string::npos) {
            file = file.substr(pos + 1);
        }

        m_output << " " << file << std::dec << ":" << line << " in " << function;
        m_hasDebugInfo = true;
    }

    if (PrintDisassembly && printListing) {
        m_output << std::endl;
        printDisassembly(mi->Name, relPc, tbSize);
    }
}

template <typename T>
void TbTrace::printRegisters(const char *regs[], const uint64_t *values, uint8_t symbMask, unsigned count,
                             unsigned breakIndex) {
    for (unsigned i = 0; i < count; ++i) {
        if (i == breakIndex) {
            m_output << '\n';
        }

        bool isSymbolic = symbMask & (1 << i);

        m_output << regs[i] << ": ";

        // Denote symbolic values with color
        m_output << (isSymbolic ? "\033[1;31m" : "") << hexval((T) values[i]) << (isSymbolic ? "\033[0m" : "");

        m_output << " ";
    }
}

void TbTrace::printRegisters(const s2e::plugins::ExecutionTraceTb *te) {
    const char *regs[] = {"EAX", "ECX", "EDX", "EBX", "ESP", "EBP", "ESI", "EDI"};
    printRegisters<uint32_t>(regs, te->registers, te->symbMask, 8, 9);
}

void TbTrace::printRegisters64(const s2e::plugins::ExecutionTraceTb64 *te) {
    const char *regs[] = {"RAX", "RCX", "RDX", "RBX", "RSP", "RBP", "RSI", "RDI"};
    printRegisters<uint64_t>(regs, te->base.registers, te->base.symbMask, 8, 4);

    const char *extRegs[] = {"R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15"};
    printRegisters<uint64_t>(extRegs, te->extendedRegisters, te->symbMask, 8, 4);
}

void TbTrace::printMemoryChecker(const s2e::plugins::ExecutionTraceMemChecker::Serialized *item) {
    ExecutionTraceMemChecker deserializedItem;

    ExecutionTraceMemChecker::deserialize(item, &deserializedItem);

    bool isStackItem = deserializedItem.name.find("stack") != deserializedItem.name.npos;
    if (!PrintMemoryCheckerStack && isStackItem) {
        return;
    }

    m_output << "\033[1;31mMEMCHECKER\033[0m";

    std::string nameHighlightCode;

    if (deserializedItem.flags & ExecutionTraceMemChecker::REVOKE) {
        nameHighlightCode = "\033[1;31m";
        m_output << nameHighlightCode << " REVOKE ";
    }

    if (deserializedItem.flags & ExecutionTraceMemChecker::GRANT) {
        nameHighlightCode = "\033[1;32m";
        m_output << nameHighlightCode << " GRANT  ";
    }

    if (deserializedItem.flags & ExecutionTraceMemChecker::READ) {
        m_output << " READ   ";
    }

    if (deserializedItem.flags & ExecutionTraceMemChecker::WRITE) {
        m_output << " WRITE  ";
    }

    m_output << nameHighlightCode << deserializedItem.name << "\033[0m";

    m_output << " address=0x" << std::hex << deserializedItem.start << " size=0x" << deserializedItem.size << std::endl;
}

void TbTrace::onItem(unsigned traceIndex, const s2e::plugins::ExecutionTraceItemHeader &hdr, void *item) {
    // m_output << "Trace index " << std::dec << traceIndex << std::endl;
    if (hdr.type == s2e::plugins::TRACE_MOD_LOAD) {
        const s2e::plugins::ExecutionTraceModuleLoad &load = *(s2e::plugins::ExecutionTraceModuleLoad *) item;
        m_output << "Loaded module " << load.name << " at 0x" << std::hex << load.loadBase << " size 0x" << std::hex
                 << load.size << " limit 0x" << std::hex << load.loadBase + load.size << " process " << hdr.pid;
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_MOD_UNLOAD) {
        const s2e::plugins::ExecutionTraceModuleUnload &unload = *(s2e::plugins::ExecutionTraceModuleUnload *) item;
        m_output << "Unloaded module at 0x" << std::hex << unload.loadBase << " process " << hdr.pid;
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_PAGEFAULT) {
        const s2e::plugins::ExecutionTracePageFault &fault = *(s2e::plugins::ExecutionTracePageFault *) item;
        m_output << "PF @" << std::hex << fault.pc << " addr=" << fault.address << " isWrite=" << (int) fault.isWrite;
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_EXCEPTION) {
        const s2e::plugins::ExecutionTraceException &fault = *(s2e::plugins::ExecutionTraceException *) item;
        m_output << "\033[1;32mEXCP\033[0m @" << hexval(fault.pc) << " vec=" << hexval(fault.vector);
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_STATE_SWITCH) {
        const s2e::plugins::ExecutionTraceStateSwitch &s = *(s2e::plugins::ExecutionTraceStateSwitch *) item;
        m_output << "State switch " << hdr.stateId << " => " << s.newStateId;
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_FORK) {
        s2e::plugins::ExecutionTraceFork *f = (s2e::plugins::ExecutionTraceFork *) item;
        m_output << "Forked at 0x" << std::hex << f->pc << " process " << hdr.pid << " - ";
        printDebugInfo(hdr.pid, f->pc, 0, false);
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_BLOCK) {
        s2e::plugins::ExecutionTraceBlock *f = (s2e::plugins::ExecutionTraceBlock *) item;
        m_output << "TB at 0x" << std::hex << f->startPc << " process " << hdr.pid << " - ";
        printDebugInfo(hdr.pid, f->endPc, 0, false);
        m_output << std::endl;
        return;
    }

    if (hdr.type == s2e::plugins::TRACE_TB_START || hdr.type == s2e::plugins::TRACE_TB_START_X64 ||
        hdr.type == s2e::plugins::TRACE_TB_END || hdr.type == s2e::plugins::TRACE_TB_END_X64) {
        const s2e::plugins::ExecutionTraceTb *te = (const s2e::plugins::ExecutionTraceTb *) item;

        bool isStart = hdr.type == s2e::plugins::TRACE_TB_START || hdr.type == s2e::plugins::TRACE_TB_START_X64;
        bool is32 = hdr.type == s2e::plugins::TRACE_TB_START || hdr.type == s2e::plugins::TRACE_TB_END;

        m_output << "\033[1;32m" << (isStart ? "START" : "END  ") << "\033[0m ";
        m_output << "RUNNING_" << (te->flags & ExecutionTraceTb::RUNNING_CONCRETE ? "CONCRETE" : "SYMBOLIC") << " ";
        m_output << (te->flags & ExecutionTraceTb::RUNNING_EXCEPTION_EMULATION_CODE
                         ? "RUNNING_EXCEPTION_EMULATION_CODE "
                         : "");
        m_output << "0x" << std::hex << hdr.pid << ":" << te->pc << " - ";
        printDebugInfo(hdr.pid, te->pc, te->size, true);
        m_output << "\n";

        if (PrintRegisters) {
            m_output << "  ";
            if (is32) {
                printRegisters(te);
            } else {
                const s2e::plugins::ExecutionTraceTb64 *te64 = (const s2e::plugins::ExecutionTraceTb64 *) item;
                printRegisters64(te64);
            }
            m_output << "\n";
        }

#ifdef ENABLE_TRACE_STACK
        if (PrintStack) {
            const int columns = 2;
            const int columnWidth = 8;

            static_assert(columns >= 1, "Invalid option");
            static_assert(columnWidth >= 1, "Invalid option");
            static_assert(sizeof(te->stack) % (columns * columnWidth) == 0, "Invalid option");

            uint64_t esp = te->registers[ExecutionTraceTb::ESP];
            if (is32) {
                esp &= 0xFFFFFFFF;
            }

            for (int line = 0; line < sizeof(te->stack) / (columns * columnWidth); line++) {
                int lineOffset = line * columns * columnWidth;

                std::ostringstream hex;
                std::ostringstream ascii;
                for (int col = 0; col < columns; col++) {
                    for (int n = 0; n < columnWidth; n++) {
                        int byteOffset = lineOffset + col * columnWidth + n;
                        bool isSet = BITMASK_GET(te->stackByteMask, byteOffset);
                        bool isSymbolic = BITMASK_GET(te->stackSymbMask, byteOffset);
                        uint8_t v = te->stack[byteOffset];

                        hex << " ";
                        if (isSet) {
                            if (isSymbolic) {
                                // Denote symbolic values with color
                                hex << "\033[1;31m";
                                ascii << "\033[1;31m";
                            }
                            hex << hexval(v, 2, false);
                            ascii << (isprint(v) ? (char) v : '.');
                            if (isSymbolic) {
                                hex << "\033[0m";
                                ascii << "\033[0m";
                            }
                        } else {
                            // Byte value is unknown (memory read failed)
                            hex << "??";
                            ascii << '.';
                        }
                    }

                    hex << " ";
                }

                m_output << "  " << hexval(esp + lineOffset, is32 ? 8 : 16, false) << " " << hex.str() << " |"
                         << ascii.str() << "|\n";
            }
        }
#endif

        m_hasItems = true;
        return;
    }

    if (PrintMemory && (hdr.type == s2e::plugins::TRACE_MEMORY)) {
        const s2e::plugins::ExecutionTraceMemory *te = (const s2e::plugins::ExecutionTraceMemory *) item;
        std::string type;

        type += te->flags & EXECTRACE_MEM_SYMBHOSTADDR ? "H" : "-";
        type += te->flags & EXECTRACE_MEM_SYMBADDR ? "A" : "-";
        type += te->flags & EXECTRACE_MEM_SYMBVAL ? "S" : "-";
        type += te->flags & EXECTRACE_MEM_WRITE ? "W" : "R";
        m_output << "S=" << std::dec << hdr.stateId << " P=0x" << std::hex << hdr.pid << " PC=0x" << std::hex << te->pc
                 << " " << type << (int) te->size << "[0x" << std::hex << te->address << "]=0x" << std::setw(10)
                 << std::setfill('0') << te->value;

        if (te->flags & EXECTRACE_MEM_HASHOSTADDR) {
            m_output << " hostAddr=0x" << te->hostAddress << " ";
        }

        if (te->flags & EXECTRACE_MEM_OBJECTSTATE) {
            m_output << " cb=0x" << te->concreteBuffer << " ";
        }

        m_output << "\t";

        printDebugInfo(hdr.pid, te->pc, 0, false);
        m_output << std::setfill(' ');
        m_output << std::endl;
        return;
    }

    if (PrintMemoryChecker && (hdr.type == s2e::plugins::TRACE_MEM_CHECKER)) {
        const s2e::plugins::ExecutionTraceMemChecker::Serialized *te =
            (const s2e::plugins::ExecutionTraceMemChecker::Serialized *) item;
        printMemoryChecker(te);
    }
}

TbTraceTool::TbTraceTool() {
    m_binaries.setPaths(ModDir);
}

TbTraceTool::~TbTraceTool() {
}

void TbTraceTool::flatTrace() {
    PathBuilder pb(&m_parser);
    m_parser.parse(TraceFiles);

    ModuleCache mc(&pb);
    TestCase tc(&pb);

    PathSet paths;
    pb.getPaths(paths);

    cl::list<unsigned>::const_iterator listit;

    if (PathList.empty()) {
        PathSet::iterator pit;
        for (pit = paths.begin(); pit != paths.end(); ++pit) {
            PathList.push_back(*pit);
        }
    }

    // XXX: this is efficient only for short paths or for a small number of
    // path, because complexity is O(n2): we reprocess the prefixes.
    for (listit = PathList.begin(); listit != PathList.end(); ++listit) {
        std::cout << "Processing path " << std::dec << *listit << std::endl;
        PathSet::iterator pit = paths.find(*listit);
        if (pit == paths.end()) {
            std::cerr << "Could not find path with id " << std::dec << *listit << " in the execution trace."
                      << std::endl;
            continue;
        }

        std::stringstream ss;
        ss << LogDir << "/" << *listit << ".txt";
        std::ofstream traceFile(ss.str().c_str());

        TbTrace trace(&m_binaries, &mc, &pb, traceFile);

        if (!pb.processPath(*listit)) {
            std::cerr << "Could not process path " << std::dec << *listit << std::endl;
            continue;
        }

        traceFile << "----------------------" << std::endl;

        if (trace.hasDebugInfo() == false) {
            traceFile << "WARNING: No debug information for any module in the path " << std::dec << *listit
                      << std::endl;
            traceFile << "WARNING: Make sure you have set the module path properly and the binaries contain debug "
                         "information."
                      << std::endl
                      << std::endl;
        }

        if (trace.hasModuleInfo() == false) {
            traceFile << "WARNING: No module information for any module in the path " << std::dec << *listit
                      << std::endl;
            traceFile << "WARNING: Make sure to use the ModuleTracer plugin before running this tool." << std::endl
                      << std::endl;
        }

        if (trace.hasItems() == false) {
            traceFile << "WARNING: No basic blocks in the path " << std::dec << *listit << std::endl;
            traceFile << "WARNING: Make sure to use the TranslationBlockTracer plugin before running this tool. "
                      << std::endl
                      << std::endl;
        }

        TestCaseState *tcs = static_cast<TestCaseState *>(pb.getState(&tc, *pit));
        if (!tcs) {
            traceFile << "WARNING: No test case in the path " << std::dec << *listit << std::endl;
            traceFile << "WARNING: Make sure to use the TestCaseGenerator plugin and terminate the states before "
                         "running this tool. "
                      << std::endl
                      << std::endl;
        } else {
            tcs->printInputs(traceFile);
        }
    }
}
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " tbtrace");

    s2etools::TbTraceTool trace;
    trace.flatTrace();

    return 0;
}
