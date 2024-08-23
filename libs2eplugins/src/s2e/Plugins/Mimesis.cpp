//
// Copyright (c) 2020-2024 Kuan-Yen Chou. All rights reserved.
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation files
// (the "Software"), to deal with the Software without restriction,
// including without limitation the rights to use, copy, modify, merge,
// publish, distribute, sublicense, and/or sell copies of the Software,
// and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// * Redistributions of source code must retain the above copyright notice,
//   this list of conditions and the following disclaimers.
//
// * Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimers in the
//   documentation and/or other materials provided with the distribution.
//
// * Neither the names of Mimesis, University of Illinois Urbana-Champaign
//   nor the names of its contributors may be used to endorse or promote products
//   derived from this Software without specific prior written permission.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// CONTRIBUTORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS WITH
// THE SOFTWARE.
//

#include "Mimesis.h"

#include <arpa/inet.h>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <string>
#include <sys/ioctl.h>
#include <unistd.h>

#include "s2e/S2E.h"
#include "s2e/S2EDeviceState.h"
#include "s2e/S2EExecutionStateMemory.h"
#include "s2e/S2EExecutionStateRegisters.h"
#include "s2e/Utils.h"
#include "s2e/opcodes.h"
#include "klee/Expr.h"
#include "klee/util/Ref.h"
#include "llvm/Support/raw_ostream.h"
#include "Core/BaseInstructions.h"
#include "OSMonitors/Linux/LinuxMonitor.h"
#include "OSMonitors/Support/ProcessExecutionDetector.h"
#include "cpu/types.h"
#include "fsigc++/fsigc++.h"
#include "libps/manager.hpp"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Mimesis,                                                     // Plugin class
                  "Automated model extraction for stateful network functions", // Plugin description
                  "",                                                          // Unused
                  "LinuxMonitor",                                              // Dependency plugins
                  "BaseInstructions",                                          // Dependency plugins
                  "ProcessExecutionDetector"                                   // Dependency plugins
);

void Mimesis::initialize() {
    // Get the dependent plugins
    _monitor = s2e()->getPlugin<LinuxMonitor>();
    _base_inst = s2e()->getPlugin<BaseInstructions>();
    _proc_detector = s2e()->getPlugin<ProcessExecutionDetector>();
    s2e_assert(nullptr, _monitor, "Plugin LinuxMonitor is missing");
    s2e_assert(nullptr, _base_inst, "Plugin BaseInstructions is missing");
    s2e_assert(nullptr, _proc_detector, "Plugin ProcessExecutionDetector is missing");

    // Collect all interfaces. Here we see the QEMU host interfaces.
    struct if_nameindex *intfs = if_nameindex();
    s2e_assert(nullptr, intfs, "if_nameindex() failed");
    _interfaces.clear();
    for (auto intf = intfs; intf->if_index != 0 || intf->if_name != nullptr; ++intf) {
        std::string if_name{intf->if_name};
        if (if_name.substr(0, 3) != "tap") {
            continue;
        }
        _interfaces.push_back(if_name);
    }
    if_freenameindex(intfs);
    s2e_assert(nullptr, !_interfaces.empty(), "No interfaces available");

    // Callbacks for the control flow of symbolic execution.
    s2e()->getCorePlugin()->onInitializationComplete.connect(sigc::mem_fun(*this, &Mimesis::onInitializationComplete));
    s2e()->getCorePlugin()->onStateForkDecide.connect(sigc::mem_fun(*this, &Mimesis::onStateForkDecide));
    s2e()->getCorePlugin()->onStateFork.connect(sigc::mem_fun(*this, &Mimesis::onStateFork));
    s2e()->getCorePlugin()->onCustomInstruction.connect(sigc::mem_fun(*this, &Mimesis::onCustomInstruction));
    s2e()->getCorePlugin()->onStateMerge.connect(sigc::mem_fun(*this, &Mimesis::onStateMerge));
    s2e()->getCorePlugin()->onStateSwitch.connect(sigc::mem_fun(*this, &Mimesis::onStateSwitch));
    s2e()->getCorePlugin()->onStateKill.connect(sigc::mem_fun(*this, &Mimesis::onStateKill));
    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &Mimesis::onEngineShutdown));

    // Callbacks for the memory access of symbolic execution.
    s2e()->getCorePlugin()->onSymbolicAddress.connect(sigc::mem_fun(*this, &Mimesis::onSymbolicAddress));
    s2e()->getCorePlugin()->onBeforeSymbolicDataMemoryAccess.connect(
        sigc::mem_fun(*this, &Mimesis::onBeforeSymbolicDataMemoryAccess));
    s2e()->getCorePlugin()->onAfterSymbolicDataMemoryAccess.connect(
        sigc::mem_fun(*this, &Mimesis::onAfterSymbolicDataMemoryAccess));
    s2e()->getCorePlugin()->onConcreteDataMemoryAccess.connect(
        sigc::mem_fun(*this, &Mimesis::onConcreteDataMemoryAccess));

    // Callbacks for when the interesting program has been loaded/unloaded.
    _proc_detector->onProcessLoad.connect(sigc::mem_fun(*this, &Mimesis::onProcessLoad));
    _proc_detector->onProcessUnload.connect(sigc::mem_fun(*this, &Mimesis::onProcessUnload));

    // Initialize the packet set library
    ps::Manager::get().init(/*n_workers=*/1,
                            /*memory_cap=*/1UL * 1024 * 1024 * 1024,
                            /*table_ratio=*/1,
                            /*initial_ratio=*/5);
}

Mimesis::~Mimesis() {
}

void Mimesis::onInitializationComplete(S2EExecutionState *state) {
    // Temporarily disable kernel tracking for userspace NFs.
    // _proc_detector->setTrackKernel(true); // Kernel tracking is always enabled.

    if (_proc_detector->isTrackedModulesEmpty()) {
        // If there is no tracked modules configured, it is most likely that the
        // kernel is being analyzed, we can start sending the input packets
        // immediately.
        getInfoStream(state) << "No target programs configured.\n";
        // send_packets_to(state, _interfaces.at(0));
    }

    getInfoStream(state) << "Timestamp: (onInitializationComplete) " + timestamp() + "\n";
}

void Mimesis::onStateForkDecide(S2EExecutionState *state, const klee::ref<klee::Expr> &condition, bool &allow_forking) {
    auto pc = get_pc(state);
    if (!_proc_detector->isTrackedPc(state, pc)) {
        // s2e()->getExecutor()->terminateState(*state, ("Kill state at untracked PC " + hexval(pc).str() +
        //                                               (_monitor->isKernelAddress(pc) ? " [kernel]" : " [program]")));
        return;
    }
}

void Mimesis::onStateFork(S2EExecutionState *original_state, const std::vector<S2EExecutionState *> &new_states,
                          const std::vector<klee::ref<klee::Expr>> &conditions) {
    auto pc = get_pc(original_state);
    if (!_proc_detector->isTrackedPc(original_state, pc)) {
        getWarningsStream(original_state) << "State forking in untracked region.\n";
        // DECLARE_PLUGINSTATE(MimesisState, original_state);
        // s2e()->getExecutor()->terminateState(*original_state, "Kill state at depth " +
        // std::to_string(plgState->depth));
        return;
    }

    // for (S2EExecutionState *state : new_states) {
    //     auto constraints = state->constraints().getConstraintSet();
    //     ps::PacketSet ps(constraints);
    //     if (ps.empty()) {
    //         s2e()->getExecutor()->terminateState(*state, "Kill unsat state");
    //     }
    // }
    // ps::Manager::get().report_stats(stdout);
}

void Mimesis::onCustomInstruction(S2EExecutionState *state, uint64_t opcode) {
    if (!OPCODE_CHECK(opcode, MIMESIS_OPCODE)) {
        return;
    }

    uint8_t op = (opcode >> 16) & 0xFF;
    switch (op) {
        case MIMESIS_OP_USER_RECV:
            user_recv(state);
            break;
        case MIMESIS_OP_USER_SEND:
            user_send(state);
            break;
        case MIMESIS_OP_KERNEL_RECV:
            kernel_recv(state);
            break;
        case MIMESIS_OP_KERNEL_SEND:
            kernel_send(state);
            break;
        default:
            getWarningsStream(state) << "Invalid Mimesis opcode " << hexval(op) << '\n';
            break;
    }
}

void Mimesis::onStateMerge(S2EExecutionState *destination, S2EExecutionState *source) {
    // getDebugStream(destination) << "onStateMerge" << '\n';
}

void Mimesis::onStateSwitch(S2EExecutionState *current_state, S2EExecutionState *next_state) {
    // The message is disabled due to frequent invocation of the callback.
    // getDebugStream(current_state) << "onStateSwitch" << '\n';
}

void Mimesis::onStateKill(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MimesisState, state);
    if (plgState->ingress_intf && plgState->ingress_pkt) {
        record_trace(state, nullptr, nullptr);
    }
}

void Mimesis::onSymbolicAddress(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr, uint64_t concrete_addr,
                                bool &concretize, CorePlugin::symbolicAddressReason reason) {
    // The message is disabled due to frequent invocation of the callback.
    // getDebugStream(state) << "onSymbolicAddress" << '\n';
}

void Mimesis::onBeforeSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr,
                                               klee::ref<klee::Expr> value, bool is_write) {
    // The message is disabled due to frequent invocation of the callback.
    // getDebugStream(state) << "onBeforeSymbolicDataMemoryAccess" << '\n';
}

void Mimesis::onAfterSymbolicDataMemoryAccess(S2EExecutionState *state, klee::ref<klee::Expr> virtual_addr,
                                              klee::ref<klee::Expr> host_addr, klee::ref<klee::Expr> value,
                                              unsigned flags) {
    // The message is disabled due to frequent invocation of the callback.
    // getDebugStream(state) << "onAfterSymbolicDataMemoryAccess" << '\n';
}

void Mimesis::onConcreteDataMemoryAccess(S2EExecutionState *state, uint64_t virtual_addr, uint64_t value, uint8_t size,
                                         unsigned flags) {
    // The message is disabled due to frequent invocation of the callback.
    // getDebugStream(state) << "onConcreteDataMemoryAccess" << '\n';
}

void Mimesis::onProcessLoad(S2EExecutionState *state, uint64_t page_dir, uint64_t pid, const std::string &proc_name) {
    getInfoStream(state) << "Target program loaded: " << proc_name << ", pid: " << hexval(pid) << ".\n";
    getInfoStream(state) << "Timestamp: (onProcessLoad) " + timestamp() + "\n";
    send_packets_to(state, _interfaces.at(0));
}

void Mimesis::onProcessUnload(S2EExecutionState *state, uint64_t page_dir, uint64_t pid, uint64_t return_code) {
    getInfoStream(state) << "Unloading target program (return: " << return_code << ")\n";
    getInfoStream(state) << "Timestamp: (onProcessUnload) " + timestamp() + "\n";
    s2e()->getExecutor()->terminateState(*state, "Kill state at program unload");
}

void Mimesis::onEngineShutdown() {
    llvm::raw_ostream *os = &g_s2e->getInfoStream();
    *os << "Timestamp: (onEngineShutdown) " + timestamp() + "\n"
        << "=======================================================\n"
        << "          Start serializing the model\n"
        << "=======================================================\n\n";
}

std::string Mimesis::timestamp() const {
    auto tp = std::chrono::high_resolution_clock::now();
    auto nano = std::chrono::duration_cast<std::chrono::nanoseconds>(tp.time_since_epoch()).count();
    std::string s = std::to_string(nano);
    return s.substr(0, s.size() - 9) + "." + s.substr(s.size() - 9);
}

uint64_t Mimesis::get_pc(S2EExecutionState *state) const {
    static_assert(std::is_fundamental<target_ulong>::value, "Read from register can only use primitive types");
    target_ulong ret;
    memset(&ret, 0, sizeof(ret));
    if (!state->regs()->read(CPU_OFFSET(eip), &ret, sizeof(ret), /*concretize=*/false)) {
        getWarningsStream(state) << "Failed to read PC (eip), possibly due to a symbolic PC value.\n";
        return 0;
    }
    return ret;
}

void Mimesis::send_packets_to(S2EExecutionState *state, const std::string &if_name) const {
    constexpr char send_packet_fn[] = "/dev/shm/send_packet";
    std::ofstream send_packet(send_packet_fn, std::ofstream::out | std::ofstream::trunc);
    s2e_assert(state, send_packet, "Failed to open " + std::string(send_packet_fn));
    send_packet << if_name << std::endl;
    send_packet.close();
}

void Mimesis::stop_sending_packets(S2EExecutionState *state) const {
    send_packets_to(state, "");
}

void Mimesis::create_sym_var(S2EExecutionState *state, uintptr_t address, unsigned int size,
                             const std::string &var_name) const {
    std::string klee_var_name;
    _base_inst->makeSymbolic(state, address, size, var_name, nullptr, &klee_var_name);
    ps::Manager::get().register_symbolic_variable(var_name, /*nbits=*/size * 8, klee_var_name);
    getInfoStream(state) << "Symbolic variable created: " << klee_var_name << "\n";
    stop_sending_packets(state);
}

// TODO: Make this configurable in `s2e-config.lua`.
constexpr int max_depth = 2;

void Mimesis::user_recv(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MimesisState, state);

    // Consecutive reception, mark the previous ingress packet as "dropped" (i.e., empty output packet set).
    if (plgState->ingress_intf && plgState->ingress_pkt) {
        record_trace(state, nullptr, nullptr);
    }

    s2e_assert(state, !plgState->ingress_intf && !plgState->ingress_pkt,
               "Ingress interface and packet must be both set or both unset");

    // Next depth (next packet in the input sequence)
    plgState->depth++;
    if (plgState->depth > max_depth) {
        s2e()->getExecutor()->terminateState(*state, "Kill state at depth " + std::to_string(plgState->depth));
        return;
    }

    // Create symbolic arrays for the ingress interface and packet.
    target_ulong intf_ptr, buffer, len;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &intf_ptr, sizeof(intf_ptr), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &buffer, sizeof(buffer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &len, sizeof(len), false);
    s2e_assert(state, ok, "Symbolic argument was passed to user_recv");
    create_sym_var(state, /*address=*/intf_ptr, /*size=*/1, "in_intf_d" + std::to_string(plgState->depth));
    create_sym_var(state, /*address=*/buffer, /*size=*/len, "in_pkt_d" + std::to_string(plgState->depth));

    // Update the plugin state with the ingress interface and packet.
    plgState->ingress_intf = state->mem()->read(intf_ptr, /*width=(bits)*/ 8, VirtualAddress);
    plgState->ingress_pkt = state->mem()->read(buffer, /*width=(bits)*/ len * 8, VirtualAddress);
}

void Mimesis::user_send(S2EExecutionState *state) {
    // Get the egress interface and packet as symbolic expressions.
    klee::ref<klee::Expr> intf, pkt;
    target_ulong buffer, len;
    bool ok = true;
    intf = state->regs()->read(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int8);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &buffer, sizeof(buffer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &len, sizeof(len), false);
    s2e_assert(state, intf, "Incorrect offset/width for user_send intf");
    s2e_assert(state, ok, "Symbolic egress buffer address or length in user_send");
    pkt = state->mem()->read(buffer, /*width=(bits)*/ len * 8, VirtualAddress);

    record_trace(state, intf, pkt);
}

void Mimesis::kernel_recv(S2EExecutionState *state) {
    DECLARE_PLUGINSTATE(MimesisState, state);

    // Consecutive reception, mark the previous ingress packet as "dropped" (i.e., empty output packet set).
    if (plgState->ingress_intf && plgState->ingress_pkt) {
        record_trace(state, nullptr, nullptr);
    }

    s2e_assert(state, !plgState->ingress_intf && !plgState->ingress_pkt,
               "Ingress interface and packet must be both set or both unset");

    // Next depth (next packet in the input sequence)
    plgState->depth++;
    if (plgState->depth > max_depth) {
        s2e()->getExecutor()->terminateState(*state, "Kill state at depth " + std::to_string(plgState->depth));
        return;
    }

    // Create symbolic arrays for the ingress interface and packet.
    target_ulong intf_ptr, buffer, len;
    bool ok = true;
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EAX]), &intf_ptr, sizeof(intf_ptr), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &buffer, sizeof(buffer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &len, sizeof(len), false);
    s2e_assert(state, ok, "Symbolic argument was passed to kernel_recv");
    create_sym_var(state, /*address=*/intf_ptr, /*size=*/1, "in_intf_d" + std::to_string(plgState->depth));
    create_sym_var(state, /*address=*/buffer, /*size=*/len, "in_pkt_d" + std::to_string(plgState->depth));

    // Update the plugin state with the ingress interface and packet.
    plgState->ingress_intf = state->mem()->read(intf_ptr, /*width=(bits)*/ 8, VirtualAddress);
    plgState->ingress_pkt = state->mem()->read(buffer, /*width=(bits)*/ len * 8, VirtualAddress);
}

void Mimesis::kernel_send(S2EExecutionState *state) {
    // Get the egress interface and packet as symbolic expressions.
    klee::ref<klee::Expr> intf, pkt;
    target_ulong buffer, len;
    bool ok = true;
    intf = state->regs()->read(CPU_OFFSET(regs[R_EAX]), klee::Expr::Int8);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_ECX]), &buffer, sizeof(buffer), false);
    ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &len, sizeof(len), false);
    s2e_assert(state, intf, "Incorrect offset/width for kernel_send intf");
    s2e_assert(state, ok, "Symbolic egress buffer address or length in kernel_send");
    pkt = state->mem()->read(buffer, /*width=(bits)*/ len * 8, VirtualAddress);

    record_trace(state, intf, pkt);
}

void Mimesis::record_trace(S2EExecutionState *state, const klee::ref<klee::Expr> egress_intf,
                           const klee::ref<klee::Expr> egress_pkt) {
    DECLARE_PLUGINSTATE(MimesisState, state);
    s2e_assert(state, plgState->ingress_intf, "Failed to record trace: null ingress interface");
    s2e_assert(state, plgState->ingress_pkt, "Failed record trace: null ingress packet");

    // Build the path constraint
    klee::ref<klee::Expr> path_constraint = klee::ConstantExpr::create(1, klee::Expr::Bool);
    for (const auto &c : state->constraints().getConstraintSet()) {
        path_constraint = klee::AndExpr::create(path_constraint, c);
    }

    llvm::raw_ostream *os = &getInfoStream(state);
    *os << "\n===== Mimesis::record_trace =====\n"
        << "  depth: " << plgState->depth << "\n"
        << "  in_intf: " << plgState->ingress_intf << "\n"
        << "  in_pkt:  " << plgState->ingress_pkt << "\n"
        << "  eg_intf: ";
    if (egress_intf) {
        *os << egress_intf << "\n";
    } else {
        *os << "(null)\n";
    }
    *os << "  eg_pkt:  ";
    if (egress_pkt) {
        *os << egress_pkt << "\n";
    } else {
        *os << "(null)\n";
    }
    *os << "------- Path constraints -------\n";
    *os << path_constraint << "\n";
    *os << "--------------------------------\n";

    s2e_assert(state,
               _model.insert(plgState->depth, plgState->ingress_intf, plgState->ingress_pkt, egress_intf, egress_pkt,
                             path_constraint),
               "Failed to insert trace to model");

    // Clear the plugin state for the current execution path.
    plgState->ingress_intf = nullptr;
    plgState->ingress_pkt = nullptr;
}

} // namespace plugins
} // namespace s2e

// namespace {
//
// void print_query_result(llvm::raw_ostream &os, const std::set<std::shared_ptr<ps::TableEntry>> &result) {
//     std::function<void(llvm::raw_ostream &, const std::shared_ptr<ps::TableEntry> &)> print_single_entry_rec;
//     print_single_entry_rec = [&print_single_entry_rec](llvm::raw_ostream &os,
//                                                        const std::shared_ptr<ps::TableEntry> &entry) -> void {
//         os << entry->to_string();
//         for (const auto &next : entry->next_entries()) {
//             print_single_entry_rec(os, next);
//         }
//     };
//
//     os << "---------  Query Result  ---------------------------\n";
//     for (const auto &entry : result) {
//         print_single_entry_rec(os, entry);
//     }
//     os << "----------------------------------------------------\n";
// }
//
// } // namespace

// void Mimesis::user_demo_stateful_queries(llvm::raw_ostream &os) const {
//     // user-demo-stateful: depth 1, drop, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_intf_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0x3 (Read w8 0x0 in_intf_d1))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         expr = klee::EqExpr::create(klee::ConstantExpr::create(0x3, klee::Expr::Int8), expr);
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(1, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
//
//     // user-demo-stateful: depth 2, pass -> pass, single-value
//     {
//         klee::ArrayPtr d1_array = klee::Array::create("in_intf_d1", 1);
//         klee::ArrayPtr d2_array = klee::Array::create("in_intf_d2", 1);
//         klee::UpdateListPtr d1_ul = klee::UpdateList::create(d1_array, 0);
//         klee::UpdateListPtr d2_ul = klee::UpdateList::create(d2_array, 0);
//         klee::ref<klee::Expr> expr, d1_expr, d2_expr;
//         // (And (Eq 0x0 (Read w8 0x0 in_intf_d1))
//         //      (Eq 0x5 (Read w8 0x0 in_intf_d2)))
//         d1_expr = klee::ReadExpr::create(d1_ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         d1_expr = klee::EqExpr::create(klee::ConstantExpr::create(0, klee::Expr::Int8), d1_expr);
//         d2_expr = klee::ReadExpr::create(d2_ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         d2_expr = klee::EqExpr::create(klee::ConstantExpr::create(5, klee::Expr::Int8), d2_expr);
//         expr = klee::AndExpr::create(d1_expr, d2_expr);
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(2, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
// }
//
// void Mimesis::user_demo_stateless_queries(llvm::raw_ostream &os) const {
//     // user-demo-stateless: depth 1, pass, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0x3
//         //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
//         expr = klee::EqExpr::create(klee::ConstantExpr::create(3, klee::Expr::Int64), expr);
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(1, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
//
//     // user-demo-stateless: depth 1, drop, single-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr;
//         // (Eq 0xff
//         //     (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         expr = klee::ZExtExpr::create(expr, klee::Expr::Int64);
//         expr = klee::EqExpr::create(klee::ConstantExpr::create(0xff, klee::Expr::Int64), expr);
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(1, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
//
//     // user-demo-stateless: depth 1, pass & drop, symbolic multi-value
//     {
//         klee::ArrayPtr array = klee::Array::create("in_pkt_d1", 1);
//         klee::UpdateListPtr ul = klee::UpdateList::create(array, 0);
//         klee::ref<klee::Expr> expr, n0;
//         // (And (Ule 0x3
//         //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1)))
//         //      (Uge 0xf
//         //           N0: (ZExt w64 (Read w8 0x0 in_pkt_d1))))
//         expr = klee::ReadExpr::create(ul, klee::ConstantExpr::create(0, klee::Expr::Int32));
//         n0 = klee::ZExtExpr::create(expr, klee::Expr::Int64);
//         expr = klee::AndExpr::create(klee::UleExpr::create(klee::ConstantExpr::create(0x3, klee::Expr::Int64), n0),
//                                      klee::UgeExpr::create(klee::ConstantExpr::create(0xf, klee::Expr::Int64), n0));
//         os << "Query constraint:\n" << expr << "\n";
//         os << "Timestamp: (queryStart) " + timestamp() + "\n";
//         auto res = _model.query(1, expr);
//         os << "Timestamp: (queryEnd) " + timestamp() + "\n";
//         print_query_result(os, res);
//         os << "=======================================================\n";
//     }
// }
