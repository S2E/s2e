///
/// Copyright (C) 2017, Cyberhaven
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

#ifndef S2E_PLUGINS_SymbolicHardware_H
#define S2E_PLUGINS_SymbolicHardware_H

#include <inttypes.h>
#include <vector>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>

#include <llvm/ADT/SmallVector.h>

namespace s2e {
namespace plugins {
namespace hw {

typedef std::vector<uint8_t> ConcreteArray;
typedef std::pair<uint16_t, uint16_t> SymbolicPortRange;
typedef std::pair<uint64_t, uint64_t> SymbolicMmioRange;

typedef llvm::SmallVector<SymbolicPortRange, 4> SymbolicPortRanges;
typedef llvm::SmallVector<SymbolicMmioRange, 4> SymbolicMmioRanges;

class SymbolicHardware : public Plugin {
    S2E_PLUGIN

private:
    // TODO: make this per-state and per-device
    SymbolicPortRanges m_ports;
    SymbolicMmioRanges m_mmio;

    template <typename T> bool parseRangeList(ConfigFile *cfg, const std::string &key, T &result);

    bool parseConfig();

    template <typename T, typename U> inline bool isSymbolic(T ports, U port);

public:
    ///
    /// \brief onSymbolicRegisterRead control whether
    /// a symbolic value should be created upon a read from a symbolic
    /// hardware region.
    ///
    sigc::signal<void, S2EExecutionState *, SymbolicHardwareAccessType /* type */, uint64_t /* physicalAddress */,
                 unsigned /* size */, bool * /* createSymbolicValue */>
        onSymbolicRegisterRead;

    SymbolicHardware(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

    bool isPortSymbolic(uint16_t port);
    bool isMmioSymbolic(uint64_t physAddr);

    klee::ref<klee::Expr> createExpression(S2EExecutionState *state, SymbolicHardwareAccessType type, uint64_t address,
                                           unsigned size, uint64_t concreteValue);
};

} // namespace hw
} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SymbolicHardware_H
