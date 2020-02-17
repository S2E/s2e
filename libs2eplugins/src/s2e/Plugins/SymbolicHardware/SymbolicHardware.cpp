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

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>

#include "SymbolicHardware.h"

namespace {
llvm::cl::opt<bool> DebugSymbHw("debug-symbolic-hardware", llvm::cl::init(false));
}

namespace s2e {
namespace plugins {
namespace hw {

extern "C" {
static bool symbhw_is_symbolic(uint16_t port, void *opaque);
static klee::ref<klee::Expr> symbhw_symbportread(uint16_t port, unsigned size, uint64_t concreteValue, void *opaque);
static bool symbhw_symbportwrite(uint16_t port, const klee::ref<klee::Expr> &value, void *opaque);

static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque);
}

static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque);

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque);

S2E_DEFINE_PLUGIN(SymbolicHardware, "SymbolicHardware S2E plugin", "", );

void SymbolicHardware::initialize() {
    if (!parseConfig()) {
        getWarningsStream() << "Could not parse config\n";
        exit(-1);
    }

    g_symbolicPortHook = SymbolicPortHook(symbhw_is_symbolic, symbhw_symbportread, symbhw_symbportwrite, this);
    g_symbolicMemoryHook = SymbolicMemoryHook(symbhw_is_mmio_symbolic, symbhw_symbread, symbhw_symbwrite, this);
}

template <typename T> bool SymbolicHardware::parseRangeList(ConfigFile *cfg, const std::string &key, T &result) {
    bool ok;

    int ranges = cfg->getListSize(key, &ok);
    if (!ok) {
        getWarningsStream() << "Could not parse ranges: " << key << "\n";
        return false;
    }

    for (int i = 0; i < ranges; ++i) {
        std::stringstream ss;
        ss << key << "[" << (i + 1) << "]";
        uint64_t start = cfg->getInt(ss.str() + "[1]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse start port: " << ss.str() + "[1]"
                                << "\n";
            return false;
        }

        uint64_t end = cfg->getInt(ss.str() + "[2]", 0, &ok);
        if (!ok) {
            getWarningsStream() << "Could not parse port range: " << ss.str() + "[2]"
                                << "\n";
            return false;
        }

        if (!(start <= end)) {
            getWarningsStream() << hexval(start) << " is greater than " << hexval(end) << "\n";
            return false;
        }

        result.push_back(std::make_pair(start, end));
    }

    return true;
}

///
/// \brief SymbolicHardware::parseConfig
///
/// pluginsConfig.SymbolicHarwdare {
///     dev1 = {
///         ports = {
///             {0x100, 0x101},
///             {0x100, 0x103},
///         }
///
///         mem = {
///             {0xfffc0000, 0xfffcffff},
///         }
///     }
/// }
///
/// \return true if parsing was successful
///
bool SymbolicHardware::parseConfig(void) {
    ConfigFile *cfg = s2e()->getConfig();
    auto keys = cfg->getListKeys(getConfigKey());
    for (auto key : keys) {
        std::stringstream ss;
        ss << getConfigKey() << "." << key;
        SymbolicPortRanges ports;
        if (!parseRangeList(cfg, ss.str() + ".ports", ports)) {
            return false;
        }

        for (auto port : ports) {
            getDebugStream() << "Adding symbolic port range " << hexval(port.first) << " - " << hexval(port.second)
                             << "\n";
            m_ports.push_back(port);
        }

        SymbolicMmioRanges mmio;
        if (!parseRangeList(cfg, ss.str() + ".mmio", mmio)) {
            return false;
        }

        for (auto m : mmio) {
            getDebugStream() << "Adding symbolic mmio range " << hexval(m.first) << " - " << hexval(m.second) << "\n";
            m_mmio.push_back(m);
        }
    }

    return true;
}

template <typename T, typename U> inline bool SymbolicHardware::isSymbolic(T ports, U port) {
    for (auto &p : ports) {
        if (port >= p.first && port <= p.second) {
            return true;
        }
    }

    return false;
}

bool SymbolicHardware::isPortSymbolic(uint16_t port) {
    return isSymbolic(m_ports, port);
}

bool SymbolicHardware::isMmioSymbolic(uint64_t physAddr) {
    return isSymbolic(m_mmio, physAddr);
}

static void SymbHwGetConcolicVector(uint64_t in, unsigned size, ConcreteArray &out) {
    union {
        // XXX: assumes little endianness!
        uint64_t value;
        uint8_t array[8];
    };

    value = in;
    out.resize(size);
    for (unsigned i = 0; i < size; ++i) {
        out[i] = array[i];
    }
}

klee::ref<klee::Expr> SymbolicHardware::createExpression(S2EExecutionState *state, SymbolicHardwareAccessType type,
                                                         uint64_t address, unsigned size, uint64_t concreteValue) {
    bool createVariable = true;
    onSymbolicRegisterRead.emit(state, type, address, size, &createVariable);

    std::stringstream ss;
    switch (type) {
        case SYMB_MMIO:
            ss << "iommuread_";
            break;
        case SYMB_DMA:
            ss << "dmaread_";
            break;
        case SYMB_PORT:
            ss << "portread_";
            break;
    }

    ss << hexval(address) << "@" << hexval(state->regs()->getPc());

    getDebugStream(g_s2e_state) << ss.str() << " size " << hexval(size) << " value=" << hexval(concreteValue)
                                << " sym=" << (createVariable ? "yes" : "no") << "\n";

    if (createVariable) {
        ConcreteArray concolicValue;
        SymbHwGetConcolicVector(concreteValue, size, concolicValue);
        return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
    } else {
        return klee::ExtractExpr::create(klee::ConstantExpr::create(concreteValue, 64), 0, size * 8);
    }
}

//////////////////////////////////////////////////////////////////////

static bool symbhw_is_symbolic(uint16_t port, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);
    return hw->isPortSymbolic(port);
}

static klee::ref<klee::Expr> symbhw_symbportread(uint16_t port, unsigned size, uint64_t concreteValue, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "reading from port " << hexval(port) << " value: " << concreteValue << "\n";
    }

    return hw->createExpression(g_s2e_state, SYMB_PORT, port, size, concreteValue);
}

static bool symbhw_symbportwrite(uint16_t port, const klee::ref<klee::Expr> &value, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "writing to port " << hexval(port) << " value: " << value << "\n";
    }

    return !hw->isPortSymbolic(port);
}

//////////////////////////////////////////////////////////////////////
static bool symbhw_is_mmio_symbolic(struct MemoryDesc *mr, uint64_t physaddr, uint64_t size, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);
    return hw->isMmioSymbolic(physaddr);
}

// XXX: remove MemoryDesc
static klee::ref<klee::Expr> symbhw_symbread(struct MemoryDesc *mr, uint64_t physaddress,
                                             const klee::ref<klee::Expr> &value, SymbolicHardwareAccessType type,
                                             void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "reading mmio " << hexval(physaddress) << " value: " << value << "\n";
    }

    unsigned size = value->getWidth() / 8;
    uint64_t concreteValue = g_s2e_state->toConstantSilent(value)->getZExtValue();
    return hw->createExpression(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
}

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "writing mmio " << hexval(physaddress) << " value: " << value << "\n";
    }

    // TODO: return bool to not call original handler, like for I/O
}

} // namespace hw
} // namespace plugins
} // namespace s2e
