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

#include <llvm/Support/CommandLine.h>

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
    if (!ARMMMIORangeConfig()) {
        getWarningsStream() << "Could not parse config\n";
        exit(-1);
    }

    bitbandFlag = false;
    std::string cpuArchName = s2e()->getConfig()->getString(getConfigKey() + ".CPUArchName", "ARMv7m");
    if (cpuArchName == "ARMv7m") {
        bitbandFlag = true;
        getInfoStream() << "bit-banding feature only support for ARMv7m CPU!\n";
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
bool SymbolicHardware::ARMMMIORangeConfig(void) {
    SymbolicMmioRange m;

    // ARM MMIO range 0x40000000-0x60000000
    m.first = 0x40000000;
    m.second = 0x5fffffff;

    getDebugStream() << "Adding symbolic mmio range: " << hexval(m.first) << " - " << hexval(m.second) << "\n";
    m_mmio.push_back(m);

    return true;
}

/*bool SymbolicHardware::parseConfig(void) {*/
    //ConfigFile *cfg = s2e()->getConfig();
    //auto keys = cfg->getListKeys(getConfigKey());
    //for (auto key : keys) {
        //std::stringstream ss;
        //ss << getConfigKey() << "." << key;
        //SymbolicPortRanges ports;
        //if (!parseRangeList(cfg, ss.str() + ".ports", ports)) {
            //return false;
        //}

        //for (auto port : ports) {
            //getDebugStream() << "Adding symbolic port range " << hexval(port.first) << " - " << hexval(port.second)
                             //<< "\n";
            //m_ports.push_back(port);
        //}

        //SymbolicMmioRanges mmio;
        //if (!parseRangeList(cfg, ss.str() + ".mmio", mmio)) {
            //return false;
        //}

        //for (auto m : mmio) {
            //getDebugStream() << "Adding symbolic mmio range " << hexval(m.first) << " - " << hexval(m.second) << "\n";
            //m_mmio.push_back(m);
        //}
    //}

    //return true;
/*}*/

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

klee::ref<klee::Expr> SymbolicHardware::onReadPeripheral(S2EExecutionState *state, SymbolicHardwareAccessType type,
                                                         uint64_t address, unsigned size, uint64_t concreteValue) {

    // peripheral address bit-band alias
    if (address >= 0x42000000 && address <= 0x43fffffc && bitbandFlag) {
        uint32_t phaddr = (address - 0x42000000) / 32 + 0x40000000;
        getDebugStream() << "bit band alias address = " << hexval(address) << " alias address = " << hexval(phaddr) << "\n";
        address = phaddr;
    }

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

    bool createSymVar = false;
    uint32_t hwModelValue = concreteValue;
    onSymbolicRegisterReadEvent.emit(state, type, address, size, &hwModelValue, &createSymVar, &ss);

    getDebugStream(g_s2e_state) << ss.str() << " size " << hexval(size) << " value =" << hexval(concreteValue)
                                << " sym =" << (createSymVar ? "yes" : "no") << "\n";

    uint64_t LSB = ((uint64_t) 1 << (size * 8));
    if (createSymVar) {
        ConcreteArray concolicValue;
        SymbHwGetConcolicVector((hwModelValue & (LSB - 1)), size, concolicValue);
        return state->createSymbolicValue(ss.str(), size * 8, concolicValue);
    } else {
        return klee::ConstantExpr::create((hwModelValue & (LSB - 1)), size * 8);
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

    return hw->onReadPeripheral(g_s2e_state, SYMB_PORT, port, size, concreteValue);
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
    return hw->onReadPeripheral(g_s2e_state, SYMB_MMIO, physaddress, size, concreteValue);
}

static void symbhw_symbwrite(struct MemoryDesc *mr, uint64_t physaddress, const klee::ref<klee::Expr> &value,
                             SymbolicHardwareAccessType type, void *opaque) {
    SymbolicHardware *hw = static_cast<SymbolicHardware *>(opaque);

    if (DebugSymbHw) {
        hw->getDebugStream(g_s2e_state) << "writing mmio " << hexval(physaddress) << " value: " << value << "\n";
    }
    hw->onWritePeripheral(g_s2e_state, physaddress, value);
}

void SymbolicHardware::onWritePeripheral(S2EExecutionState *state, uint64_t phaddr,
                                                const klee::ref<klee::Expr> &value) {
    // peripheral address bit-band alias
    uint32_t curMMIOvalue = 0;
    uint32_t bit_loc = 0;
    bool bit_alias = false;
    if (phaddr >= 0x42000000 && phaddr <= 0x43fffffc && bitbandFlag) {
        bit_loc = ((phaddr - 0x42000000) % 32) / 4;
        phaddr = (phaddr - 0x42000000) / 32 + 0x40000000;
        bool createSymFlag = false;
        std::stringstream ss;
        onSymbolicRegisterReadEvent.emit(state, SYMB_MMIO, phaddr, 0x4, &curMMIOvalue, &createSymFlag, &ss);
        getDebugStream() << "write bit band alias address = " << hexval(phaddr)
                         << " bit loc = " << hexval(bit_loc) << " cur value =" << hexval(curMMIOvalue) <<"\n";
        bit_alias = true;
    }

    uint32_t writeConcreteValue;
    if (isa<klee::ConstantExpr>(value)) {
        klee::ref<klee::ConstantExpr> ce = dyn_cast<klee::ConstantExpr>(value);
        writeConcreteValue = ce->getZExtValue();
        if (bit_alias) {
            if (writeConcreteValue) {
                curMMIOvalue |= (uint32_t)(1<< bit_loc);
            } else {
                curMMIOvalue &= (uint32_t)(~(1<< bit_loc));
            }
            writeConcreteValue = curMMIOvalue;
        }
        getInfoStream() << "writing mmio " << hexval(phaddr) << " concrete value: " << hexval(writeConcreteValue) << "\n";
        onSymbolicRegisterWriteEvent.emit(g_s2e_state, SYMB_MMIO, phaddr, writeConcreteValue);
    } else {
        if (bit_alias) {
            getWarningsStream() << " bit band does not support symbolic value\n";
            exit(-1);
        }
        // evaluate symbolic regs
        klee::ref<klee::ConstantExpr> ce;
        ce = dyn_cast<klee::ConstantExpr>(g_s2e_state->concolics->evaluate(value));
        writeConcreteValue = ce->getZExtValue();
        getInfoStream() << "writing mmio " << hexval(phaddr) << " symbolic to concrete value: " << hexval(writeConcreteValue) << "\n";
        onSymbolicRegisterWriteEvent.emit(g_s2e_state, SYMB_MMIO, phaddr, writeConcreteValue);
    }

}

} // namespace hw
} // namespace plugins
} // namespace s2e
