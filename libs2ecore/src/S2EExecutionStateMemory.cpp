///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#include <s2e/S2EExecutionStateMemory.h>

// Undefine cat from "compiler.h"
#undef cat
#include <llvm/Support/CommandLine.h>

extern llvm::cl::opt<bool> PrintModeSwitch;
using namespace klee;

namespace s2e {

ObjectKey S2EExecutionStateMemory::s_dirtyMask;

S2EExecutionStateMemory::S2EExecutionStateMemory()
    : m_dirtyMask(nullptr), m_active(nullptr), m_asCache(nullptr), m_addressSpace(nullptr), m_notification(nullptr),
      m_concretizer(nullptr) {
}

void S2EExecutionStateMemory::initialize(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache,
                                         const bool *active, klee::IAddressSpaceNotification *notification,
                                         klee::IConcretizer *concretizer, const klee::ObjectStatePtr &dirtyMask) {
    assert(!s_dirtyMask.address);
    s_dirtyMask = dirtyMask->getKey();
    dirtyMask->setName("DirtyMask");

    update(addressSpace, asCache, active, notification, concretizer);
}

void S2EExecutionStateMemory::update(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache, const bool *active,
                                     klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer) {
    auto dirtyMaskObject = addressSpace->findObject(s_dirtyMask.address);
    m_dirtyMask = addressSpace->getWriteable(dirtyMaskObject);

    m_addressSpace = addressSpace;
    m_asCache = asCache;
    m_notification = notification;
    m_concretizer = concretizer;
    m_active = active;
}

/***/

uint64_t S2EExecutionStateMemory::getPhysicalAddress(uint64_t virtualAddress) const {
    assert(*m_active && "Can not use getPhysicalAddress when the state"
                        " is not active (TODO: fix it)");
    target_phys_addr_t physicalAddress = cpu_get_phys_page_debug(env, virtualAddress & TARGET_PAGE_MASK);
    if (physicalAddress == (target_phys_addr_t) -1) {
        return (uint64_t) -1;
    }

    return physicalAddress | (virtualAddress & ~TARGET_PAGE_MASK);
}

uint64_t S2EExecutionStateMemory::getHostAddress(uint64_t address, AddressType addressType) const {
    if (addressType != HostAddress) {
        // XXX: fix this variable name
        uint64_t hostAddress = address & TARGET_PAGE_MASK;
        if (addressType == VirtualAddress) {
            hostAddress = getPhysicalAddress(hostAddress);
            if (hostAddress == (uint64_t) -1) {
                return (uint64_t) -1;
            }
        }

        hostAddress = g_sqi.mem.get_host_address(hostAddress);

        if (!hostAddress)
            return (uint64_t) -1;

        return hostAddress | (address & ~TARGET_PAGE_MASK);

    } else {
        return address;
    }
}

/***/

ref<Expr> S2EExecutionStateMemory::read(uint64_t address, Expr::Width width, AddressType addressType) {
    auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
        hostAddress = getHostAddress(addressToTranslate, addressType);
        return hostAddress != (uint64_t) -1;
    };

    return m_addressSpace->read(address, width, translate);
}

ref<Expr> S2EExecutionStateMemory::readMemory8(uint64_t address, AddressType addressType) {
#ifdef CONFIG_SYMBEX_MP
    return read(address, Expr::Int8, addressType);
#else
    uint64_t hostAddress = getHostAddress(address, addressType);
    if (hostAddress == (uint64_t) -1) {
        return nullptr;
    }
    return ConstantExpr::create(*((uint8_t *) hostAddress), Expr::Int8);
#endif
}

bool S2EExecutionStateMemory::read(uint64_t address, void *buf, uint64_t size, AddressType addressType) {
#ifdef CONFIG_SYMBEX_MP
    auto concretizer = [&](const ref<Expr> &e, const ObjectStateConstPtr &mo, size_t offset) -> uint8_t {
        return (uint8_t) m_concretizer->concretize(e, "S2EExecutionStateMemory::read");
    };

    auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
        hostAddress = getHostAddress(addressToTranslate, addressType);
        return hostAddress != (uint64_t) -1;
    };

    return m_addressSpace->read(address, (uint8_t *) buf, size, concretizer, translate);
#else
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address, addressType);
        if (hostAddress == (uint64_t) -1) {
            return false;
        }

        *((uint8_t *) buf) = *((uint8_t *) hostAddress);
        uint64_t length = 1;

        buf = (uint8_t *) buf + length;
        address += length;
        size -= length;
    }

    return true;
#endif
}

/***/

bool S2EExecutionStateMemory::writeMemory8(uint64_t address, const ref<Expr> &value, AddressType addressType) {
    assert(value->getWidth() == 8);

#ifdef CONFIG_SYMBEX_MP
    auto concretizer = [&](const ref<Expr> &e, const ObjectStateConstPtr &mo, size_t offset) -> uint8_t {
        return (uint8_t) m_concretizer->concretize(e, "S2EExecutionStateMemory::writeMemory8");
    };

    auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
        hostAddress = getHostAddress(addressToTranslate, addressType);
        return hostAddress != (uint64_t) -1;
    };

    return m_addressSpace->write(address, value, concretizer, translate);
#else
    uint64_t hostAddress = getHostAddress(address, addressType);
    if (hostAddress == (uint64_t) -1) {
        return false;
    }

    ConstantExpr *ce = dyn_cast<ConstantExpr>(value);
    *((uint8_t *) hostAddress) = (uint8_t) ce->getZExtValue();
    return true;
#endif
}

bool S2EExecutionStateMemory::write(uint64_t address, const ref<Expr> &value, AddressType addressType) {
    if (!value) {
        return false;
    }

    Expr::Width width = value->getWidth();
    unsigned numBytes = Expr::getMinBytesForWidth(value->getWidth());

    ConstantExpr *constantExpr = dyn_cast<ConstantExpr>(value);
    if (constantExpr && width <= 64) {
        // Concrete write of supported width
        uint64_t val = constantExpr->getZExtValue();
        if (value->getWidth() == Expr::Bool) {
            val &= 1;
        }

        return write(address, &val, numBytes, addressType);
    } else {
#ifdef CONFIG_SYMBEX_MP
        auto concretizer = [&](const ref<Expr> &e, const ObjectStateConstPtr &mo, size_t size) -> uint8_t {
            return (uint8_t) m_concretizer->concretize(e, "S2EExecutionStateMemory::write");
        };

        auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
            hostAddress = getHostAddress(addressToTranslate, addressType);
            return hostAddress != (uint64_t) -1;
        };

        return m_addressSpace->write(address, value, concretizer, translate);
#else
        pabort("Not supported in single-path mode");
#endif
    }
    return true;
}

bool S2EExecutionStateMemory::write(uint64_t address, const void *buf, uint64_t size, AddressType addressType) {
    if (!buf) {
        return false;
    }

#ifdef CONFIG_SYMBEX_MP
    auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
        hostAddress = getHostAddress(addressToTranslate, addressType);
        return hostAddress != (uint64_t) -1;
    };

    return m_addressSpace->write(address, (uint8_t *) buf, size, translate);
#else
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address, addressType);
        if (hostAddress == (uint64_t) -1) {
            return false;
        }

        *((uint8_t *) hostAddress) = *((uint8_t *) buf);
        uint64_t length = 1;

        buf = (uint8_t *) buf + length;
        address += length;
        size -= length;
    }

    return true;
#endif
}

klee::ObjectStateConstPtr S2EExecutionStateMemory::getMemoryObject(uint64_t address, AddressType addressType) const {
    uint64_t hostAddr = getHostAddress(address, addressType);
    uint64_t pageAddr = hostAddr & SE_RAM_OBJECT_MASK;
    return m_addressSpace->findObject(pageAddr);
}

const void *S2EExecutionStateMemory::getConcreteBuffer(uint64_t address, AddressType addressType) const {
    auto obj = getMemoryObject(address, addressType);
    if (!obj) {
        return nullptr;
    }

    auto store = obj->getConcreteBuffer();
    if (!store) {
        return nullptr;
    }

    return store + (address & ~SE_RAM_OBJECT_MASK);
}

// TODO: redo this
bool S2EExecutionStateMemory::symbolic(uint64_t address, uint64_t size, AddressType addressType) {
#ifdef CONFIG_SYMBEX_MP
    auto translate = [&](uint64_t addressToTranslate, uint64_t &hostAddress) -> bool {
        hostAddress = getHostAddress(addressToTranslate, addressType);
        return hostAddress != (uint64_t) -1;
    };

    return m_addressSpace->symbolic(address, size, translate);
#endif
    return false;
}

/***/

void S2EExecutionStateMemory::transferRam(struct CPUTLBRAMEntry *te, uint64_t hostAddress, void *buf, uint64_t size,
                                          bool isWrite, bool exitOnSymbolicRead) {
    // TODO: update CPUTLBRAMEntry entry on access to the page.
    // This should probably be done using a signal in AddressSpace to notify
    // S2EExecutionStateTlb of the access.
    if (te) {
        auto os = m_addressSpace->findObject(hostAddress);
        if (!os) {
            pabort("Unmapped host address");
        }

        if (!os->isSharedConcrete() && os->isAllConcrete()) {
            /* The object state pointer will be automatically updated if it becomes writable */
            // XXX: do proper reference counting
            te->object_state = (void *) os.get();
            te->host_page = os->getAddress();
            te->addend = (uintptr_t) os->getConcreteBufferPtr()->get() - os->getAddress();
            if (!m_addressSpace->isOwnedByUs(os)) {
                te->host_page |= TLB_NOT_OURS;
            }
        }
    }

    if (isWrite) {
        if (!m_addressSpace->write(hostAddress, (uint8_t *) buf, size)) {
            pabort("Error while writing to ram");
        }
    } else {
        auto concretizer = [&](const ref<Expr> &e, const ObjectStateConstPtr &mo, size_t size) -> uint8_t {
            return (uint8_t) m_concretizer->concretize(e, "S2EExecutionStateMemory::transferRam");
        };

        if (!m_addressSpace->read(hostAddress, (uint8_t *) buf, size, concretizer)) {
            pabort("Error while reading from ram");
        }
    }

    return;
}

uint8_t S2EExecutionStateMemory::readDirtyMask(uint64_t host_address) {
    uint8_t val = 0;
    host_address -= s_dirtyMask.address;
    m_dirtyMask->readConcrete8(host_address, &val);
    return val;
}

void S2EExecutionStateMemory::writeDirtyMask(uint64_t host_address, uint8_t val) {
    host_address -= s_dirtyMask.address;
    m_dirtyMask->write(host_address, val);
}

/** Read an ASCIIZ string from memory */
bool S2EExecutionStateMemory::readString(uint64_t address, std::string &s, unsigned maxLen) {
    return readGenericString<uint8_t>(address, s, maxLen);
}

/** Read a unicode string from memory */
bool S2EExecutionStateMemory::readUnicodeString(uint64_t address, std::string &s, unsigned maxLen) {
    return readGenericString<uint16_t>(address, s, maxLen);
}

} // namespace s2e
