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
    if (physicalAddress == (target_phys_addr_t) -1)
        return (uint64_t) -1;

    return physicalAddress | (virtualAddress & ~TARGET_PAGE_MASK);
}

uint64_t S2EExecutionStateMemory::getHostAddress(uint64_t address, AddressType addressType) const {
    if (addressType != HostAddress) {
        // XXX: fix this variable name
        uint64_t hostAddress = address & TARGET_PAGE_MASK;
        if (addressType == VirtualAddress) {
            hostAddress = getPhysicalAddress(hostAddress);
            if (hostAddress == (uint64_t) -1)
                return (uint64_t) -1;
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
    assert(width == 1 || (width & 7) == 0);
    uint64_t size = Expr::getMinBytesForWidth(width);

    /* Access spawns multiple MemoryObject's */
    ref<Expr> res(0);
    for (unsigned i = 0; i != size; ++i) {
        unsigned idx = klee::Context::get().isLittleEndian() ? i : (size - i - 1);
        ref<Expr> byte = readMemory8(address + idx, addressType);
        if (byte.isNull())
            return ref<Expr>(0);
        res = idx ? ConcatExpr::create(byte, res) : byte;
    }
    return res;
}

ref<Expr> S2EExecutionStateMemory::readMemory8(uint64_t address, AddressType addressType) {
    uint64_t hostAddress = getHostAddress(address, addressType);
    if (hostAddress == (uint64_t) -1)
        return ref<Expr>(0);

    ref<Expr> retVal(0);
#ifdef CONFIG_SYMBEX_MP
    transferRam(nullptr, hostAddress, &retVal, 1, false, false, true);
#else
    retVal = ConstantExpr::create(*((uint8_t *) hostAddress), Expr::Int8);
#endif

    return retVal;
}

bool S2EExecutionStateMemory::read(uint64_t address, void *buf, uint64_t size, AddressType addressType) {
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address, addressType);
        if (hostAddress == (uint64_t) -1)
            return false;
#ifdef CONFIG_SYMBEX_MP
        uint64_t hostPage = hostAddress & SE_RAM_OBJECT_MASK;
        uint64_t length = (hostPage + SE_RAM_OBJECT_SIZE) - hostAddress;
        if (length > size) {
            length = size;
        }
        // XXX: return failure if could not read symbolic byte
        transferRam(nullptr, hostAddress, buf, length, false, false, false);
#else
        *((uint8_t *) buf) = *((uint8_t *) hostAddress);
        uint64_t length = 1;
#endif
        buf = (uint8_t *) buf + length;
        address += length;
        size -= length;
    }

    return true;
}

/***/

bool S2EExecutionStateMemory::writeMemory8(uint64_t address, const ref<Expr> &value, AddressType addressType) {
    assert(value->getWidth() == 8);

    uint64_t hostAddress = getHostAddress(address, addressType);
    if (hostAddress == (uint64_t) -1)
        return false;
#ifdef CONFIG_SYMBEX_MP
    transferRam(nullptr, hostAddress, (void *) &value, 1, true, false, true);
#else
    ConstantExpr *ce = dyn_cast<ConstantExpr>(value);
    *((uint8_t *) hostAddress) = (uint8_t) ce->getZExtValue();
#endif

    return true;
}

bool S2EExecutionStateMemory::write(uint64_t address, const ref<Expr> &value, AddressType addressType) {
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
        // Slowest case (TODO: could optimize it)
        for (unsigned i = 0; i < numBytes; ++i) {
            unsigned idx = Context::get().isLittleEndian() ? i : (numBytes - i - 1);
            if (!writeMemory8(address + idx, ExtractExpr::create(value, 8 * i, Expr::Int8), addressType)) {
                return false;
            }
        }
    }
    return true;
}

bool S2EExecutionStateMemory::write(uint64_t address, const void *buf, uint64_t size, AddressType addressType) {
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address, addressType);
        if (hostAddress == (uint64_t) -1)
            return false;
#ifdef CONFIG_SYMBEX_MP
        uint64_t hostPage = hostAddress & SE_RAM_OBJECT_MASK;
        uint64_t length = (hostPage + SE_RAM_OBJECT_SIZE) - hostAddress;
        if (length > size) {
            length = size;
        }

        transferRam(nullptr, hostAddress, const_cast<void *>(buf), length, true, false, false);
#else
        *((uint8_t *) hostAddress) = *((uint8_t *) buf);
        uint64_t length = 1;
#endif

        buf = (uint8_t *) buf + length;
        address += length;
        size -= length;
    }

    return true;
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

bool S2EExecutionStateMemory::symbolic(uint64_t address, uint64_t size, AddressType addressType) {
#ifdef CONFIG_SYMBEX_MP
    while (size > 0) {
        uint64_t hostAddress = getHostAddress(address, addressType);
        if (hostAddress == (uint64_t) -1) {
            return false;
        }

        uint64_t pageAddr = hostAddress & SE_RAM_OBJECT_MASK;
        auto os = m_asCache->get(pageAddr);
        assert(os);

        uint64_t pageOffset = address % os->getSize();
        uint64_t pageLength = os->getSize() - pageOffset;

        if (pageLength > size) {
            pageLength = size;
        }

        if (!os->isAllConcrete()) {
            for (unsigned i = 0; i < pageLength; ++i) {
                if (!os->isConcrete(pageOffset + i, klee::Expr::Int8)) {
                    return true;
                }
            }
        }

        address += pageLength;
        size -= pageLength;
    }
#endif
    return false;
}

/***/

void S2EExecutionStateMemory::transferRamInternal(const klee::ObjectStateConstPtr &os_, uint64_t object_offset,
                                                  uint8_t *buf, uint64_t size, bool write, bool exitOnSymbolicRead) {
    klee::ObjectStateConstPtr os = os_;

    if (os->isSharedConcrete()) {
        assert(!exitOnSymbolicRead);

        /* This can happen in case of access to device memory */
        uint8_t *concreteStore = (uint8_t *) os->getAddress();
        if (write) {
            memcpy(concreteStore + object_offset, buf, size);
        } else {
            memcpy(buf, concreteStore + object_offset, size);
        }
        return;
    }

    if (write) {
        auto wos = m_addressSpace->getWriteable(os);
        bool oldAllConcrete = wos->isAllConcrete();

        for (uint64_t i = 0; i < size; ++i) {
            wos->write8(object_offset + i, buf[i]);
        }

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->notifyOnConcretenessChange())) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }

    } else {
        ObjectStatePtr wos = nullptr;
        for (uint64_t i = 0; i < size; ++i) {
            if (!os->readConcrete8(object_offset + i, buf + i)) {
                if (exitOnSymbolicRead) {
                    // m_startSymbexAtPC = getPc();
                    // XXX: what about regs_to_env ?
                    pabort("Check cpu_restore_state");
                    // fast_longjmp(env->jmp_env, 1);
                }

                if (!wos) {
                    os = wos = m_addressSpace->getWriteable(os);
                }

                buf[i] = m_concretizer->concretize(wos->read8(object_offset + i), "memory access from concrete code");
                wos->write8(object_offset + i, buf[i]);
            }
        }
    }
}

void S2EExecutionStateMemory::transferRamInternalSymbolic(const klee::ObjectStateConstPtr &os, uint64_t object_offset,
                                                          klee::ref<klee::Expr> *buf, uint64_t size, bool write) {
    if (write) {
        auto wos = m_addressSpace->getWriteable(os);
        bool oldAllConcrete = wos->isAllConcrete();

        for (uint64_t i = 0; i < size; ++i) {
            assert(buf[i]->getWidth() == Expr::Int8);
            wos->write(object_offset + i, buf[i]);
        }

        bool newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && (wos->notifyOnConcretenessChange())) {
            m_notification->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }

    } else {
        for (uint64_t i = 0; i < size; ++i) {
            buf[i] = os->read8(object_offset + i);
        }
    }
}

void S2EExecutionStateMemory::transferRam(struct CPUTLBRAMEntry *te, uint64_t hostAddress, void *buf, uint64_t size,
                                          bool isWrite, bool exitOnSymbolicRead, bool isSymbolic) {
    assert(*m_active);
    uint64_t page_offset = hostAddress & ~SE_RAM_OBJECT_MASK;
    if (!(page_offset + size <= SE_RAM_OBJECT_SIZE)) {
        /* Access spans multiple MemoryObject's */
        uint64_t size1 = SE_RAM_OBJECT_SIZE - page_offset;
        uint8_t *ptr = static_cast<uint8_t *>(buf);
        ref<Expr> *exprPtr = static_cast<ref<Expr> *>(buf);

        if (isSymbolic) {
            transferRam(te, hostAddress, exprPtr, size1, isWrite, exitOnSymbolicRead, isSymbolic);
            transferRam(te, hostAddress + size1, exprPtr + size1, size - size1, isWrite, exitOnSymbolicRead,
                        isSymbolic);
        } else {
            transferRam(te, hostAddress, ptr, size1, isWrite, exitOnSymbolicRead, isSymbolic);
            transferRam(te, hostAddress + size1, ptr + size1, size - size1, isWrite, exitOnSymbolicRead, isSymbolic);
        }

        return;
    }

    /* Single-object access */
    uint64_t page_addr = hostAddress & SE_RAM_OBJECT_MASK;

    auto os = m_asCache->get(page_addr);
    assert(os);

    unsigned osSize = os->getBitArraySize();

    /* Common case, the page is not split */
    if (osSize == os->getSize()) {
        assert(osSize == SE_RAM_OBJECT_SIZE);
        if (te) {
            if (!os->isSharedConcrete() && os->isAllConcrete()) {
                /* The object state pointer will be automatically updated if it becomes writable */
                // XXX: do proper reference counting
                te->object_state = (void *) os.get();
                te->host_page = os->getAddress();
                te->addend = (uintptr_t) os->getConcreteBufferPtr()->get() - os->getAddress();
                if (!m_asCache->isOwnedByUs(os)) {
                    te->host_page |= TLB_NOT_OURS;
                }
            }
        }

        if (isSymbolic) {
            transferRamInternalSymbolic(os, page_offset, static_cast<ref<Expr> *>(buf), size, isWrite);
        } else {
            transferRamInternal(os, page_offset, static_cast<uint8_t *>(buf), size, isWrite, exitOnSymbolicRead);
        }

        return;
    }

    assert(!os->isSharedConcrete());

    /* Slower path, fetch every individual object and do the transfer */
    while (size > 0) {
        os = m_addressSpace->findObject(page_addr);
        assert(os);

        /* Check that we indeed fall into this page */
        if (page_offset && os->getSize() <= page_offset) {
            page_offset -= os->getSize();
            page_addr += os->getSize();
            continue;
        }

        uint64_t transferSize = os->getSize() < size ? os->getSize() : size;

        if (isSymbolic) {
            transferRamInternalSymbolic(os, page_offset, static_cast<ref<Expr> *>(buf), transferSize, isWrite);
        } else {
            transferRamInternal(os, page_offset, static_cast<uint8_t *>(buf), transferSize, isWrite,
                                exitOnSymbolicRead);
        }

        size -= transferSize;

        // Only the first access can access the middle of an object
        page_offset = 0;
        page_addr += transferSize;
    }
}

uint8_t S2EExecutionStateMemory::readDirtyMask(uint64_t host_address) {
    uint8_t val = 0;
    host_address -= s_dirtyMask.address;
    m_dirtyMask->readConcrete8(host_address, &val);
    return val;
}

void S2EExecutionStateMemory::writeDirtyMask(uint64_t host_address, uint8_t val) {
    host_address -= s_dirtyMask.address;
    m_dirtyMask->write8(host_address, val);
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
