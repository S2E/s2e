///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016, Cyberhaven
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

#ifndef S2E_EXECUTION_STATE_MEMORY

#define S2E_EXECUTION_STATE_MEMORY

#include <klee/IAddressSpaceNotification.h>
#include <klee/IConcretizer.h>
#include "AddressSpaceCache.h"

namespace s2e {

enum AddressType { VirtualAddress, PhysicalAddress, HostAddress };

class S2EExecutionStateMemory {

protected:
    static klee::ObjectKey s_dirtyMask;
    klee::ObjectStatePtr m_dirtyMask;
    const bool *m_active;
    AddressSpaceCache *m_asCache;
    klee::AddressSpace *m_addressSpace;
    klee::IAddressSpaceNotification *m_notification;
    klee::IConcretizer *m_concretizer;

    bool writeMemory8(uint64_t address, const klee::ref<klee::Expr> &value, AddressType addressType = VirtualAddress);

    klee::ref<klee::Expr> readMemory8(uint64_t address, AddressType addressType = VirtualAddress);

public:
    S2EExecutionStateMemory();

    void initialize(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache, const bool *active,
                    klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer,
                    const klee::ObjectStatePtr &dirtyMask);

    void update(klee::AddressSpace *addressSpace, AddressSpaceCache *asCache, const bool *active,
                klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer);

    ////////////////////////////////////////////////////////////
    // The APIs below are for use by the engine only
    ////////////////////////////////////////////////////////////

    /// Dirty mask management
    uint8_t readDirtyMask(uint64_t host_address);
    void writeDirtyMask(uint64_t host_address, uint8_t val);
    void registerDirtyMask(uint64_t host_address, uint64_t size);

    static const klee::ObjectKey &getDirtyMask() {
        return s_dirtyMask;
    }

    uintptr_t getDirtyMaskStoreAddend() const {
        return (uintptr_t) m_dirtyMask->getConcreteBuffer(false) - s_dirtyMask.address;
    }

    /// Read/write from physical memory, concretizing if necessary on reads.
    /// Note: this function accepts host address. Used by softmmu code.
    void transferRam(struct CPUTLBRAMEntry *te, uint64_t hostAddress, void *buf, uint64_t size, bool isWrite,
                     bool exitOnSymbolicRead);

    klee::ObjectStateConstPtr getMemoryObject(uint64_t address, AddressType addressType = VirtualAddress) const;

    ///
    /// \brief Return the per-state host address where concrete data is actually stored.
    /// \param address the address to translate
    /// \param addressType the type of address specified
    /// \return The address or null if the address could not be determineds
    ///
    const void *getConcreteBuffer(uint64_t address, AddressType addressType) const;

    ////////////////////////////////////////////////////////////
    // The APIs below may be used by plugins
    ////////////////////////////////////////////////////////////

    ///
    /// \brief Compute the guest physical address for the given virtual address
    /// \param virtualAddress the virtual address to translate
    /// \return The physical address (or -1 in case of error)
    ///
    uint64_t getPhysicalAddress(uint64_t virtualAddress) const;

    ///
    /// \brief Compute the host address for the given address
    /// \param address the address to translate
    /// \param addressType the type of address specified
    /// \return The computed host address (or -1 in case of failure)
    ///
    uint64_t getHostAddress(uint64_t address, AddressType addressType = VirtualAddress) const;

    /** Read memory to buffer, concretize if necessary */

    ///
    /// \brief Read data from memory
    ///
    /// This function can only return concrete data and concretizes any
    /// symbolic data that it encounters.
    ///
    /// This function may fail if the address is invalid (e.g., not mapped
    /// in page tables) or if other errors occur.
    ///
    /// \param address the address to read from
    /// \param buf the buffer where to store the data
    /// \param size the number of bytes to read
    /// \param addressType the type of address
    /// \return True if all bytes could be read successfully
    ///
    bool read(uint64_t address, void *buf, uint64_t size, AddressType addressType = VirtualAddress);

    ///
    /// \brief Read data from memory
    ///
    /// This function can only return concrete data and may optionally
    /// concretize any symbolic data that it encounters. Disabling
    /// concretization may be useful for plugins that do not want to
    /// modify state while still getting concrete data.
    ///
    /// Note: not adding a constraint may cause consistency issues for
    /// plugins, use carefully.
    ///
    /// This function may fail if the address is invalid (e.g., not mapped
    /// in page tables) or if other errors occur.
    ///
    /// \param address the address to read from
    /// \param result pointer where to store the data
    /// \param addressType the type of address
    /// \param addConstraint whether or not to add constraints when reading symbolic data
    /// \return True if read was successful, false otherwise
    ///
    template <typename T, typename std::enable_if<std::is_integral<T>::value, T>::type * = nullptr>
    bool read(uint64_t address, T *result, AddressType addressType = VirtualAddress, bool addConstraint = true) {
        static_assert(std::is_integral<T>::value, "Read from memory can only use primitive types");

#ifdef CONFIG_SYMBEX_MP

        klee::ref<klee::Expr> expr = read(address, sizeof(T) * 8, addressType);
        if (!expr) {
            return false;
        }

        expr = klee::ConstantExpr::create(m_concretizer->concretize(expr, "readMemory", !addConstraint), sizeof(T) * 8);
        klee::ConstantExpr *ce = dyn_cast<klee::ConstantExpr>(expr);
        assert(ce && "Broken solver");

        if (result) {
            *result = ce->getZExtValue();
        }

        if (addConstraint) {
            return write(address, expr);
        }

        return true;
#else
        return read(address, result, sizeof(T), addressType);
#endif
    }

    ///
    /// \brief Determine if the given memory region contains symbolic data
    /// \param address the beginning of the region
    /// \param size the size of the region
    /// \param addressType the type of address
    /// \return true if the region contains symbolic data
    ///
    bool symbolic(uint64_t address, uint64_t size, AddressType addressType = VirtualAddress);

    ///
    /// \brief Read symbolic data from memory
    ///
    /// This function reads symbolic data at the given address.
    /// Note that if the address contains concrete data, the function
    /// will return the corresponding constant expression.
    ///
    /// This function may fail if the address is invalid (e.g., not mapped
    /// in page tables) or if other errors occur.
    ///
    /// \param address the address to read from
    /// \param width the size of the data to read
    /// \param addressType the type of address
    /// \return An expression containing the requested data, or null in case of failure
    ///
    klee::ref<klee::Expr> read(uint64_t address, klee::Expr::Width width = klee::Expr::Int8,
                               AddressType addressType = VirtualAddress);

    /** Write concrete buffer to memory */

    ///
    /// \brief Write concrete data to memory
    ///
    /// This function may fail if the address is invalid (e.g., not mapped
    /// in page tables) or if other errors occur.
    ///
    /// \param address the address to write to
    /// \param buf the buffer to write
    /// \param size the number of bytes to write
    /// \param addressType the type of address
    /// \return True if all bytes could be written successfully, false otherwise
    ///
    bool write(uint64_t address, const void *buf, uint64_t size, AddressType addressType = VirtualAddress);

    ///
    /// \brief Write symbolic data to memory
    ///
    /// \param address the address to write to
    /// \param value the symbolic value to write
    /// \param addressType the type of address
    /// \return True if the data could be written successully, false otherwise
    ///
    bool write(uint64_t address, const klee::ref<klee::Expr> &value, AddressType addressType = VirtualAddress);

    ///
    /// \brief Write concrete data of a primitive type to memory
    ///
    /// \param address the address to write to
    /// \param value the value to write
    /// \param addressType the type of address
    /// \return True if the data could be written successully, false otherwise
    ///
    template <typename T, typename std::enable_if<std::is_integral<T>::value, T>::type * = nullptr>
    bool write(uint64_t address, T value, AddressType addressType = VirtualAddress) {
        static_assert(std::is_integral<T>::value, "Write to memory can only use primitive types");
        return write(address, (T *) &value, sizeof(T), addressType);
    }

    ///
    /// \brief Read a null-terminated string whose characters are of the
    /// specified generic type (usually char or short)
    ///
    /// \param address the address to read from
    /// \param s where to store the string
    /// \param maxLen the maximum size of the string
    /// \return True if the string could be read, false otherwise
    ///
    template <typename T> bool readGenericString(uint64_t address, std::string &s, unsigned maxLen) {
        s = "";
        bool ret = false;
        T c;

        do {
            c = 0;

            ret = read(address, &c, sizeof(c));
            maxLen--;
            address += sizeof(T);

            if (c) {
                s = s + (char) c;
            }

        } while (c && (maxLen > 0));

        return ret;
    }

    ///
    /// \brief Read an asciiz string from memory
    ///
    /// \param address the address to read from
    /// \param s where to store the string
    /// \param maxLen the maximum size of the string
    /// \return True if the string could be read, false otherwise
    ///
    bool readString(uint64_t address, std::string &s, unsigned maxLen = 256);

    ///
    /// \brief Read a UTF-16 string from memory
    ///
    /// \param address the address to read from
    /// \param s where to store the string
    /// \param maxLen the maximum size of the string
    /// \return True if the string could be read, false otherwise
    ///
    bool readUnicodeString(uint64_t address, std::string &s, unsigned maxLen = 256);
};

} // namespace s2e

#endif
