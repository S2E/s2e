///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
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

#ifndef S2E_REGISTERS_H_

#define S2E_REGISTERS_H_

#include <inttypes.h>
#include <klee/AddressSpace.h>
#include <klee/IAddressSpaceNotification.h>
#include <klee/IConcretizer.h>
#include <klee/Memory.h>

extern "C" {
struct CPUX86State;
}

#define CPU_OFFSET(field) offsetof(CPUX86State, field)

namespace s2e {

///
/// \brief This class represents the CPU register file.
///
/// In S2E, the register file is split in two regions:
/// the first region contains the general purpose registers
/// as well as the flags registers, while the second region
/// contains control registers.
///
/// Only the first region may contain symbolic data. Any symbolic
/// data written to the second region will be immediately concretized.
///
/// Limitations:
///   - It is currently not possible to perform read/write operations that
///     span the symbolic and the concrete region.
///
class S2EExecutionStateRegisters {
protected:
    // Static because they do not change
    static klee::ObjectKey s_symbolicRegs;
    static klee::ObjectKey s_concreteRegs;

    klee::ObjectStatePtr m_symbolicRegs;
    klee::ObjectStatePtr m_concreteRegs;

    const bool *m_active;
    const bool *m_runningConcrete;
    klee::IAddressSpaceNotification *m_notification;
    klee::IConcretizer *m_concretizer;

private:
    /// Read CPU general purpose register
    klee::ref<klee::Expr> readSymbolicRegion(unsigned offset, klee::Expr::Width width) const;

    /// Read concrete value from general purpose CPU register.
    /// Return false if the data was symbolic and no concretization is request.
    bool readSymbolicRegion(unsigned offset, void *buf, unsigned size, bool concretize = false) const;

    ///  Read CPU system state, size is in bytes
    void readConcreteRegion(unsigned offset, void *buffer, unsigned size) const;

    /// Write CPU system state, size is in bytes
    void writeConcreteRegion(unsigned offset, const void *buffer, unsigned size);

    ///  Write CPU general purpose register
    void writeSymbolicRegion(unsigned offset, klee::ref<klee::Expr> value);

    /// Write concrete value to general purpose CPU register
    void writeSymbolicRegion(unsigned offset, const void *buf, unsigned size);

    static bool getRegionType(unsigned offset, unsigned size, bool *isConcrete);

public:
    ////////////////////////////////////////////////////////////
    // The APIs below are for use by the engine only
    ////////////////////////////////////////////////////////////

    S2EExecutionStateRegisters(const bool *active, const bool *running_concrete,
                               klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer)
        : m_active(active), m_runningConcrete(running_concrete), m_notification(notification),
          m_concretizer(concretizer){};

    void initialize(klee::AddressSpace &addressSpace, const klee::ObjectStatePtr &symbolicRegs,
                    const klee::ObjectStatePtr &concreteRegs);

    void update(klee::AddressSpace &addressSpace, const bool *active, const bool *running_concrete,
                klee::IAddressSpaceNotification *notification, klee::IConcretizer *concretizer);

    void copySymbRegs(bool toNative);

    int compareArchitecturalConcreteState(const S2EExecutionStateRegisters &other);

    inline void saveConcreteState() {
        memcpy((void *) m_concreteRegs->getConcreteBuffer(), (void *) s_concreteRegs.address, s_concreteRegs.size);
    }

    inline void restoreConcreteState() {
        memcpy((void *) s_concreteRegs.address, (void *) m_concreteRegs->getConcreteBuffer(), s_concreteRegs.size);
    }

    bool addressSpaceChange(const klee::ObjectKey &key, const klee::ObjectStateConstPtr &oldState,
                            const klee::ObjectStatePtr &newState);

    static const klee::ObjectKey &getConcreteRegs() {
        return s_concreteRegs;
    }

    void dump(std::ostream &ss) const;

    /// Returns a pointer to the store where the concrete
    /// data of the cpu registers reside. It can either point
    /// to the backing store if the state is inactive, or to
    /// the global CPUState object if active.
    CPUX86State *getCpuState() const;

    bool allConcrete() const {
        return m_symbolicRegs->isAllConcrete();
    }

    bool flagsRegistersAreSymbolic() const;

    static bool initialized() {
        return s_concreteRegs.address != 0 && s_symbolicRegs.address != 0;
    }

    ///  Same as writeSymbolicRegion but also allows writing symbolic values
    ///  while running in concrete mode
    void writeSymbolicRegionUnsafe(unsigned offset, klee::ref<klee::Expr> value);

    ////////////////////////////////////////////////////////////
    // The APIs below may be used by plugins
    ////////////////////////////////////////////////////////////

    ///
    /// \brief Read symbolic data from the register file
    ///
    /// This function will return the expression corresponding
    /// to the symbolic data stored at the given offset. If the
    /// offset contains concrete data, the function returns
    /// the corresponding constant expression.
    ///
    /// The function will fail if offset, width overlap the symbolic
    /// and concrete regions.
    ///
    /// \param offset the offset to read from
    /// \param width the size of the data
    /// \return a symbolic expression if successful, null otherwise
    ///
    klee::ref<klee::Expr> read(unsigned offset, klee::Expr::Width width) const;

    ///
    /// \brief Read the cpu register file
    ///
    /// This function returns reads concrete data from the cpu register file,
    /// concretizing it if necessary.
    ///
    /// The function will fail if:
    ///   - it encounters symbolic data while concretize is set to false
    ///   - the (offset, size) pair overlaps the symbolic and concrete
    ///     region of the register file
    ///
    /// \param offset where to start reading in the cpu
    /// \param buffer where to store the data
    /// \param size the size of the data
    /// \param concretize whether to concretize any symbolic data read
    /// \return True in case of success, false otherwise
    ///
    bool read(unsigned offset, void *buffer, unsigned size, bool concretize = true) const;

    ///
    /// \brief Read a primitive type from the register file
    ///
    /// This function is a shortcut, it will return 0 in case of failure.
    /// The caller is responsible for verifying that the given offset
    /// is correct.
    ///
    /// \param offset the offset of the register to read
    /// \return The data that is read
    template <typename T> T read(unsigned offset) const {
        static_assert(std::is_fundamental<T>::value, "Read from register can only use primitive types");
        T ret;
        memset(&ret, 0, sizeof(ret));
        read(offset, &ret, sizeof(ret));
        return ret;
    }

    ///
    /// \brief Write concrete data to the register file
    ///
    /// The offset/size may not overlap the symbolic and concrete
    /// region of the register file.
    ///
    /// \param offset the offset of the register
    /// \param buffer a pointer to the data to write
    /// \param size the size of the data to write
    /// \return True if the write was successful, false otherwise
    ///
    bool write(unsigned offset, const void *buffer, unsigned size);

    ///
    /// \brief Write symbolic data to the register file
    ///
    /// The symbolic value will be concretized if it is written to
    /// the concrete part of the register file.
    ///
    /// The write operation may not overlap the symbolic and concrete
    /// region of the register file.
    ///
    /// \param offset where to write the data
    /// \param value the symbolic expression to write
    /// \return True if the write was successful, false otherwise
    ///
    bool write(unsigned offset, const klee::ref<klee::Expr> &value);

    ///
    /// \brief Write data of a primitive type to the register file
    ///
    /// The write operation may not overlap the symbolic and concrete
    /// region of the register file.
    ///
    /// \param offset where to write the data
    /// \param value the value to write
    /// \return True if the write was successful, false otherwise
    ///
    template <typename T, typename std::enable_if<std::is_integral<T>::value, T>::type * = nullptr>
    bool write(unsigned offset, T value) {
        static_assert(std::is_integral<T>::value, "Write to register can only use primitive types");
        return write(offset, &value, sizeof(T));
    }

    ///
    /// \brief Read the content of the stack frame pointer register
    ///
    /// This may concretized any symbolic data stored in the register.
    ///
    /// \return the frame pointer
    ///
    uint64_t getBp() const;

    ///
    /// \brief Read the content of the stack pointer register
    ///
    /// This may concretized any symbolic data stored in the register.
    ///
    /// \return the stack pointer
    ///
    uint64_t getSp() const;

    ///
    /// \brief Read the content of the program counter
    ///
    /// This may concretized any symbolic data stored in the register.
    ///
    /// \return the program counter
    ///
    uint64_t getPc() const;

    ///
    /// \brief Read the content of the page directory register
    /// \return the page directory register
    ///
    uint64_t getPageDir() const;

    ///
    /// \brief Read the content of the flags register
    ///
    /// This may concretized any symbolic data stored in the register.
    ///
    /// \return the falgs register
    ///
    uint64_t getFlags();

    ///
    /// \brief Write to the frame pointer register
    /// \param bp the new value of the frame pointer
    ///
    void setBp(uint64_t bp);

    ///
    /// \brief Write to the stack pointer register
    /// \param sp the new value of the stack pointer
    ///
    void setSp(uint64_t sp);

    ///
    /// \brief Write to the program counter register
    ///
    /// In order to restart execution at the new program counter, plugins must also
    /// force an exit from the CPU loop as follows:
    ///
    /// \code{.cpp}
    /// void MyPlugin::myInstrumentation(S2EExecutionState *state, uint64_t pc) {
    ///     state->regs()->setPc(0xdeadbeef);
    ///     throw CpuExitException();
    /// }
    /// \endcode
    ///
    /// This is required because otherwise the current translation block
    /// will keep running, possibly in an inconsistent state
    /// because of the changed program counter value.
    ///
    /// Exiting the CPU loop will ensure that execution will restart
    /// at the correct program counter.
    ///
    /// It is up to the plugin to ensure that the new program counter value
    /// will not cause the guest to crash.
    ///
    /// \param pc the new value of the program counter
    ///
    void setPc(uint64_t pc);
};
} // namespace s2e

#endif
