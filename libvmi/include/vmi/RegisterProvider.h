///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
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

#ifndef VMI_REGPROVIDER_H

#define VMI_REGPROVIDER_H

namespace vmi {

class RegisterProvider {
public:
    typedef bool (*ReadRegCb)(void *opaque, unsigned reg, void *value, unsigned size);
    typedef bool (*WriteRegCb)(void *opaque, unsigned reg, const void *value, unsigned size);

protected:
    void *m_opaque;
    ReadRegCb m_read;
    WriteRegCb m_write;

public:
    RegisterProvider(void *opaque, ReadRegCb _read, WriteRegCb _write)
        : m_opaque(opaque), m_read(_read), m_write(_write) {
    }

    template <typename T> bool read(unsigned reg, T *value) {
        if (!m_read)
            return false;
        return m_read(m_opaque, reg, value, sizeof(*value));
    }

    template <typename T> bool write(unsigned reg, const T *value) {
        if (!m_write)
            return false;
        return m_write(m_opaque, reg, value, sizeof(*value));
    }
};

/* Prefix the regs to avoid conflicts. Ordering is important (clients may assume
 * it) */
#if defined(TARGET_ARM)
enum ARMRegisters {
    ARM_R0,
    ARM_R1,
    ARM_R2,
    ARM_R3,
    ARM_R4,
    ARM_R5,
    ARM_R6,
    ARM_R7,
    ARM_R8,
    ARM_R9,
    ARM_R10,
    ARM_R11,
    ARM_R12,
    ARM_R13,
    ARM_R14,
    ARM_R15
};

class ARMRegisterProvider : public RegisterProvider {
public:
    ARMRegisterProvider(void *opaque, ReadRegCb _read, WriteRegCb _write) : RegisterProvider(opaque, _read, _write) {
    }

    template <typename T> bool read(ARMRegisters reg, T *value) {
        if (!m_read)
            return false;
        return m_read(m_opaque, reg, value, sizeof(*value));
    }

    template <typename T> bool write(ARMRegisters reg, const T *value) {
        if (!m_write)
            return false;
        return m_write(m_opaque, reg, value, sizeof(*value));
    }
};
#else
enum X86Registers {
    X86_EAX,
    X86_ECX,
    X86_EDX,
    X86_EBX,
    X86_ESP,
    X86_EBP,
    X86_ESI,
    X86_EDI,
    X86_ES,
    X86_CS,
    X86_SS,
    X86_DS,
    X86_FS,
    X86_GS,
    X86_CR0,
    X86_CR1,
    X86_CR2,
    X86_CR3,
    X86_CR4,
    X86_DR0,
    X86_DR1,
    X86_DR2,
    X86_DR3,
    X86_DR4,
    X86_DR5,
    X86_DR6,
    X86_DR7,
    X86_EFLAGS,
    X86_EIP
};

class X86RegisterProvider : public RegisterProvider {
public:
    X86RegisterProvider(void *opaque, ReadRegCb _read, WriteRegCb _write) : RegisterProvider(opaque, _read, _write) {
    }

    template <typename T> bool read(X86Registers reg, T *value) {
        if (!m_read)
            return false;
        return m_read(m_opaque, reg, value, sizeof(*value));
    }

    template <typename T> bool write(X86Registers reg, const T *value) {
        if (!m_write)
            return false;
        return m_write(m_opaque, reg, value, sizeof(*value));
    }
};
#endif
} // namespace vmi

#endif
