///
/// Copyright (C) 2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
}

#endif
