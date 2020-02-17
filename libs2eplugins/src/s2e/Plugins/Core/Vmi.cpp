///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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
#include <s2e/Utils.h>
#include <s2e/cpu.h>

#include <iostream>
#include <llvm/Config/config.h>
#include <llvm/Support/FileSystem.h>

#include "Vmi.h"

using namespace vmi;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(Vmi, "Virtual Machine Introspection", "", );

void Vmi::initialize() {
    // Load the list of directories in which to search for
    // executable files.
    ConfigFile *cfg = s2e()->getConfig();
    if (!parseDirectories(cfg, getConfigKey() + ".baseDirs")) {
        exit(-1);
    }
}

bool Vmi::parseDirectories(ConfigFile *cfg, const std::string &baseDirsKey) {
    // Load the list of directories in which to search for
    // executable files.
    ConfigFile::string_list dirs = cfg->getStringList(baseDirsKey);
    foreach2 (it, dirs.begin(), dirs.end()) {
        getDebugStream() << "adding path " << *it << "\n";
        if (!llvm::sys::fs::exists((*it))) {
            getWarningsStream() << "Path " << (*it) << " does not exist\n";
            return false;
        }

        m_baseDirectories.push_back(*it);
    }

    if (m_baseDirectories.empty()) {
        m_baseDirectories.push_back(s2e()->getOutputDirectory());
    }

    return true;
}

std::string Vmi::stripWindowsModulePath(const std::string &path) {
    std::string modPath(path);

    // XXX: this is really ugly
    if (modPath.substr(0, 23) == "\\Device\\HarddiskVolume2") {
        modPath = modPath.substr(23);
    } else if (modPath.substr(0, 23) == "\\Device\\HarddiskVolume1") {
        modPath = modPath.substr(23);
    } else if (modPath.substr(0, 11) == "\\SystemRoot") {
        modPath = "\\Windows" + modPath.substr(11);
    } else if (modPath.substr(0, 7) == "\\??\\c:\\") {
        modPath = "\\" + modPath.substr(7);
    }

    foreach2 (it, modPath.begin(), modPath.end()) {
        if (*it == '\\')
            *it = '/';
    }

    return modPath;
}

bool Vmi::findModule(const std::string &module, std::string &path) {
    if (module.empty()) {
        return false;
    }

    /* Find the path prefix for the given relative file */
    foreach2 (it, m_baseDirectories.begin(), m_baseDirectories.end()) {
        llvm::SmallString<128> tempPath(*it);
        llvm::sys::path::append(tempPath, module);

        if (llvm::sys::fs::exists(tempPath)) {
            path = tempPath.c_str();
            return true;
        }

        char buffer[1024];
        ssize_t slLen;

        // Try to resolve the symlink
        if ((slLen = readlink(tempPath.c_str(), buffer, sizeof(buffer) - 1)) != -1) {
            buffer[slLen] = '\0';
        } else {
            continue;
        }

        std::string sl = buffer;

        tempPath.clear();
        llvm::sys::path::append(tempPath, *it);
        llvm::sys::path::append(tempPath, sl);
        if (llvm::sys::fs::exists(tempPath)) {
            path = tempPath.c_str();
            return true;
        }
    }

    return false;
}

bool Vmi::getHostPathForModule(const std::string &modulePath, const std::string &moduleName, bool caseInsensitive,
                               std::string &hostPath) {
    // This is a no-op for Linux systems, normally.
    std::string strippedPath = Vmi::stripWindowsModulePath(modulePath);

    if (findModule(strippedPath, hostPath)) {
        return true;
    }

    if (caseInsensitive) {
        std::transform(strippedPath.begin(), strippedPath.end(), strippedPath.begin(), ::tolower);
        if (findModule(strippedPath, hostPath)) {
            return true;
        }
    }

    if (findModule(moduleName, hostPath)) {
        return true;
    }

    std::string Name = moduleName;
    std::transform(Name.begin(), Name.end(), Name.begin(), ::tolower);
    return findModule(Name, hostPath);
}

std::shared_ptr<vmi::ExecutableFile> Vmi::getFromDisk(const std::string &modulePath, const std::string &moduleName,
                                                      bool caseInsensitive) {
    getDebugStream() << "Loading module from disk " << modulePath << " (" << moduleName << ")\n";

    std::string hostPath;
    if (!getHostPathForModule(modulePath, moduleName, caseInsensitive, hostPath)) {
        getWarningsStream() << "Could not find host path for " << moduleName << "\n";
        return nullptr;
    }

    auto it = m_cache.find(hostPath);
    if (it != m_cache.end()) {
        getDebugStream() << "Found cached entry for " << hostPath << "\n";
        return (*it).second;
    }

    getDebugStream() << "Attempting to load binary file: " << hostPath << "\n";
    auto fp = vmi::FileSystemFileProvider::get(hostPath, false);

    if (!fp) {
        getDebugStream() << "Cannot open file " << hostPath << "\n";
        return nullptr;
    }

    auto exe = vmi::ExecutableFile::get(fp, false, 0);

    if (!exe) {
        getDebugStream() << "Cannot parse file " << hostPath << "\n";
        return nullptr;
    }

    m_cache[hostPath] = exe;
    return exe;
}

bool Vmi::readGuestVirtual(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->read(address, dest, size);
}

bool Vmi::writeGuestVirtual(void *opaque, uint64_t address, const void *source, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->write(address, source, size);
}

bool Vmi::readGuestPhysical(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->read(address, dest, size, PhysicalAddress);
}

bool Vmi::writeGuestPhysical(void *opaque, uint64_t address, const void *source, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->write(address, source, size, PhysicalAddress);
}

bool Vmi::readX86Register(void *opaque, unsigned reg, void *buffer, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    vmi::X86Registers regIndex = (vmi::X86Registers) reg;

    if (size >= sizeof(uint64_t)) {
        return false;
    }

    S2EExecutionStateRegisters *regs = state->regs();

    if (regIndex <= X86_GS) {
        switch (regIndex) {
            case X86_EAX:
                regs->read(offsetof(CPUX86State, regs[R_EAX]), buffer, size);
                break;
            case X86_EBX:
                regs->read(offsetof(CPUX86State, regs[R_EBX]), buffer, size);
                break;
            case X86_ECX:
                regs->read(offsetof(CPUX86State, regs[R_ECX]), buffer, size);
                break;
            case X86_EDX:
                regs->read(offsetof(CPUX86State, regs[R_EDX]), buffer, size);
                break;
            case X86_ESI:
                regs->read(offsetof(CPUX86State, regs[R_ESI]), buffer, size);
                break;
            case X86_EDI:
                regs->read(offsetof(CPUX86State, regs[R_EDI]), buffer, size);
                break;
            case X86_ESP:
                regs->read(offsetof(CPUX86State, regs[R_ESP]), buffer, size);
                break;
            case X86_EBP:
                regs->read(offsetof(CPUX86State, regs[R_EBP]), buffer, size);
                break;

            case X86_CS:
                regs->read(offsetof(CPUX86State, segs[R_CS].selector), buffer, size);
                break;
            case X86_DS:
                regs->read(offsetof(CPUX86State, segs[R_DS].selector), buffer, size);
                break;
            case X86_ES:
                regs->read(offsetof(CPUX86State, segs[R_ES].selector), buffer, size);
                break;
            case X86_SS:
                regs->read(offsetof(CPUX86State, segs[R_SS].selector), buffer, size);
                break;
            case X86_FS:
                regs->read(offsetof(CPUX86State, segs[R_FS].selector), buffer, size);
                break;
            case X86_GS:
                regs->read(offsetof(CPUX86State, segs[R_GS].selector), buffer, size);
                break;
            default:
                assert(false);
        }
        return true;
    } else if (regIndex <= X86_CR4) {
        regs->read(offsetof(CPUX86State, cr[regIndex - X86_CR0]), buffer, size);
        return true;
    } else if (regIndex <= X86_DR7) {
        regs->read(offsetof(CPUX86State, dr[regIndex - X86_DR0]), buffer, size);
        return true;
    } else if (regIndex == X86_EFLAGS) {
        uint64_t flags = regs->getFlags();
        memcpy(buffer, &flags, size);
    } else if (regIndex == X86_EIP) {
        regs->read(offsetof(CPUX86State, eip), buffer, size);
    } else {
        return false;
    }

    return true;
}

bool Vmi::writeX86Register(void *opaque, unsigned reg, const void *buffer, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    vmi::X86Registers regIndex = (vmi::X86Registers) reg;

    if (size >= sizeof(uint64_t)) {
        return false;
    }

    S2EExecutionStateRegisters *regs = state->regs();

    if (regIndex <= X86_GS) {
        switch (regIndex) {
            case X86_EAX:
                regs->write(offsetof(CPUX86State, regs[R_EAX]), buffer, size);
                break;
            case X86_EBX:
                regs->write(offsetof(CPUX86State, regs[R_EBX]), buffer, size);
                break;
            case X86_ECX:
                regs->write(offsetof(CPUX86State, regs[R_ECX]), buffer, size);
                break;
            case X86_EDX:
                regs->write(offsetof(CPUX86State, regs[R_EDX]), buffer, size);
                break;
            case X86_ESI:
                regs->write(offsetof(CPUX86State, regs[R_ESI]), buffer, size);
                break;
            case X86_EDI:
                regs->write(offsetof(CPUX86State, regs[R_EDI]), buffer, size);
                break;
            case X86_ESP:
                regs->write(offsetof(CPUX86State, regs[R_ESP]), buffer, size);
                break;
            case X86_EBP:
                regs->write(offsetof(CPUX86State, regs[R_EBP]), buffer, size);
                break;

            case X86_CS:
                regs->write(offsetof(CPUX86State, segs[R_CS].selector), buffer, size);
                break;
            case X86_DS:
                regs->write(offsetof(CPUX86State, segs[R_DS].selector), buffer, size);
                break;
            case X86_ES:
                regs->write(offsetof(CPUX86State, segs[R_ES].selector), buffer, size);
                break;
            case X86_SS:
                regs->write(offsetof(CPUX86State, segs[R_SS].selector), buffer, size);
                break;
            case X86_FS:
                regs->write(offsetof(CPUX86State, segs[R_FS].selector), buffer, size);
                break;
            case X86_GS:
                regs->write(offsetof(CPUX86State, segs[R_GS].selector), buffer, size);
                break;
            default:
                assert(false);
        }
        return true;
    } else if (regIndex <= X86_CR4) {
        regs->write(offsetof(CPUX86State, cr[regIndex - X86_CR0]), buffer, size);
        return true;
    } else if (regIndex <= X86_DR7) {
        regs->write(offsetof(CPUX86State, dr[regIndex - X86_DR0]), buffer, size);
        return true;
    } else if (regIndex == X86_EFLAGS) {
        pabort("Not implemented");
    } else if (regIndex == X86_EIP) {
        regs->write(offsetof(CPUX86State, eip), buffer, size);
    } else {
        return false;
    }

    return true;
}

bool Vmi::readModuleData(const ModuleDescriptor &module, uint64_t addr, uint8_t &val) {
    auto file = getFromDisk(module.Path, module.Name, false);
    if (!file) {
        getDebugStream() << "No executable file for " << module.Name << "\n";
        return false;
    }

    bool addrInSection = false;
    const vmi::Sections &sections = file->getSections();
    for (auto it : sections) {
        if (it.start <= addr && addr + sizeof(char) <= it.start + it.size) {
            addrInSection = true;
            break;
        }
    }
    if (!addrInSection) {
        getDebugStream() << "Address " << hexval(addr) << " is not in any section of " << module.Name << "\n";
        return false;
    }

    uint8_t byte;
    ssize_t size = file->read(&byte, sizeof(byte), addr);
    if (size != sizeof(byte)) {
        getDebugStream() << "Failed to read byte at " << hexval(addr) << " in " << module.Name << "\n";
        return false;
    }

    val = byte;
    return true;
}

vmi::Imports Vmi::resolveImports(S2EExecutionState *state, uint64_t loadBase, const vmi::Imports &imports) {
    vmi::Imports ret;
    for (auto it : imports) {
        auto &symbols = it.second;
        for (auto fit : symbols) {
            uint64_t itl = fit.second.importTableLocation + loadBase;
            uint64_t address = fit.second.address;

            if (!state->readPointer(itl, address)) {
                getWarningsStream(state) << "could not read address " << hexval(itl) << "\n";
                continue;
            }

            ret[it.first][fit.first] = ImportedSymbol(address, itl);
        }
    }

    return ret;
}

// XXX: support other binary formats, not just PE
bool Vmi::getResolvedImports(S2EExecutionState *state, const ModuleDescriptor &module, vmi::Imports &imports) {
    if (module.AddressSpace && state->regs()->getPageDir() != module.AddressSpace) {
        return false;
    }

    auto exe = getFromDisk(module.Path, module.Name, true);
    if (!exe) {
        getDebugStream(state) << "could not find on-disk image\n";
        return false;
    }

    auto pe = std::dynamic_pointer_cast<vmi::PEFile>(exe);
    if (!pe) {
        getWarningsStream(state) << "getResolvedImports only supports PE files\n";
        return false;
    }

    imports = resolveImports(state, module.LoadBase, pe->getImports());
    return true;
}

} // namespace plugins
} // namespace s2e
