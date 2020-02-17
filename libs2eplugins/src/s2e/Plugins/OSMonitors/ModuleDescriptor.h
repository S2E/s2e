///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
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

#ifndef _MODULE_DESCRIPTOR_H_

#define _MODULE_DESCRIPTOR_H_

#include <inttypes.h>
#include <iostream>
#include <map>
#include <ostream>
#include <set>
#include <string>
#include <vector>

#include <cstring>
#include <s2e/Utils.h>

#include <vmi/ExecutableFile.h>
#include <vmi/PEFile.h>

namespace s2e {

struct SectionDescriptor {
    uint64_t runtimeLoadBase;
    uint64_t nativeLoadBase;
    uint64_t size;
    bool readable;
    bool writable;
    bool executable;
    std::string name;

    SectionDescriptor()
        : runtimeLoadBase(0), nativeLoadBase(0), size(0), readable(false), writable(false), executable(false) {
    }

    bool contains(uint64_t address) const {
        return address >= runtimeLoadBase && address < (runtimeLoadBase + size);
    }
};

using ModuleSections = std::vector<SectionDescriptor>;

///
/// \brief The ModuleDescriptor structure describes a module loaded in memory.
///
/// The module can be a user space binary, a kernel driver, etc.
///
struct ModuleDescriptor {
    // The page directory register value
    uint64_t AddressSpace;

    // The OS-defined PID where this module resides
    uint64_t Pid;

    // Full path to the module
    std::string Path;

    // The name of the module (eg. MYAPP.EXE or DRIVER.SYS)
    std::string Name;

    // The size of the image of the module
    uint64_t Size;

    // The entry point of the module
    uint64_t EntryPoint;

    // PE checksum
    uint32_t Checksum;

    // A list of sections
    ModuleSections Sections;

    // This is the address where the module's header is loaded.
    // When 0, there is no mapped header. This field is mostly
    // useful on Windows, where binaries have a load base.
    uint64_t LoadBase;

    // Only valid for Windows binaries for now, which have
    // a native load base. Linux and other ELF binaries don't have
    // that, they map sections instead.
    uint64_t NativeBase;

    ModuleDescriptor() {
        AddressSpace = 0;
        Size = 0;
        EntryPoint = 0;
        LoadBase = 0;
        NativeBase = 0;
    }

    bool Contains(uint64_t RunTimeAddress) const {
        return getSection(RunTimeAddress) != nullptr;
    }

    bool ToNativeBase(uint64_t RunTimeAddress, uint64_t &NativeAddress) const {
        if (NativeBase && LoadBase) {
            NativeAddress = RunTimeAddress - LoadBase + NativeBase;
            return true;
        }

        auto section = getSection(RunTimeAddress);
        if (!section) {
            return false;
        }

        NativeAddress = RunTimeAddress - section->runtimeLoadBase + section->nativeLoadBase;
        return true;
    }

    bool ToRuntime(uint64_t NativeAddress, uint64_t &RunTimeAddress) const {
        if (NativeBase && LoadBase) {
            RunTimeAddress = NativeAddress - NativeBase + LoadBase;
            return true;
        }

        for (auto &section : Sections) {
            if (NativeAddress >= section.nativeLoadBase && (NativeAddress < section.nativeLoadBase + section.size)) {
                RunTimeAddress = NativeAddress - section.nativeLoadBase + section.runtimeLoadBase;
                return true;
            }
        }

        return false;
    }

    static ModuleDescriptor get(const vmi::PEFile &bin, uint64_t as, uint64_t pid, const std::string &name,
                                const std::string &path, uint64_t loadbase);
    static ModuleDescriptor get(const std::string &path, const std::string &name, uint64_t pid, uint64_t as,
                                uint64_t entryPoint, const std::vector<SectionDescriptor> &mappedSections);

    const SectionDescriptor *getSection(uint64_t RunTimeAddress) const {
        for (unsigned i = 0; i < Sections.size(); ++i) {
            if (Sections[i].contains(RunTimeAddress)) {
                return &Sections[i];
            }
        }
        return nullptr;
    }
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const ModuleDescriptor &md) {
    out << "ModuleDescriptor Name=" << md.Name << " Path=" << md.Path << " Size=" << hexval(md.Size)
        << " AddressSpace=" << hexval(md.AddressSpace) << " Pid=" << hexval(md.Pid)
        << " EntryPoint=" << hexval(md.EntryPoint) << " Checksum=" << hexval(md.Checksum);

    return out;
}

using ModuleDescriptorConstPtr = std::shared_ptr<const ModuleDescriptor>;
using ModuleDescriptorList = std::vector<ModuleDescriptorConstPtr>;
} // namespace s2e

#endif
