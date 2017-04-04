///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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

namespace s2e {

/**
 *  Defines some section of memory
 */
struct SectionDescriptor {
    enum SectionType { NONE = 0, READ = 1, WRITE = 2, READWRITE = 3, EXECUTE = 4 };

    uint64_t loadBase;
    uint64_t size;
    SectionType type;
    std::string name;

    SectionDescriptor() : loadBase(0), size(0), type(NONE) {
    }

    void setRead(bool b) {
        if (b)
            type = SectionType(type | READ);
        else
            type = SectionType(type & (-1 - READ));
    }

    void setWrite(bool b) {
        if (b)
            type = SectionType(type | WRITE);
        else
            type = SectionType(type & (-1 - WRITE));
    }

    void setExecute(bool b) {
        if (b)
            type = SectionType(type | EXECUTE);
        else
            type = SectionType(type & (-1 - EXECUTE));
    }

    bool isReadable() const {
        return type & READ;
    }
    bool isWritable() const {
        return type & WRITE;
    }
    bool isExecutable() const {
        return type & EXECUTE;
    }

    bool contains(uint64_t address) const {
        return address >= loadBase && address < (loadBase + size);
    }
};

typedef std::vector<SectionDescriptor> ModuleSections;

struct SymbolDescriptor {
    std::string name;
    unsigned size;

    bool operator()(const SymbolDescriptor &s1, const SymbolDescriptor &s2) const {
        return s1.name.compare(s2.name) < 0;
    }
};

typedef std::set<SymbolDescriptor, SymbolDescriptor> SymbolDescriptors;

/**
 *  Characterizes whatever module can be loaded in the memory.
 *  This can be a user-mode library, or a kernel-mode driver.
 */
struct ModuleDescriptor {
    // The page directory register value
    uint64_t AddressSpace;

    // The OS-defined PID where this module resides
    uint64_t Pid;

    // Full paths to the module
    std::string Path;

    // The name of the module (eg. MYAPP.EXE or DRIVER.SYS)
    std::string Name;

    // Where the the preferred load address of the module.
    // This is defined by the linker and put into the header of the image.
    uint64_t NativeBase;

    // Where the image of the module was actually loaded by the OS.
    uint64_t LoadBase;

    // The size of the image of the module
    uint64_t Size;

    // The entry point of the module
    uint64_t EntryPoint;

    // Data section
    uint64_t DataBase;
    uint64_t DataSize;

    // Initial SP value
    uint64_t StackTop;

    // PE checksum
    uint32_t Checksum;

    // A list of sections
    ModuleSections Sections;

    ModuleDescriptor() {
        AddressSpace = 0;
        NativeBase = 0;
        LoadBase = 0;
        Size = 0;
        EntryPoint = 0;
    }

    bool Contains(uint64_t RunTimeAddress) const {
        uint64_t RVA = RunTimeAddress - LoadBase;
        return RVA < Size;
    }

    uint64_t ToRelative(uint64_t RunTimeAddress) const {
        uint64_t RVA = RunTimeAddress - LoadBase;
        return RVA;
    }

    uint64_t ToNativeBase(uint64_t RunTimeAddress) const {
        return RunTimeAddress - LoadBase + NativeBase;
    }

    uint64_t ToRuntime(uint64_t NativeAddress) const {
        return NativeAddress - NativeBase + LoadBase;
    }

    bool EqualInsensitive(const char *Name) const {
        return strcasecmp(this->Name.c_str(), Name) == 0;
    }

    const SectionDescriptor *getSection(uint64_t RunTimeAddress) const {
        for (unsigned i = 0; i < Sections.size(); ++i) {
            if (Sections[i].contains(RunTimeAddress)) {
                return &Sections[i];
            }
        }
        return NULL;
    }

    struct ModuleByLoadBase {
        bool operator()(const struct ModuleDescriptor &s1, const struct ModuleDescriptor &s2) const {
            if (s1.AddressSpace == s2.AddressSpace) {
                return s1.LoadBase + s1.Size <= s2.LoadBase;
            }
            return s1.AddressSpace < s2.AddressSpace;
        }

        bool operator()(const struct ModuleDescriptor *s1, const struct ModuleDescriptor *s2) const {
            if (s1->AddressSpace == s2->AddressSpace) {
                return s1->LoadBase + s1->Size <= s2->LoadBase;
            }
            return s1->AddressSpace < s2->AddressSpace;
        }
    };

    struct ModuleByLoadBasePid {
        bool operator()(const struct ModuleDescriptor &s1, const struct ModuleDescriptor &s2) const {
            if (s1.Pid == s2.Pid) {
                return s1.LoadBase + s1.Size <= s2.LoadBase;
            }
            return s1.Pid < s2.Pid;
        }

        bool operator()(const struct ModuleDescriptor *s1, const struct ModuleDescriptor *s2) const {
            if (s1->Pid == s2->Pid) {
                return s1->LoadBase + s1->Size <= s2->LoadBase;
            }
            return s1->Pid < s2->Pid;
        }
    };

    struct ModuleByPidName {
        bool operator()(const struct ModuleDescriptor &s1, const struct ModuleDescriptor &s2) const {
            if (s1.Pid == s2.Pid) {
                return s1.Name < s2.Name;
            }
            return s1.Pid < s2.Pid;
        }

        bool operator()(const struct ModuleDescriptor *s1, const struct ModuleDescriptor *s2) const {
            if (s1->Pid == s2->Pid) {
                return s1->Name < s2->Name;
            }
            return s1->Pid < s2->Pid;
        }
    };

    struct ModuleByName {
        bool operator()(const struct ModuleDescriptor &s1, const struct ModuleDescriptor &s2) const {
            return s1.Name < s2.Name;
        }

        bool operator()(const struct ModuleDescriptor *s1, const struct ModuleDescriptor *s2) const {
            return s1->Name < s2->Name;
        }
    };

    typedef std::set<struct ModuleDescriptor, ModuleByLoadBase> MDSet;
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const ModuleDescriptor &md) {
    out << "ModuleDescriptor Name=" << md.Name << " Path=" << md.Path << " NativeBase=" << hexval(md.NativeBase)
        << " LoadBase=" << hexval(md.LoadBase) << " Size=" << hexval(md.Size)
        << " AddressSpace=" << hexval(md.AddressSpace) << " Pid=" << hexval(md.Pid)
        << " EntryPoint=" << hexval(md.EntryPoint) << " Checksum=" << hexval(md.Checksum);

    return out;
}

typedef std::vector<const ModuleDescriptor *> ModuleDescriptorList;
}

#endif
