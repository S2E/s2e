///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ModuleDescriptor.h"
#include <llvm/ADT/DenseSet.h>

namespace s2e {

ModuleDescriptor ModuleDescriptor::get(const vmi::PEFile &bin, uint64_t as, uint64_t pid, const std::string &name,
                                       const std::string &path, uint64_t loadBase) {
    ModuleDescriptor ret;

    ret.AddressSpace = as;
    ret.Pid = pid;
    ret.Name = name;
    ret.Path = path;
    ret.EntryPoint = bin.getEntryPoint();
    ret.Checksum = bin.getCheckSum();
    ret.Size = bin.getImageSize();

    ret.LoadBase = loadBase;
    ret.NativeBase = bin.getImageBase();

    for (auto &section : bin.getSections()) {
        SectionDescriptor sd;
        sd.nativeLoadBase = section.start;
        sd.runtimeLoadBase = section.start - ret.NativeBase + ret.LoadBase;
        sd.size = section.virtualSize;
        sd.readable = section.readable;
        sd.writable = section.writable;
        sd.executable = section.executable;
        sd.name = section.name;

        if (sd.size) {
            ret.Sections.push_back(sd);
        }
    }

    return ret;
}

ModuleDescriptor ModuleDescriptor::get(const std::string &path, const std::string &name, uint64_t pid, uint64_t as,
                                       uint64_t entryPoint, const std::vector<SectionDescriptor> &mappedSections) {
    ModuleDescriptor ret;

    ret.AddressSpace = as;
    ret.Pid = pid;
    ret.Name = name;
    ret.Path = path;
    ret.EntryPoint = entryPoint;
    ret.Checksum = 0;
    ret.Size = 0;

    for (auto &s : mappedSections) {
        ret.Size += s.size;
    }

    ret.Sections = mappedSections;

    return ret;
}
} // namespace s2e
