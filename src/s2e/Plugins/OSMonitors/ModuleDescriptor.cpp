///
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ModuleDescriptor.h"

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
        sd.size = section.size;
        sd.readable = section.readable;
        sd.writable = section.writable;
        sd.executable = section.executable;
        sd.name = section.name;

        ret.Sections.push_back(sd);
    }

    return ret;
}

ModuleDescriptor ModuleDescriptor::get(const vmi::ExecutableFile &bin, uint64_t as, uint64_t pid,
                                       const std::string &name, const std::string &path,
                                       const std::vector<uint64_t> &runTimeAddresses) {
    ModuleDescriptor ret;

    ret.AddressSpace = as;
    ret.Pid = pid;
    ret.Name = name;
    ret.Path = path;
    ret.EntryPoint = bin.getEntryPoint();
    ret.Checksum = bin.getCheckSum();
    ret.Size = bin.getImageSize();

    auto &sections = bin.getSections();
    if (sections.size() != runTimeAddresses.size()) {
        // XXX: may want to abort here
        return ret;
    }

    auto i = 0;

    for (auto &section : bin.getSections()) {
        SectionDescriptor sd;
        sd.nativeLoadBase = section.start;
        sd.runtimeLoadBase = runTimeAddresses[i++];
        sd.size = section.size;
        sd.readable = section.readable;
        sd.writable = section.writable;
        sd.executable = section.executable;
        sd.name = section.name;

        ret.Sections.push_back(sd);
    }

    return ret;
}
}
