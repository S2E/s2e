///
/// Copyright (C) 2019, Cyberhaven
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
