///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2016, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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

static bool VmiReadMemory(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->readMemoryConcrete(address, dest, size);
}

Vmi::~Vmi() {
    foreach2 (it, m_cachedBinData.begin(), m_cachedBinData.end()) {
        delete it->second.fp;
        delete it->second.ef;
    }
    m_cachedBinData.clear();
}

void Vmi::initialize() {
    // Load the list of directories in which to search for
    // executable files.
    ConfigFile *cfg = s2e()->getConfig();
    if (!parseDirectories(cfg, getConfigKey() + ".baseDirs")) {
        exit(-1);
    }

    if (!parseModuleInfo(cfg, getConfigKey() + ".modules")) {
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

bool Vmi::parseModuleInfo(ConfigFile *cfg, const std::string &modules_key) {
    ConfigFile::string_list checksums = cfg->getListKeys(modules_key);
    foreach2 (it, checksums.begin(), checksums.end()) {
        Module mod;
        std::stringstream ss;
        bool ok = true;
        ss << modules_key << "." << *it;

        mod.Checksum = cfg->getInt(ss.str() + ".checksum", 0, &ok);
        if (!ok) {
            getWarningsStream() << "no checksum in " << ss.str() << "\n";
            return false;
        }

        mod.NativeBase = cfg->getInt(ss.str() + ".nativebase", 0, &ok);
        if (!ok) {
            getWarningsStream() << "no native base in " << ss.str() << "\n";
            return false;
        }

        mod.Name = cfg->getString(ss.str() + ".name", "", &ok);
        if (!ok) {
            getWarningsStream() << "no name in " << ss.str() << "\n";
            return false;
        }

        mod.Version = cfg->getString(ss.str() + ".version", "", &ok);
        if (!ok) {
            getWarningsStream() << "no version in " << ss.str() << "\n";
            return false;
        }

        ConfigFile::string_list symbols = cfg->getListKeys(ss.str() + ".symbols");
        foreach2 (fit, symbols.begin(), symbols.end()) {
            std::string name = *fit;
            std::stringstream fss;
            fss << ss.str() << ".symbols." << name;
            uint64_t address = cfg->getInt(fss.str(), 0, &ok);
            if (!ok) {
                getWarningsStream() << "no address for function " << fss.str() << "\n";
                return false;
            }

            mod.Symbols[name] = address;
            if (name == "__C_specific_handler") {
                mod.CHandler = address;
            } else if (name == "__CxxFrameHandler3") {
                mod.CXXHandlers.insert(address);
            } else if (name == "__GSHandlerCheck") {
                mod.CXXHandlers.insert(address);
            } else if (name == "__GSHandlerCheck_EH") {
                mod.CXXHandlers.insert(address);
            }
        }

        unsigned syscallCount = cfg->getListSize(ss.str() + ".syscalls");
        for (unsigned i = 0; i < syscallCount; ++i) {
            std::stringstream fss;
            fss << ss.str() << ".syscalls[" << (i + 1) << "]";

            uint64_t address = cfg->getInt(fss.str() + "[1]", 0, &ok);
            std::string name = cfg->getString(fss.str() + "[2]", "", &ok);

            if (!ok || name == "") {
                getWarningsStream() << "Could not get syscall for " << fss.str() << "\n";
                break;
            }

            mod.Syscalls.push_back(std::make_pair(address, name));
        }

        ConfigFile::integer_list range = cfg->getIntegerList(ss.str() + ".range");
        if (range.size() == 2) {
            mod.IgnoredAddressRanges.push_back(std::make_pair(range[0], range[1]));
        }

        llvm::raw_ostream &os = getDebugStream();
        os << "added module " << mod.Name << " " << mod.Version << " " << hexval(mod.Checksum) << " "
           << "- " << mod.Symbols.size() << " functions "
           << "- " << mod.Syscalls.size() << " syscalls";

        if (mod.IgnoredAddressRanges.size() > 0) {
            os << " range: " << hexval(mod.IgnoredAddressRanges[0].first) << ","
               << hexval(mod.IgnoredAddressRanges[0].second) << "\n";
        } else {
            os << "\n";
        }

        m_moduleInfo[mod.Checksum] = mod;
    }

    return true;
}

bool Vmi::getSymbolAddress(uint64_t PeChecksum, const std::string &symbolName, bool relative, uint64_t *address) const {
    Modules::const_iterator mit = m_moduleInfo.find(PeChecksum);
    if (mit == m_moduleInfo.end()) {
        return false;
    }

    const Module &mod = (*mit).second;
    Symbols::const_iterator sit = mod.Symbols.find(symbolName);
    if (sit == mod.Symbols.end()) {
        return false;
    }

    *address = (*sit).second;
    if (relative) {
        *address -= mod.NativeBase;
    }
    return true;
}

bool Vmi::getVersion(uint64_t PeChecksum, std::string &version) const {
    Modules::const_iterator mit = m_moduleInfo.find(PeChecksum);
    if (mit == m_moduleInfo.end()) {
        return false;
    }

    const Module &mod = (*mit).second;
    version = mod.Version;

    return true;
}

bool Vmi::getSyscallInfo(uint64_t PeChecksum, unsigned num, uint64_t &address, std::string &name) const {
    Modules::const_iterator mit = m_moduleInfo.find(PeChecksum);
    if (mit == m_moduleInfo.end()) {
        return false;
    }

    const Module &mod = (*mit).second;

    if (num >= mod.Syscalls.size()) {
        return false;
    }

    address = mod.Syscalls[num].first;
    name = mod.Syscalls[num].second;
    return true;
}

bool Vmi::initializeExecutable(const std::string &file, ExeData &data) {

    vmi::Vmi *vmi;
    vmi::ElfDwarf *dwarf;
    vmi::FileSystemFileProvider *fp;
    vmi::ExecutableFile *execFile;
    std::string moduleName = llvm::sys::path::filename(file);

    fp = vmi::FileSystemFileProvider::get(file, false);
    if (!fp) {
        getWarningsStream() << file << " could not be opened\n";
        goto err1;
    }

    execFile = vmi::ExecutableFile::get(fp, false, 0);
    if (!execFile) {
        getWarningsStream() << file << " does not appear to be a valid executable file\n";
        goto err1;
    }

    dwarf = vmi::ElfDwarf::get(getDebugStream(), file);
    if (!dwarf) {
        getWarningsStream()
            << file
            << " does not appear to contain valid DWARF debug info. Please recompile your kernel with debug symbols.\n";
        goto err2;
    }

    vmi = new vmi::Vmi(dwarf);
    vmi->registerCallbacks(&VmiReadMemory);

    data.dwarf = dwarf;
    data.execFile = execFile;
    data.vmi = vmi;

    return true;

err2:
    delete execFile;
err1:
    delete fp;
    return false;
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
    /* Find the path prefix for the given relative file */
    foreach2 (it, m_baseDirectories.begin(), m_baseDirectories.end()) {
        llvm::SmallString<128> tempPath(*it);
        llvm::sys::path::append(tempPath, module);

        if (llvm::sys::fs::exists(tempPath)) {
            path = tempPath.c_str();
            return true;
        }
    }

    return false;
}

bool Vmi::get(const std::string &module, ExeData &data) {
    std::string file;
    if (!findModule(module, file)) {
        getWarningsStream() << "Could not find module file " << module << "\n";
        return false;
    }

    Executables::const_iterator it = m_executables.find(module);
    if (it != m_executables.end()) {
        data = (*it).second;
        return true;
    }

    if (!initializeExecutable(file, data)) {
        return false;
    }

    m_executables[module] = data;
    return true;
}

// XXX: avoid code duplication with getPeFromDisk
Vmi::BinData Vmi::getFromDisk(const ModuleDescriptor &module, bool useModulePath) {
    getDebugStream() << "reading executable file from host disk\n";
    std::string modPath;
    if (!findModule(useModulePath ? module.Path : module.Name, modPath)) {
        if (!findModule(module.Name, modPath)) {
            return BinData();
        }
    }

    getDebugStream() << "attempting to load executable file: " << modPath << "\n";

    vmi::FileSystemFileProvider *fp = FileSystemFileProvider::get(modPath, false);

    if (!fp) {
        getDebugStream() << "cannot open file\n";
        delete fp;
        return BinData();
    }

    vmi::ExecutableFile *efile = vmi::ExecutableFile::get(fp, false, 0);

    if (!efile) {
        delete fp;
        getDebugStream() << "cannot load file\n";
        return BinData();
    }

    BinData pd;
    pd.fp = fp;
    pd.ef = efile;
    return pd;
}

Vmi::PeData Vmi::getPeFromDisk(const ModuleDescriptor &module, bool caseInsensitive) {
    getDebugStream() << "reading PE file from disk\n";
    // Try to load back pe file from disk
    std::string strippedPath = Vmi::stripWindowsModulePath(module.Path);
    std::string modPath;
    if (!findModule(strippedPath, modPath)) {
        bool found = false;
        if (caseInsensitive) {
            std::transform(strippedPath.begin(), strippedPath.end(), strippedPath.begin(), ::tolower);
            found = findModule(strippedPath, modPath);
        }

        if (!found) {
            found = findModule(module.Name, modPath);
            if (!found) {
                std::string Name = module.Name;
                std::transform(Name.begin(), Name.end(), Name.begin(), ::tolower);
                found = findModule(Name, modPath);
            }
        }

        if (!found) {
            getDebugStream() << "could not find " << strippedPath << "\n";
            return PeData();
        }
    }

    getDebugStream() << "attempting to load PE file: " << modPath << "\n";

    vmi::FileSystemFileProvider *fp = vmi::FileSystemFileProvider::get(modPath, false);

    if (!fp) {
        getDebugStream() << "cannot open file\n";
        delete fp;
        return PeData();
    }

    vmi::PEFile *pefile = vmi::PEFile::get(fp, false, 0);

    if (!pefile) {
        delete fp;
        getDebugStream() << "cannot load file\n";
        return PeData();
    }

    PeData pd;
    pd.fp = fp;
    pd.pe = pefile;
    return pd;
}

bool Vmi::readGuestVirtual(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->readMemoryConcrete(address, dest, size);
}

bool Vmi::writeGuestVirtual(void *opaque, uint64_t address, const void *source, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->writeMemoryConcrete(address, source, size);
}

bool Vmi::readGuestPhysical(void *opaque, uint64_t address, void *dest, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->readMemoryConcrete(address, dest, size, PhysicalAddress);
}

bool Vmi::writeGuestPhysical(void *opaque, uint64_t address, const void *source, unsigned size) {
    S2EExecutionState *state = static_cast<S2EExecutionState *>(opaque);
    return state->mem()->writeMemoryConcrete(address, source, size, PhysicalAddress);
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
        assert(false && "Not implemented");
    } else if (regIndex == X86_EIP) {
        regs->write(offsetof(CPUX86State, eip), buffer, size);
    } else {
        return false;
    }

    return true;
}

void Vmi::toModuleDescriptor(ModuleDescriptor &desc, vmi::PEFile *pe) {
    if (!desc.Size) {
        desc.Size = pe->getImageSize();
    }
    desc.NativeBase = pe->getImageBase();
    desc.EntryPoint = pe->getEntryPoint();
    desc.Checksum = pe->getCheckSum();

    for (auto it : pe->getSections()) {
        const vmi::SectionDescriptor &vd = it;
        SectionDescriptor d;
        d.loadBase = desc.ToRuntime(vd.start);
        d.size = vd.size;
        d.name = vd.name;
        d.setExecute(vd.isExecutable());
        d.setRead(vd.isReadable());
        d.setWrite(vd.isWritable());
        desc.Sections.push_back(d);
    }
}

/*
 * Read memory from binary data.
 */
bool Vmi::readModuleData(const ModuleDescriptor &module, uint64_t addr, uint8_t &val) {
    vmi::ExecutableFile *file;
    std::map<std::string, Vmi::BinData>::const_iterator it = m_cachedBinData.find(module.Name);
    if (it == m_cachedBinData.end()) {
        Vmi::BinData bindata = getFromDisk(module, false);
        if (!bindata.ef) {
            getDebugStream() << "No executable file for " << module.Name << "\n";
            return false;
        }
        m_cachedBinData[module.Name] = bindata;
        file = bindata.ef;
    } else {
        file = it->second.ef;
    }

    bool addrInSection = false;
    const vmi::Sections &sections = file->getSections();
    foreach2 (it, sections.begin(), sections.end()) {
        if (it->start <= addr && addr + sizeof(char) <= it->start + it->size) {
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

// XXX: support other binary formats, not just PE
bool Vmi::patchImportsFromDisk(S2EExecutionState *state, const ModuleDescriptor &module, uint32_t checkSum,
                               vmi::Imports &imports) {
    bool result = true;
    getDebugStream(state) << "trying to open the on-disk image to parse imports\n";

    Vmi::PeData pd = getPeFromDisk(module, true);
    if (!pd.pe) {
        getDebugStream(state) << "could not find on-disk image\n";
        return false;
    }

    if (checkSum != pd.pe->getCheckSum()) {
        getDebugStream(state) << "checksum mismatch for " << module.Name << "\n";
        result = false;
        goto err1;
    }

    imports = pd.pe->getImports();

    for (vmi::Imports::iterator it = imports.begin(); it != imports.end(); ++it) {
        vmi::ImportedSymbols &symbols = (*it).second;

        for (vmi::ImportedSymbols::iterator fit = symbols.begin(); fit != symbols.end(); ++fit) {
            uint64_t itl = (*fit).second.importTableLocation + module.LoadBase;
            uint64_t address = (*fit).second.address;

            if (!state->readPointer(itl, address)) {
                getWarningsStream(state) << "could not read address " << hexval(itl) << "\n";
                continue;
            }

            (*fit).second.importTableLocation = itl;
            (*fit).second.address = address;
        }
    }

err1:
    delete pd.pe;
    delete pd.fp;
    return result;
}

// TODO: remove duplicate code in all these getXXX functions.
bool Vmi::getEntryPoint(S2EExecutionState *state, const ModuleDescriptor &Desc, uint64_t &Addr) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    Addr = image->getEntryPoint();
    delete image;
    return true;
}

bool Vmi::getImports(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Imports &I) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    getDebugStream(state) << "getting import for " << Desc << "\n";

    bool result = true;
    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    /**
     * If the import table is in the INIT section, it's likely that the OS
     * unloaded it. Instead of failing, reconstruct the import table from
     * the original binary.
     */
    if (patchImportsFromDisk(state, Desc, image->getCheckSum(), I)) {
        goto end;
    }

    I = image->getImports();

end:
    delete image;
    return result;
}

bool Vmi::getExports(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Exports &E) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    E = image->getExports();
    delete image;
    return true;
}

bool Vmi::getRelocations(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Relocations &R) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::PEFile *image = vmi::PEFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    R = image->getRelocations();
    delete image;
    return true;
}

bool Vmi::getSections(S2EExecutionState *state, const ModuleDescriptor &Desc, vmi::Sections &S) {
    if (Desc.AddressSpace && state->getPageDir() != Desc.AddressSpace) {
        return false;
    }

    vmi::GuestMemoryFileProvider file(state, &Vmi::readGuestVirtual, NULL, Desc.Name);
    vmi::ExecutableFile *image = vmi::ExecutableFile::get(&file, true, Desc.LoadBase);
    if (!image) {
        return false;
    }

    S = image->getSections();
    delete image;
    return true;
}

} // namespace plugins
} // namespace s2e
