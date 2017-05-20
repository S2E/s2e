///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_Vmi_H
#define S2E_PLUGINS_Vmi_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>
#include <llvm/Support/Path.h>
#include <vmi/ElfDwarf.h>
#include <vmi/ExecutableFile.h>
#include <vmi/PEFile.h>
#include <vmi/Vmi.h>

#include <vmi/FileProvider.h>
#include <vmi/RegisterProvider.h>

namespace s2e {

class ConfigFile;

namespace plugins {

typedef std::pair<uint64_t, uint64_t> AddressRange;

class Vmi : public Plugin {
    S2E_PLUGIN
public:
    struct ExeData {
        vmi::ExecutableFile *execFile;
        vmi::ElfDwarf *dwarf;
        vmi::Vmi *vmi;
    };

    // XXX: really need some ref counting for fp
    struct BinData {
        vmi::FileProvider *fp;
        vmi::ExecutableFile *ef;
        BinData() : fp(NULL), ef(NULL) {
        }
    };

    struct PeData {
        vmi::FileProvider *fp;
        vmi::PEFile *pe;
        PeData() : fp(NULL), pe(NULL) {
        }
    };

    typedef uint64_t PeChecksum;
    typedef std::tr1::unordered_map<std::string, uint64_t> Symbols;
    typedef std::vector<std::pair<uint64_t, std::string>> Syscalls;
    typedef llvm::DenseSet<uint64_t> Addresses;
    typedef std::map<PeChecksum, Addresses> ModuleAddresses;

    struct Module {
        std::string Version;
        PeChecksum Checksum;
        std::string Name;
        uint64_t NativeBase;
        Symbols Symbols;
        Syscalls Syscalls;
        std::set<uint64_t> CXXHandlers;
        uint64_t CHandler;
        std::vector<AddressRange> IgnoredAddressRanges;
    };

    typedef std::tr1::unordered_map<PeChecksum, Module> Modules;

    Vmi(S2E *s2e) : Plugin(s2e) {
    }
    ~Vmi();

    void initialize();

    bool get(const std::string &module, ExeData &data);

    static bool readGuestVirtual(void *opaque, uint64_t address, void *dest, unsigned size);
    static bool writeGuestVirtual(void *opaque, uint64_t address, const void *source, unsigned size);

    static bool readGuestPhysical(void *opaque, uint64_t address, void *dest, unsigned size);
    static bool writeGuestPhysical(void *opaque, uint64_t address, const void *source, unsigned size);

    static bool readX86Register(void *opaque, unsigned reg, void *value, unsigned size);
    static bool writeX86Register(void *opaque, unsigned reg, const void *value, unsigned size);

    static std::string stripWindowsModulePath(const std::string &path);

    bool findModule(const std::string &module, std::string &path);

    bool getSymbolAddress(uint64_t PeChecksum, const std::string &symbolName, bool relative, uint64_t *address) const;
    bool getVersion(uint64_t PeChecksum, std::string &version) const;
    bool getSyscallInfo(uint64_t PeChecksum, unsigned num, uint64_t &address, std::string &name) const;

    const Modules &getModules() const {
        return m_moduleInfo;
    }

    Vmi::BinData getFromDisk(const ModuleDescriptor &module, bool useModulePath = true);
    Vmi::PeData getPeFromDisk(const ModuleDescriptor &module, bool caseInsensitive = false);

    void addFuctionAddress(uint64_t PeChecksum, uint64_t address) {
        m_addresses[PeChecksum].insert(address);
    }

    const ModuleAddresses &getModuleAddresses() const {
        return m_addresses;
    }

    static void toModuleDescriptor(ModuleDescriptor &desc, vmi::PEFile *pe);

    bool readModuleData(const ModuleDescriptor &module, uint64_t addr, uint8_t &val);
    bool patchImportsFromDisk(S2EExecutionState *state, const ModuleDescriptor &module, uint32_t checkSum,
                              vmi::Imports &imports);

    static bool getEntryPoint(S2EExecutionState *s, const ModuleDescriptor &desc, uint64_t &Addr);
    bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I);
    static bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E);
    static bool getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R);
    static bool getSections(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Sections &S);

private:
    typedef llvm::StringMap<ExeData> Executables;

    std::vector<std::string> m_baseDirectories;
    Executables m_executables;
    Modules m_moduleInfo;

    ModuleAddresses m_addresses;

    std::map<std::string /* moduleName */, Vmi::BinData> m_cachedBinData;

    bool initializeExecutable(const std::string &path, ExeData &data);
    bool parseModuleInfo(ConfigFile *cfg, const std::string &modules_key);
    bool parseDirectories(ConfigFile *cfg, const std::string &baseDirsKey);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_Vmi_H
