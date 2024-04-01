///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2019, Cyberhaven
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

#ifndef S2E_PLUGINS_Vmi_H
#define S2E_PLUGINS_Vmi_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/S2EExecutionState.h>

#include <llvm/ADT/DenseSet.h>
#include <llvm/Support/Path.h>
#include <vmi/ExecutableFile.h>
#include <vmi/PEFile.h>

#include <vmi/FileProvider.h>
#include <vmi/RegisterProvider.h>

namespace s2e {

class ConfigFile;

namespace plugins {

class Vmi : public Plugin {
    S2E_PLUGIN
public:
    Vmi(S2E *s2e) : Plugin(s2e) {
    }

    ~Vmi() {
    }

    void initialize();

    static bool readGuestVirtual(void *opaque, uint64_t address, void *dest, unsigned size);
    static bool writeGuestVirtual(void *opaque, uint64_t address, const void *source, unsigned size);

    static bool readGuestPhysical(void *opaque, uint64_t address, void *dest, unsigned size);
    static bool writeGuestPhysical(void *opaque, uint64_t address, const void *source, unsigned size);

    static bool readX86Register(void *opaque, unsigned reg, void *value, unsigned size);
    static bool writeX86Register(void *opaque, unsigned reg, const void *value, unsigned size);

    static std::string stripWindowsModulePath(const std::string &path);

    std::shared_ptr<vmi::ExecutableFile> getFromDisk(const std::string &modulePath, const std::string &moduleName,
                                                     bool caseInsensitive);

    bool readModuleData(const ModuleDescriptor &module, uint64_t addr, uint8_t &val);

    bool getResolvedImports(S2EExecutionState *state, const ModuleDescriptor &module, vmi::Imports &imports);

private:
    std::vector<std::string> m_baseDirectories;
    std::unordered_map<std::string /* guestfs path */, std::shared_ptr<vmi::ExecutableFile>> m_cache;

    void findModule(const std::string &module, std::vector<std::string> &paths);
    bool findModule(const std::string &module, std::string &path);
    bool parseDirectories(ConfigFile *cfg, const std::string &baseDirsKey);

    bool getHostPathForModule(const std::string &modulePath, const std::string &moduleName, bool caseInsensitive,
                              std::string &hostPath);
    vmi::Imports resolveImports(S2EExecutionState *state, uint64_t loadBase, const vmi::Imports &imports);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_Vmi_H
