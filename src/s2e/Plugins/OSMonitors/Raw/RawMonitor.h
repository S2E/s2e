///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _RAWMON_PLUGIN_H_

#define _RAWMON_PLUGIN_H_

#include <s2e/monitors/commands/raw.h>

#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>

#include <vector>

namespace s2e {
namespace plugins {

class RawMonitor : public OSMonitor, public BaseInstructionsPluginInvokerInterface {
    S2E_PLUGIN

public:
    struct Cfg {
        std::string name;
        uint64_t start;
        uint64_t size;
        uint64_t nativebase;
        uint64_t entrypoint;
        bool kernelMode;
    };

    struct OpcodeModuleConfig {
        uint64_t name;
        uint64_t nativeBase;
        uint64_t loadBase;
        uint64_t entryPoint;
        uint64_t size;
        uint32_t kernelMode;
    } __attribute__((packed));

    typedef std::vector<Cfg> CfgList;

private:
    Vmi *m_vmi;

    CfgList m_cfg;
    sigc::connection m_onTranslateInstruction;

    uint64_t m_kernelStart;
    S2E_RAWMON_COMMAND_STACK m_stack;

    vmi::Imports m_imports;

    bool initSection(const std::string &cfgKey, const std::string &svcId);
    void loadModule(S2EExecutionState *state, const Cfg &c);

    void handleModuleLoad(S2EExecutionState *state, const S2E_RAWMON_COMMAND_MODULE_LOAD &m);

public:
    RawMonitor(S2E *s2e) : OSMonitor(s2e) {
    }
    virtual ~RawMonitor();
    void initialize();

    void onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb,
                                     uint64_t pc);

    virtual bool getImports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Imports &I);
    virtual bool getExports(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Exports &E);
    virtual bool getRelocations(S2EExecutionState *s, const ModuleDescriptor &desc, vmi::Relocations &R);
    virtual bool isKernelAddress(uint64_t pc) const;
    virtual uint64_t getAddressSpace(S2EExecutionState *s, uint64_t pc);

    virtual bool getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size);

    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);

    uint64_t getPid(S2EExecutionState *state, uint64_t pc) {
        return getAddressSpace(state, pc);
    }

    virtual uint64_t getPid(S2EExecutionState *state) {
        assert(false && "Not implemented!");
        return false;
    }

    virtual uint64_t getTid(S2EExecutionState *state) {
        assert(false && "Not implemented!");
        return false;
    }

    virtual bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) {
        assert(false && "Not implemented!");
        return false;
    }
};

} // namespace plugins
} // namespace s2e

#endif
