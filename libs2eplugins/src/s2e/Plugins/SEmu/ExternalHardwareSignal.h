///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ExternalHardwareSignal_H
#define S2E_PLUGINS_ExternalHardwareSignal_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Plugins/SymbolicHardware/SymbolicHardware.h>
#include <utility>
#include <queue>

namespace s2e {
namespace plugins {

typedef struct field {
    std::string type; // R: receive; T: transmit; O: other
    uint32_t phaddr;
    std::vector<long> bits;
    uint32_t value;
    field() :
        type("*"), phaddr(0), bits({-1}), value(0) {
    }
} Field;

typedef struct signal {
    uint32_t id;
    int32_t irq;
    std::vector<Field> key;
    std::vector<Field> control;
    std::vector<Field> status;
    std::vector<Field> other;
    std::vector<Field> dma;
    signal() :
        id(0), irq(-1), key({}), control({}), status({}), other({}), dma({}) {
    }
} Signal;

typedef std::vector<Field> FieldList;
typedef std::map<int32_t, std::vector<Signal>> SignalPair;
typedef std::map<uint32_t, SignalPair> IRQRules;

class ExternalHardwareSignal : public Plugin {
    S2E_PLUGIN
public:
    ExternalHardwareSignal(S2E *s2e) :
        Plugin(s2e) {
    }
    sigc::signal<void, S2EExecutionState *, SignalPair &> onSignalUpdate;
    sigc::signal<void, S2EExecutionState *, SymbolicHardwareAccessType /* type */, uint32_t /* physicalAddress */,
                 unsigned /* size */, uint32_t * /* NLPsymbolicvalue */, bool *, std::stringstream *>
        onReadUpdate;

    sigc::signal<void, S2EExecutionState *, SymbolicHardwareAccessType /* type */, uint32_t /* physicalAddress */,
                 uint32_t /* writeconcretevalue */>
        onWriteUpdate;

private:
    IRQRules interrupt_conditions;

    std::string SignalfileName;
    void initialize();
    bool readSignalfromFile(std::string &fileName);
    bool getSignals(std::string &peripheralcache);
    bool getSequences(std::string &peripheralcache);
    void extractSignal(std::string &expressions, int32_t interrupt, std::string &status, Signal &signal);
    void recordRule(Signal &signal, FieldList &fieldlist);
    void ReadField(std::string &v, Field &field);
    std::vector<long> getBits(std::string &bits);
    void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c);
    void SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype);

    void triggerIRQ(S2EExecutionState *state, uint32_t phaddr);
    void onPeripheralRead(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr, unsigned size,
                          uint32_t *NLPsymbolicvalue, bool *flag, std::stringstream *ss);
    void onPeripheralWrite(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                           uint32_t writeconcretevalue);
};

}
} // namespace s2e::plugins

#endif // S2E_PLUGINS_ExternalHardwareSignal_H
