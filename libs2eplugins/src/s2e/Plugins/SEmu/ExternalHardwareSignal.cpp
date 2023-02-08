//
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include "ExternalHardwareSignal.h"
#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/SymbolicHardwareHook.h>
#include <s2e/Utils.h>
#include <s2e/cpu.h>
#include <sys/shm.h>
#include <algorithm>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ExternalHardwareSignal, "External Hardware Signal", "ExternalHardwareSignal");

void ExternalHardwareSignal::initialize() {
    SignalfileName = s2e()->getConfig()->getString(getConfigKey() + ".SignalfileName", "all.txt");
    if (!readSignalfromFile(SignalfileName)) {
        getWarningsStream() << "Could not open cache Signal file: " << SignalfileName << "\n";
        exit(-1);
    } else {
        getDebugStream() << "Signal peripheral model file name is " << SignalfileName << "\n";
    }
    hw::SymbolicHardware *symbolicPeripheralConnection = s2e()->getPlugin<hw::SymbolicHardware>();
    symbolicPeripheralConnection->onSymbolicRegisterReadEvent.connect(
        sigc::mem_fun(*this, &ExternalHardwareSignal::onPeripheralRead));
    symbolicPeripheralConnection->onSymbolicRegisterWriteEvent.connect(
        sigc::mem_fun(*this, &ExternalHardwareSignal::onPeripheralWrite));
}

bool ExternalHardwareSignal::readSignalfromFile(std::string &fileName) {
    std::ifstream fNLP;
    std::string line;
    fNLP.open(fileName, std::ios::in);
    if (!fNLP) {
        return false;
    }

    std::string peripheralcache;
    while (getline(fNLP, peripheralcache)) {
        if (peripheralcache == "==")
            break;
        if (!getSignals(peripheralcache))
            return false;
    }

    return true;
}

void ExternalHardwareSignal::recordRule(Signal &signal, FieldList &fieldlist) {
    for (auto &c : fieldlist) {
        interrupt_conditions[c.phaddr][signal.irq].push_back(signal);
    }
}

bool ExternalHardwareSignal::getSignals(std::string &peripheralcache) {
    getDebugStream() << peripheralcache << "\n";
    std::vector<std::string> v;
    SplitString(peripheralcache, v, "->");
    std::vector<std::string> tmp;
    SplitString(v[1], tmp, "IRQ");
    int32_t interrupt = -1;
    bool is_irq = true;
    if (tmp.size() == 1) {
        is_irq = false;
        tmp.clear();
        SplitString(v[1], tmp, "DMA");
    }
    if (tmp.size() == 2) {
        interrupt = std::stoi(tmp[1].substr(1, tmp[1].size() - 1).c_str(), NULL, 10);
    }
    Signal signal;
    extractSignal(v[0], interrupt, v[2], signal);
    recordRule(signal, signal.control);
    recordRule(signal, signal.dma);
    recordRule(signal, signal.other);
    for (auto &c : signal.key) {
        if (c.type.find_first_of("TR") != std::string::npos)
            interrupt_conditions[c.phaddr][signal.irq].push_back(signal);
    }
    return true;
}

void ExternalHardwareSignal::ReadField(std::string &expressions, Field &field) {
    std::vector<std::string> v;
    SplitString(expressions, v, ",");
    field.type = v[0];
    field.phaddr = std::stoull(v[1].c_str(), NULL, 16);
    field.bits = getBits(v[2]);

    if (v.size() == 5 && v[4] != "*") {
        field.value = std::stoull(v[4].c_str(), NULL, 2);
    }
}

std::vector<long> ExternalHardwareSignal::getBits(std::string &bits) {
    std::vector<long> res;
    if (bits == "*")
        return {-1};
    else {
        SplitStringToInt(bits, res, "/", 10);
        return res;
    }
}

void ExternalHardwareSignal::SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(std::strtol(s.substr(pos1, pos2 - pos1).c_str(), NULL, dtype));
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length()) {
        v.push_back(std::strtol(s.substr(pos1).c_str(), NULL, dtype));
    }
}

void ExternalHardwareSignal::extractSignal(std::string &expressions, int32_t interrupt, std::string &status, Signal &signal) {
    signal.irq = interrupt;
    std::vector<std::string> v;
    SplitString(status, v, "&");
    for (auto &rule : v) {
        Field field;
        ReadField(rule, field);
        signal.key.push_back(field);
    }
    v.clear();
    SplitString(expressions, v, "&");
    for (auto &rule : v) {
        Field field;
        ReadField(rule, field);
        if (field.type == "C")
            signal.control.push_back(field);
        else if (field.type == "S")
            signal.status.push_back(field);
        else if (field.type == "D")
            signal.dma.push_back(field);
        else if (field.type == "O")
            signal.other.push_back(field);
    }
}

void ExternalHardwareSignal::SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c) {
    std::string::size_type pos1, pos2;
    pos2 = s.find(c);
    pos1 = 0;
    while (std::string::npos != pos2) {
        v.push_back(s.substr(pos1, pos2 - pos1));
        pos1 = pos2 + c.size();
        pos2 = s.find(c, pos1);
    }
    if (pos1 != s.length())
        v.push_back(s.substr(pos1));
}

void ExternalHardwareSignal::triggerIRQ(S2EExecutionState *state, uint32_t phaddr) {
    onSignalUpdate.emit(state, interrupt_conditions[phaddr]);
}

void ExternalHardwareSignal::onPeripheralRead(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                                              unsigned size, uint32_t *NLPSymbolicValue, bool *createSymFlag,
                                              std::stringstream *ss) {
    getDebugStream() << "ExternalHardwareSignal READ\n";
    onReadUpdate.emit(state, type, phaddr, size, NLPSymbolicValue, createSymFlag, ss);
    triggerIRQ(state, phaddr);
}

void ExternalHardwareSignal::onPeripheralWrite(S2EExecutionState *state, SymbolicHardwareAccessType type, uint32_t phaddr,
                                               uint32_t writeconcretevalue) {
    getDebugStream() << "ExternalHardwareSignal WRITE\n";
    onWriteUpdate.emit(state, type, phaddr, writeconcretevalue);
    triggerIRQ(state, phaddr);
}
}
} // namespace s2e::plugins
