///
/// Copyright (C) 2010-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_ComplianceCheck_H
#define S2E_PLUGINS_ComplianceCheck_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/SEmu/NLPPeripheralModel.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/SymbolicHardwareHook.h>

namespace s2e {

namespace plugins {

typedef struct access {
    std::string type; // R: receive; T: transmit; O: other
    uint32_t time;
    int32_t irq;
    uint32_t phaddr;
    uint32_t cur_value;
    uint32_t pc;
    access(std::string a, uint32_t b, int32_t c, uint32_t d, uint32_t e, uint32_t f)
        : type(a), time(b), irq(c), phaddr(d), cur_value(e), pc(f) {
    }
} Access;

typedef std::vector<std::vector<FieldList>> Type1Rules;
typedef std::map<uint32_t, std::vector<Access>> AccessRecords;
typedef std::map<int32_t, std::vector<uint32_t>> AccessPair;
typedef std::vector<std::vector<uint32_t>> Race;

class ComplianceCheck : public Plugin {
    S2E_PLUGIN
public:
    ComplianceCheck(S2E *s2e) : Plugin(s2e) {
    }

private:
    NLPPeripheralModel *onNLPPeripheralModelConnection;

    Type1Rules sequences;
    IRQRules interrupt_conditions;
    AccessRecords recording_write;
    AccessRecords recording_read;
    AccessRecords recording_check;
    Race races;

    uint32_t cur_time = 0;
    uint32_t fork_point;
    std::string CCfileName;
    void initialize();
    void onComplianceCheck();
    void type1Check(Race &races);
    bool checkField(Field &field, uint32_t cur_value);
    void getExsitence(std::vector<Access> &access, Field &rule, AccessPair &pair);
    void checkAtomic(std::vector<AccessPair> &existence_seq, Race &races);

    bool readCCModelfromFile(std::string &fileName);
    bool getSequences(std::string &peripheralcache);
    void ReadField(std::string &v, Field &field);
    std::vector<long> getBits(std::string &bits);
    void SplitString(const std::string &s, std::vector<std::string> &v, const std::string &c);
    void SplitStringToInt(const std::string &s, std::vector<long> &v, const std::string &c, int dtype);

    void onPeripheralRead(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val);
    void onPeripheralWrite(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val);
    void onHardwareWrite(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val);
    void onPeripheralCondition(S2EExecutionState *state, uint32_t phaddr, uint32_t cur_val);
    void onTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc,
                             bool staticTarget, uint64_t staticTargetPc);
    void onForkPoints(S2EExecutionState *state, uint64_t pc, unsigned source_type);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_ComplianceCheck_H
