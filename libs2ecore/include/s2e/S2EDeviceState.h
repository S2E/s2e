///
/// Copyright (C) 2010-2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef _S2E_DEVICE_STATE_H_

#define _S2E_DEVICE_STATE_H_

#include <llvm/ADT/SmallVector.h>
#include <map>
#include <set>
#include <stdint.h>
#include <vector>

#include <klee/AddressSpace.h>

#include "s2e_block.h"

namespace s2e {

class S2EExecutionState;

class S2EDeviceState {
private:
    static const unsigned SECTOR_SIZE;

    /* Give 64GB of KLEE address space for each block device */
    static const uint64_t BLOCK_DEV_AS;

    static std::vector<void *> s_devices;
    static std::set<std::string> s_customDevices;
    static bool s_devicesInited;

    uint8_t *m_stateBuffer;
    unsigned m_stateBufferSize;

    static llvm::SmallVector<struct S2EBlockDevice *, 5> s_blockDevices;
    klee::AddressSpace m_deviceState;

    void allocateBuffer(unsigned int Sz);

    static unsigned getBlockDeviceId(struct S2EBlockDevice *dev);
    static uint64_t getBlockDeviceStart(struct S2EBlockDevice *dev);

public:
    S2EDeviceState(klee::ExecutionState *state);
    S2EDeviceState(const S2EDeviceState &state);
    ~S2EDeviceState();

    void setExecutionState(klee::ExecutionState *state) {
        m_deviceState.state = state;
    }

    void initDeviceState();

    int putBuffer(const uint8_t *buf, int64_t pos, int size);
    int getBuffer(uint8_t *buf, int64_t pos, int size);

    int writeSector(struct S2EBlockDevice *bs, int64_t sector, const uint8_t *buf, int nb_sectors);
    int readSector(struct S2EBlockDevice *bs, int64_t sector, uint8_t *buf, int nb_sectors);
};
}

#endif
