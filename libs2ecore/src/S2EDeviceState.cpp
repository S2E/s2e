///
/// Copyright (C) 2010-2015, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2015-2016, Cyberhaven
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

#include <s2e/cpu.h>

#include <s2e/s2e_block.h>

#include <iostream>
#include <llvm/Support/CommandLine.h>
#include <s2e/S2E.h>
#include <s2e/S2EDeviceState.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Utils.h>
#include <s2e/s2e_libcpu.h>
#include <sstream>

namespace {
// Force writes to disk to be persistent (and disable copy on write)
llvm::cl::opt<bool> PersistentDiskWrites("s2e-persistent-disk-writes", llvm::cl::init(false));
// Share device state between states
llvm::cl::opt<std::string> SharedDevices("s2e-shared-devices",
                                         llvm::cl::desc("Comma-separated list of devices to be shared between states."),
                                         llvm::cl::init(""));
} // namespace

using namespace s2e;
using namespace std;
using namespace klee;

const unsigned S2EDeviceState::SECTOR_SIZE = 512;
const uint64_t S2EDeviceState::BLOCK_DEV_AS = (1024UL * 1024UL * 1024UL) * 64UL;

std::vector<void *> S2EDeviceState::s_devices;
llvm::SmallVector<struct S2EBlockDevice *, 5> S2EDeviceState::s_blockDevices;

bool S2EDeviceState::s_devicesInited = false;

extern "C" {

void s2e_init_device_state(void) {
    g_s2e_state->getDeviceState()->initDeviceState();
}

} // extern C

S2EDeviceState::S2EDeviceState(const S2EDeviceState &state) : m_deviceState(state.m_deviceState) {
    if (state.m_stateBuffer) {
        m_stateBuffer = (uint8_t *) malloc(state.m_stateBufferSize);
        m_stateBufferSize = state.m_stateBufferSize;
        memcpy(m_stateBuffer, state.m_stateBuffer, m_stateBufferSize);
    } else {
        m_stateBuffer = nullptr;
        m_stateBufferSize = 0;
    }
}

S2EDeviceState::S2EDeviceState(klee::ExecutionState *state) : m_deviceState(state) {
    m_stateBuffer = nullptr;
    m_stateBufferSize = 0;
}

S2EDeviceState::~S2EDeviceState() {
    if (m_stateBuffer) {
        free(m_stateBuffer);
    }
}

void S2EDeviceState::initDeviceState() {
    m_stateBuffer = nullptr;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

void S2EDeviceState::allocateBuffer(unsigned int size) {
    if (size < m_stateBufferSize) {
        return;
    }

    /* Need to expand the buffer */
    uint8_t *new_buffer = (uint8_t *) realloc(m_stateBuffer, size);
    if (!new_buffer) {
        cerr << "Cannot reallocate memory for device state snapshot" << endl;
        exit(-1);
    }
    m_stateBuffer = new_buffer;
    m_stateBufferSize = size;
}

int S2EDeviceState::putBuffer(const uint8_t *buf, int64_t pos, int size) {
    uint8_t *dest;

    allocateBuffer(pos + size);
    dest = &m_stateBuffer[pos];

    memcpy(dest, buf, size);
    return size;
}

int S2EDeviceState::getBuffer(uint8_t *buf, int64_t pos, int size) {
    assert(m_stateBuffer);
    int toCopy = pos + size <= m_stateBufferSize ? size : m_stateBufferSize - pos;

    memcpy(buf, &m_stateBuffer[pos], toCopy);
    return toCopy;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

unsigned S2EDeviceState::getBlockDeviceId(struct S2EBlockDevice *dev) {
    unsigned i = 0;
    foreach2 (it, s_blockDevices.begin(), s_blockDevices.end()) {
        if ((*it) == dev) {
            return i;
        }
        ++i;
    }
    s_blockDevices.push_back(dev);
    return i;
}

uint64_t S2EDeviceState::getBlockDeviceStart(struct S2EBlockDevice *dev) {
    unsigned id = getBlockDeviceId(dev);
    return id * BLOCK_DEV_AS;
}

/* Return 0 upon success */
int S2EDeviceState::writeSector(struct S2EBlockDevice *bs, int64_t sector, const uint8_t *buf, int nb_sectors) {
    uint64_t bstart = getBlockDeviceStart(bs);

    while (nb_sectors > 0) {
        uintptr_t address = (uintptr_t) bstart + sector * SECTOR_SIZE;
        auto os = m_deviceState.findObject(address);
        if (!os) {
            auto mo = ObjectState::allocate(address, SECTOR_SIZE, true);
            m_deviceState.bindObject(mo);
            os = mo;
        }

        auto osw = m_deviceState.getWriteable(os);
        memcpy(osw->getConcreteBuffer(false), buf, SECTOR_SIZE);
        buf += SECTOR_SIZE;
        --nb_sectors;
        ++sector;
    }

    return 0;
}

/* Return the number of sectors that could be read from the local store */
int S2EDeviceState::readSector(struct S2EBlockDevice *bs, int64_t sector, uint8_t *buf, int nb_sectors) {
    int readCount = 0;

    uint64_t bstart = getBlockDeviceStart(bs);

    while (nb_sectors > 0) {
        uintptr_t address = (uintptr_t) bstart + sector * SECTOR_SIZE;
        auto os = m_deviceState.findObject(address);
        if (!os) {
            return readCount;
        }

        memcpy(buf, os->getConcreteBuffer(false), SECTOR_SIZE);
        buf += SECTOR_SIZE;
        ++readCount;
        --nb_sectors;
        ++sector;
    }

    return readCount;
}

/*****************************************************************************/
/*****************************************************************************/
/*****************************************************************************/

/**
 *  Functions facing KVM. They simply forward the call to the right
 *  device state.
 */

extern "C" {

int s2e_bdrv_read(struct S2EBlockDevice *bs, int64_t sector_num, uint8_t *buf, int nb_sectors) {
    S2EDeviceState *devState = g_s2e_state->getDeviceState();
    return devState->readSector(bs, sector_num, buf, nb_sectors);
}

int s2e_bdrv_write(S2EBlockDevice *bs, int64_t sector_num, const uint8_t *buf, int nb_sectors) {
    S2EDeviceState *devState = g_s2e_state->getDeviceState();

    return devState->writeSector(bs, sector_num, buf, nb_sectors);
}

void s2e_bdrv_fail(void) {
    fprintf(stderr, "\n\033[31m========================================================================\n"
                    "You are using a disk image format not compatible with symbolic execution\n"
                    "(qcow2, etc.).\n\n"
                    "Please use the S2E image format for your VM when running in S2E mode.\n"
                    "The S2E format is identical to the RAW format, except that the filename\n"
                    "of the image ends with the .s2e extension and snapshots are saved in a\n"
                    "separate file, in the same folder as the base image.\n"
                    "The S2E image and snapshots are always read-only, multiple S2E instances\n"
                    "can use them at the same time.\n\n"
                    "Refer to the S2E documentation for more details.\n"
                    "========================================================================\033[0m\n");
    exit(-1);
}

int s2e_dev_save(const void *buffer, size_t size) {
    S2EDeviceState *devState = g_s2e_state->getDeviceState();
    return devState->putBuffer((const uint8_t *) buffer, 0, size);
}

int s2e_dev_restore(void *buffer, int pos, size_t size) {
    S2EDeviceState *devState = g_s2e_state->getDeviceState();
    return devState->getBuffer((uint8_t *) buffer, pos, size);
}
}
