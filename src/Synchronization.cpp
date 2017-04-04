///
/// Copyright (C) 2011-2016, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <cassert>

#include <fcntl.h>
#include <iostream>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
#include <semaphore.h>

#include <s2e/S2E.h>
#include <s2e/Synchronization.h>
#include <s2e/cpu.h>

namespace s2e {

struct SyncHeader {
    unsigned lock;
    unsigned inited;
};

#define SYNCHEADER_FREE 1
#define SYNCHEADER_LOCKED 0

/// \brief Create synchronized object
///
/// \param size shared memory size
/// \param name shared memory name
///
S2ESynchronizedObjectInternal::S2ESynchronizedObjectInternal(unsigned size, const char *name) {
    m_fd = -1;
    m_size = size;
    m_headerSize = sizeof(SyncHeader);

    unsigned totalSize = m_headerSize + size;

    if (name) {
        m_fd = shm_open(name, O_CREAT | O_RDWR, 0600);
        if (m_fd < 0) {
            fprintf(stderr, "Could not open shared memory %s (%d, %s)", name, errno, strerror(errno));
            exit(-1);
        }
    }

    int flags = MAP_SHARED;
    if (m_fd == -1) {
        flags |= MAP_ANON;
    } else {
        if (ftruncate(m_fd, totalSize) < 0) {
            fprintf(stderr, "Could not resize shared memory (%d, %s)", errno, strerror(errno));
            exit(-1);
        }
    }

    m_sharedBuffer = (uint8_t *) mmap(NULL, totalSize, PROT_READ | PROT_WRITE, flags, m_fd, 0);
    if (m_sharedBuffer == MAP_FAILED) {
        fprintf(stderr, "Could not allocate shared memory (%d, %s)", errno, strerror(errno));
        exit(-1);
    }

    SyncHeader *hdr = static_cast<SyncHeader *>((void *) m_sharedBuffer);

    if (!hdr->inited) {
        hdr->lock = SYNCHEADER_FREE;
        hdr->inited = 1;
    }
}

S2ESynchronizedObjectInternal::~S2ESynchronizedObjectInternal() {
    unsigned totalSize = m_headerSize + m_size;
    munmap(m_sharedBuffer, totalSize);
}

/// \brief Try to acquire synchronization lock
///
/// \returns pointer to shared memory if lock was acquired, otherwise NULL
///
void *S2ESynchronizedObjectInternal::tryAcquire() {
    SyncHeader *hdr = (SyncHeader *) m_sharedBuffer;

    unsigned expected = SYNCHEADER_FREE; // this variable will contain actual value after call
    if (!__atomic_compare_exchange_n(&hdr->lock, &expected, SYNCHEADER_LOCKED, false, __ATOMIC_SEQ_CST,
                                     __ATOMIC_SEQ_CST)) {
        return NULL;
    }

    return ((uint8_t *) m_sharedBuffer + m_headerSize);
}

/// \brief Acquire synchronization lock
///
/// Call \ref tryAquire until it succeeds
///
/// \returns pointer to shared memory
///
void *S2ESynchronizedObjectInternal::acquire() {
    while (true) {
        void *ret = tryAcquire();
        if (ret != NULL) {
            return ret;
        }
    }
}

/// \brief Release previously acquired lock
void S2ESynchronizedObjectInternal::release() {
    SyncHeader *hdr = (SyncHeader *) m_sharedBuffer;

    assert(__atomic_load_n(&hdr->lock, __ATOMIC_SEQ_CST) == SYNCHEADER_LOCKED && "Lock was not acquired");
    __atomic_store_n(&hdr->lock, SYNCHEADER_FREE, __ATOMIC_SEQ_CST);
}
}
