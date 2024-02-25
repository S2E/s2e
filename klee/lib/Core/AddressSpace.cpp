//===-- AddressSpace.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/AddressSpace.h"
#include "klee/ExecutionState.h"
#include "klee/Memory.h"

namespace klee {

void AddressSpace::bindObject(const ObjectStatePtr &os) {
    assert(os->getAddress() && os->getSize());

    auto oldOS = findObject(os->getAddress());

    if (oldOS) {
        addressSpaceChange(oldOS->getKey(), oldOS, nullptr);
    }

    addressSpaceChange(os->getKey(), nullptr, os);

    assert(os->getOwnerId() == 0 && "object already has owner");

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();
    os->setOwnerId(cowKey);
    objects = objects.replace(std::make_pair(key, os));
    m_cache.add(os);
}

void AddressSpace::unbindObject(const ObjectKey &key) {
    assert(key.address && key.size);
    auto os = findObject(key.address);
    assert(os.get()->getSize() == key.size);

    if (os) {
        addressSpaceChange(os->getKey(), os, nullptr);
    }

    objects = objects.remove(key);
    m_cache.invalidate(os->getAddress());
}

const ObjectStateConstPtr AddressSpace::findObject(uint64_t address) const {
    auto ret = m_cache.get(address);
    if (ret) {
        return ret;
    }

    ObjectKey key;
    key.address = address;
    key.size = 1;
    auto res = objects.lookup(key);
    ret = res ? res->second : 0;
    if (ret) {
        m_cache.add(ret);
    }
    return ret;
}

bool AddressSpace::findObject(uint64_t address, unsigned size, ObjectStateConstPtr &result, bool &inBounds) {
    auto res = findObject(address);
    if (!res) {
        return false;
    }

    assert(res->getAddress() <= address && res->getSize());

    result = res;

    inBounds = address + size <= res->getAddress() + res->getSize();
    return true;
}

ObjectStatePtr AddressSpace::getWriteableInternal(const ObjectStateConstPtr &os) {
    auto n = os->copy();
    n->setOwnerId(cowKey);

    // Clients must take into account the change
    // of location of the concrete buffer.
    assert(n->getKey() == os->getKey());
    addressSpaceChange(n->getKey(), os, n);

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();

    objects = objects.replace(std::make_pair(key, n));
    m_cache.add(n);
    return n;
}

void AddressSpace::updateWritable(const ObjectStateConstPtr &os, const ObjectStatePtr &wos) {
    wos->setOwnerId(cowKey);

    // XXX: should this come at the end?
    addressSpaceChange(os->getKey(), os, wos);

    ObjectKey key;
    key.address = os->getAddress();
    key.size = os->getSize();
    objects = objects.replace(std::make_pair(key, wos));
    m_cache.add(wos);
}

void AddressSpace::addressSpaceChange(const klee::ObjectKey &key, const ObjectStateConstPtr &oldState,
                                      const ObjectStatePtr &newState) {
    assert(state);
    state->addressSpaceChange(key, oldState, newState);
}

ObjectStatePtr AddressSpace::getWriteable(const ObjectStateConstPtr &os) {
    assert(!os->isReadOnly());

    if (isOwnedByUs(os)) {
        return ObjectStatePtr(const_cast<ObjectState *>(os.get()));
    }

    // Check whether we have a split object
    unsigned size = os->getBitArraySize();
    if (size == os->getSize()) {
        assert(os->getStoreOffset() == 0);
        return getWriteableInternal(os);
    }

    // Split objects are just like other objects, we may
    // need to get a private copy of them later on.
    assert(size > os->getSize());

    // Find all the pieces and make them writable
    uint64_t address = os->getAddress() - os->getStoreOffset();
    ObjectStatePtr ret = nullptr;

    std::vector<ObjectStateConstPtr> readOnlyObjects;

    do {
        auto mo = findObject(address);
        assert(!isOwnedByUs(mo));

        readOnlyObjects.push_back(mo);
        address += mo->getSize();
        size -= mo->getSize();
    } while (size > 0);

    auto concreteBuffer = ConcreteBuffer::create(os->getConcreteBufferPtr());
    auto concreteMask = BitArray::create(os->getConcreteMask());
    assert(concreteMask->getBitCount() == concreteBuffer->size());

    for (unsigned i = 0; i < readOnlyObjects.size(); ++i) {
        auto &ros = readOnlyObjects[i];
        auto wos = ros->copy(concreteMask, concreteBuffer);

        if (ros == os) {
            ret = wos;
        }

        updateWritable(ros, wos);
    }

    assert(ret);
    return ret;
}

bool AddressSpace::splitMemoryObject(IAddressSpaceNotification &state, const ObjectStateConstPtr &originalObject,
                                     ResolutionList &rl) {
    static const unsigned PAGE_SIZE = 0x1000;
    // Only split memory objects
    if (originalObject->getSize() != PAGE_SIZE || !originalObject->isSplittable()) {
        return false;
    }

    // The split must not affect any other state, therefore,
    // we need to get a private copy of the object
    auto originalWritableObject = getWriteable(originalObject);

    // When the entire object is concrete, it does not have
    // a concrete mask. For simplicity, we create one in case
    // of splitting.
    originalWritableObject->initializeConcreteMask();

    std::vector<ObjectStatePtr> objectStates;
    std::vector<unsigned> offsets;

    // XXX: for now, split into fixed-size objects
    const auto size = 128u;
    for (unsigned i = 0; i < PAGE_SIZE / size; ++i) {
        offsets.push_back(i * 128);
    }

    for (unsigned i = 0; i < offsets.size(); ++i) {
        auto offset = offsets[i];
        auto newObject = originalWritableObject->split(offset, size);
        objectStates.push_back(newObject);
        rl.push_back(newObject);
        offset += newObject->getSize();
        assert(size == newObject->getSize());
    }

    // Notify the system that the objects were split
    state.addressSpaceObjectSplit(originalObject, objectStates);

    // Once this is done, delete the old object and activate the new ones
    unbindObject(originalObject->getKey());

    for (auto it : objectStates) {
        bindObject(it);
    }

    return true;
}

bool AddressSpace::iterateRead(uintptr_t address, size_t size, IterateCb cb, AddressTranslator tr) {
    while (size > 0) {
        uint64_t hostAddress = address;
        if (tr) {
            if (!tr(address, hostAddress)) {
                return false;
            }
        }

        auto mo = findObject(hostAddress);
        if (!mo) {
            return false;
        }

        auto offset = mo->getOffset(hostAddress);
        auto objSize = mo->getSize() - offset;
        auto sizeToRead = objSize < size ? objSize : size;

        if (!cb(mo, offset, sizeToRead)) {
            return false;
        }

        size -= sizeToRead;
        address += sizeToRead;
    }

    return true;
}

bool AddressSpace::read(uintptr_t address, uint8_t *buffer, size_t size, Concretizer c, AddressTranslator tr) {
    auto cb = [&](ObjectStateConstPtr &mo, unsigned offset, unsigned sizeToRead) {
        // TODO: optimize case when the memory object is fully concrete.
        for (size_t i = 0; i < sizeToRead; ++i) {
            auto expr = mo->read8(offset + i);
            auto *ce = dyn_cast<ConstantExpr>(expr);
            if (ce) {
                buffer[i] = ce->getZExtValue();
            } else {
                if (!c) {
                    return false;
                }

                buffer[i] = c(expr, mo, offset + i);
            }
        }

        buffer += sizeToRead;
        return true;
    };

    return iterateRead(address, size, cb, tr);
}

bool AddressSpace::read(uintptr_t address, std::vector<ref<Expr>> &data, size_t size, AddressTranslator tr) {
    auto cb = [&](ObjectStateConstPtr &mo, unsigned offset, unsigned sizeToRead) {
        for (size_t i = 0; i < sizeToRead; ++i) {
            data.push_back(mo->read8(offset + i));
        }
        return true;
    };

    return iterateRead(address, size, cb, tr);
}

ref<Expr> AddressSpace::read(uintptr_t address, Expr::Width width, AddressTranslator tr) {
    ref<Expr> ret = nullptr;
    auto littleEndian = Context::get().isLittleEndian();

    if (!(width == 1 || (width & 7) == 0)) {
        return nullptr;
    }

    uint64_t size = Expr::getMinBytesForWidth(width);

    auto cb = [&](ObjectStateConstPtr &mo, unsigned offset, unsigned sizeToRead) {
        for (size_t i = 0; i < sizeToRead; ++i) {
            auto byte = mo->read8(offset + i);
            if (ret) {
                ret = littleEndian ? ConcatExpr::create(byte, ret) : ConcatExpr::create(ret, byte);
            } else {
                ret = byte;
            }
        }
        return true;
    };

    if (!iterateRead(address, size, cb, tr)) {
        return nullptr;
    }

    if (width == Expr::Bool) {
        return ExtractExpr::create(ret, 0, Expr::Bool);
    }

    return ret;
}

bool AddressSpace::iterateWrite(uintptr_t address, size_t size, IterateWriteCb cb, AddressTranslator tr) {
    while (size > 0) {
        uint64_t hostAddress = address;
        if (tr) {
            if (!tr(address, hostAddress)) {
                return false;
            }
        }

        auto mo = findObject(hostAddress);
        if (!mo) {
            return false;
        }

        if (mo->isReadOnly()) {
            return false;
        }

        auto wos = getWriteable(mo);
        if (!wos) {
            return false;
        }

        auto oldAllConcrete = wos->isAllConcrete();
        auto offset = wos->getOffset(hostAddress);
        auto objSize = wos->getSize() - offset;
        auto sizeToWrite = objSize < size ? objSize : size;

        auto ret = cb(wos, offset, sizeToWrite);

        auto newAllConcrete = wos->isAllConcrete();
        if ((oldAllConcrete != newAllConcrete) && wos->notifyOnConcretenessChange()) {
            state->addressSpaceSymbolicStatusChange(wos, newAllConcrete);
        }

        if (!ret) {
            return false;
        }

        size -= sizeToWrite;
        address += sizeToWrite;
    }

    return true;
}

// This may partially write data and fail.
bool AddressSpace::write(uintptr_t address, const uint8_t *buffer, size_t size, AddressTranslator tr) {
    auto cb = [&](ObjectStatePtr &mo, unsigned offset, unsigned sizeToWrite) {
        // TODO: use fast memcpy to optimize.
        for (size_t i = 0; i < sizeToWrite; ++i) {
            mo->write(offset + i, buffer[i]);
        }
        buffer += sizeToWrite;
        return true;
    };

    return iterateWrite(address, size, cb, tr);
}

bool AddressSpace::write(uintptr_t address, const ref<Expr> &data, Concretizer c, AddressTranslator tr) {
    auto dataSize = Expr::getMinBytesForWidth(data->getWidth());
    auto littleEndian = Context::get().isLittleEndian();

    int j = 0;

    auto cb = [&](ObjectStatePtr &mo, unsigned offset, unsigned sizeToWrite) {
        for (size_t i = 0; i < sizeToWrite; ++i) {
            unsigned idx = littleEndian ? i + j : (dataSize - i - j - 1);
            auto e = ExtractExpr::create(data, 8 * idx, Expr::Int8);
            if (mo->isSharedConcrete() && !isa<ConstantExpr>(e)) {
                if (!c) {
                    return false;
                }

                auto ce = c(e, mo, offset + i);
                mo->write(offset + i, ce);
            } else {
                mo->write(offset + i, e);
            }
        }

        j += sizeToWrite;
        return true;
    };

    auto ce = dyn_cast<ConstantExpr>(data);
    if (littleEndian && dataSize <= 8 && ce) {
        auto cste = ce->getZExtValue(64);
        return write(address, (uint8_t *) &cste, dataSize, tr);
    } else {
        return iterateWrite(address, dataSize, cb, tr);
    }
}

bool AddressSpace::symbolic(uintptr_t address, size_t size, AddressTranslator tr) {
    bool isSymbolic = false;

    auto cb = [&](ObjectStateConstPtr &mo, unsigned offset, unsigned sizeToRead) {
        if (!mo->isAllConcrete()) {
            for (size_t i = 0; i < sizeToRead; ++i) {
                if (!mo->isConcrete(offset + i, klee::Expr::Int8)) {
                    isSymbolic = true;
                    return false;
                }
            }
        }
        return true;
    };

    // TODO: check for errors somehow.
    iterateRead(address, size, cb, tr);
    return isSymbolic;
}

} // namespace klee
