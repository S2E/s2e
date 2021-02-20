//===-- KInstIterator.h -----------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_KINSTITERATOR_H
#define KLEE_KINSTITERATOR_H

#include <vector>

namespace klee {
struct KInstruction;

class KInstIterator {
    KInstruction **it;

public:
    KInstIterator() : it(0) {
    }
    KInstIterator(KInstruction **_it) : it(_it) {
    }
    KInstIterator(const KInstIterator &b) : it(b.it) {
    }
    KInstIterator(std::vector<KInstruction *> &b) : it(&b[0]) {
    }
    ~KInstIterator() {
    }

    KInstIterator &operator=(const KInstIterator &b) {
        it = b.it;
        return *this;
    }

    bool operator==(const KInstIterator &b) const {
        return it == b.it;
    }
    bool operator!=(const KInstIterator &b) const {
        return !(*this == b);
    }

    KInstIterator &operator++() {
        ++it;
        return *this;
    }

    operator KInstruction *() const {
        return it ? *it : 0;
    }
    operator bool() const {
        return it != 0;
    }

    KInstruction *operator->() const {
        return *it;
    }
};
} // namespace klee

#endif
