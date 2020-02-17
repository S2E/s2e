///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
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

#ifndef S2E_TB_H

#define S2E_TB_H

#include <boost/intrusive_ptr.hpp>
#include <llvm/ADT/SmallVector.h>
#include <llvm/IR/Function.h>
#include <s2e/CorePlugin.h>

namespace s2e {

struct S2ETranslationBlock {
    /// Reference counter. S2ETranslationBlock should not be freed
    /// until all LLVM functions are completely executed. This reference
    /// counter controls it.
    unsigned refCount;

    llvm::Function *translationBlock;

    // A list of all instruction execution signals associated with
    // this translation block. The LLVM function has hard-coded pointers
    // to this vector.
    llvm::SmallVector<ExecutionSignal *, 16> executionSignals;

    S2ETranslationBlock() {
        translationBlock = nullptr;
        refCount = 0;
        executionSignals.push_back(new ExecutionSignal);
    }

    ~S2ETranslationBlock();
};

inline void intrusive_ptr_add_ref(S2ETranslationBlock *ptr) {
    ++ptr->refCount;
}

inline void intrusive_ptr_release(S2ETranslationBlock *ptr) {
    if (--ptr->refCount == 0) {
        delete ptr;
    }
}

typedef boost::intrusive_ptr<S2ETranslationBlock> S2ETranslationBlockPtr;

struct S2ETranslationBlockHash {
    size_t operator()(const S2ETranslationBlockPtr &x) const {
        return (size_t) x.get();
    }
};

struct S2ETranslationBlockEqual {
    bool operator()(const S2ETranslationBlockPtr &x, const S2ETranslationBlockPtr &y) const {
        return x == y;
    }
};
} // namespace s2e

#endif
