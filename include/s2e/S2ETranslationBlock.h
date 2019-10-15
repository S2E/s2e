///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_TB_H

#define S2E_TB_H

#include <boost/intrusive_ptr.hpp>
#include <llvm/IR/Function.h>
#include <s2e/CorePlugin.h>
#include <vector>

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
    std::vector<ExecutionSignal *> executionSignals;

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
}

#endif
