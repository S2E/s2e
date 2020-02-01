///
/// Copyright (C) 2010-2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExternalDispatcher.h>
#include <s2e/S2ETranslationBlock.h>

namespace s2e {

S2ETranslationBlock::~S2ETranslationBlock() {
    if (translationBlock) {
        auto executor = g_s2e->getExecutor();

        auto kmodule = executor->getModule();

        // We may have generated LLVM code that was never executed
        if (kmodule->functionMap.find(translationBlock) != kmodule->functionMap.end()) {
            kmodule->removeFunction(translationBlock);
        } else {
            translationBlock->eraseFromParent();
        }
    }

    for (auto it : executionSignals) {
        delete it;
    }
}
} // namespace s2e
