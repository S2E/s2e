//===-- IncompleteSolver.cpp ----------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/IncompleteSolver.h"
#include <klee/Common.h>

#include "klee/Constraints.h"

using namespace klee;
using namespace llvm;

/***/

IncompleteSolver::PartialValidity IncompleteSolver::negatePartialValidity(PartialValidity pv) {
    switch (pv) {
        default:
            pabort("invalid partial validity");
        case MustBeTrue:
            return MustBeFalse;
        case MustBeFalse:
            return MustBeTrue;
        case MayBeTrue:
            return MayBeFalse;
        case MayBeFalse:
            return MayBeTrue;
        case TrueOrFalse:
            return TrueOrFalse;
    }
}

IncompleteSolver::PartialValidity IncompleteSolver::computeValidity(const Query &query) {
    PartialValidity trueResult = computeTruth(query);

    if (trueResult == MustBeTrue) {
        return MustBeTrue;
    } else {
        PartialValidity falseResult = computeTruth(query.negateExpr());

        if (falseResult == MustBeTrue) {
            return MustBeFalse;
        } else {
            bool trueCorrect = trueResult != None, falseCorrect = falseResult != None;

            if (trueCorrect && falseCorrect) {
                return TrueOrFalse;
            } else if (trueCorrect) { // ==> trueResult == MayBeFalse
                return MayBeFalse;
            } else if (falseCorrect) { // ==> falseResult == MayBeFalse
                return MayBeTrue;
            } else {
                return None;
            }
        }
    }
}

/***/

StagedSolverImpl::StagedSolverImpl(IncompleteSolverPtr _primary, SolverPtr _secondary)
    : primary(_primary), secondary(_secondary) {
}

StagedSolverImpl::~StagedSolverImpl() {
}

bool StagedSolverImpl::computeTruth(const Query &query, bool &isValid) {
    IncompleteSolver::PartialValidity trueResult = primary->computeTruth(query);

    if (trueResult != IncompleteSolver::None) {
        isValid = (trueResult == IncompleteSolver::MustBeTrue);
        return true;
    }

    return secondary->impl->computeTruth(query, isValid);
}

bool StagedSolverImpl::computeValidity(const Query &query, Validity &result) {
    bool tmp;

    switch (primary->computeValidity(query)) {
        case IncompleteSolver::MustBeTrue:
            result = Validity::True;
            break;
        case IncompleteSolver::MustBeFalse:
            result = Validity::False;
            break;
        case IncompleteSolver::TrueOrFalse:
            result = Validity::Unknown;
            break;
        case IncompleteSolver::MayBeTrue:
            if (!secondary->impl->computeTruth(query, tmp))
                return false;
            result = tmp ? Validity::True : Validity::Unknown;
            break;
        case IncompleteSolver::MayBeFalse:
            if (!secondary->impl->computeTruth(query.negateExpr(), tmp))
                return false;
            result = tmp ? Validity::False : Validity::Unknown;
            break;
        default:
            if (!secondary->impl->computeValidity(query, result))
                return false;
            break;
    }

    return true;
}

bool StagedSolverImpl::computeValue(const Query &query, ref<Expr> &result) {
    if (primary->computeValue(query, result))
        return true;

    return secondary->impl->computeValue(query, result);
}

bool StagedSolverImpl::computeInitialValues(const Query &query, const ArrayVec &objects,
                                            std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    if (primary->computeInitialValues(query, objects, values, hasSolution))
        return true;

    return secondary->impl->computeInitialValues(query, objects, values, hasSolution);
}
