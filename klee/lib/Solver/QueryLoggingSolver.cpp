//===-- QueryLoggingSolver.cpp --------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "QueryLoggingSolver.h"
#include "klee/Config/config.h"
#include "klee/Internal/System/Time.h"
#include "klee/Statistics.h"
#ifdef HAVE_ZLIB_H
#include "klee/Internal/Support/CompressionStream.h"
#include "klee/Internal/Support/ErrorHandling.h"
#endif

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"

using namespace klee::util;

namespace {
llvm::cl::opt<bool> DumpPartialQueryiesEarly("log-partial-queries-early", llvm::cl::init(false),
                                             llvm::cl::desc("Log queries before calling the solver (default=off)"));

#ifdef HAVE_ZLIB_H
llvm::cl::opt<bool> CreateCompressedQueryLog("compress-query-log", llvm::cl::init(false),
                                             llvm::cl::desc("Compress query log files (default=off)"));
#endif
} // namespace

QueryLoggingSolver::QueryLoggingSolver(Solver *_solver, std::string path, const std::string &commentSign,
                                       int queryTimeToLog)
    : solver(_solver), os(0), BufferString(""), logBuffer(BufferString), queryCount(0),
      minQueryTimeToLog(queryTimeToLog), startTime(0.0f), lastQueryTime(0.0f), queryCommentSign(commentSign) {
#ifdef HAVE_ZLIB_H
    if (!CreateCompressedQueryLog) {
#endif
        std::error_code ec;
        os = new llvm::raw_fd_ostream(path.c_str(), ec, llvm::sys::fs::OpenFlags::F_Text);
        if (ec)
            ErrorInfo = ec.message();
#ifdef HAVE_ZLIB_H
    } else {
        os = new compressed_fd_ostream((path + ".gz").c_str(), ErrorInfo);
    }
    if (ErrorInfo != "") {
        klee_error("Could not open file %s : %s", path.c_str(), ErrorInfo.c_str());
    }
#endif
    assert(0 != solver);
}

QueryLoggingSolver::~QueryLoggingSolver() {
    delete solver;
    delete os;
}

void QueryLoggingSolver::flushBufferConditionally(bool writeToFile) {
    logBuffer.flush();
    if (writeToFile) {
        *os << logBuffer.str();
        os->flush();
    }
    // prepare the buffer for reuse
    BufferString = "";
}

void QueryLoggingSolver::startQuery(const Query &query, const char *typeName, const Query *falseQuery,
                                    const ArrayVec &objects) {
    Statistic *S = theStatisticManager->getStatisticByName("Instructions");
    uint64_t instructions = S ? S->getValue() : 0;

    logBuffer << queryCommentSign << " Query " << queryCount++ << " -- "
              << "Type: " << typeName << ", "
              << "Instructions: " << instructions << "\n";

    printQuery(query, falseQuery, objects);

    if (DumpPartialQueryiesEarly) {
        flushBufferConditionally(true);
    }
    startTime = getWallTime();
}

void QueryLoggingSolver::finishQuery(bool success) {
    lastQueryTime = getWallTime() - startTime;
    logBuffer << queryCommentSign << "   " << (success ? "OK" : "FAIL") << " -- "
              << "Elapsed: " << lastQueryTime << "\n";
}

void QueryLoggingSolver::flushBuffer() {
    bool writeToFile = false;

    if ((0 == minQueryTimeToLog) || (static_cast<int>(lastQueryTime * 1000) > minQueryTimeToLog)) {
        // we either do not limit logging queries or the query time
        // is larger than threshold (in ms)

        if (minQueryTimeToLog >= 0) {
            // we do additional check here to log only timeouts in case
            // user specified negative value for minQueryTimeToLog param
            writeToFile = true;
        }
    }

    flushBufferConditionally(writeToFile);
}

bool QueryLoggingSolver::computeTruth(const Query &query, bool &isValid) {
    startQuery(query, "Truth");

    bool success = solver->impl->computeTruth(query, isValid);

    finishQuery(success);

    if (success) {
        logBuffer << queryCommentSign << "   Is Valid: " << (isValid ? "true" : "false") << "\n";
    }
    logBuffer << "\n";

    flushBuffer();

    return success;
}

bool QueryLoggingSolver::computeValidity(const Query &query, Solver::Validity &result) {
    startQuery(query, "Validity");

    bool success = solver->impl->computeValidity(query, result);

    finishQuery(success);

    if (success) {
        logBuffer << queryCommentSign << "   Validity: " << result << "\n";
    }
    logBuffer << "\n";

    flushBuffer();

    return success;
}

bool QueryLoggingSolver::computeValue(const Query &query, ref<Expr> &result) {
    Query withFalse = query.withFalse();
    startQuery(query, "Value", &withFalse);

    bool success = solver->impl->computeValue(query, result);

    finishQuery(success);

    if (success) {
        logBuffer << queryCommentSign << "   Result: " << result << "\n";
    }
    logBuffer << "\n";

    flushBuffer();

    return success;
}

bool QueryLoggingSolver::computeInitialValues(const Query &query, const ArrayVec &objects,
                                              std::vector<std::vector<unsigned char>> &values, bool &hasSolution) {
    startQuery(query, "InitialValues", 0, objects);

    bool success = solver->impl->computeInitialValues(query, objects, values, hasSolution);

    finishQuery(success);

    if (success) {
        logBuffer << queryCommentSign << "   Solvable: " << (hasSolution ? "true" : "false") << "\n";
        if (hasSolution) {
            std::vector<std::vector<unsigned char>>::iterator values_it = values.begin();

            for (auto i = objects.begin(), e = objects.end(); i != e; ++i, ++values_it) {
                auto &array = *i;
                std::vector<unsigned char> &data = *values_it;
                logBuffer << queryCommentSign << "     " << array->getName() << " = [";

                for (unsigned j = 0; j < array->getSize(); j++) {
                    logBuffer << (int) data[j];

                    if (j + 1 < array->getSize()) {
                        logBuffer << ",";
                    }
                }
                logBuffer << "]\n";
            }
        }
    }
    logBuffer << "\n";

    flushBuffer();

    return success;
}
