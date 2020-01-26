/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef Z3BUILDER_H_
#define Z3BUILDER_H_

#include "klee/Expr.h"
#include "klee/util/ExprHashMap.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/ImmutableMap.h"

#include <z3++.h>

#include <list>
#include <map>
#include <stack>

#include <boost/shared_ptr.hpp>

namespace llvm {

template <> struct ImutProfileInfo<z3::expr> {
    typedef const z3::expr value_type;
    typedef const z3::expr &value_type_ref;

    static inline void Profile(FoldingSetNodeID &ID, value_type_ref X) {
        ID.AddInteger(X);
    }
};

template <typename T> struct ImutProfileInfo<klee::ref<T>> {
    typedef const klee::ref<T> value_type;
    typedef const klee::ref<T> &value_type_ref;

    static inline void Profile(FoldingSetNodeID &ID, value_type_ref X) {
        ID.AddPointer(X.get());
    }
};

template <> struct ImutProfileInfo<klee::ArrayPtr> {
    typedef const klee::ArrayPtr value_type;
    typedef const klee::ArrayPtr &value_type_ref;

    static inline void Profile(FoldingSetNodeID &ID, value_type_ref X) {
        ID.AddPointer(X.get());
    }
};
} // namespace llvm

namespace klee {

class Z3BuilderCache {
public:
    virtual ~Z3BuilderCache() {
    }

    virtual bool findExpr(ref<Expr> e, z3::expr &expr) = 0;
    virtual void insertExpr(ref<Expr> e, const z3::expr &expr) = 0;

protected:
    virtual void push() = 0;
    virtual void pop(unsigned n) = 0;
    virtual void reset() = 0;

    friend class Z3Builder;
};

class Z3Builder {
public:
    Z3Builder(z3::context &context, Z3BuilderCache *cache);
    virtual ~Z3Builder();

    z3::context &context() {
        return context_;
    }

    z3::expr construct(ref<Expr> e) {
        return getOrMakeExpr(e);
    }

    virtual z3::expr getInitialRead(const ArrayPtr &root, unsigned index) = 0;

    void push() {
        cache_->push();
    }
    void pop(unsigned n) {
        cache_->pop(n);
    }
    void reset() {
        cache_->reset();
    }

protected:
    z3::expr getOrMakeExpr(ref<Expr> e);
    z3::expr makeExpr(ref<Expr> e);
    virtual z3::expr makeReadExpr(ref<ReadExpr> re) = 0;

    z3::context &context_;
    Z3BuilderCache *cache_;

private:
    Z3Builder(const Z3Builder &);
};

} /* namespace klee */

#endif /* Z3BUILDER_H_ */
