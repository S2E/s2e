///
/// Copyright (C) 2012-2016, Dependable Systems Laboratory, EPFL
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

#include <inttypes.h>
#include <klee/Expr.h>
#include <llvm/ADT/SmallVector.h>
#include <s2e/ExprInterface.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>
#include <s2e/s2e_config.h>
#include <s2e/s2e_libcpu.h>

/**
 * The expression interface allows the libcpu emulation code to manipulate
 * symbolic values as simply as possible, even in concrete mode.
 * This avoids the need of invoking the LLVM interpreter for the simple
 * common case where the symbolic values only affect the data flow
 * (i.e., no need for forking).
 *
 * Eventually, we'll need an LLVM pass that automatically instruments
 * the data flow with symbolic-aware operations in order to avoid
 * the messy manual part.
 *
 * The interface encapsulates klee expressions in an opaque object
 * that the C code can pass around. ExprManager keeps track of all these
 * objects in order to avoid memory leaks.
 */

using namespace klee;

struct ExprBox {
    bool constant;
    uint64_t value;
    klee::ref<Expr> expr;

    ExprBox() {
        constant = false;
        value = 0;
        expr = nullptr;
    }
};

class ExprManager {
    static const unsigned int s_max_expr_count = 8;
    ExprBox expressions[s_max_expr_count];
    unsigned m_current_expr;

public:
    ExprManager() {
        m_current_expr = 0;
    }

    inline void clear() {
        m_current_expr = 0;
    }

    inline ExprBox *create() {
        assert(m_current_expr < s_max_expr_count);
        return &expressions[m_current_expr++];
    }
};

static ExprManager s_mgr;
static bool s_mgr_allocated = false;

void *s2e_expr_mgr() {
    assert(!s_mgr_allocated);
    s_mgr_allocated = true;
    return &s_mgr;
}

void s2e_expr_clear(void *_mgr) {
    ExprManager *mgr = static_cast<ExprManager *>(_mgr);
    mgr->clear();
    s_mgr_allocated = false;
}

void s2e_expr_mgr_clear() {
    if (s_mgr_allocated) {
        s_mgr.clear();
        s_mgr_allocated = false;
    }
}

void s2e_expr_set(void *expr, uint64_t constant) {
    ExprBox *box = static_cast<ExprBox *>(expr);
    box->value = constant;
    box->constant = true;
}

void *s2e_expr_and(void *_mgr, void *_lhs, uint64_t constant) {
    ExprManager *mgr = static_cast<ExprManager *>(_mgr);
    ExprBox *box = static_cast<ExprBox *>(_lhs);
    ExprBox *retbox = mgr->create();

    if (box->constant) {
        retbox->value = box->value & constant;
        retbox->constant = true;
    } else {
        ConstantExpr *cste = dyn_cast<ConstantExpr>(box->expr);
        if (cste) {
            retbox->value = cste->getZExtValue() & constant;
            retbox->constant = true;
        } else {
            retbox->expr = AndExpr::create(box->expr, ConstantExpr::create(constant, box->expr->getWidth()));
            retbox->constant = false;
        }
    }
    return retbox;
}

uint64_t s2e_expr_to_constant(void *_expr) {
    ExprBox *box = static_cast<ExprBox *>(_expr);
    if (box->constant) {
        return box->value;
    } else {
        ref<Expr> expr = g_s2e_state->toConstant(box->expr, "klee_expr_to_constant");
        ConstantExpr *cste = dyn_cast<ConstantExpr>(expr);
        return cste->getZExtValue();
    }
}

void s2e_expr_write_cpu(void *expr, unsigned offset, unsigned size) {
    ExprBox *box = static_cast<ExprBox *>(expr);
    if (box->constant) {
        g_s2e_state->regs()->write(offset, ConstantExpr::create(box->value, size * 8));
    } else {
        unsigned exprSizeInBytes = box->expr->getWidth() / 8;
        if (exprSizeInBytes == size) {
            g_s2e_state->regs()->writeSymbolicRegionUnsafe(offset, box->expr);
        } else if (exprSizeInBytes > size) {
            g_s2e_state->regs()->writeSymbolicRegionUnsafe(offset, ExtractExpr::create(box->expr, 0, size * 8));
        } else {
            g_s2e_state->regs()->writeSymbolicRegionUnsafe(offset, ZExtExpr::create(box->expr, size * 8));
        }
    }
}

void *s2e_expr_read_cpu(void *_mgr, unsigned offset, unsigned size) {
    ExprManager *mgr = static_cast<ExprManager *>(_mgr);
    ExprBox *retbox = mgr->create();

    retbox->expr = g_s2e_state->regs()->read(offset, size * 8);
    ConstantExpr *constant = dyn_cast<ConstantExpr>(retbox->expr);
    if (constant) {
        retbox->constant = true;
        retbox->value = constant->getZExtValue();
    }

    return retbox;
}

// XXX: trace memory access!
template <typename T> static inline bool s2e_fast_read_mem(uint64_t addr, T *res) {
    int object_index, page_index;
    // uintptr_t physaddr;
    int mmu_idx;

    object_index = addr >> SE_RAM_OBJECT_BITS;
    page_index = object_index & (CPU_TLB_SIZE - 1);

    mmu_idx = cpu_mmu_index(env);
    CPUTLBEntry *tlb_entry = &env->tlb_table[mmu_idx].table[page_index];
    if (unlikely(env->tlb_table[mmu_idx].table[page_index].addr_read !=
                 (addr & (TARGET_PAGE_MASK | (sizeof(*res) - 1))))) {
        return false;
    } else {
        // When we get here, the address is aligned with the size of the access,
        // which by definition means that it will fall inside the small page, without overflowing.
        // physaddr = addr + env->tlb_table[mmu_idx][page_index].addend;

#ifdef CONFIG_SYMBEX_MP
        uint64_t addend = tlb_entry->se_addend;
#else
        uint64_t addend = tlb_entry->addend;
#endif

        // XXX: assumes host == guest endianness
        if (sizeof(*res) == 4) {
            *res = *(uint32_t *) (addr + addend);
        } else if (sizeof(*res) == 8) {
            *res = *(uint64_t *) (addr + addend);
        } else {
            assert(false && "Not supported size");
        }

        // XXX: Fix this to be on the dataflow
        // res = S2E_AFTER_MEMORY_ACCESS(addr, physaddr, res, 0, 0);
        // S2E_AFTER_MEMORY_ACCESS(addr, physaddr, res, 0, 0);
        return true;
    }
}

template <typename T> static void *s2e_expr_read_mem(void *_mgr, uint64_t virtual_address) {
    ExprManager *mgr = static_cast<ExprManager *>(_mgr);
    ExprBox *retbox = mgr->create();

    // Fast path
    T res;
    if (s2e_fast_read_mem<T>(virtual_address, &res)) {
        retbox->constant = true;
        retbox->value = res;
        return retbox;
    }

    retbox->expr = g_s2e_state->mem()->read(virtual_address, sizeof(T) * 8);

    // XXX: What do we do if the result is nullptr?
    // For now we call this function from iret-type of handlers where
    // some checks must have been done before accessing the memory
    assert(retbox->expr && "Failed memory access");

    ConstantExpr *constant = dyn_cast<ConstantExpr>(retbox->expr);
    if (constant) {
        retbox->constant = true;
        retbox->value = constant->getZExtValue();
    }

    return retbox;
}

// XXX: trace memory access!
void *s2e_expr_read_mem_l(void *_mgr, uint64_t virtual_address) {
    return s2e_expr_read_mem<uint32_t>(_mgr, virtual_address);
}

void *s2e_expr_read_mem_q(void *_mgr, uint64_t virtual_address) {
    return s2e_expr_read_mem<uint64_t>(_mgr, virtual_address);
}
