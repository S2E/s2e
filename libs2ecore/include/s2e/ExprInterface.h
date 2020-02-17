///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_EXPR_INTERFACE_H

#define S2E_EXPR_INTERFACE_H

#ifdef __cplusplus
extern "C" {
#endif

void *s2e_expr_mgr();
void s2e_expr_clear(void *_mgr);
void s2e_expr_mgr_clear();
void *s2e_expr_and(void *_mgr, void *_lhs, uint64_t constant);
uint64_t s2e_expr_to_constant(void *expr);
void s2e_expr_set(void *expr, uint64_t constant);
void s2e_expr_write_cpu(void *expr, unsigned offset, unsigned size);
void *s2e_expr_read_cpu(void *_mgr, unsigned offset, unsigned size);
void *s2e_expr_read_mem_l(void *_mgr, uint64_t virtual_address);
void *s2e_expr_read_mem_q(void *_mgr, uint64_t virtual_address);

#ifdef __cplusplus
}
#endif

#endif
