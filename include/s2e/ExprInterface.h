///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
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
