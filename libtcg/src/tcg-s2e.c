///
/// Copyright (C) 2015-2024, Cyberhaven
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

#include <tcg/tcg-s2e.h>

// Computes the register mask of the last instruction in the current context
void tcg_calc_regmask(TCGContext *s, uint64_t *rmask, uint64_t *wmask, uint64_t *accesses_mem) {
    const TCGOp *op;
    const TCGOpDef *def;
    int c, i, nb_oargs, nb_iargs;

    *rmask = *wmask = *accesses_mem = 0;

    // We must go in reverse as we need only the last instruction
    QTAILQ_FOREACH_REVERSE(op, &s->ops, link) {
        c = op->opc;
        def = &tcg_op_defs[c];

        if (c == INDEX_op_insn_start) {
            break;
        }

        if (c == INDEX_op_call) {
            /* variable number of arguments */
            nb_oargs = TCGOP_CALLO(op);
            nb_iargs = TCGOP_CALLI(op);

            /* We don't track register masks for helpers anymore, assume access everything */
            *rmask |= -1;
            *wmask |= -1;
            *accesses_mem |= 1;
            return;
        }

        nb_oargs = def->nb_oargs;
        nb_iargs = def->nb_iargs;

        for (i = 0; i < nb_iargs; i++) {
            TCGArg arg = op->args[nb_oargs + i];
            TCGTemp *tmp = arg_temp(arg);
            size_t idx = temp_idx(tmp);

            if (idx < s->nb_globals) {
                *rmask |= (1 << idx);
            }
        }

        for (i = 0; i < nb_oargs; i++) {
            TCGArg arg = op->args[i];
            TCGTemp *tmp = arg_temp(arg);
            size_t idx = temp_idx(tmp);

            if (idx < s->nb_globals) {
                *wmask |= (1 << idx);
            }
        }
    }
}
