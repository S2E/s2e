/// Copyright (C) 2003  Fabrice Bellard
/// Copyright (C) 2010  Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2019  Cyberhaven
/// Copyrights of all contributions belong to their respective owners.
///
/// This library is free software; you can redistribute it and/or
/// modify it under the terms of the GNU Library General Public
/// License as published by the Free Software Foundation; either
/// version 2 of the License, or (at your option) any later version.
///
/// This library is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
/// Library General Public License for more details.
///
/// You should have received a copy of the GNU Library General Public
/// License along with this library; if not, see <http://www.gnu.org/licenses/>.

#include <cpu/config.h>
#include <cpu/types.h>
#include <tcg/tcg.h>

#include "cpu.h"
#include "exec-tb.h"
#include "exec.h"

#include <cpu/precise-pc.h>
#include <tcg/insn-start-words.h>

/* Encode VAL as a signed leb128 sequence at P.
   Return P incremented past the encoded value.  */
static uint8_t *encode_sleb128(uint8_t *p, target_long val) {
    int more, byte;

    do {
        byte = val & 0x7f;
        val >>= 7;
        more = !((val == 0 && (byte & 0x40) == 0) || (val == -1 && (byte & 0x40) != 0));
        if (more) {
            byte |= 0x80;
        }
        *p++ = byte;
    } while (more);

    return p;
}

/* Decode a signed leb128 sequence at *PP; increment *PP past the
   decoded value.  Return the decoded value.  */
static target_long decode_sleb128(uint8_t **pp) {
    uint8_t *p = *pp;
    target_long val = 0;
    int byte, shift = 0;

    do {
        byte = *p++;
        val |= (target_ulong) (byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);
    if (shift < TARGET_LONG_BITS && (byte & 0x40)) {
        val |= -(target_ulong) 1 << shift;
    }

    *pp = p;
    return val;
}

/* Encode the data collected about the instructions while compiling TB.
   Place the data at BLOCK, and return the number of bytes consumed.

   The logical table consists of TARGET_INSN_START_WORDS target_ulong's,
   which come from the target's insn_start data, followed by a uintptr_t
   which comes from the host pc of the end of the code implementing the insn.

   Each line of the table is encoded as sleb128 deltas from the previous
   line.  The seed for the first line is { tb->pc, 0..., tb->tc.ptr }.
   That is, the first column is seeded with the guest pc, the last column
   with the host pc, and the middle columns with zeros.  */

int encode_search(TCGContext *tcg_ctx, TranslationBlock *tb, uint8_t *block) {
    uint8_t *highwater = tcg_ctx->code_gen_highwater;
    uint64_t *insn_data = tcg_ctx->gen_insn_data;
    uint16_t *insn_end_off = tcg_ctx->gen_insn_end_off;
    uint8_t *p = block;
    int i, j, n;

    for (i = 0, n = tb->icount; i < n; ++i) {
        uint64_t prev, curr;

        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            if (i == 0) {
                prev = (!(tb_cflags(tb) & CF_PCREL) && j == 0 ? tb->pc : 0);
            } else {
                prev = insn_data[(i - 1) * TARGET_INSN_START_WORDS + j];
            }
            curr = insn_data[i * TARGET_INSN_START_WORDS + j];
            p = encode_sleb128(p, curr - prev);
        }
        prev = (i == 0 ? 0 : insn_end_off[i - 1]);
        curr = insn_end_off[i];
        p = encode_sleb128(p, curr - prev);

        /* Test for (pending) buffer overflow.  The assumption is that any
           one row beginning below the high water mark cannot overrun
           the buffer completely.  Thus we can test for overflow after
           encoding a row without having to check during encoding.  */
        if (unlikely(p > highwater)) {
            return -1;
        }
    }

    return p - block;
}

int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc) {
    target_ulong data[TARGET_INSN_START_WORDS] = {tb->pc};
    uint8_t *p = tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    if (pc < tb->pc || pc >= tb->pc + tb->size) {
        return 0;
    }

    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        decode_sleb128(&p);
        if (data[0] == pc) {
            if (i == num_insns - 1) {
                return tb->size - (pc - tb->pc);
            } else {
                for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
                    data[j] += decode_sleb128(&p);
                }
                return data[0] - pc;
            }
        }
    }

    return 0;
}

static int tb_find_guest_pc(TranslationBlock *tb, uintptr_t searched_host_pc, target_ulong *data) {
    uintptr_t host_pc = (uintptr_t) tb->tc.ptr;
    uint8_t *p = tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    searched_host_pc -= GETPC_ADJ;

    if (searched_host_pc < host_pc) {
        return -1;
    }

    // Reconstruct the stored insn data while looking for the point at
    // which the end of the insn exceeds the searched_pc.
    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < TARGET_INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        host_pc += decode_sleb128(&p);
        if (host_pc > searched_host_pc) {
            return 0;
        }
    }
    return -1;
}

/* The cpu state corresponding to 'searched_pc' is restored.
 * When reset_icount is true, current TB will be interrupted and
 * icount should be recalculated.
 */
static int cpu_restore_state_from_tb(CPUArchState *env, TranslationBlock *tb, uintptr_t searched_pc) {
    target_ulong data[TARGET_INSN_START_WORDS] = {tb->pc};

    if (tb_find_guest_pc(tb, searched_pc, data) < 0) {
        return -1;
    }

    restore_state_to_opc(env, tb, data);

    return 0;
}

extern TCGContext tcg_init_ctx;

bool cpu_restore_state(CPUArchState *env, uintptr_t host_pc) {
    TranslationBlock *tb;
    bool r = false;
    uintptr_t check_offset;

    /* The host_pc has to be in the region of current code buffer. If
     * it is not we will not be able to resolve it here. The two cases
     * where host_pc will not be correct are:
     *
     *  - fault during translation (instruction fetch)
     *  - fault from helper (not using GETPC() macro)
     *
     * Either way we need return early as we can't resolve it here.
     *
     * We are using unsigned arithmetic so if host_pc <
     * tcg_init_ctx.code_gen_buffer check_offset will wrap to way
     * above the code_gen_buffer_size
     */
    check_offset = host_pc - (uintptr_t) tcg_init_ctx.code_gen_buffer;

    if (check_offset < tcg_init_ctx.code_gen_buffer_size) {
        tb = tcg_tb_lookup(host_pc);
        if (tb) {
            cpu_restore_state_from_tb(env, tb, host_pc);
            if (tb_cflags(tb) & CF_NOCACHE) {
                /* one-shot translation, invalidate it immediately */
                tb_phys_invalidate(tb, -1);
                tcg_tb_remove(tb);
            }
            r = true;
        }
    }

    return r;
}
