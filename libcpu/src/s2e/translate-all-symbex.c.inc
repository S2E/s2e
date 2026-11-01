/// Copyright (C) 2026  Vitaly Chipounov
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

/// @file
/// The S2E part of translate-all.c, which includes this file at its end so that
/// the search data format has one definition.

int tb_get_instruction_size(TranslationBlock *tb, uint64_t pc) {
    uint64_t data[INSN_START_WORDS] = {tb->pc};
    const uint8_t *p = tb->tc.ptr + tb->tc.size;
    int i, j, num_insns = tb->icount;

    if (pc < tb->pc || pc >= tb->pc + tb->size) {
        return 0;
    }

    for (i = 0; i < num_insns; ++i) {
        for (j = 0; j < INSN_START_WORDS; ++j) {
            data[j] += decode_sleb128(&p);
        }
        decode_sleb128(&p);
        if (data[0] == pc) {
            if (i == num_insns - 1) {
                return tb->size - (pc - tb->pc);
            } else {
                for (j = 0; j < INSN_START_WORDS; ++j) {
                    data[j] += decode_sleb128(&p);
                }
                return data[0] - pc;
            }
        }
    }

    return 0;
}
