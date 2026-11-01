// Copyright (c) 2026, Vitaly Chipounov
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

/// @file
/// Checks that a store into translated code takes effect before the overwritten
/// instruction runs. The cases are a TB that overwrites its next instruction, a
/// TB that crosses a page and overwrites an instruction on its second page, a
/// store from outside the TB into the second page of a TB, an instruction that
/// overwrites itself and the next instruction, and, in 64-bit mode, a chain of
/// instructions where each one decodes the following ones. Each case runs natively
/// and then in KLEE, which S2E uses while a register is symbolic.

#include <s2e/s2e.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

// mov byte ptr [rcx], imm8. The encoding is the same in 32-bit and 64-bit mode.
#define STORE_TO_RCX(imm) 0xc6, 0x01, (imm)
// xor cs:[rcx], edx
#define XOR_RCX_EDX 0x2e, 0x31, 0x11
// mov eax, imm8
#define MOV_EAX(imm) 0xb8, (imm), 0x00, 0x00, 0x00
#define RET          0xc3
#define NOP          0x90

// Offset of the immediate value inside MOV_EAX.
#define MOV_EAX_IMM_OFFSET 1

static int g_failures;

/// Returns a new executable mapping of two pages, which no TB covers yet.
static uint8_t *alloc_code(void) {
    void *ret = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ret == MAP_FAILED) {
        s2e_kill_state(1, "mmap failed");
    }
    return ret;
}

/// Calls the code at the given address.
///
/// @param code the code to call
/// @param store_addr the address that the code stores to, passed in rcx
/// @param key the value that the code uses to decode instructions, passed in rdx
/// @param sym the value of esi during the call. The code does not use it, and a
/// symbolic value makes S2E run the code in KLEE.
/// @return the value of eax after the call
static uint32_t run(const uint8_t *code, uint8_t *store_addr, uintptr_t key, uint32_t sym) {
    uint32_t ret;
    __asm__ __volatile__("call *%[code]"
                         : "=a"(ret)
                         : [code] "r"(code), "c"(store_addr), "d"(key), "S"(sym)
                         : "cc", "memory");
    return ret;
}

static void check(const char *name, const char *mode, uint32_t actual, uint32_t expected) {
    if (actual != expected) {
        s2e_printf("FAILED: %s (%s): got %#x, expected %#x\n", name, mode, actual, expected);
        ++g_failures;
    } else {
        s2e_printf("passed: %s (%s)\n", name, mode);
    }
}

static void check_bytes(const char *name, const char *mode, const uint8_t *actual, const uint8_t *expected,
                        size_t size) {
    for (size_t i = 0; i < size; ++i) {
        if (actual[i] != expected[i]) {
            s2e_printf("FAILED: %s (%s): byte %u is %#x, expected %#x\n", name, mode, (unsigned) i, actual[i],
                       expected[i]);
            ++g_failures;
            return;
        }
    }
    s2e_printf("passed: %s (%s)\n", name, mode);
}

static void test_next_instruction(const char *mode, uint32_t sym) {
    const uint8_t code[] = {STORE_TO_RCX(0x22), MOV_EAX(0x11), RET};
    uint8_t *buf = alloc_code();
    uint8_t *imm = buf + 3 + MOV_EAX_IMM_OFFSET;

    memcpy(buf, code, sizeof(code));
    check("next instruction", mode, run(buf, imm, 0, sym), 0x22);

    // The second run goes through a new translation of the restored code.
    *imm = 0x11;
    check("next instruction again", mode, run(buf, imm, 0, sym), 0x22);
}

static void test_store_to_second_page(const char *mode, uint32_t sym) {
    const uint8_t first[] = {STORE_TO_RCX(0x55), NOP, NOP};
    const uint8_t second[] = {MOV_EAX(0x33), RET};
    uint8_t *buf = alloc_code();
    uint8_t *start = buf + PAGE_SIZE - sizeof(first);

    memcpy(start, first, sizeof(first));
    memcpy(buf + PAGE_SIZE, second, sizeof(second));
    check("store to second page", mode, run(start, buf + PAGE_SIZE + MOV_EAX_IMM_OFFSET, 0, sym), 0x55);
}

static void test_write_to_second_page(const char *mode, uint32_t sym) {
    const uint8_t first[] = {NOP, NOP};
    const uint8_t second[] = {MOV_EAX(0x33), RET};
    uint8_t *buf = alloc_code();
    uint8_t *start = buf + PAGE_SIZE - sizeof(first);

    memcpy(start, first, sizeof(first));
    memcpy(buf + PAGE_SIZE, second, sizeof(second));
    check("second page before write", mode, run(start, NULL, 0, sym), 0x33);

    buf[PAGE_SIZE + MOV_EAX_IMM_OFFSET] = 0x44;
    check("second page after write", mode, run(start, NULL, 0, sym), 0x44);
}

/// The xor instruction changes all three of its own bytes and turns the nop that
/// follows it into a ret. It must complete with its original encoding, and the ret
/// must run instead of the mov that follows the nop.
static void test_self_overwrite(const char *mode, uint32_t sym) {
    const uint8_t code[] = {MOV_EAX(0x22), XOR_RCX_EDX, NOP, MOV_EAX(0x11), RET};
    const size_t xor_offset = 5;
    const uint8_t expected[] = {0xf0, 0x37, 0x15, RET};
    uint8_t *buf = alloc_code();

    memcpy(buf, code, sizeof(code));
    check("self overwrite", mode, run(buf, buf + xor_offset, 0x530406de, sym), 0x22);
    check_bytes("self overwrite memory", mode, buf + xor_offset, expected, sizeof(expected));
}

#ifdef __x86_64__
/// Each instruction of the chain xors 8 bytes at rcx + offset with rdx. The first
/// one changes itself and decodes the instruction after it, which has offset 8,
/// and so on. The last three encode the ret instructions that follow the code into
/// three copies of an instruction sequence that leaves through the first ret past
/// them. That sequence writes eax from esp, so the test only checks the memory.
static void test_decoder_chain(const char *mode, uint32_t sym) {
    const uint8_t code[] = {0x2e, 0x48, 0x31, 0x11, 0x90, 0xd9, 0x56, 0x53, 0x96, 0x37, 0x55, 0xd9,
                            0x90, 0xd9, 0x56, 0x43, 0x96, 0x37, 0x55, 0xe9, 0x90, 0xd9, 0x56, 0x73};
    const uint8_t expected[] = {0xf0, 0x4e, 0x35, 0xd8, 0x48, 0x31, 0x51, 0x08, // the first xor changed these
                                0x48, 0x31, 0x51, 0x10, 0x48, 0x31, 0x51, 0x18, //
                                0x48, 0x31, 0x51, 0x20, 0x48, 0x31, 0x51, 0x28, //
                                0x1d, 0xc5, 0xc7, 0x0a, 0x1b, 0x2b, 0xc4, 0x98, // the last three xors encoded these
                                0x1d, 0xc5, 0xc7, 0x0a, 0x1b, 0x2b, 0xc4, 0x98, //
                                0x1d, 0xc5, 0xc7, 0x0a, 0x1b, 0x2b, 0xc4, 0x98, //
                                RET,  RET,  RET,  RET,  RET,  RET,  RET,  RET};
    // An offset that is not aligned, so that the 8-byte stores are not aligned either.
    uint8_t *start = alloc_code() + 0x1bd;

    memset(start, RET, PAGE_SIZE);
    memcpy(start, code, sizeof(code));
    run(start, start, 0x5b07e8d8c90406deULL, sym);
    check_bytes("decoder chain", mode, start, expected, sizeof(expected));
}
#endif

static void run_all(const char *mode, uint32_t sym) {
    test_next_instruction(mode, sym);
    test_store_to_second_page(mode, sym);
    test_write_to_second_page(mode, sym);
    test_self_overwrite(mode, sym);
#ifdef __x86_64__
    test_decoder_chain(mode, sym);
#endif
}

int main(int argc, char **argv) {
    uint32_t sym = 0;

    run_all("native", sym);

    s2e_make_symbolic(&sym, sizeof(sym), "sym");
    run_all("klee", sym);

    if (g_failures == 0) {
        s2e_printf("All good\n");
    }

    return 0;
}
