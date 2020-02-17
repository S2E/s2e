///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2016-2017, Cyberhaven
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

#define _GNU_SOURCE 1

#include <BitcodeLibrary/Runtime.h>

#include "LibraryFunctionDetector.h"

/* Check if the function computes strlen properly */
void detect_strlen(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp) {
    printf("  Testing strlen on %llx\n", func_addr);

    const char *tests[] = {"str1", "asdfsaf", "k0", NULL};

    for (unsigned i = 0; tests[i]; ++i) {
        char *str1;

        g_syscall_transmit_size = 0;
        reset(stack);
        str1 = push_str(tests[i]);
        push(str1);
        push(0xdeadbeef); /* Dummy return value */
        func(&myenv);
        pop();

        int expected = strlen(tests[i]);
        int actual = myenv.regs[R_EAX];
        printf("    actual=%d expected=%d str1='%s'\n", actual, expected, tests[i]);
        if (actual != expected) {
            return;
        }

        if (g_syscall_transmit_size) {
            printf("    output is not empty\n");
            return;
        }
    }

    *result = true;
    printf("    found strlen\n");
    fprintf(fp, "  type=\"strlen\",\n");

    /**
     * Check if null pointer returns a 0 length.
     * Normally, it should crash in such cases.
     */
    push(0);
    push(0xdeadbeef); /* Dummy return value */
    func(&myenv);
    pop();
    if (myenv.regs[R_EAX] == 0) {
        fprintf(fp, "  accepts_null_input = true,\n");
    }
}

static int detect_strcmp_invoke(uint8_t *stack, revgen_function_t func, void *b1, unsigned len1, void *b2,
                                unsigned len2, unsigned n) {
    reset(stack);
    myenv.regs[R_ESP] -= 0x20;
    char *str1 = NULL;
    if (b1) {
        str1 = (char *) myenv.regs[R_ESP];
        memcpy(str1, b1, len1);
    }

    myenv.regs[R_ESP] -= 0x20;

    char *str2 = NULL;

    if (b2) {
        str2 = (char *) myenv.regs[R_ESP];
        memcpy(str2, b2, len2);
    }

    push(n); /* normal strcmp should not use this value */
    push(str2);
    push(str1);
    push(0xdeadbeef); /* Dummy return value */
    func(&myenv);
    pop();
    pop();
    pop();
    return myenv.regs[R_EAX];
}

void detect_strcmp(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp) {
    printf("  Testing strcmp on %llx\n", func_addr);

    struct tests {
        const char *str1, *str2;
        int blen1, blen2;
        int n;
    };

    /* These are basic tests for all comparison functions */
    struct tests t[] = {
        {"abc", "abc", 4, 4, 3}, {"def", "abc", 4, 4, 3}, {"abc", "def", 4, 4, 3}, {NULL, NULL, 0, 0, 0}};

    unsigned swapped_count = 0;
    for (unsigned i = 0; t[i].str1; ++i) {
        int ret = detect_strcmp_invoke(stack, func, t[i].str1, t[i].blen1, t[i].str2, t[i].blen2, t[i].n);
        /* strcmp returns an integer greater than or less than 0, spec does not say which */
        int actual_orig = ret;
        int actual;

        if (ret < 0)
            actual = -1;
        else if (ret == 0)
            actual = 0;
        else
            actual = 1;

        ret = strcmp(t[i].str1, t[i].str2);
        int expected;
        if (ret < 0)
            expected = -1;
        else if (ret == 0)
            expected = 0;
        else
            expected = 1;

        printf("    actual=%d (0x%x) expected=%d str1='%s' str2='%s'\n", actual, actual_orig, expected, t[i].str1,
               t[i].str2);
        if (actual != expected) {
            if (actual == -expected) {
                ++swapped_count;
            } else {
                return;
            }
        }
    }

    /**
     * Inverted means that the function returns the opposite
     * of the expected result.
     */
    if (swapped_count == 2) {
        printf("    function inverts order\n");
        fprintf(fp, "  inverted=true,\n");
    } else if (swapped_count != 0) {
        return;
    }

    printf("    Discriminating memcmp, strcmp, strncmp\n");

    /* At this point, we are sure to have either memcmp, strcmp, or strncmp */
    *result = true;

    /* Differentiate between strcmp and strncmp */
    /* strncmp should return 0, memcmp something else */
    int ret = detect_strcmp_invoke(stack, func, "abcd", 5, "abcf", 5, 3);
    if (ret != 0) {
        /* we have strcmp */
        printf("    detected strcmp\n");
        fprintf(fp, "  type=\"strcmp\",\n");
        return;
    }

    /* Now we have either strncmp or memcmp */
    ret = detect_strcmp_invoke(stack, func, "atoms\0\0\0\0", 10, "atoms\0abc", 10, 8);
    if (ret == 0) {
        printf("    detected strncmp\n");
        fprintf(fp, "  type=\"strncmp\",\n");
    } else {
        printf("    detected memcmp\n");
        fprintf(fp, "  type=\"memcmp\",\n");
    }

    /* Check if the function accepts null pointers */
    detect_strcmp_invoke(stack, func, NULL, 10, "atoms\0abc", 10, 8);
    fprintf(fp, "  accepts_null_input_p0 = true,\n");

    detect_strcmp_invoke(stack, func, "abc", 10, NULL, 10, 8);
    fprintf(fp, "  accepts_null_input_p1 = true,\n");

    detect_strcmp_invoke(stack, func, NULL, 10, NULL, 10, 8);
    fprintf(fp, "  accepts_null_input_p0p1 = true,\n");
}

static long detect_strtol_invoke(uint8_t *stack, revgen_function_t func, const char *nptr, char **endptr, int base) {
    myenv.regs[R_ESP] = (target_ulong)(stack + STACK_SIZE - 0x10);
    myenv.regs[R_ESP] -= 0x100;

    char *str1 = (char *) myenv.regs[R_ESP];
    memcpy(str1, nptr, strlen(nptr) + 1);

    target_ulong _endptr = 0;
    if (endptr) {
        myenv.regs[R_ESP] -= 0x20;
        _endptr = myenv.regs[R_ESP];
    }

    push(base);
    push(_endptr);
    push(str1);
    push(0xdeadbeef); /* Dummy return value */
    func(&myenv);
    pop();
    pop();
    pop();

    if (endptr) {
        *endptr = *(char **) _endptr;
    }

    return myenv.regs[R_EAX];
}

void detect_strtol(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp) {
    printf("  Testing strtol on %llx\n", func_addr);

    const char *tests[] = {"1", "0x12345", "-1234", "12345678912345665432123", NULL};

    for (unsigned i = 0; tests[i]; ++i) {
        printf("    Testing %s\n", tests[i]);
        long expected = strtol(tests[i], NULL, 0);
        long actual = detect_strtol_invoke(stack, func, tests[i], NULL, 0);
        printf("    expected=%#lx actual=%#lx\n", expected, actual);
        if (expected != actual) {
            return;
        }
    }

    *result = true;

    printf("    detected strtol\n");
    fprintf(fp, "  type=\"strtol\",\n");
}
