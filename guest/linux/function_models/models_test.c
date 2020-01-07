/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2017 Dependable Systems Lab, EPFL
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

#include <string.h>

#include <s2e/s2e.h>

#include "function_models.h"

#define STR_LEN 8

//
// Check that the signs of the two results validate the correctness of the
// function model
//
static inline void validate_signs(int res1, int res2) {
    if ((res1 ^ res2) < 0) {
        s2e_kill_state(-1, "Bad model!");
    } else {
        s2e_kill_state(0, "Good model!");
    }
}

//
// Check that the memory contents validate the correctness of the function
// model
//
static inline void validate_contents(const void *mem1, const void *mem2) {
    if (memcmp(mem1, mem2, STR_LEN)) {
        s2e_kill_state(-1, "Bad model!");
    } else {
        s2e_kill_state(0, "Good model!");
    }
}

//
// Ensure that the two strings to have the same memory contents
//
static inline void init_strings(char *str1, char *str2) {
    memset(str1, 'A', STR_LEN);
    memset(str2, 'A', STR_LEN);
}

//
// Unit tests
//

static void test_strcpy(const char *src) {
    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    strcpy(str1, src);
    strcpy_model(str2, src);

    validate_contents(str1, str2);
}

static void test_strncpy(const char *src, unsigned src_len) {
    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    strncpy(str1, src, src_len);
    strncpy_model(str2, src, src_len);

    validate_contents(str1, str2);
}

static void test_strcmp(const char *str1) {
    char *str2 = "123";
    s2e_make_symbolic(str2, strlen(str2), "test_string_2");

    int res1 = strcmp(str1, str2);
    int res2 = strcmp_model(str1, str2);

    validate_signs(res1, res2);
}

static void test_strncmp(const char *str1) {
    char *str2 = "123";
    s2e_make_symbolic(str2, strlen(str2), "test_string_2");

    int res1 = strncmp(str1, str2, 4);
    int res2 = strncmp_model(str1, str2, 4);

    validate_signs(res1, res2);
}

static void test_strcat(const char *src) {
    char *dest = "ABCD";
    const unsigned dest_len = strlen(dest);
    s2e_make_symbolic(dest, dest_len, "deststring");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < dest_len; ++i) {
        str1[i] = str2[i] = dest[i];
    }

    strcat(str1, src);
    strcat_model(str2, src);

    validate_contents(str1, str2);
}

static void test_strncat(const char *src, unsigned src_len) {
    char *dest = "ABCD";
    s2e_make_symbolic(dest, strlen(dest), "deststring");

    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    // Make sure that the two destination strings have the same symbolic data
    for (unsigned i = 0; i < strlen(dest); ++i) {
        str1[i] = str2[i] = dest[i];
    }

    strncat(str1, src, src_len);
    strncat_model(str2, src, src_len);

    validate_contents(str1, str2);
}

static void test_strlen(const char *str) {
    int res1 = strlen(str);
    int res2 = strlen_model(str);

    if (res1 == res2) {
        s2e_kill_state(0, "Good Model!");
    } else {
        s2e_kill_state(-1, "Bad Model!");
    }
}

static void test_memcpy(const char *src, unsigned src_len) {
    char str1[STR_LEN];
    char str2[STR_LEN];

    init_strings(str1, str2);

    memcpy(str1, src, src_len);
    memcpy_model(str2, src, src_len);

    validate_contents(str1, str2);
}

static void test_memcmp(const char *str1, unsigned str1_len) {
    char *str2 = "123";
    s2e_make_symbolic(str2, strlen(str2), "test_string_2");

    int res1 = memcmp(str1, str2, str1_len);
    int res2 = memcmp_model(str1, str2, str1_len);

    validate_signs(res1, res2);
}

static void test_crc32(void) {
    // Test empty buffer
    uint32_t crc = crc32_model(0, NULL, 0);
    s2e_assert(crc == 0);

    const char *test = "test";
    const uint32_t expected_crc = 0xd87f7e0c;
    crc = crc32_model(crc, (const uint8_t *) test, strlen(test));
    s2e_printf("actual crc: %#x expected: %#x\n", crc, expected_crc);
    s2e_assert(crc == expected_crc);
}

static void test_crc16(void) {
    // Test empty buffer
    uint16_t crc = crc16_model(0, NULL, 0);
    s2e_assert(crc == 0);

    const char *test = "test";
    const uint16_t expected_crc = 0xdc2e;
    crc = crc16_model(crc, (const uint8_t *) test, strlen(test));
    s2e_printf("actual crc: %#x expected: %#x\n", crc, expected_crc);
    s2e_assert(crc == expected_crc);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        s2e_printf("Usage: %s function_name\n", argv[0]);
        return -1;
    }

    char *src = "abc";
    const unsigned src_length = strlen(src);
    s2e_make_symbolic(src, src_length, "source_string");

    s2e_printf("Testing function model for libc: %s\n", argv[1]);

    initialize_models();

    if (!strcmp(argv[1], "strcpy")) {
        test_strcpy(src);
    } else if (!strcmp(argv[1], "strncpy")) {
        test_strncpy(src, src_length);
    } else if (!strcmp(argv[1], "strcmp")) {
        test_strcmp(src);
    } else if (!strcmp(argv[1], "strncmp")) {
        test_strncmp(src);
    } else if (!strcmp(argv[1], "strcat")) {
        test_strcat(src);
    } else if (!strcmp(argv[1], "strncat")) {
        test_strncat(src, src_length);
    } else if (!strcmp(argv[1], "memcpy")) {
        test_memcpy(src, src_length);
    } else if (!strcmp(argv[1], "memcmp")) {
        test_memcmp(src, src_length);
    } else if (!strcmp(argv[1], "strlen")) {
        test_strlen(src);
    } else if (!strcmp(argv[1], "crc32")) {
        test_crc32();
    } else if (!strcmp(argv[1], "crc16")) {
        test_crc16();
    } else {
        s2e_printf("Function %s is not supported!\n", argv[1]);
    }

    return 0;
}
