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

#include <stdio.h>

#include <BitcodeLibrary/Runtime.h>

#include "LibraryFunctionDetector.h"

typedef enum {
    PARAM_STRING,
    PARAM_LENGTH,
    PARAM_FD,
    PARAM_OUT_LEN,
} output_params_t;

static void push_base_params(uint8_t *stack, output_params_t *param_types, int param_count, int test_fd, uintptr_t fmt,
                             int test_len, uintptr_t out_len, int *check_length) {
    for (int i = param_count - 1; i >= 0; --i) {
        switch (param_types[i]) {
            case PARAM_STRING: {
                push(fmt);
            } break;

            case PARAM_LENGTH: {
                push(test_len);
                if (check_length) {
                    *check_length;
                }
            } break;

            case PARAM_FD: {
                push(test_fd);
            } break;

            case PARAM_OUT_LEN: {
                push(out_len);
            } break;
        }
    }
}

/* Detect the type of format string character that is used */
static char detect_format_char(revgen_function_t func, uint8_t *stack, output_params_t *param_types, int param_count) {
    const char *test_format_chars = "$%";
    const char *test_string = "098asfd80c";
    const int test_len = strlen(test_string);
    int actual_length;

    for (int i = 0; test_format_chars[i]; ++i) {
        char fmtstr[10] = {0};
        sprintf(fmtstr, "%cs", test_format_chars[i]);

        g_syscall_transmit_size = 0;
        reset(stack);
        char *test_string_ptr = push_str(test_string);
        char *fmt_string_ptr = push_str(fmtstr);
        push(test_string_ptr);
        push_base_params(stack, param_types, param_count, 1, fmt_string_ptr, test_len, NULL, NULL);
        push(0xdeadbeef); /* Dummy return value */
        func(&myenv);

        actual_length = g_syscall_transmit_size;
        if (!strncmp(g_syscall_transmit_data, test_string, actual_length)) {
            return test_format_chars[i];
        }
    }

    return 0;
}

static const unsigned FORMAT_d = 1;
static const unsigned FORMAT_x = 2;
static const unsigned FORMAT_X = 4;

struct format_test_t {
    unsigned value;
    const char *specifier;
    const char *expected_value;
    unsigned flag_if_success;
};

static unsigned detect_integer_formats(revgen_function_t func, uint8_t *stack, output_params_t *param_types,
                                       int param_count, char format_char) {
    unsigned ret = 0;

    struct format_test_t formats[] = {{1234, "d", "1234", FORMAT_d},
                                      {0x1234, "x", "1234", FORMAT_x},
                                      {0x1234a, "X", "1234A", FORMAT_X},
                                      {0, NULL, NULL, 0}};

    for (int i = 0; formats[i].expected_value; ++i) {
        char fmtstr[10] = {0};
        sprintf(fmtstr, "%c%s", format_char, formats[i].specifier);

        g_syscall_transmit_size = 0;
        reset(stack);
        char *fmt_string_ptr = push_str(fmtstr);
        push(formats[i].value);

        int test_len = strlen(formats[i].expected_value);
        push_base_params(stack, param_types, param_count, 1, fmt_string_ptr, test_len, NULL, NULL);
        push(0xdeadbeef); /* Dummy return value */
        func(&myenv);

        printf("%s: fmtstr=%s size=%d out: %p %.*s \n", __FUNCTION__, fmtstr, g_syscall_transmit_size,
               g_syscall_transmit_data, g_syscall_transmit_size, g_syscall_transmit_data);

        if (!strncmp(g_syscall_transmit_data, formats[i].expected_value, test_len)) {
            ret |= formats[i].flag_if_success;
        }
    }

    return ret;
}

static unsigned detect_width_arguments(revgen_function_t func, uint8_t *stack, output_params_t *param_types,
                                       int param_count, char format_char) {
    /* find holw many width arguments are accepted by function */
    /* printf("%*x", 8, val), printf("%**x", 8, 8, val), printf("%***x", 8, 8, 8, val), ... */
    int width_args = 0;
    while (width_args < 16) {
        char test[256] = {0};
        sprintf(test, "%c", format_char);
        for (int j = 0; j <= width_args; j++) {
            strcat(test, "*");
        }
        strcat(test, "x");

        char result[256];
        int val = 0xbadcafe;
        sprintf(result, "%8x", val);

        g_syscall_transmit_size = 0;
        reset(stack);
        char *fmt = push_str(test);

        push(val);
        for (int j = 0; j <= width_args; j++) {
            push(8);
        }

        push_base_params(stack, param_types, param_count, 1, fmt, strlen(result), NULL, NULL);
        push(0xdeadbeef); /* Dummy return value */
        func(&myenv);

        if (!g_syscall_transmit_size || strncmp(g_syscall_transmit_data, result, g_syscall_transmit_size) != 0) {
            break;
        }

        width_args++;
    }

    return width_args;
}

static unsigned detect_max_direct_arguments(revgen_function_t func, uint8_t *stack, output_params_t *param_types,
                                            int param_count, char format_char) {
    /* find maximum direct argument number accepted by function */
    /* printf("%1$x", val), printf("%2$x", 0, val), printf("%3$x", 0, 0, val), ... */
    int direct_args = 0;

    while (direct_args < 4096) {
        char test[256];
        sprintf(test, "%c%i$x", format_char, direct_args + 1);

        char result[256];
        int val = 0xbadcafe;
        sprintf(result, "%x", val);

        g_syscall_transmit_size = 0;
        reset(stack);
        char *fmt = push_str(test);

        push(val);
        for (int j = 0; j < direct_args; j++) {
            push(0);
        }

        push_base_params(stack, param_types, param_count, 1, fmt, strlen(result), NULL, NULL);
        push(0xdeadbeef); /* Dummy return value */
        func(&myenv);

        if (!g_syscall_transmit_size || strncmp(g_syscall_transmit_data, result, g_syscall_transmit_size) != 0) {
            break;
        }

        direct_args++;
    }

    return direct_args;
}

static void detect_output_fcn(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                              FILE *fp, output_params_t *param_types, int param_count) {
    const char *test_string = "098asfd80c";
    const int test_real_len = strlen(test_string);
    const int test_len = test_real_len - 3;
    const int test_fd = 1888;

    int check_length = false;
    int uses_length = false;
    int actual_length = 0;
    int appends_new_line = false;
    int uses_fd = false;
    char uses_format_char = 0;
    int has_s_conversion_fmt = 0;
    unsigned supported_fmts = 0;
    int width_args = 0;
    int direct_args = 0;

    g_syscall_transmit_size = 0;
    reset(stack);
    char *fmt = push_str(test_string);
    int out_len = 0;
    push_base_params(stack, param_types, param_count, test_fd, fmt, test_len, &out_len, &check_length);
    push(0xdeadbeef); /* Dummy return value */
    func(&myenv);

    if (g_syscall_transmit_size == test_len) {
        uses_length = true;
    } else if (g_syscall_transmit_size != test_real_len) {
        printf("    invalid transmit size %i\n", g_syscall_transmit_size);
        return;
    }

    actual_length = g_syscall_transmit_size;

    /* Check if function appends new line to the buffer */
    if (g_syscall_transmit_data[actual_length - 1] == '\n') {
        appends_new_line = true;
    }

    if (appends_new_line) {
        --actual_length;
    }

    if (g_syscall_transmit_fd == test_fd) {
        uses_fd = true;
    }

    if (strncmp(g_syscall_transmit_data, test_string, actual_length) != 0) {
        printf("    invalid output %.*s of size %i\n", g_syscall_transmit_size, g_syscall_transmit_data,
               g_syscall_transmit_size);
        return;
    }

    for (int i = 0; i < param_count; ++i) {
        /* If we specified an out_len parameter, check that it corresponds to the actual length */
        if (param_types[i] == PARAM_OUT_LEN && actual_length != out_len) {
            printf("    actual_length (%d) != (%d) out_len\n", actual_length, out_len);
            return;
        }
    }

    printf("%s: size=%d out: %p %.*s out_len: %d \n", __FUNCTION__, actual_length, g_syscall_transmit_data,
           actual_length, g_syscall_transmit_data, out_len);

    /* Detect the type of format string character that is used */
    uses_format_char = detect_format_char(func, stack, param_types, param_count);

    if (uses_format_char) {
        /* This is checked by uses_format_char */
        has_s_conversion_fmt = true;

        /* We have a printf-like function, try to detect formats */
        supported_fmts = detect_integer_formats(func, stack, param_types, param_count, uses_format_char);
        width_args = detect_width_arguments(func, stack, param_types, param_count, uses_format_char);
        direct_args = detect_max_direct_arguments(func, stack, param_types, param_count, uses_format_char);
    }

    *result = true;

    fprintf(fp, "  type=\"output\",\n");
    fprintf(fp, "  appends_new_line=%d,\n", (int) appends_new_line);
    fprintf(fp, "  uses_length=%d,\n", (int) uses_length);
    fprintf(fp, "  uses_fd=%d,\n", (int) uses_fd);

    if (uses_format_char) {
        fprintf(fp, "  uses_format_char=\"%c\",\n", uses_format_char);
        fprintf(fp, "  supported_formats={");

        if (has_s_conversion_fmt) {
            fprintf(fp, "\"s\",");
        }

        if (supported_fmts & FORMAT_d) {
            fprintf(fp, "\"d\",");
        }

        if (supported_fmts & FORMAT_x) {
            fprintf(fp, "\"x\",");
        }

        if (supported_fmts & FORMAT_X) {
            fprintf(fp, "\"X\",");
        }

        fprintf(fp, "  },\n");
    }

    fprintf(fp, "  params={");

    for (int i = 0; i < param_count; ++i) {
        switch (param_types[i]) {
            case PARAM_STRING:
                fprintf(fp, "\"string\",");
                break;
            case PARAM_LENGTH:
                fprintf(fp, "\"length\",");
                break;
            case PARAM_FD:
                fprintf(fp, "\"fd\",");
                break;
            case PARAM_OUT_LEN:
                fprintf(fp, "\"out_len\",");
                break;
        }
    }

    fprintf(fp, "  },\n");

    if (uses_format_char) {
        fprintf(fp, "  width_args=%i,\n", width_args);
        fprintf(fp, "  direct_args=%i,\n", direct_args);
    }
}

void detect_output_str(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp) {
    printf("Trying %s\n", __FUNCTION__);
    output_params_t params[] = {PARAM_STRING};
    detect_output_fcn(func, func_addr, stack, result, fp, params, 1);
}

void detect_output_str_len(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                           FILE *fp) {
    printf("Trying %s\n", __FUNCTION__);
    output_params_t params[] = {PARAM_STRING, PARAM_LENGTH};
    detect_output_fcn(func, func_addr, stack, result, fp, params, 2);
}

void detect_output_fd_str(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result, FILE *fp) {
    printf("Trying %s\n", __FUNCTION__);
    output_params_t params[] = {PARAM_FD, PARAM_STRING};
    detect_output_fcn(func, func_addr, stack, result, fp, params, 2);
}

void detect_output_fd_str_len(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                              FILE *fp) {
    printf("Trying %s\n", __FUNCTION__);
    output_params_t params[] = {PARAM_FD, PARAM_STRING, PARAM_LENGTH};
    detect_output_fcn(func, func_addr, stack, result, fp, params, 3);
}

void detect_output_fd_str_len_outlen(revgen_function_t func, uint64_t func_addr, uint8_t *stack, volatile bool *result,
                                     FILE *fp) {
    printf("Trying %s\n", __FUNCTION__);
    output_params_t params[] = {PARAM_FD, PARAM_STRING, PARAM_LENGTH, PARAM_OUT_LEN};
    detect_output_fcn(func, func_addr, stack, result, fp, params, 4);
}
