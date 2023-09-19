/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2023 Vitaly Chipounov
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

#include <hw/port.h>
#include <stdarg.h>
#include <string.h>

static void printchar(char c) {
    outb(0x402, c);
}

static void reverse(char s[]) {
    int i, j;
    char c;

    int len = strlen(s);
    for (i = 0, j = len - 1; i < j; i++, j--) {
        c = s[i];
        s[i] = s[j];
        s[j] = c;
    }
}

static void printd(int n) {
    int i = 0;
    char s[10];
    do {
        s[i++] = n % 10 + '0';
    } while ((n /= 10) > 0);
    s[i] = '\0';
    reverse(s);
    for (i = 0; i < strlen(s); i++) {
        printchar(s[i]);
    }
}

static void printx(unsigned int n) {
    int i = 0;
    char s[10];
    do {
        s[i++] = "0123456789abcdef"[n % 16];
    } while ((n /= 16) > 0);
    s[i] = '\0';
    reverse(s);
    for (i = 0; i < strlen(s); i++) {
        printchar(s[i]);
    }
}

static void printllx(unsigned long long n) {
    int i = 0;
    char s[20];
    do {
        s[i++] = "0123456789abcdef"[n % 16];
    } while ((n /= 16) > 0);
    s[i] = '\0';
    reverse(s);
    for (i = 0; i < strlen(s); i++) {
        printchar(s[i]);
    }
}

int printf(const char *format, ...) {
    va_list arg;
    va_start(arg, format);

    while (*format) {
        if (*format == '%') {
            format++;
            switch (*format) {
                case 'd':
                    printd(va_arg(arg, int));
                    break;
                case 'x':
                    printx(va_arg(arg, unsigned int));
                    break;
                case 'l':
                    format++;
                    if (*format == 'l') {
                        format++;
                        if (*format == 'x') {
                            printllx(va_arg(arg, unsigned long long));
                        }
                    }
                    break;
            }
        } else {
            printchar(*format);
        }
        format++;
    }
    va_end(arg);
    return 0;
}

int vsnprintf(char *s, size_t n, const char *format, va_list arg) {
    return 0;
}