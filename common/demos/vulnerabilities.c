/// S2E Selective Symbolic Execution Platform
///
/// Copyright (c) 2018 Cyberhaven
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
/// This is a proof of vulnerability generation demo.
///
/// For the sake of simplicity, this assumes no ASLR, DEP, or other
/// fancy mitigation techniques.
///
/// See comments in the code for an explanation of the types of vulnerabilities.
///

#if defined(__WIN32__)
#include <windows.h>
#else
#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/types.h>
#endif

#include <s2e/s2e.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>

/// Types of vulnerabilities
typedef enum { SIMPLE_STACK_SMASHING = 0, FUNCTION_PTR_OVERWRITE } vuln_type_t;

/// Allocate a chunk of executable memory at a fixed location.
/// Fixed location is important to ensure that the PoV is replayable.
/// In real life, an attacker would have to provide a more advanced,
/// position-independent shellcode.
static void *allocate(size_t size) {
#if defined(__WIN32__)
    return VirtualAlloc((PVOID) 0x5000000, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
#else
    return mmap((void *) 0x5000000, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE, -1, 0);
#endif
}

///
/// \brief This is a simple return address overwrite demo.
///
/// This will work with a basic type1 recipes (usually type1_ebp.rcp),
/// where eip and ebp will be overwritten by an attacker-controlled
/// value.
///
/// Note: recipes containing shellcode that assume fixed stack
/// location will produce non-replayable PoVs.
///
static void demo_stack_smashing(FILE *fp) {
    uint8_t buffer[32];

    printf("Demoing stack smashing\n");

    // Read twice the size of the actual buffer in order
    // to cause stack overflow.
    int to_read = sizeof(buffer) * 2;
    if (fread(buffer, to_read, 1, fp) != 1) {
        fprintf(stderr, "Could not read %d bytes\n", to_read);
        return;
    }
}

static int test_func(void) {
    return 42;
}

typedef struct demo_t {
    char buffer[32];
    int (*f_ptr)(void);
} demo_t;

///
/// \brief Demonstrates overwriting of a function pointer in
/// a data structure allocated on the heap.
///
static void demo_function_ptr_overwrite(FILE *fp) {
    printf("Demoing function pointer overwrite\n");

    demo_t *demo = (demo_t *) allocate(sizeof(demo_t));
    if (!demo) {
        fprintf(stderr, "Could not allocate memory\n");
        return;
    }

    demo->f_ptr = test_func;

    // Read twice the size of the actual buffer in order
    // to cause heap overflow.
    int to_read = sizeof(demo->buffer) * 2;
    if (fread(demo->buffer, to_read, 1, fp) != 1) {
        fprintf(stderr, "Could not read %d bytes\n", to_read);
        return;
    }

    // In a successful attack, this will call an attacker-controlled
    // address rather than the original test_func().
    int value = demo->f_ptr();
    printf("value: %d\n", value);
}

static void demo(FILE *fp, vuln_type_t vuln_type) {
    switch (vuln_type) {
        case SIMPLE_STACK_SMASHING:
            demo_stack_smashing(fp);
            break;
        case FUNCTION_PTR_OVERWRITE:
            demo_function_ptr_overwrite(fp);
            break;
        default:
            fprintf(stderr, "Invalid demo type\n");
            break;
    }
}

int main(int argc, char **argv) {
    FILE *fp = NULL;
    int ret = -1;
    vuln_type_t vuln_type;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s input_file\n", argv[0]);
        goto err;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", argv[1]);
        goto err;
    }

    if (fread(&vuln_type, sizeof(vuln_type), 1, fp) != 1) {
        fprintf(stderr, "Could not read from file\n");
        goto err;
    }

    demo(fp, vuln_type);

    ret = 0;

err:

    if (fp) {
        fclose(fp);
    }

    return ret;
}
