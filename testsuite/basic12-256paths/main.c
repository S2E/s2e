/// Copyright (c) 2019, Cyberhaven
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

#include <s2e/s2e.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int ret = 0;
    FILE *fp = NULL;
    unsigned char bytes[8] = {0};

    if (argc != 2) {
        fprintf(stderr, "Usage: %s input_file\n", argv[0]);
        ret = 1;
        goto err;
    }

    fp = fopen(argv[1], "rb");
    if (!fp) {
        fprintf(stderr, "Could not open %s\n", argv[1]);
        ret = 2;
        goto err;
    }

    if (fread(bytes, 8, 1, fp) != 1) {
        fprintf(stderr, "Could not read bytes from file\n");
        ret = 3;
        goto err;
    }

    // 8 independent byte checks produce 2^8 = 256 paths
    for (int i = 0; i < 8; i++) {
        if (bytes[i]) {
            s2e_printf("Byte %d is non-zero\n", i);
        } else {
            s2e_printf("Byte %d is zero\n", i);
        }
    }

err:
    if (fp) {
        fclose(fp);
    }

    return ret;
}
