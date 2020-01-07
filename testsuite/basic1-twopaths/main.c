// Copyright (c) 2019, Cyberhaven
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

#include <s2e/s2e.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int ret = 0;
    FILE *fp = NULL;
    int value = 0;

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

    if (fread(&value, sizeof(value), 1, fp) != 1) {
        fprintf(stderr, "Could not read value from file\n");
        ret = 3;
        goto err;
    }

    if (value == 1) {
        s2e_printf("Value is 1\n");
    } else {
        s2e_printf("Value is not 1\n");
    }

err:
    if (fp) {
        fclose(fp);
    }

    return ret;
}
