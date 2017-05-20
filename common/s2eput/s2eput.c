/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2014, Cisco Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Cisco Systems nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL CISCO SYSTEMS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <s2e/s2e.h>

#define MIN(x, y) ((x) > (y) ? (y) : (x))

#define BUFFER_SIZE 1024 * 64

/* file is a path relative to the HostFile's base directory */
static int copy_file(const char *file, int get_example) {
    int retval = 0;

    // Get the base name of the guest file. Note that this buffer should not be passed to free()
    const char *guest_file = basename((char *) file);
    if (!guest_file) {
        fprintf(stderr, "Could not allocate memory for the file basename\n");

        retval = -1;
        goto end;
    }

    int oflags = O_RDONLY;
#ifdef _WIN32
    oflags |= O_BINARY;
#endif

    int fd = open(file, oflags);
    if (fd == -1) {
        fprintf(stderr, "cannot open file %s\n", file);

        retval = -1;
        goto end;
    }

    int s2e_fd = s2e_create(guest_file);
    if (s2e_fd == -1) {
        fprintf(stderr, "s2e_create failed. Does the file %s already exist on the host?\n", guest_file);

        retval = -1;
        goto fd_cleanup;
    }

    struct stat st;
    stat(file, &st);

    char *buf = malloc(st.st_size);
    if (!buf) {
        fprintf(stderr, "Could not allocate %lu bytes\n", st.st_size);

        retval = -1;
        goto s2e_fd_cleanup;
    }

    int ret = read(fd, buf, st.st_size);
    if (ret != st.st_size) {
        fprintf(stderr, "can not read file\n");

        retval = -1;
        goto buf_cleanup;
    }

    if (get_example) {
        // Have to call s2e_get_example for the whole file at once as it doesn't add constraints.
        // Calling s2e_concretize produces silent concretization warnings.
        s2e_get_example(buf, st.st_size);
    }

    off_t off = 0;
    while (off < st.st_size) {
        size_t to_send = MIN(BUFFER_SIZE, st.st_size - off);
        ret = s2e_write(s2e_fd, buf + off, to_send);
        if (ret != to_send) {
            fprintf(stderr, "s2e_write failed\n");

            retval = -1;
            goto buf_cleanup;
        }
        off += ret;
    }

    printf("... file %s of size %lu was transferred successfully\n", file, st.st_size);

buf_cleanup:
    free(buf);

s2e_fd_cleanup:
    s2e_close(s2e_fd);

fd_cleanup:
    close(fd);

end:
    if (retval < 0) {
        retval = -retval;
    }

    return retval;
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [options] file_name\n", prog_name);
    fprintf(stderr, "file_name    - File path of the file to upload to the host\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -e         - Concertize the data before writing it to the file\n");
    fprintf(stderr, "  --help     - Display this message\n");
}

static int parse_arguments(int argc, const char **argv, const char **file, int *get_example) {
    if (argc < 2) {
        return -1;
    }

    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else if (strcmp(argv[i], "-e") == 0) {
            *get_example = 1;
        } else {
            fprintf(stderr, "invalid option: %s\n", argv[i]);
            return -1;
        }
    }

    *file = argv[argc - 1];

    return 0;
}

static int validate_arguments(const char *file) {
    if (!file) {
        return -1;
    }

    return 0;
}

int main(int argc, const char **argv) {
    const char *file = NULL;
    int get_example = 0;

    if (parse_arguments(argc, argv, &file, &get_example) < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    if (validate_arguments(file) < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    printf("Waiting for S2E mode...\n");
    while (s2e_check() == 0) {
        // nothing
    }
    printf("... S2E mode detected\n");

    return copy_file(file, get_example);
}
