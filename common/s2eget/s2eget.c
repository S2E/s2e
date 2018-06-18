/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
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

#define BUFFER_SIZE 1024 * 64

const char *g_host_file = NULL;
const char *g_dest_file = NULL;

static char *get_dest_file(const char *dest_file, const char *host_file) {
    char *path = NULL;
    char *cwd = NULL;

    if (dest_file) {
        // Make a copy of the destination file path so that we don't mess around with argv
        unsigned max_len = strlen(dest_file) + 1;
        path = calloc(max_len, sizeof(char));
        if (!path) {
            fprintf(stderr, "Could not allocate memory for the file path\n");
            goto end;
        }

        strncpy(path, dest_file, max_len);
    } else {
        // If no destination file path was given, construct a destination path based on the host file's name and the
        // guest's current working directory. Otherwise use the given destination file path

        // Get the base name of the host file. Note that this buffer should not be passed to free()
        char *host_file_basename = basename((char *) host_file);
        if (!host_file_basename) {
            fprintf(stderr, "Could not allocate memory for the file basename\n");
            goto end;
        }

        // Get the current working directory
        cwd = getcwd(NULL, 0);
        if (!cwd) {
            fprintf(stderr, "Could not allocate memory for the current directory\n");
            goto end;
        }

        // Allocate a buffer for the destination path. When allocating this buffer we must take into account the
        // path separator between the current working directory and the file name, plus the null terminator
        unsigned max_len = strlen(cwd) + strlen(host_file_basename) + 1 + 1;
        path = calloc(max_len, sizeof(char));
        if (!path) {
            fprintf(stderr, "Could not allocate memory for the file path\n");
            goto end;
        }

        // Construct the destination path and clean up
        snprintf(path, max_len, "%s/%s", cwd, host_file_basename);
    }

end:
    free(cwd);
    return path;
}

static int copy_file(const char *dest_file, const char *host_file) {
    char *path = NULL;
    int retval = -1;
    int fd = -1;
    int s2e_fd = -1;

    path = get_dest_file(dest_file, host_file);
    if (!path) {
        goto end;
    }

    // Delete anything that already exists at this location
    unlink(path);

    // Open the host file path for reading.
    s2e_fd = s2e_open(host_file);
    if (s2e_fd < 0) {
        fprintf(stderr, "s2e_open of %s failed\n", host_file);
        goto end;
    }

// Open the destination file path for writing
#ifdef _WIN32
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, S_IRWXU);
#else
    fd = creat(path, S_IRWXU);
#endif
    if (fd < 0) {
        fprintf(stderr, "Could not create file %s\n", path);
        goto end;
    }

    int fsize = 0;
    char buf[BUFFER_SIZE] = {0};

    // Copy and write data from host to guest
    while (1) {
        int ret = s2e_read(s2e_fd, buf, sizeof(buf));
        if (ret == -1) {
            fprintf(stderr, "s2e_read failed\n");
            goto end;
        } else if (ret == 0) {
            break;
        }

        int ret1 = write(fd, buf, ret);
        if (ret1 != ret) {
            fprintf(stderr, "Could not write to file\n");
            goto end;
        }

        fsize += ret;
    }

    printf("... file %s of size %d was transferred successfully to %s\n", host_file, fsize, path);

    retval = 0;

end:
    if (s2e_fd >= 0) {
        s2e_close(s2e_fd);
    }

    if (fd >= 0) {
        close(fd);
    }

    free(path);

    if (retval < 0) {
        // There was an error, clean up any partially transferred files
        if (path) {
            unlink(path);
        }
        retval = -retval;
    }

    return retval;
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [options] host_file [dest_file]\n\n", prog_name);
    fprintf(stderr, "host_file      - File path relative to the HostFiles plugin's base directory\n");
    fprintf(stderr, "dest_file      - File path of the downloaded file on the guest. "
                    "The directories must already exist [default: working directory]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --help       - Display this message\n");
}

static int parse_arguments(int argc, const char **argv) {
    unsigned i = 1;

    while (i < argc) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            exit(0);
        } else {
            g_host_file = argv[i++];

            // If there are still arguments left, take the next argument as
            // the destination file on the guest
            if (i < argc) {
                g_dest_file = argv[i];
            } else {
                g_dest_file = NULL;
            }

            // We are done. Don't look for any more arguments
            break;
        }
    }

    return 0;
}

static int validate_arguments(void) {
    if (!g_host_file) {
        return -1;
    }

    return 0;
}

int main(int argc, const char **argv) {
    if (parse_arguments(argc, argv) < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    if (validate_arguments() < 0) {
        print_usage(argv[0]);
        exit(1);
    }

    printf("Waiting for S2E mode...\n");
    while (s2e_check() == 0) {
        // nothing
    }
    printf("... S2E mode detected\n");

    return copy_file(g_dest_file, g_host_file);
}
