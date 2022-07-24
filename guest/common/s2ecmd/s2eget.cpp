/*
 * S2E Selective Symbolic Execution Platform
 *
 * Copyright (c) 2010, Dependable Systems Laboratory, EPFL
 * Copyright (c) 2022, Vitaly Chipounov
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

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>

#include <s2e/s2e.h>

#include "s2ecmd.h"

using defer = std::shared_ptr<void>;

namespace s2e {

static void handler_get_usage() {
    std::cerr << "Usage: s2ecmd get [options] host_file [dest_file]\n\n";
    std::cerr << "host_file      - File path relative to the HostFiles plugin's base directory\n";
    std::cerr << "dest_file      - File path of the downloaded file on the guest. "
              << "The directories must already exist [default: working directory]\n";
    std::cerr << "Options:\n";
    std::cerr << "  --help       - Display this message\n";
}

struct args_t {
    std::string host_file;
    std::string dest_file;
};

static int parse_arguments(const std::vector<std::string> &args, args_t &ret) {
    for (const auto &arg : args) {
        if (arg == "--help") {
            handler_get_usage();
            return 0;
        }
    }

    for (size_t i = 0; i < args.size(); ++i) {
        switch (i) {
            case 0:
                ret.host_file = args[i];
                break;
            case 1:
                ret.dest_file = args[i];
                break;
            default:
                std::cerr << "Incorrect number of arguments\n";
                return -1;
        }
    }

    return 0;
}

std::string get_dest_file(const args_t &args) {
    if (!args.dest_file.empty()) {
        return args.dest_file;
    }

    // If no destination file path was given, construct a destination path based on the host file's name and the
    // guest's current working directory. Otherwise use the given destination file path

    // Get the base name of the host file. Note that this buffer should not be passed to free()
    auto host_file_basename = std::filesystem::path(args.host_file).filename();

    auto cwd = std::filesystem::current_path();

    auto ret = cwd / host_file_basename;
    return ret.string();
}

static int copy_file(const args_t &args) {
    int ret = -1;

    auto path = get_dest_file(args);
    defer _(nullptr, [&ret, &path](void *p) {
        if (ret < 0) {
            std::cerr << "Removing " << path << "\n";
            std::filesystem::remove(path);
        }
    });

    // Delete anything that already exists at this location
    std::filesystem::remove(path);

    // Open the host file path for reading
    auto s2e_fd = s2e::host_fd_t::open(args.host_file);
    if (!s2e_fd) {
        std::cerr << "s2e_open of " << args.host_file << " failed\n";
        return -1;
    }

    std::ofstream out(path, std::ios::binary | std::ios::out);
    if (!out) {
        std::cerr << "Could not create file " << path << "\n";
        return -1;
    }

    int fsize = 0;

    std::vector<uint8_t> buf;
    buf.resize(0x1000);

    // Copy and write data from host to guest
    while (true) {
        int ret = s2e_fd->read(buf);
        if (ret < 0) {
            std::cerr << "s2e_read failed\n";
            return -1;
        }

        if (ret == 0) {
            break;
        }

        out.write((char *) &buf[0], ret);
        if (out.bad()) {
            std::cerr << "Could not write " << path << "\n";
            return -1;
        }

        fsize += ret;
    }

    std::cout << "File " << args.host_file << " of size " << fsize << " was transferred successfully to " << path
              << "\n";

    ret = 0;
    return ret;
}

int handler_get(const std::vector<std::string> &args) {
    args_t parsed_args;

    auto ret = parse_arguments(args, parsed_args);
    if (ret < 0) {
        return ret;
    }

    wait_s2e_mode();

    return copy_file(parsed_args);
}

} // namespace s2e