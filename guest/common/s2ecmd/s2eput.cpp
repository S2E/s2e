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

namespace s2e {
static void handler_get_usage() {
    fprintf(stderr, "Usage: s2ecmd put [options] file_path\n");
    fprintf(stderr, "file_path    - File path of the file to upload to the host\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -e         - Concertize the data before writing it to the file\n");
    fprintf(stderr, "  --help     - Display this message\n");
}

struct args_t {
    bool get_example;
    std::string file;
};

static bool parse_arguments(const std::vector<std::string> &args, args_t &ret) {
    for (const auto &arg : args) {
        if (arg == "--help") {
            handler_get_usage();
            return false;
        } else if (arg == "-e") {
            ret.get_example = true;
        }
    }

    if (args.size() > 0) {
        ret.file = args.back();
    }

    return true;
}

static int copy_file(const args_t &args) {
    auto host_file = std::filesystem::path(args.file).filename();

    std::ifstream in(args.file, std::ios::binary | std::ios::in);
    if (!in) {
        std::cerr << "Could not open file " << args.file << "\n";
        return false;
    }

    // Open the host file path for reading
    auto s2e_fd = s2e::host_fd_t::open(host_file.string(), true);
    if (!s2e_fd) {
        std::cerr << "s2e_open of " << host_file << " failed\n";
        return false;
    }

    auto file_size = std::filesystem::file_size(args.file);

    std::vector<uint8_t> buf;
    buf.resize(0x1000);

    auto transferred = 0;
    while (!in.eof()) {
        in.read((char *) buf.data(), buf.size());
        auto count = in.gcount();

        if (args.get_example) {
            s2e_get_example(buf.data(), count);
        }

        if (s2e_fd->write(buf.data(), count) < 0) {
            std::cerr << "Could not write chunk to s2e\n";
            return false;
        }

        transferred += count;
    }

    if (transferred != (int) file_size) {
        std::cerr << "Source file size and actually transferred size mismatch\n";
        return false;
    }

    std::cout << "File " << args.file << " of size " << file_size << " transferred successfully\n";

    return true;
}

int handler_put(const std::vector<std::string> &args) {
    args_t parsed_args;

    auto ret = parse_arguments(args, parsed_args);
    if (!ret) {
        return -1;
    }

    wait_s2e_mode();

    return copy_file(parsed_args);
}

} // namespace s2e