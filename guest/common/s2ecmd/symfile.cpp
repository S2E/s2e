// S2E Selective Symbolic Execution Platform
//
// Copyright (c) 2010, Dependable Systems Laboratory, EPFL
// Copyright (c) 2018, Cyberhaven
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//     * Neither the name of the Dependable Systems Laboratory, EPFL nor the
//       names of its contributors may be used to endorse or promote products
//       derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE DEPENDABLE SYSTEMS LABORATORY, EPFL BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include <s2e/s2e.h>
#include <s2e/test_case_generator/commands.h>

#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <locale>
#include <sstream>
#include <string>
#include <vector>

struct offset_size_t {
    unsigned offset;
    unsigned size;
};

typedef std::vector<offset_size_t> symbolic_locs_t;
typedef std::vector<bool> bitmap_t;

// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch) { return !std::isspace(ch); }));
}

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) { return !std::isspace(ch); }).base(), s.end());
}

// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

///
/// \brief Decode symbolic ranges from the given string.
///
/// The string must have the following format:
/// O1-S1 O2-S2 ... On-Sn
///
/// Oi are the offsets
/// Si are the sizes
///
/// For example, the string "1-2 4-3" encodes two symbolic ranges,
/// the first one starts at offset 1 and is 2 byte-long, while the
/// second one starts at offset 4 and has size 3.
///
/// Notes:
///   - Ranges may overlap each other
///   - Numbers may be decimal or hexadecimal
///   - Each range may be separated by a new line
///   - A line may start with #, in which case it is ignored
///   - Lines may have trailing and leading whitespaces, which
///     are ignored.
///
/// \param input the symbolic range string
/// \param out the decoded ranges
/// \return true if success, false if the input string is invalid
///
static bool parse_symbolic_ranges(std::istream &input, symbolic_locs_t &out) {
    std::string token, line;

    while (std::getline(input, line, '\n')) {
        trim(line);
        if (line.size() == 0) {
            continue;
        }

        if (line[0] == '#') {
            continue;
        }

        std::stringstream ss(line);
        while (std::getline(ss, token, ' ')) {
            trim(token);
            if (token.size() == 0) {
                continue;
            }

            offset_size_t os;
            std::string offset, size;
            std::istringstream pair(token);

            if (!std::getline(pair, offset, '-')) {
                return false;
            }

            if (!std::getline(pair, size, '-')) {
                return false;
            }

            os.offset = strtoll(offset.c_str(), nullptr, 0);
            os.size = strtoll(size.c_str(), nullptr, 0);
            out.push_back(os);
        }
    }

    return true;
}

///
/// \brief Generate a bitmap of file locations that must be symbolic
///
/// The bitmap has as many bits as the file size. A bit set to 1 indicates
/// that this file location must be made symbolic.
///
/// \param locs the symbolic ranges
/// \param input_size the size of the file
/// \param out the bitmap
/// \return true if successful, false otherwise (e.g., some offsets exceed file size)
///
static bool get_bitmap(const symbolic_locs_t &locs, unsigned input_size, bitmap_t &out) {
    out.resize(input_size);

    for (const auto &loc : locs) {
        for (unsigned i = loc.offset; i < loc.offset + loc.size; ++i) {
            if (i >= input_size) {
                return false;
            }
            out[i] = true;
        }
    }

    return true;
}

///
/// \brief replace special characters in the filename with underscores.
///
/// Symbolic variable names for a file are derived from the file path.
/// However, symbolic variable cannot have any special character. This
/// function strips them.
///
/// \param name the string to sanitize
/// \return the sanitized string
///
static std::string get_cleaned_name(const std::string &name) {
    std::string cleaned_name = name;

    for (unsigned i = 0; name[i]; ++i) {
        if (!isalnum(name[i])) {
            cleaned_name[i] = '_';
        }
    }

    return cleaned_name;
}

///
/// \brief Encode a name, chunk id, and total chunks into a symbolic variable name
///
/// This variable name will be used by the TestCaseGenerator plugin in order
/// to reconstruct the concrete input files.
///
/// \param cleaned_name the original file path stripped of any special characters
/// \param current_chunk the chunk identifier
/// \param total_chunks how many chunks are expected for the file
/// \return the variable name
///
static std::string get_chunk_name(const std::string &cleaned_name, unsigned current_chunk, unsigned total_chunks) {
    std::stringstream symbvarname;
    symbvarname << "__symfile___" << cleaned_name << "___" << current_chunk << "_" << total_chunks << "_symfile__";
    return symbvarname.str();
}

///
/// \brief Make the specified file chunk symbolic
///
/// \param fd the descriptor of the file to be made symbolic (must be located in a ram disk)
/// \param offset the offset in the file to be made symbolic
/// \param buffer the pointer where to store the original concrete data
/// \param buffer_size the size of the buffer in bytes
/// \param variable_name the name of the variable that encodes the chunk information
/// \return the number of bytes read/written to the file
///
static ssize_t make_chunk_symbolic(int fd, off_t offset, void *buffer, unsigned buffer_size,
                                   const std::string &variable_name) {
    // Read the file in chunks and make them symbolic
    if (lseek(fd, offset, SEEK_SET) < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not seek to position %d", offset);
        return -3;
    }

    // Read the data
    ssize_t read_count = read(fd, buffer, buffer_size);
    if (read_count < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not read from file");
        return -4;
    }

    // Make the buffer symbolic
    s2e_make_symbolic(buffer, read_count, variable_name.c_str());

    // Write it back
    if (lseek(fd, offset, SEEK_SET) < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not seek to position %d", offset);
        return -5;
    }

    ssize_t written_count = write(fd, buffer, read_count);
    if (written_count < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not write to file");
        return -6;
    }

    if (read_count != written_count) {
        // XXX: should probably retry...
        s2e_kill_state_printf(-1, "symbfile: could not write the read amount");
        return -7;
    }

    return read_count;
}

///
/// \brief Send to the test case generator plugin a chunk of data for the concrete file template
///
/// The concrete file template is the original file content before it was made partly symbolic.
/// We send it in chunks to make sure that the plugin can read it back. Larger chunks
/// may be swapped out by the OS, smaller ones must remain in the working set.
///
/// \param data pointer to the chunk data
/// \param chunk_size the size of the chunk
/// \param offset the offset of the chunk in the original file
/// \param name the sanitized name (must match the one in symbolic variable names)
///
static void testcase_generator_send_chunk(void *data, unsigned chunk_size, unsigned offset, const std::string &name) {
    S2E_TCGEN_COMMAND cmd;
    cmd.Command = TCGEN_ADD_CONCRETE_FILE_CHUNK;
    cmd.Chunk.data = (uintptr_t) data;
    cmd.Chunk.name = (uintptr_t) name.c_str();
    cmd.Chunk.offset = offset;
    cmd.Chunk.size = chunk_size;
    s2e_invoke_plugin("TestCaseGenerator", &cmd, sizeof(cmd));
}

///
/// \brief Send the content of the concrete input file to the test case generator plugin
///
/// The test case generator plugin will use this information to reconstruct a complete test
/// case in case only part of the files are made symbolic.
///
/// \param filename the path to the concrete file on the guest
/// \param cleaned_name the name that identifies the file in the test case generator plugin
/// \return error code, 0 on success
///
static int testcase_generator_register_concrete_file(const std::string &filename, const std::string &cleaned_name) {
    uint8_t buffer[0x1000];
    size_t read_count = 0;
    unsigned offset = 0;
    int ret = 0;

    FILE *fp = fopen(filename.c_str(), "rb");
    if (!fp) {
        ret = 1;
        goto err;
    }

    while (!feof(fp)) {
        read_count = fread(buffer, 1, sizeof(buffer), fp);
        if (read_count > 0) {
            testcase_generator_send_chunk(buffer, read_count, offset, cleaned_name.c_str());
            offset += read_count;
        }
    }

err:
    if (fp) {
        fclose(fp);
    }

    return ret;
}

///
/// \brief Make parts of the given file symbolic
///
/// \param fd the descriptor of the file to be made symbolic (must be on a ram disk)
/// \param cleaned_name the sanitized name of the file
/// \param bitmap the parts of the file to be made symbolic
/// \return error code, 0 on success
///
static int make_partial_file_symbolic(int fd, const std::string &cleaned_name, const bitmap_t &bitmap) {
    for (unsigned i = 0; i < bitmap.size(); ++i) {
        if (!bitmap[i]) {
            continue;
        }

        uint8_t buffer;
        std::string name = get_chunk_name(cleaned_name, i, bitmap.size());
        auto ret = make_chunk_symbolic(fd, i, &buffer, sizeof(buffer), name);
        if (ret < 0) {
            return ret;
        }
    }

    return 0;
}

///
/// \brief Make the entire file symbolic
///
/// \param fd the descriptor of the file to be made symbolic (must be on a ram disk)
/// \param file_size the size in bytes of the file
/// \param block_size the size of a chunk (or symbolic variable)
/// \param cleaned_name the sanitized name of the file
/// \return error code (0 on success)
///
static int make_whole_file_symbolic(int fd, unsigned file_size, unsigned block_size, const std::string &cleaned_name) {
    char buffer[block_size];

    unsigned current_chunk = 0;
    unsigned total_chunks = file_size / sizeof(buffer);
    if (file_size % sizeof(buffer)) {
        ++total_chunks;
    }

    off_t offset = 0;
    do {
        ssize_t totransfer = file_size > sizeof(buffer) ? sizeof(buffer) : file_size;

        std::string name = get_chunk_name(cleaned_name, current_chunk, total_chunks);
        auto read_count = make_chunk_symbolic(fd, offset, buffer, totransfer, name);

        offset += read_count;
        file_size -= read_count;
        ++current_chunk;
    } while (file_size > 0);

    return 0;
}

///
/// \brief Process the "s2ecmd symbfile" command.
///
/// This command can be invoked as follows:
///
///   S2E_SYMFILE_RANGES="1-2 3-1 3-3" ./s2ecmd symbfile [chunk_size] /path/to/file/on/ramdisk
///
/// S2E_SYMFILE_RANGES is an optional environment variable that specifies which
/// parts of the file must be made symbolic. If this variable is missing, the
/// whole file is made symbolic.
///
/// S2E_SYMFILE_RANGES may also contain a file name, in which case the ranges
/// are read from the file.
///
/// The concrete file is split into chunks, each chunk gets a symbolic variable.
/// The chunk_size parameter specifies the maximum size of each symbolic variable.
/// The chunk_size must be 1 for some applications (e.g., PoV generation).
/// The chunk_size is ignored when S2E_SYMFILE_RANGES is present (in which case chunk size
/// is set to 1).
///
/// The path to the file must be located on a RAM disk, otherwise it will not
/// be possible to make it symbolic. This commands overwrites the original file
/// with symbolic data. That data will be immediately concretized by S2E if the file
/// is on a hard drive.
///
/// \param argc the number of arguments
/// \param args the arguments
/// \return error code (0 on success)
///
int handler_symbfile(int argc, const char **args) {
    int ret = 0;
    int flags = O_RDWR;

#ifdef _WIN32
    flags |= O_BINARY;
#endif

    symbolic_locs_t sym_ranges;
    bitmap_t sym_bitmap;

    // TODO: implement proper command line args parsing
    const char *sym_ranges_env = getenv("S2E_SYMFILE_RANGES");
    if (sym_ranges_env) {
        // First check if this is a file
        std::istream *is = nullptr;
        std::ifstream ifs(sym_ranges_env);
        std::istringstream iss(sym_ranges_env);

        if (ifs.is_open()) {
            s2e_printf("Opened symranges file %s\n", sym_ranges_env);
            is = &ifs;
        } else {
            is = &iss;
        }

        if (!parse_symbolic_ranges(*is, sym_ranges)) {
            s2e_kill_state_printf(0, "Invalid S2E_SYMFILE_RANGES variable: %s", sym_ranges_env);
            return -1;
        }
    }

    unsigned block_size = 0x1000;

    if (argc == 2) {
        block_size = atoi(args[0]);
        ++args;
        --argc;
    }

    const char *filename = args[0];
    std::string cleaned_name = get_cleaned_name(filename);

    if (sym_ranges_env) {
        testcase_generator_register_concrete_file(filename, cleaned_name);
    }

    int fd = open(filename, flags);
    if (fd < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not open %s\n", filename);
        return -1;
    }

    // Determine the size of the file
    off_t size = lseek(fd, 0, SEEK_END);
    if (size < 0) {
        s2e_kill_state_printf(-1, "symbfile: could not determine the size of %s\n", filename);
        return -2;
    }

    if (sym_ranges_env) {
        if (!get_bitmap(sym_ranges, size, sym_bitmap)) {
            s2e_kill_state_printf(-1, "Symbolic ranges exceed the size of the concrete file");
            return -3;
        }
        ret = make_partial_file_symbolic(fd, cleaned_name, sym_bitmap);
    } else {
        ret = make_whole_file_symbolic(fd, size, block_size, cleaned_name);
    }

    close(fd);
    return ret;
}
