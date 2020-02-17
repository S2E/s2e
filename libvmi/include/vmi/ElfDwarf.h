///
/// Copyright (C) 2012, Dependable Systems Laboratory, EPFL
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

#ifndef S2E_VMI_ELFDWARF_H

#define S2E_VMI_ELFDWARF_H

extern "C" {
#include <libdwarf.h>
#include <libelf.h>
}

#include <llvm/ADT/StringMap.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <memory>
#include "Vmi.h"

namespace vmi {

class ElfDwarf {
private:
    typedef llvm::StringMap<Dwarf_Die> Types;
    llvm::raw_ostream &m_errs;
    int m_fd;

    Elf *m_arf;
    std::vector<Elf *> m_elfs;

    std::string m_fileName;
    Types m_types;
    Dwarf_Debug m_dbg;

    /* Largest representable address offset */
    Dwarf_Addr m_elf_max_address;

    /* Target pointer size */
    Dwarf_Half m_elf_address_size;

    ElfDwarf(llvm::raw_ostream &errs, int fd, const std::string &fileName)
        : m_errs(errs), m_fd(fd), m_arf(nullptr), m_fileName(fileName) {
    }
    bool initialize();
    bool processFile(Elf *elf);
    bool processTypes();

    bool buildMemberType(Dwarf_Die member_die, std::string &member_name, VmiStructureType::Member &result,
                         bool parentIsUnion);

    bool buildPrimitiveType(Dwarf_Die member_die, VmiType **result);
    bool buildPointerType(Dwarf_Die member_die, VmiType **result);
    bool buildArrayType(Dwarf_Die die, VmiType **result);
    bool buildTypedefType(Dwarf_Die member_die, VmiType **result);
    bool buildStructureType(Dwarf_Die die, bool isUnion, VmiType **type);
    bool buildType(Dwarf_Die type_die, VmiType **result);

    bool getMemberOffsetInBytes(Dwarf_Die member_die, unsigned *offset);

    bool getTypeAttribute(Dwarf_Die die, Dwarf_Die *result_die);
    bool getNameAttribute(Dwarf_Die die, const char **name);
    bool getByteSizeAttribute(Dwarf_Die die, Dwarf_Unsigned *size);

    std::string getVariableName(const std::string &anonPrefix, Dwarf_Die die);

    void printDie(Dwarf_Die die);
    void printAttributes(Dwarf_Die die);
    void printError(const char *file, int line, const char *func, int res, Dwarf_Die die, Dwarf_Error error);

public:
    ~ElfDwarf();
    static std::shared_ptr<ElfDwarf> get(llvm::raw_ostream &errs, const std::string &elfBinary);

    const VmiType *getType(const std::string &name);
};
} // namespace vmi

#endif
