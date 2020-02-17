///
/// Copyright (C) 2012-2013, Dependable Systems Laboratory, EPFL
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

extern "C" {
#include <dwarf.h>
#include <fcntl.h>
#include <libdwarf.h>
#include <libelf.h>
#include <stdio.h>
#include <unistd.h>
}

#include <map>
#include <sstream>

#include <vmi/ElfDwarf.h>
#include <vmi/Vmi.h>

//#define DEBUG_VMI

#define LOG_ERROR(res, die, err) printError(__FILE__, __LINE__, __FUNCTION__, res, die, err)

namespace vmi {

ElfDwarf::~ElfDwarf() {
    if (m_dbg) {
        for (Types::iterator it = m_types.begin(); it != m_types.end(); ++it) {
            dwarf_dealloc(m_dbg, (*it).second, DW_DLA_DIE);
        }

        Dwarf_Error err;
        dwarf_finish(m_dbg, &err);
    }

    for (unsigned i = 0; i < m_elfs.size(); ++i) {
        elf_end(m_elfs[i]);
    }

    if (m_arf) {
        elf_end(m_arf);
    }

    close(m_fd);
}

void ElfDwarf::printDie(Dwarf_Die die) {
    Dwarf_Error err;

    /* Display the tag name of the DIE */
    Dwarf_Half tag;
    const char *tag_name;
    dwarf_tag(die, &tag, &err);
    dwarf_get_TAG_name(tag, &tag_name);

    m_errs << tag_name << " ";
    printAttributes(die);
}

void ElfDwarf::printAttributes(Dwarf_Die die) {
    int res;
    Dwarf_Error err;
    Dwarf_Attribute *attributes;
    Dwarf_Signed attr_count;
    const char *attr_name = nullptr;

    m_errs << "ATTR: ";

    res = dwarf_attrlist(die, &attributes, &attr_count, &err);
    if (res != DW_DLV_OK) {
        return;
    }

    for (int ai = 0; ai < attr_count; ++ai) {
        Dwarf_Half attr;
        dwarf_whatattr(attributes[ai], &attr, &err);
        dwarf_get_AT_name(attr, &attr_name);

        m_errs << attr_name << ' ';

        dwarf_dealloc(m_dbg, attributes[ai], DW_DLA_ATTR);
    }
    dwarf_dealloc(m_dbg, attributes, DW_DLA_LIST);
    m_errs << '\n';
}

void ElfDwarf::printError(const char *file, int line, const char *func, int res, Dwarf_Die die, Dwarf_Error error) {
    std::stringstream ss;

    ss << "ERROR " << file << ":" << line << "@" << func << " - ";

    if (res == DW_DLV_ERROR) {
        ss << dwarf_errmsg(error);
    } else {
        ss << " error=" << error << " ";
    }

    m_errs << ss.str() << "\n";

    if (die) {
        printDie(die);
    }
}

bool ElfDwarf::getNameAttribute(Dwarf_Die die, const char **name) {
    int res;
    bool retval = false;
    Dwarf_Error err;
    Dwarf_Attribute name_attr;

    res = dwarf_attr(die, DW_AT_name, &name_attr, &err);
    if (res != DW_DLV_OK) {
#ifdef DEBUG_VMI
        LOG_ERROR(res, die, err);
#endif
        goto err1;
    }

    res = dwarf_formstring(name_attr, const_cast<char **>(name), &err);
    if (res != DW_DLV_OK) {
#ifdef DEBUG_VMI
        LOG_ERROR(res, die, err);
#endif
        goto err2;
    }

    retval = true;

err2:
    dwarf_dealloc(m_dbg, name_attr, DW_DLA_ATTR);
err1:

    return retval;
}

// XXX: rename method + memory cleanup
bool ElfDwarf::getTypeAttribute(Dwarf_Die die, Dwarf_Die *result_die) {
    bool retval = false;
    int res;
    Dwarf_Error err;
    Dwarf_Off type_offset;
    Dwarf_Attribute attribute;

    res = dwarf_attr(die, DW_AT_type, &attribute, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err1;
    }

    res = dwarf_global_formref(attribute, &type_offset, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err1;
    }

    res = dwarf_offdie(m_dbg, type_offset, result_die, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err2;
    }

    retval = true;

err2:
    dwarf_dealloc(m_dbg, attribute, DW_DLA_ATTR);
err1:
    return retval;
}

bool ElfDwarf::getByteSizeAttribute(Dwarf_Die die, Dwarf_Unsigned *size) {
    bool retval = false;
    int res;
    Dwarf_Error err;
    Dwarf_Attribute attribute;

    res = dwarf_attr(die, DW_AT_byte_size, &attribute, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err1;
    }

    res = dwarf_formudata(attribute, size, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err2;
    }

    retval = true;

err2:
    dwarf_dealloc(m_dbg, attribute, DW_DLA_ATTR);
err1:
    return retval;
}

bool ElfDwarf::buildType(Dwarf_Die type_die, VmiType **result) {
    *result = nullptr;

    Dwarf_Error err;
    int res;
    bool retval = false;
    const char *tag_name = nullptr;

    /* Get the type of the die */
    /* Display the tag name of the DIE */
    Dwarf_Half tag;
    res = dwarf_tag(type_die, &tag, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, type_die, err);
        goto err1;
    }

    dwarf_get_TAG_name(tag, &tag_name);

    switch (tag) {
        case DW_TAG_base_type: {
            retval = buildPrimitiveType(type_die, result);
        } break;

        case DW_TAG_pointer_type: {
            retval = buildPointerType(type_die, result);
        } break;

        case DW_TAG_typedef: {
            retval = buildTypedefType(type_die, result);
        } break;

        case DW_TAG_array_type: {
            retval = buildArrayType(type_die, result);
        } break;

        case DW_TAG_union_type: {
            retval = buildStructureType(type_die, true, result);
        }

        case DW_TAG_structure_type: {
            retval = buildStructureType(type_die, false, result);
        } break;

        case DW_TAG_volatile_type: {
            /* Ignore the volatile type for now */
            /* Process the attributes */
            if (!getTypeAttribute(type_die, &type_die)) {
                break;
            }

            return buildType(type_die, result);
        } break;

        default: {
            printAttributes(type_die);
            m_errs << "ElfDwarf::buildType: "
                   << "Unhandled tag: " << tag_name << '\n';
            retval = false;
        } break;
    }

err1:
    return retval;
}

bool ElfDwarf::buildPointerType(Dwarf_Die member_die, VmiType **result) {
    const char *type_name;

#ifdef DEBUG_VMI
    m_errs << "buildPointerType ";
    printDie(member_die);
#endif

    Dwarf_Die type_die;
    if (getTypeAttribute(member_die, &type_die)) {
        if (!getNameAttribute(type_die, &type_name)) {
            *result = VmiPointerType::get("");
        } else {
#ifdef DEBUG_VMI
            m_errs << "  type=" << type_name << '\n';
#endif
            *result = VmiPointerType::get(type_name);
        }
        dwarf_dealloc(m_dbg, type_die, DW_DLA_DIE);
    } else {
        *result = VmiPointerType::get("");
    }

    return true;
}

bool ElfDwarf::buildArrayType(Dwarf_Die die, VmiType **result) {
    bool retval = false;
    int res;
    Dwarf_Attribute upper_bound_attr;
    Dwarf_Unsigned elements;
    Dwarf_Die basetype_die;
    Dwarf_Error err;

    // Fetch the type of the array elements
    if (!getTypeAttribute(die, &basetype_die)) {
        goto err1;
    }

    // Fetch the array descriptor (number of elements)
    Dwarf_Die array_desc_die;
    Dwarf_Half array_desc_tag;
    res = dwarf_child(die, &array_desc_die, &err);
    if (res != DW_DLV_OK) {
        goto err2;
    }

    res = dwarf_tag(array_desc_die, &array_desc_tag, &err);
    if (array_desc_tag != DW_TAG_subrange_type) {
        goto err3;
    }

    res = dwarf_attr(array_desc_die, DW_AT_upper_bound, &upper_bound_attr, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err3;
    }

    res = dwarf_formudata(upper_bound_attr, &elements, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, die, err);
        goto err4;
    }

    // Build the type
    VmiType *base_type;
    if (!buildType(basetype_die, &base_type)) {
        goto err4;
    }

    *result = VmiArrayType::get(base_type, elements);

    retval = true;

err4:
    dwarf_dealloc(m_dbg, upper_bound_attr, DW_DLA_ATTR);
err3:
    dwarf_dealloc(m_dbg, array_desc_die, DW_DLA_DIE);
err2:
    dwarf_dealloc(m_dbg, basetype_die, DW_DLA_DIE);
err1:
    return retval;
}

bool ElfDwarf::buildTypedefType(Dwarf_Die die, VmiType **result) {
    Dwarf_Die basetype_die;
    const char *type_name;
    if (!getNameAttribute(die, &type_name)) {
        return false;
    }

#ifdef DEBUG_VMI
    m_errs << "ElfDwarf::buildTypedefType: " << type_name << '\n';
#endif

    *result = VmiTypedefType::get(type_name);
    if (*result) {
        return true;
    }

    if (!getTypeAttribute(die, &basetype_die)) {
        return false;
    }

    VmiType *base_type;
    if (!buildType(basetype_die, &base_type)) {
        return false;
    }

    *result = VmiTypedefType::get(type_name, base_type);
    return true;
}

bool ElfDwarf::buildPrimitiveType(Dwarf_Die member_die, VmiType **result) {
    int res;
    Dwarf_Error err;
    Dwarf_Unsigned size;
    res = dwarf_bytesize(member_die, &size, &err);
    if (res != DW_DLV_OK) {
        return false;
    }

    *result = VmiPrimitiveType::get(size);

    return true;
}

bool ElfDwarf::getMemberOffsetInBytes(Dwarf_Die member_die, unsigned *offset) {
    int res;
    bool retval = false;
    Dwarf_Error err;
    Dwarf_Attribute member_location_attr;
    Dwarf_Off block_offset;

    Dwarf_Signed loc_count;
    Dwarf_Locdesc *loc_buf;

    // DW_AT_data_member_location stores the member's offset from the start of the
    // parent structure
    res = dwarf_attr(member_die, DW_AT_data_member_location, &member_location_attr, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, member_die, err);
        goto err1;
    }

    // dwarf_whatform(member_location_attr, &form, &err);
    res = dwarf_attr_offset(member_die, member_location_attr, &block_offset, &err);
    if (res != DW_DLV_OK) {
        LOG_ERROR(res, member_die, err);
        goto err2;
    }

    // Fetch the list of locations
    res = dwarf_loclist(member_location_attr, &loc_buf, &loc_count, &err);
    if (res != DW_DLV_OK || loc_count != 1) {
        LOG_ERROR(res, member_die, err);
        goto err2;
    }

    // We support only one location entry
    if (loc_buf[0].ld_cents != 1) {
        LOG_ERROR(res, member_die, err);
        goto err3;
    }

    // The type of the location must be DW_OP_plus_uconst
    if (loc_buf[0].ld_s[0].lr_atom != DW_OP_plus_uconst) {
        m_errs << "ElfDwarf::getMemberOffsetInBytes: location atom must be "
                  "DW_OP_plus_uconst\n";
        goto err3;
    }

    *offset = loc_buf[0].ld_s[0].lr_number;
    retval = true;

err3:
    dwarf_dealloc(m_dbg, loc_buf[0].ld_s, DW_DLA_LOC_BLOCK);
    dwarf_dealloc(m_dbg, loc_buf, DW_DLA_LOCDESC);
err2:
    dwarf_dealloc(m_dbg, member_location_attr, DW_DLA_ATTR);
err1:
    return retval;
}

bool ElfDwarf::buildMemberType(Dwarf_Die member_die, std::string &member_name, VmiStructureType::Member &result,
                               bool parentIsUnion) {
    Dwarf_Die type_die = 0;

    member_name = getVariableName("anonymous_member", member_die);

#ifdef DEBUG_VMI
    m_errs << "ElfDwarf::buildMemberType: " << member_name << '\n';
#endif

    result.offset = 0;
    if (!parentIsUnion) {
        if (!getMemberOffsetInBytes(member_die, &result.offset)) {
            return false;
        }
    }

    /* Get the type of the member */
    if (!getTypeAttribute(member_die, &type_die)) {
        return false;
    }

    return buildType(type_die, &result.type);
}

std::string ElfDwarf::getVariableName(const std::string &anonPrefix, Dwarf_Die die) {
    const char *name = nullptr;
    getNameAttribute(die, &name);

    if (name) {
        return name;
    } else {
        std::stringstream ss;
        ss << anonPrefix << die;
        return ss.str();
    }
}

bool ElfDwarf::buildStructureType(Dwarf_Die die, bool isUnion, VmiType **type) {
    Dwarf_Error err;
    int res;

    std::string struct_name = getVariableName("anonymous_struct_", die);

    VmiStructureType *existing_struct = VmiStructureType::get(struct_name);
    if (existing_struct) {
#ifdef DEBUG_VMI
        m_errs << "ElfDwarf::buildStructure: found " << struct_name << "\n";
#endif
        *type = existing_struct;
        return true;
    }

#ifdef DEBUG_VMI
    m_errs << "ElfDwarf::buildStructure: " << struct_name << "\n";
    printDie(die);
#endif

    /* Process the structure members */

    Dwarf_Die kid, old_kid = nullptr;
    VmiStructureType::Members members;
    std::vector<std::string> members_name;

    /* Process the children */
    res = dwarf_child(die, &kid, &err);
    if (res == DW_DLV_OK) {
        do {
            if (old_kid) {
                dwarf_dealloc(m_dbg, old_kid, DW_DLA_DIE);
            }

            VmiStructureType::Member result;
            std::string member_name;
            if (!buildMemberType(kid, member_name, result, isUnion)) {
                m_errs << "ElfDwarf::buildStructure: Could not build member " << member_name << " of structure "
                       << struct_name << '\n';
                break;
            }

            members.push_back(result);
            members_name.push_back(member_name);

            old_kid = kid;
        } while (dwarf_siblingof(m_dbg, old_kid, &kid, &err) == DW_DLV_OK);
        dwarf_dealloc(m_dbg, old_kid, DW_DLA_DIE);
    }

    Dwarf_Unsigned strucSize;
    if (!getByteSizeAttribute(die, &strucSize)) {
#ifdef DEBUG_VMI
        m_errs << "ElfDwarf::buildStructure: could not determine the size\n";
#endif
        return false;
    }

    *type = VmiStructureType::build(struct_name, members, members_name, isUnion, strucSize);
    return true;
}

/* get all the data in .debug_types */
bool ElfDwarf::processTypes() {
    int res;
    Dwarf_Error err;
    Dwarf_Type *typebuf = nullptr;
    Dwarf_Signed count = 0;

    res = dwarf_get_pubtypes(m_dbg, &typebuf, &count, &err);
    if (res != DW_DLV_ERROR && res != DW_DLV_NO_ENTRY) {
        char *name;
        Dwarf_Off die_off = 0;
        Dwarf_Off cu_off = 0;

        for (int i = 0; i < count; i++) {
            res = dwarf_pubtype_name_offsets(typebuf[i], &name, &die_off, &cu_off, &err);
            if (res != DW_DLV_OK) {
                continue;
            }

            Dwarf_Die die = 0;
            res = dwarf_offdie(m_dbg, die_off, &die, &err);
            if (res != DW_DLV_OK) {
                continue;
            }

            m_types[name] = die;
        }
    }

    if (res == DW_DLV_ERROR) {
        LOG_ERROR(res, nullptr, err);
    }

    dwarf_pubtypes_dealloc(m_dbg, typebuf, count);

    return true;
}

bool ElfDwarf::processFile(Elf *elf) {
    int dres;
    Dwarf_Error err;

    dres = dwarf_elf_init(elf, DW_DLC_READ, nullptr, nullptr, &m_dbg, &err);
    if (dres == DW_DLV_NO_ENTRY) {
        LOG_ERROR(dres, nullptr, err);
        m_errs << "The given descriptor has no DWARF data\n";
        return false;
    }

    if (dres != DW_DLV_OK) {
        LOG_ERROR(dres, nullptr, err);
    }

    dwarf_set_frame_rule_initial_value(m_dbg, DW_FRAME_UNDEFINED_VAL);
    dwarf_set_frame_rule_table_size(m_dbg, 100);
    dwarf_set_frame_cfa_value(m_dbg, DW_FRAME_CFA_COL3);
    dwarf_set_frame_same_value(m_dbg, DW_FRAME_SAME_VAL);
    dwarf_set_frame_undefined_value(m_dbg, DW_FRAME_UNDEFINED_VAL);

    /* Get address size and largest representable address */
    dres = dwarf_get_address_size(m_dbg, &m_elf_address_size, &err);
    if (dres != DW_DLV_OK) {
        LOG_ERROR(dres, nullptr, err);
        return false;
    }

    m_elf_max_address = (m_elf_address_size == sizeof(uint64_t)) ? 0xffffffffffffffffULL : 0xffffffff;

    processTypes();

    return true;
}

bool ElfDwarf::initialize() {
    Elf *elf;
    m_arf = elf_begin(m_fd, ELF_C_READ, nullptr);
    Elf_Cmd cmd = ELF_C_READ;

    if (elf_kind(m_arf) == ELF_K_AR) {
        m_errs << "Can't parse archives " << m_fileName << '\n';
        return false;
    }

    while ((elf = elf_begin(m_fd, cmd, m_arf)) != 0) {
        m_elfs.push_back(elf);

        Elf32_Ehdr *eh32 = elf32_getehdr(elf);
        Elf64_Ehdr *eh64 = elf64_getehdr(elf);

        if (eh64) {
            m_errs << "64-bits binaries not supported yet...\n";
            return false;
        }

        if (eh32) {
            processFile(elf);
            break;
        }

        cmd = elf_next(elf);
    }

    return true;
}

std::shared_ptr<ElfDwarf> ElfDwarf::get(llvm::raw_ostream &errs, const std::string &elfBinary) {
    std::shared_ptr<ElfDwarf> elfDwarf = nullptr;

    elf_version(EV_NONE);
    if (elf_version(EV_CURRENT) == EV_NONE) {
        errs << "dwarfdump: libelf.a out of date.\n";
        return nullptr;
    }

    int fd = open(elfBinary.c_str(), O_RDONLY);
    if (fd < 0) {
        errs << "Could not find file " << elfBinary << '\n';
        return nullptr;
    }

    elfDwarf = std::shared_ptr<ElfDwarf>{new ElfDwarf(errs, fd, elfBinary)};
    if (!elfDwarf->initialize()) {
        return nullptr;
    }

    return elfDwarf;
}

const VmiType *ElfDwarf::getType(const std::string &name) {
    Types::const_iterator it = m_types.find(name);
    if (it == m_types.end()) {
        return nullptr;
    }

    VmiType *result = nullptr;
    if (!buildType((*it).second, &result)) {
        return nullptr;
    }

    return result;
}
} // namespace vmi
