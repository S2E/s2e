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

#include <vmi/ElfDwarf.h>
#include <vmi/Vmi.h>

namespace {

struct hexval {
    uint64_t value;
    int width;

    hexval(uint64_t _value, int _width = 0) : value(_value), width(_width) {
    }
    hexval(void *_value, int _width = 0) : value((uint64_t) _value), width(_width) {
    }
};

inline llvm::raw_ostream &operator<<(llvm::raw_ostream &out, const hexval &h) {
    out << "0x";
    out.write_hex(h.value);
    return out;
}

void indent(llvm::raw_ostream &os, unsigned count) {
    while (count--) {
        os << ' ';
    }
}
} // namespace

namespace vmi {

VmiStructureType::StructMap VmiStructureType::s_structures;
VmiPrimitiveType::PrimitiveTypes VmiPrimitiveType::s_primitiveTypes;
VmiPointerType::PointerTypes VmiPointerType::s_pointerTypes;
VmiTypedefType::Typedefs VmiTypedefType::s_typedefs;
VmiArrayType::Arrays VmiArrayType::s_arrays;

template <typename T> static void cleanType(T &type) {
    auto it = type.begin();
    while (it != type.end()) {
        delete (*it).second;
    }
    type.clear();
}

void VmiCleanAllTypes() {

// Need to implement reference counting for that...
#if 0
    cleanType<VmiPrimitiveType::PrimitiveTypes>(VmiPrimitiveType::s_primitiveTypes);
    cleanType<VmiStructureType::StructMap>(VmiStructureType::s_structures);
    cleanType<VmiPointerType::PointerTypes>(VmiPointerType::s_pointerTypes);
    cleanType<VmiTypedefType::Typedefs>(VmiTypedefType::s_typedefs);
    cleanType<VmiArrayType::Arrays>(VmiArrayType::s_arrays);
#endif
}

const VmiPrimitiveType *VmiType::asPrimitive() const {
    return dynamic_cast<const VmiPrimitiveType *>(this);
}

const VmiPointerType *VmiType::asPointer() const {
    return dynamic_cast<const VmiPointerType *>(this);
}

const VmiArrayType *VmiType::asArray() const {
    return dynamic_cast<const VmiArrayType *>(this);
}

const VmiStructureType *VmiType::asStructure() const {
    return dynamic_cast<const VmiStructureType *>(this);
}

inline const VmiTypedefType *VmiType::asTypedef() const {
    return dynamic_cast<const VmiTypedefType *>(this);
}

const VmiType *VmiType::getRealType() const {
    const VmiType *currentType = this;
    const VmiTypedefType *td = nullptr;

    do {
        td = currentType->asTypedef();
        if (td) {
            currentType = td->getBaseType();
        }
    } while (td);

    return currentType;
}

const VmiType *Vmi::fetchType(const std::string &name) const {
    Types::const_iterator it = m_types.find(name);
    if (it != m_types.end()) {
        return (*it).second;
    }

    const VmiType *type = m_dwarf->getType(name);
    if (type != nullptr) {
        m_types[name] = type;
    }

    return type;
}

bool Vmi::nextPathElement(std::string &name, std::string &token, bool &followPointer) const {
    followPointer = false;

    if (name.size() == 0) {
        return false;
    }

    std::string::size_type pos;
    pos = name.find_first_of(".->");
    if (pos == std::string::npos) {
        token = name;
        name = "";
        return true;
    }

    token = name.substr(0, pos);
    if (name.at(pos) == '.') {
        name = name.substr(pos + 1);
        return true;
    }

    if (pos + 2 >= name.size()) {
        return false;
    }

    if ((name.at(pos) == '-') && (name.at(pos + 1) == '>')) {
        name = name.substr(pos + 2);
        followPointer = true;
        return true;
    }

    return false;
}

bool Vmi::parseExpression(const std::string &path, PathElements &elements) const {
    std::string pathLeft = path;
    std::string element;
    bool followPointer;
    while (nextPathElement(pathLeft, element, followPointer)) {
        PathElement pathElement;

        // Check if there is an array index
        std::string::size_type pos;
        pos = element.find_first_of("[");
        if (pos != std::string::npos) {
            std::string indexStr = element.substr(pos + 1);
            std::string::size_type arrayEndPos = indexStr.find_first_of("]");
            if (arrayEndPos == std::string::npos) {
                return false;
            }
            indexStr = indexStr.substr(0, arrayEndPos);
            pathElement.hasArrayIndex = true;
            pathElement.arrayIndex = atoi(indexStr.c_str());
            element = element.substr(0, pos);
        }

        pathElement.followPointer = followPointer;
        pathElement.name = element;
        elements.push_back(pathElement);
    }

    return pathLeft.size() == 0;
}

bool Vmi::allocateBufferAndFetchData(void *opaque, uint64_t address, const VmiType *type, void **buffer,
                                     unsigned *bufferSize) const {
    unsigned typeSize = type->getSize();
    if (!typeSize) {
        return false;
    }

    *buffer = malloc(typeSize);
    if (!*buffer) {
        return false;
    }

    *bufferSize = typeSize;

    if (!m_readMemory(opaque, address, *buffer, typeSize)) {
        free(*buffer);
        return false;
    }

    return true;
}

bool Vmi::dereferencePointer(const VmiType *type, uint64_t pointer, uint64_t *value, void *opaque) {
    // We've got a token followed by -> (e.g., member->...), means
    // that we have to dereference the pointer in order to follow it.
    const VmiPointerType *pointerType = dynamic_cast<const VmiPointerType *>(type);
    if (!pointerType) {
        return false;
    }

    void *nextAddressBuf;
    unsigned nextAddressBufSize;
    if (!allocateBufferAndFetchData(opaque, pointer, pointerType, &nextAddressBuf, &nextAddressBufSize)) {
        return false;
    }

    switch (pointerType->getSize()) {
        case sizeof(uint32_t):
            *value = *(uint32_t *) nextAddressBuf;
            break;
        case sizeof(uint64_t):
            *value = *(uint64_t *) nextAddressBuf;
            break;
        default:
            assert(false && "Unsupported pointer size");
    }

    free(nextAddressBuf);

    return true;
}

bool Vmi::getTypeAndAddress(const std::string &topLevelType, const std::string &path, uint64_t startAddress,
                            const VmiType **effectiveType, uint64_t *effectiveAddress, void *opaque) {
    const VmiType *type = fetchType(topLevelType)->getRealType();
    if (!type) {
        return false;
    }

    const VmiStructureType *structType = dynamic_cast<const VmiStructureType *>(type);
    if (!structType) {
        // If the top level is not a structure, it does not make sense to have a
        // non-empty path
        if (path.size() != 0) {
            return false;
        }
        *effectiveAddress = startAddress;
        *effectiveType = type;
        return true;
    }

    PathElements elements;
    if (!parseExpression(path, elements)) {
        return false;
    }

    const VmiType *currentType = type;
    assert(currentType);

    PathElements::const_iterator it;
    for (it = elements.begin(); it != elements.end(); ++it) {
        const PathElement &element = *it;

        structType = dynamic_cast<const VmiStructureType *>(currentType);
        if (!structType) {
            break;
        }

        uint64_t offset = 0;
        type = structType->getMember(element.name, &offset)->getRealType();
        if (!type) {
            return false;
        }

        startAddress += offset;

        if (type->getTypeEnum() == ARRAY) {
            if (element.hasArrayIndex) {
                const VmiArrayType *array = type->asArray();
                if (array->getElementsCount() <= element.arrayIndex) {
                    return false;
                }
                type = array->getBaseType();
                startAddress += element.arrayIndex * type->getSize();
            } else {
                // An array must be index or be the last item in the path
                ++it;
                break;
            }
        }

        if (type->getTypeEnum() == POINTER) {
            if (element.followPointer) {
                if (!dereferencePointer(type, startAddress, &startAddress, opaque)) {
                    return false;
                }
                const VmiPointerType *pointer = type->asPointer();
                type = get(pointer->getBaseType());
                if (!type) {
                    return false;
                }
            } else {
                ++it;
                break;
            }
        }

        currentType = type;
    }

    if (it != elements.end()) {
        return false;
    }

    *effectiveType = type;
    *effectiveAddress = startAddress;

    return true;
}

bool Vmi::getData(const std::string &topLevelType, const std::string &path, uint64_t address, void **data,
                  unsigned *size, void *opaque) {
    const VmiType *effectiveType;
    uint64_t effectiveAddress;

    if (!getTypeAndAddress(topLevelType, path, address, &effectiveType, &effectiveAddress, opaque)) {
        return false;
    }

    return allocateBufferAndFetchData(opaque, effectiveAddress, effectiveType, data, size);
}

bool Vmi::getString(const std::string &topLevelType, const std::string &path, uint64_t address, std::string &result,
                    void *opaque) {
    const VmiType *effectiveType;
    uint64_t effectiveAddress;

    if (!getTypeAndAddress(topLevelType, path, address, &effectiveType, &effectiveAddress, opaque)) {
        return false;
    }

    unsigned stringSize = (unsigned) -1;

    switch (effectiveType->getTypeEnum()) {
        // Check for an array of chars
        case ARRAY: {
            const VmiArrayType *array = effectiveType->asArray();
            const VmiPrimitiveType *baseType = dynamic_cast<const VmiPrimitiveType *>(array->getBaseType());
            if (!baseType || baseType->getSize() != 1) {
                return false;
            }
            stringSize = array->getElementsCount();
        } break;

        // Check for a pointer to char
        case POINTER: {
            const VmiPointerType *pointer = effectiveType->asPointer();
            if (!pointer) {
                return false;
            }

            const VmiType *ptrType = get(pointer->getBaseType());
            if (!ptrType) {
                return false;
            }

            const VmiPrimitiveType *primitive = ptrType->asPrimitive();
            if (!primitive || primitive->getSize() != 1) {
                return false;
            }

            if (!dereferencePointer(ptrType, effectiveAddress, &effectiveAddress, opaque)) {
                return false;
            }
        } break;

        default:
            return false;
    }

    while (stringSize > 0) {
        char chr;
        if (!m_readMemory(opaque, effectiveAddress, &chr, sizeof(chr))) {
            return false;
        }
        if (!chr) {
            break;
        }

        result = result + chr;
        --stringSize;
        ++effectiveAddress;
    }

    return true;
}

bool Vmi::getOffset(const VmiStructureType *struc, const std::string &path, uintptr_t &offset) const {
    const VmiType *type;

    offset = 0;

    PathElements elements;
    if (!parseExpression(path, elements)) {
        return false;
    }

    PathElements::const_iterator it;
    for (it = elements.begin(); it != elements.end(); ++it) {
        const PathElement element = *it;

        if (!struc || element.followPointer) {
            return false;
        }

        uintptr_t curoffset = 0;
        if (!(type = struc->getMember(element.name, &curoffset))) {
            return false;
        }
        offset += curoffset;

        if (element.hasArrayIndex) {
            offset += element.arrayIndex * type->getSize();
            const VmiArrayType *array = type->asArray();
            type = array->getBaseType();
        }

        struc = dynamic_cast<const VmiStructureType *>(type->getRealType());
    }

    return true;
}

bool Vmi::getOffset(const std::string &strucName, const std::string &path, uintptr_t &offset) const {
    const VmiType *type = fetchType(strucName)->getRealType();
    if (type == nullptr || type->getTypeEnum() != STRUCTURE) {
        return false;
    }

    const VmiStructureType *struc = dynamic_cast<const VmiStructureType *>(type->getRealType());
    return getOffset(struc, path, offset);
}

const VmiType *Vmi::get(const std::string &name) const {
    return fetchType(name);
}

bool Vmi::dump(llvm::raw_ostream &os, const std::string &strucName, uint64_t address, void *opaque,
               unsigned margin) const {
    const VmiType *type = fetchType(strucName);
    if (type == nullptr || type->getTypeEnum() != STRUCTURE) {
        return false;
    }

    const VmiStructureType *struc = dynamic_cast<const VmiStructureType *>(type);

    const VmiStructureType::MembersMap &members = struc->getMembers();
    VmiStructureType::MembersMap::const_iterator it = members.begin();

    indent(os, margin);
    os << "struct " << struc->getName() << " at " << hexval(address) << "\n";
    margin += 2;

    while (it != members.end()) {
        const VmiType *nextType = (*it).second.type;
        uint64_t offset = (*it).second.offset;
        const char *name = (const char *) (&(*it).second + 1);

        indent(os, margin);
        os << (char) 0xc3 << name << '=';

        switch (nextType->getTypeEnum()) {
            case POINTER:
            case PRIMITIVE: {
                uint64_t data;

                if (getPrimitiveData(nextType, address + offset, &data, opaque)) {
                    os << hexval(data);
                } else {
                    os << "UNREADABLE";
                }
                os << '\n';
            } break;

            case STRUCTURE: {
                os << "struct\n";
                dump(os, name, address + offset, opaque, margin + 2);
            } break;

            default:
                os << "Unknown type\n";
                break;
        }

        ++it;
    }

    return true;
}
} // namespace vmi
