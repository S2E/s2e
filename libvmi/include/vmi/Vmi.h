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

#ifndef S2E_VMI_H

#define S2E_VMI_H

#include <assert.h>
#include <inttypes.h>
#include <llvm/ADT/StringMap.h>
#include <llvm/Support/raw_ostream.h>
#include <map>
#include <string>
#include <vector>

namespace vmi {

class ElfDwarf;
class VmiPrimitiveType;
class VmiPointerType;
class VmiArrayType;
class VmiStructureType;
class VmiTypedefType;

enum VmiTypeEnum { PRIMITIVE, POINTER, STRUCTURE, TYPEDEF, ARRAY, INVALID };

class VmiType {
protected:
    VmiTypeEnum m_type;

    VmiType(VmiTypeEnum type) : m_type(type) {
    }

public:
    virtual ~VmiType() {
    }
    virtual unsigned getSize() const = 0;
    virtual const std::string &getName() const = 0;
    VmiTypeEnum getTypeEnum() const {
        return m_type;
    }

    inline const VmiPrimitiveType *asPrimitive() const;
    inline const VmiPointerType *asPointer() const;
    inline const VmiArrayType *asArray() const;
    inline const VmiStructureType *asStructure() const;
    inline const VmiTypedefType *asTypedef() const;

    // Goes down the typedef chains and returns the actual type
    const VmiType *getRealType() const;
};

// XXX: signed vs unsigned
class VmiPrimitiveType : public VmiType {
    typedef std::map<unsigned, VmiPrimitiveType *> PrimitiveTypes;
    static PrimitiveTypes s_primitiveTypes;
    std::string m_name;
    unsigned m_size;

    VmiPrimitiveType(unsigned size) : VmiType(PRIMITIVE), m_size(size) {
    }

public:
    static VmiPrimitiveType *get(unsigned size) {
        PrimitiveTypes::iterator it = s_primitiveTypes.find(size);
        if (it == s_primitiveTypes.end()) {
            VmiPrimitiveType *ret = new VmiPrimitiveType(size);

            switch (ret->m_size) {
                case sizeof(uint8_t):
                    ret->m_name = "char";
                    break;
                case sizeof(uint16_t):
                    ret->m_name = "short";
                    break;
                case sizeof(uint32_t):
                    ret->m_name = "int";
                    break;
                case sizeof(uint64_t):
                    ret->m_name = "long";
                    break;
                default:
                    ret->m_name = "unknown";
                    break;
            }

            s_primitiveTypes[size] = ret;
            return ret;
        }
        return (*it).second;
    }

    virtual unsigned getSize() const {
        return m_size;
    }

    const std::string &getName() const {
        return m_name;
    }
};

class VmiPointerType : public VmiType {
    typedef std::map<std::string, VmiPointerType *> PointerTypes;
    static PointerTypes s_pointerTypes;

    // empty string means void
    std::string m_baseType;
    std::string m_name;

    VmiPointerType(const std::string &baseType) : VmiType(POINTER) {
        m_baseType = baseType;
        m_name = m_baseType + "*";
    }

public:
    static VmiPointerType *get(const std::string &baseType) {
        PointerTypes::iterator it = s_pointerTypes.find(baseType);
        if (it == s_pointerTypes.end()) {
            VmiPointerType *ret = new VmiPointerType(baseType);
            s_pointerTypes[baseType] = ret;
            return ret;
        }
        return (*it).second;
    }

    virtual unsigned getSize() const {
        return sizeof(uint32_t); // XXX
    }

    const std::string &getName() const {
        return m_name;
    }

    const std::string &getBaseType() const {
        return m_baseType;
    }
};

class VmiArrayType : public VmiType {
    typedef std::pair<const VmiType *, unsigned> ArrayDescriptor;
    typedef std::map<ArrayDescriptor, VmiArrayType *> Arrays;

    static Arrays s_arrays;

    unsigned m_elements;
    const VmiType *m_baseType;
    // XXX: names don't make sense here...
    std::string m_name;

    VmiArrayType(const VmiType *base, unsigned elements) : VmiType(ARRAY) {
        m_elements = elements;
        m_baseType = base;
    }

public:
    static VmiArrayType *get(const VmiType *base, unsigned elements) {
        Arrays::iterator it = s_arrays.find(ArrayDescriptor(base, elements));
        if (it == s_arrays.end()) {
            VmiArrayType *ret = new VmiArrayType(base, elements);
            s_arrays[ArrayDescriptor(base, elements)] = ret;
            return ret;
        }
        return (*it).second;
    }

    unsigned getElementsCount() const {
        return m_elements;
    }

    const VmiType *getBaseType() const {
        return m_baseType;
    }

    virtual unsigned getSize() const {
        return m_baseType->getSize();
    }

    const std::string &getName() const {
        return m_name;
    }
};

class VmiTypedefType : public VmiType {
    typedef std::map<std::string, VmiTypedefType *> Typedefs;
    static Typedefs s_typedefs;

    std::string m_name;
    const VmiType *m_baseType;

    VmiTypedefType(const std::string &name, const VmiType *type) : VmiType(TYPEDEF) {
        m_name = name;
        m_baseType = type;
    }

public:
    static VmiTypedefType *get(const std::string &name) {
        Typedefs::iterator it = s_typedefs.find(name);
        if (it == s_typedefs.end()) {
            return nullptr;
        }
        return (*it).second;
    }

    static VmiTypedefType *get(const std::string &name, const VmiType *type) {
        Typedefs::iterator it = s_typedefs.find(name);
        if (it == s_typedefs.end()) {
            VmiTypedefType *ret = new VmiTypedefType(name, type);
            s_typedefs[name] = ret;
            return ret;
        }
        assert((*it).second->m_baseType == type);
        return (*it).second;
    }

    virtual unsigned getSize() const {
        return m_baseType->getSize();
    }

    const VmiType *getBaseType() const {
        return m_baseType;
    }

    const std::string &getName() const {
        return m_name;
    }
};

class VmiStructureType : public VmiType {
public:
    struct Member {
        unsigned offset;
        VmiType *type;
    };

    typedef llvm::StringMap<VmiStructureType *> StructMap;
    typedef llvm::StringMap<Member> MembersMap;
    typedef std::vector<Member> Members;

protected:
    static StructMap s_structures;

    std::string m_name;
    MembersMap m_members;
    unsigned m_size;
    bool m_union;

    VmiStructureType(const std::string &name, bool isUnion) : VmiType(STRUCTURE) {
        m_name = name;
        m_size = 0;
        m_union = isUnion;
    }

public:
    const MembersMap &getMembers() const {
        return m_members;
    }

    static VmiStructureType *get(const std::string &name) {
        StructMap::iterator it = s_structures.find(name);
        if (it != s_structures.end()) {
            return (*it).second;
        }
        return nullptr;
    }

    static VmiStructureType *build(const std::string &name, const Members &members,
                                   const std::vector<std::string> &memberNames, bool isUnion, unsigned size) {
        assert(members.size() == memberNames.size());
        assert(get(name) == nullptr);

        VmiStructureType *ret = new VmiStructureType(name, isUnion);

        for (unsigned i = 0; i < members.size(); ++i) {
            ret->m_members[memberNames[i]] = members[i];
        }

        ret->m_size = size;
        s_structures[name] = ret;
        return ret;
    }

    const std::string &getName() const {
        return m_name;
    }

    virtual unsigned getSize() const {
        return m_size;
    }

    const VmiType *getMember(const std::string &name, uintptr_t *offset) const {
        MembersMap::const_iterator it = m_members.find(name);
        if (it != m_members.end()) {
            if (offset) {
                *offset = (*it).second.offset;
            }
            return (*it).second.type;
        }
        return nullptr;
    }
};

struct PathElement {
    std::string name;
    bool followPointer;
    bool hasArrayIndex;
    unsigned arrayIndex;

    PathElement() {
        followPointer = hasArrayIndex = false;
        arrayIndex = 0;
    }
};

typedef std::vector<PathElement> PathElements;

class Vmi {
private:
    typedef llvm::StringMap<const VmiType *> Types;
    typedef bool (*ReadMemoryCb)(void *opaque, uint64_t address, void *dest, unsigned size);

    mutable Types m_types;
    std::shared_ptr<ElfDwarf> m_dwarf;
    ReadMemoryCb m_readMemory;

    const VmiType *fetchType(const std::string &name) const;

    bool nextPathElement(std::string &name, std::string &token, bool &followPointer) const;
    bool allocateBufferAndFetchData(void *opaque, uint64_t address, const VmiType *type, void **buffer,
                                    unsigned *bufferSize) const;
    bool dereferencePointer(const VmiType *type, uint64_t pointer, uint64_t *value, void *opaque);

    bool parseExpression(const std::string &path, PathElements &elements) const;

    Vmi(std::shared_ptr<ElfDwarf> dwarf) : m_dwarf(dwarf) {
        m_readMemory = nullptr;
    }

public:
    static std::shared_ptr<Vmi> get(std::shared_ptr<ElfDwarf> dwarf) {
        return std::shared_ptr<Vmi>{new Vmi(dwarf)};
    }

    void registerCallbacks(ReadMemoryCb cb) {
        m_readMemory = cb;
    }

    bool dump(llvm::raw_ostream &os, const std::string &strucName, uint64_t address, void *opaque,
              unsigned margin) const;

    /**
     * Returns the offset relative to the start of the top-level structure.
     * E.g., if path="se.on_rq" and struct="task_struct", the function follows the
     * follows the member variable of task_struct se and returns
     * the offset of on_rq relative to the start of task_struct.
     */
    bool getOffset(const VmiStructureType *struc, const std::string &path, uint64_t &offset) const;
    bool getOffset(const std::string &strucName, const std::string &path, uint64_t &offset) const;

    bool getTypeAndAddress(const std::string &topLevelType, const std::string &path, uint64_t startAddress,
                           const VmiType **effectiveType, uint64_t *effectiveAddress, void *opaque);

    const VmiType *get(const std::string &name) const;

    /**
     * Traverses the specified data structures and stores the data of the last
     * member in the passed buffer.
     */
    bool getData(const std::string &topLevelType, const std::string &path, uint64_t address, void **data,
                 unsigned *size, void *opaque);

    template <typename T>
    bool get(const std::string &topLevelType, const std::string &path, uint64_t address, T *data, void *opaque) {
        T *retdata;
        uint32_t size;

        bool res = getData(topLevelType, path, address, (void **) &retdata, &size, opaque);
        if (!res) {
            return false;
        }

        if (size != sizeof(T)) {
            free(retdata);
            return false;
        }

        *data = *retdata;
        free(retdata);
        return true;
    }

    template <typename T> bool get(const VmiType *type, uint64_t address, T *data, void *opaque) const {
        void *retdata;
        uint32_t size;

        if (!allocateBufferAndFetchData(opaque, address, type, &retdata, &size)) {
            return false;
        }

        if (size != sizeof(T)) {
            free(retdata);
            return false;
        }

        *data = *static_cast<T *>(retdata);
        free(retdata);
        return true;
    }

    bool getPrimitiveData(const VmiType *type, uint64_t address, uint64_t *data, void *opaque) const {
        const VmiType *primitiveType = dynamic_cast<const VmiPrimitiveType *>(type);
        if (!primitiveType) {
            const VmiPointerType *pointerType = dynamic_cast<const VmiPointerType *>(type);
            if (!pointerType) {
                return false;
            }
            uint32_t retdata = 0;
            bool b = get(pointerType, address, &retdata, opaque);
            *data = retdata;
            return b;
        }

        switch (type->getSize()) {
            case sizeof(uint8_t):
                return get(primitiveType, address, (uint8_t *) data, opaque);
            case sizeof(uint16_t):
                return get(primitiveType, address, (uint16_t *) data, opaque);
            case sizeof(uint32_t):
                return get(primitiveType, address, (uint32_t *) data, opaque);
            case sizeof(uint64_t):
                return get(primitiveType, address, (uint64_t *) data, opaque);
        }

        return false;
    }

    bool getString(const std::string &topLevelType, const std::string &path, uint64_t address, std::string &result,
                   void *opaque);
};
} // namespace vmi

#endif
