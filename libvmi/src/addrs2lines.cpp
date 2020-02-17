///
/// Copyright (C) 2019, Cyberhaven
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

///
/// addrs2lines is a much a faster version of addr2line from binutils.
///
/// It can be used for two purposes:
/// - Dump line information from Dwarf debug info into a json file
/// - Compute code coverage by translating a set of addresses passed on stdin
///   to the corresponding files/lines/function information.
///

#include <fcntl.h>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <llvm/ADT/DenseSet.h>
#include <llvm/Support/CommandLine.h>

#include <dwarf.h>
#include <libdwarf.h>

#define RAPIDJSON_HAS_STDSTRING 1
#include <rapidjson/document.h>
#include <rapidjson/encodings.h>
#include <rapidjson/istreamwrapper.h>
#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>

using namespace llvm;

namespace {
cl::opt<std::string> File("file", cl::desc("Binary file"), cl::Positional);
cl::opt<bool> GenerateCoverage("coverage",
                               cl::desc("Generate coverage for the address list passed on the standard input"),
                               cl::Optional);
cl::opt<bool> IncludeCoveredFilesOnly(
    "include-covered-files-only",
    cl::desc(
        "The coverage report includes all files by default. Use this option to exclude ones that have no coverage."),
    cl::Optional);
cl::opt<bool> JsonPretty("pretty", cl::desc("Prettify Json output"), cl::Optional);
} // namespace

///////////////////////////////////////////////////////////////////
using StringPtr = std::shared_ptr<const std::string>;

struct StringPtrHash {
    size_t operator()(const StringPtr &Str) const {
        return std::hash<std::string>{}(*Str.get());
    }
};

struct StringPtrEq {
    bool operator()(const StringPtr &A, const StringPtr &B) const {
        return *A.get() == *B.get();
    }
};

// Debug information stores many identical strings in different places.
// In order to be efficient, we make sure that strings are unique and
// refer to them through shared pointers.
using UniqueStringSet = std::unordered_set<StringPtr, StringPtrHash, StringPtrEq>;

static StringPtr GetUniqueString(UniqueStringSet &StrSet, const std::string &Str) {
    auto Ret = std::make_shared<const std::string>(Str);

    auto It = StrSet.find(Ret);
    if (It != StrSet.end()) {
        return *It;
    }
    StrSet.insert(Ret);

    return Ret;
}
///////////////////////////////////////////////////////////////////

struct AddressRange {
    uint64_t Start;
    unsigned Length;

    AddressRange() : Start(0), Length(0) {
    }
    AddressRange(uint64_t Start_, unsigned Length_) : Start(Start_), Length(Length_) {
    }

    bool operator<(const AddressRange &A2) const {
        return Start + Length <= A2.Start;
    }
};

struct AddressInfo {
    StringPtr File;
    uint32_t Line;
};

struct FunctionInfo {
    StringPtr Name;

    FunctionInfo(StringPtr Name_) : Name(Name_) {
    }
    FunctionInfo() {
    }
};

using LinesSet = std::set<uint32_t>;
using FunctionsSet = std::unordered_set<StringPtr, StringPtrHash, StringPtrEq>;

using AddressToFunctionMap = std::map<AddressRange, FunctionInfo>;
using AddressToLocation = std::unordered_map<uint64_t, AddressInfo>;

using Addresses = llvm::DenseSet<uint64_t>;
using LineToAddresses = std::map<uint32_t, Addresses>;
using FunctionToAddresses = std::unordered_map<StringPtr, AddressRange>;

struct CompilationUnitInfo {
    LineToAddresses Lines;
    FunctionToAddresses Functions;
};

using FileToCUInfo = std::unordered_map<StringPtr, CompilationUnitInfo, StringPtrHash, StringPtrEq>;

///
/// \brief The DebugInfo structure holds the processed line and function information.
///
struct DebugInfo {
    ///
    /// \brief Strings is a set of shared pointers to unique strings.
    /// When a function needs to store a string, it uses this structure
    /// to make sure that string doesn't already exist.
    ///
    UniqueStringSet Strings;

    ///
    /// \brief AddressCache allows a quick mapping between an address and
    /// a program location (line, file).
    ///
    AddressToLocation AddressCache;

    ///
    /// \brief Functions provides a map from an address to a function name.
    ///
    AddressToFunctionMap Functions;

    ///
    /// \brief FileToLines stores line and function information for each source file.
    ///
    FileToCUInfo FileToLines;
};

///////////////////////////////////////////////////////////////////

///
/// \brief The CompilationUnitCoverage structure stores the coverage report
/// for a given source file.
///
/// It does not store line count information, as it's not really meaningful.
/// The input consist of a list of address ranges. A range represents
/// a basic block. So consecutive addresses might correspond to the same
/// line, counting it several times.
///
struct CompilationUnitCoverage {

    LinesSet Lines;
    FunctionsSet Functions;
};

using CoverageMap = std::unordered_map<StringPtr, CompilationUnitCoverage, StringPtrHash, StringPtrEq>;

///////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////

///
/// \brief getString retrives the string associated with the given DWARF attribute.
/// \return true if the string could be retrieved, false otherwise.
///
static bool getString(Dwarf_Debug Dbg, Dwarf_Attribute Attr, std::string &Str) {
    int Res;
    char *AttrStr;
    Dwarf_Error Error;
    Dwarf_Half Form;

    Res = dwarf_whatform(Attr, &Form, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    if (Form != DW_FORM_string && Form != DW_FORM_strp) {
        return false;
    }

    Res = dwarf_formstring(Attr, &AttrStr, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    Str = AttrStr;

    dwarf_dealloc(Dbg, AttrStr, DW_DLA_STRING);

    return true;
}

///
/// \brief getFunctionInfo retrieves the function information associated with the given
/// debug information entriy (Die).
///
/// \param Dbg The DWARF debug info descriptor
/// \param Die The debug information entry for the sub program
/// \param LowPc The start address of the function
/// \param HighPc The last address of the function
/// \param Name The function name
/// \return true if the function information could be retrieved, false otherwise
///
static bool getFunctionInfo(Dwarf_Debug Dbg, Dwarf_Die Die, uint64_t &LowPc, uint64_t &HighPc, std::string &Name) {
    int Res;
    Dwarf_Error Error;
    Dwarf_Half Tag, Form;
    Dwarf_Addr LowPcAddr, HighPcAddr;
    enum Dwarf_Form_Class FormClass;
    Dwarf_Attribute AttrName;

    Res = dwarf_tag(Die, &Tag, &Error);
    if (Res != DW_DLV_OK || Tag != DW_TAG_subprogram) {
        return false;
    }

    Res = dwarf_lowpc(Die, &LowPcAddr, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    LowPc = LowPcAddr;

    Res = dwarf_highpc_b(Die, &HighPcAddr, &Form, &FormClass, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    if (FormClass == DW_FORM_CLASS_ADDRESS) {
        HighPc = HighPcAddr;
    } else if (FormClass == DW_FORM_CLASS_CONSTANT) {
        HighPc = LowPc + HighPcAddr;
    } else {
        return false;
    }

    Res = dwarf_attr(Die, DW_AT_name, &AttrName, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    auto Ret = getString(Dbg, AttrName, Name);
    dwarf_dealloc(Dbg, AttrName, DW_DLA_ATTR);
    return Ret;
}

///
/// \brief getFunctions retrieves all functions of a compilation unit
/// and stores their metadata into the DebugInfo struction.
///
/// \param Dbg The DWARF debug info descriptor
/// \param CuDie The debug info entry of the compilation unit
/// \param FilePath The file path of the compilation unit
/// \param Info The debug info structure where to put the data
/// \return true if the function information could be retrieved, false otherwise
///
static bool getFunctions(Dwarf_Debug Dbg, Dwarf_Die CuDie, const StringPtr &FilePath, DebugInfo &Info) {
    Dwarf_Error Error = nullptr;
    Dwarf_Die SDie = nullptr, Die = nullptr;
    Dwarf_Half tag = 0;
    int Res = 0;

    Res = dwarf_child(CuDie, &Die, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    do {
        Res = dwarf_tag(Die, &tag, &Error);
        if (Res == DW_DLV_OK && tag == DW_TAG_subprogram) {
            uint64_t LowPc, HighPc;
            std::string Name;
            if (getFunctionInfo(Dbg, Die, LowPc, HighPc, Name)) {
                auto UniqueName = GetUniqueString(Info.Strings, Name);
                auto Range = AddressRange(LowPc, HighPc - LowPc);
                Info.Functions[Range] = FunctionInfo(UniqueName);
                Info.FileToLines[FilePath].Functions[UniqueName] = Range;
            }
        }

        Res = dwarf_siblingof(Dbg, Die, &SDie, &Error);

        dwarf_dealloc(Dbg, Die, DW_DLA_DIE);

        Die = SDie;
    } while (Res == DW_DLV_OK);

    return true;
}

///
/// \brief getCompilationUnitPath retrieves the source file path of the given compilation unit.
/// \param Dbg The DWARF debug info descriptor
/// \param CuDie The debug info entry of the compilation unit
/// \param FilePath The file path of the compilation unit
/// \return true if the path could be retrieved, false otherwise
///
static bool getCompilationUnitPath(Dwarf_Debug Dbg, Dwarf_Die CueDie, std::string &Path) {
    int Res = 0;
    Dwarf_Error Error;
    Dwarf_Attribute AttrCompDir = nullptr, AttrName = nullptr;
    char *CompDirStr = nullptr, *NameStr = nullptr;

    Res = dwarf_attr(CueDie, DW_AT_comp_dir, &AttrCompDir, &Error);
    if (Res == DW_DLV_OK) {
        Res = dwarf_formstring(AttrCompDir, &CompDirStr, &Error);
    }

    Res = dwarf_attr(CueDie, DW_AT_name, &AttrName, &Error);
    if (Res == DW_DLV_OK) {
        Res = dwarf_formstring(AttrName, &NameStr, &Error);
    }

    std::stringstream SS;

    if (CompDirStr) {
        SS << CompDirStr << "/";
    }

    if (NameStr) {
        SS << NameStr;
    }

    Path = SS.str();

    if (CompDirStr) {
        dwarf_dealloc(Dbg, CompDirStr, DW_DLA_STRING);
    }

    if (NameStr) {
        dwarf_dealloc(Dbg, NameStr, DW_DLA_STRING);
    }

    if (AttrCompDir) {
        dwarf_dealloc(Dbg, AttrCompDir, DW_DLA_ATTR);
    }

    if (AttrName) {
        dwarf_dealloc(Dbg, AttrName, DW_DLA_ATTR);
    }

    return Path.size() > 0;
}

///
/// \brief getLineInfo retrieves line and information for the given compilation unit.
///
/// \param CuDie The debug info entry of the compilation unit
/// \param Info The debug info structure where to put the data
/// \return true if line information could be retrieved, false otherwise
///
static bool getLineInfo(Dwarf_Die CueDie, DebugInfo &Info) {
    int Res = 0;
    Dwarf_Error Error;
    Dwarf_Unsigned Version;
    Dwarf_Small TableCount;
    Dwarf_Line_Context LineContext;
    Dwarf_Line *Lines;
    Dwarf_Signed LineCount;

    Res = dwarf_srclines_b(CueDie, &Version, &TableCount, &LineContext, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    Res = dwarf_srclines_from_linecontext(LineContext, &Lines, &LineCount, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    for (auto i = 0; i < LineCount; ++i) {
        Dwarf_Unsigned LineNumber;
        Dwarf_Addr Address;
        char *FileName;
        Res = dwarf_linesrc(Lines[i], &FileName, &Error);
        Res = dwarf_lineno(Lines[i], &LineNumber, &Error);
        Res = dwarf_lineaddr(Lines[i], &Address, &Error);

        auto &AC = Info.AddressCache[Address];
        AC.File = GetUniqueString(Info.Strings, FileName);
        AC.Line = LineNumber;
        Info.FileToLines[AC.File].Lines[AC.Line].insert(Address);
    }

    dwarf_srclines_dealloc_b(LineContext);

    return true;
}

///
/// \brief parseCompilationUnit retrieves line and function information from the given
/// compilation unit.
///
/// \param Dbg The DWARF debug info descriptor
/// \param CuDie The debug info entry of the compilation unit
/// \param Info The debug info structure where to put the data
/// \return true if the information could be retrieved, false otherwise
///
static bool parseCompilationUnit(Dwarf_Debug Dbg, Dwarf_Die CuDie, DebugInfo &Info) {
    int Res = 0;
    Dwarf_Error Error;
    Dwarf_Half Tag;

    Res = dwarf_tag(CuDie, &Tag, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    if (Tag != DW_TAG_compile_unit) {
        return false;
    }

    Dwarf_Off CuDieOffset;

    Res = dwarf_dieoffset(CuDie, &CuDieOffset, &Error);
    if (Res != DW_DLV_OK) {
        return false;
    }

    std::string Path;
    if (!getCompilationUnitPath(Dbg, CuDie, Path)) {
        return false;
    }

    auto UniquePath = GetUniqueString(Info.Strings, Path);

    if (!getFunctions(Dbg, CuDie, UniquePath, Info)) {
        std::cerr << "Could not get functions for " << Path << "\n";
    }

    if (!getLineInfo(CuDie, Info)) {
        std::cerr << "Could not get line info for " << Path << "\n";
    }

    return true;
}

///
/// \brief parseCompilationUnits retrieves line and function information
/// from the given binary file.
///
/// \param Dbg The DWARF debug info descriptor
/// \param Info The debug info structure where to put the data
/// \return true if the information could be retrieved, false otherwise
///
static bool parseCompilationUnits(Dwarf_Debug Dbg, DebugInfo &Info) {
    int Res = 0;
    Dwarf_Error Error;
    Dwarf_Die NoDie = nullptr, CuDie = nullptr;

    while (true) {

        Dwarf_Unsigned CuHeaderLength;
        Dwarf_Half Version;
        Dwarf_Off AbbrevOffset;
        Dwarf_Half AddressSize;
        Dwarf_Unsigned NextCuHeaderOffset;

        Res = dwarf_next_cu_header(Dbg, &CuHeaderLength, &Version, &AbbrevOffset, &AddressSize, &NextCuHeaderOffset,
                                   &Error);
        if (Res != DW_DLV_OK) {
            return Res != DW_DLV_ERROR;
        }

        Res = dwarf_siblingof(Dbg, NoDie, &CuDie, &Error);
        if (Res != DW_DLV_OK) {
            return Res != DW_DLV_ERROR;
        }

        parseCompilationUnit(Dbg, CuDie, Info);
    }

    return true;
}

///
/// \brief computeCoverage translate a set of addresses into coverage information.
///
/// \param Info The debug information obtained with parseCompilationUnits()
/// \param Addresses The set of addresses for which to translate to line/function info
/// \param Coverage The resulting coverage data
///
static void computeCoverage(DebugInfo &Info, const std::unordered_set<uint64_t> &Addresses, CoverageMap &Coverage,
                            bool includeAllFiles) {
    for (auto Address : Addresses) {
        const auto &It = Info.AddressCache.find(Address);
        if (It == Info.AddressCache.end()) {
            continue;
        }

        auto &Unit = Coverage[It->second.File];
        Unit.Lines.insert(It->second.Line);

        // Lookup function
        auto Range = AddressRange(Address, 1);
        auto FunctionIt = Info.Functions.find(Range);
        if (FunctionIt != Info.Functions.end()) {
            Unit.Functions.insert(FunctionIt->second.Name);
        }
    }

    if (!includeAllFiles) {
        // By default, include only files with non-zero coverage.
        return;
    }

    for (const auto &It : Info.FileToLines) {
        const auto &FileName = It.first;
        if (Coverage.find(FileName) == Coverage.end()) {
            Coverage[FileName] = CompilationUnitCoverage();
        }
    }
}

///
/// \brief dumpFunctions returns a JSON object representing functions.
/// The returned object looks as follows:
/// {
///     "function_name1": [start, size],
///     "function_name2": [start, size],
///     ...
/// }
///
static rapidjson::Value dumpFunctions(rapidjson::Document::AllocatorType &Allocator,
                                      const FunctionToAddresses &Functions) {
    rapidjson::Value Ret(rapidjson::kObjectType);
    for (const auto &F : Functions) {
        rapidjson::Value Range(rapidjson::kArrayType);
        Range.PushBack(F.second.Start, Allocator);
        Range.PushBack(F.second.Length, Allocator);

        rapidjson::Value Name(rapidjson::kStringType);
        Name.SetString(*F.first.get(), Allocator);
        Ret.AddMember(Name, Range, Allocator);
    }
    return Ret;
}

///
/// \brief dumpLines returns a JSON object that reprents line information.
/// The returned object looks as follows:
///
/// [
///   [line1, [addr1, addr2, addr3...]],
///   [line2, [addr1, addr2, addr3...]],
///   ...
/// ]
///
/// Note that a line can correspond to multiple addresses (e.g., inlined functions).
///
static rapidjson::Value dumpLines(rapidjson::Document::AllocatorType &Allocator, const LineToAddresses &Lines) {
    rapidjson::Value Ret(rapidjson::kArrayType);

    for (const auto &AddressLine : Lines) {
        const auto Line = AddressLine.first;
        const auto &Addresses = AddressLine.second;

        rapidjson::Value JAddress(rapidjson::kArrayType);

        for (auto Address : Addresses) {
            JAddress.PushBack(Address, Allocator);
        }

        rapidjson::Value JAddressAndLine(rapidjson::kArrayType);
        JAddressAndLine.PushBack(Line, Allocator);
        JAddressAndLine.PushBack(JAddress, Allocator);

        Ret.PushBack(JAddressAndLine, Allocator);
    }

    return Ret;
}

///
/// \brief dumpLineAndFunctionInformation returns a JSON document that represents
/// the line and function information of the binary.
///
/// The format is the following:
/// {
///     "source_path1:" {
///         "functions": { ... }, // Function info returned by dumpFunctions()
///         "lines": { ... } // Line info returned by dumpLines()
///     }
/// }
///
static rapidjson::Document dumpLineAndFunctionInformation(const DebugInfo &Info) {
    rapidjson::Document Doc;
    auto &Allocator = Doc.GetAllocator();
    Doc.SetObject();

    for (const auto &It : Info.FileToLines) {
        const auto &FileName = *It.first.get();
        const auto &LineInfo = It.second;

        rapidjson::Value CUValue(rapidjson::kObjectType);
        auto Functions = dumpFunctions(Doc.GetAllocator(), LineInfo.Functions);
        auto Lines = dumpLines(Doc.GetAllocator(), LineInfo.Lines);

        CUValue.AddMember("functions", Functions, Allocator);
        CUValue.AddMember("lines", Lines, Allocator);

        rapidjson::Value Path(rapidjson::kStringType);
        Path.SetString(FileName, Allocator);
        Doc.AddMember(Path, CUValue, Allocator);
    }

    return Doc;
}

///
/// \brief dumpLineCoverage returns a JSON array representing a set of covered/non-covered lines.
///
/// [
///   [ line1, 0], // 0 means that the source line is not covered
///   [ line2, 1],  // 1 meanns that the line is covered
///   ...
/// ]
///
static rapidjson::Value dumpLineCoverage(rapidjson::Document::AllocatorType &Allocator, const LineToAddresses &AllLines,
                                         const LinesSet &Lines) {
    rapidjson::Value Ret(rapidjson::kArrayType);

    std::set<uint32_t> SortedAllLines;
    for (const auto &LIt : AllLines) {
        SortedAllLines.insert(LIt.first);
    }

    for (const auto &LIt : SortedAllLines) {
        auto Line = LIt;
        bool Covered = Lines.find(Line) != Lines.end();
        rapidjson::Value LineStatusPair(rapidjson::kArrayType);
        LineStatusPair.PushBack(Line, Allocator);
        LineStatusPair.PushBack(Covered ? 1 : 0, Allocator);
        Ret.PushBack(LineStatusPair, Allocator);
    }

    return Ret;
}

///
/// \brief dumpFunctionCoverage returns a JSON array representing a list of covered functions.
///
/// ["function1", "function2", ...]
///
static rapidjson::Value dumpFunctionCoverage(rapidjson::Document::AllocatorType &Allocator,
                                             const FunctionsSet &Functions) {
    rapidjson::Value Ret(rapidjson::kArrayType);

    for (const auto &FIt : Functions) {
        rapidjson::Value Name(rapidjson::kStringType);
        Name.SetString(*FIt.get(), Allocator);
        Ret.PushBack(Name, Allocator);
    }

    return Ret;
}

///
/// \brief dumpCoverage returns a JSON document that represents code coverage.
///
/// {
///     "source_path1:" {
///         "functions": { ... }, // Function info returned by dumpFunctionCoverage()
///         "lines": { ... } // Line info returned by dumpLineCoverage()
///     }
/// }
///

static rapidjson::Document dumpCoverage(const DebugInfo &Info, const CoverageMap &Coverage) {
    rapidjson::Document Doc;
    auto &Allocator = Doc.GetAllocator();
    Doc.SetObject();

    for (const auto &It : Coverage) {
        auto FileName = It.first;
        const auto &CU = It.second;

        const auto &Lines = CU.Lines;
        const auto &Functions = CU.Functions;
        const auto &AllLines = (*Info.FileToLines.find(FileName)).second.Lines;

        auto JFunctions = dumpFunctionCoverage(Doc.GetAllocator(), Functions);
        auto JLines = dumpLineCoverage(Doc.GetAllocator(), AllLines, Lines);

        rapidjson::Value CUValue(rapidjson::kObjectType);
        CUValue.AddMember("functions", JFunctions, Allocator);
        CUValue.AddMember("lines", JLines, Allocator);

        rapidjson::Value Path(rapidjson::kStringType);
        Path.SetString(*FileName.get(), Allocator);
        Doc.AddMember(Path, CUValue, Allocator);
    }

    return Doc;
}

///
/// \brief readAddresses retrieves a set of addresses from the given JSON document.
///
/// \param Doc The document must have the following format:
/// [
///     [Start, Size],
///     [Start, Size],
///     ...
/// ]
///
/// \param Addresses is the set of byte addresses covered by the input
///
static void readAddresses(rapidjson::Document &Doc, std::unordered_set<uint64_t> &Addresses) {
    for (auto It = Doc.Begin(); It != Doc.End(); ++It) {
        auto Range = It->GetArray();
        uint64_t Start = Range[0].GetUint64();
        uint64_t Size = Range[1].GetUint64();
        while (Size != 0) {
            Addresses.insert(Start);
            ++Start;
            --Size;
        }
    }
}

int main(int argc, char **argv) {
    Dwarf_Debug Dbg = 0;
    Dwarf_Error Error;

    CoverageMap Coverage;
    DebugInfo Info;
    std::vector<uint64_t> Addresses;

    int Res = 0;

    cl::ParseCommandLineOptions(argc, (char **) argv, " addrs2lines");

    int FD = open(File.c_str(), O_RDONLY);
    if (FD < 0) {
        std::cerr << "Could not open " << File << "\n";
        return -1;
    }

    Res = dwarf_init(FD, DW_DLC_READ, nullptr, nullptr, &Dbg, &Error);
    if (Res != DW_DLV_OK) {
        std::cerr << "Could not init dwarf\n";
        return -1;
    }

    if (parseCompilationUnits(Dbg, Info)) {
        rapidjson::Document Doc;

        if (GenerateCoverage) {
            rapidjson::IStreamWrapper Input(std::cin);
            Doc.ParseStream(Input);
            if (Doc.HasParseError()) {
                std::cerr << "Invalid json input\n";
                return -1;
            }

            std::unordered_set<uint64_t> Addresses;
            readAddresses(Doc, Addresses);
            computeCoverage(Info, Addresses, Coverage, !IncludeCoveredFilesOnly);
            Doc = dumpCoverage(Info, Coverage);
        } else {
            Doc = dumpLineAndFunctionInformation(Info);
        }

        rapidjson::StringBuffer Buffer;

        if (JsonPretty) {
            rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::UTF8<>>
                Writer(Buffer);
            Doc.Accept(Writer);
        } else {
            rapidjson::Writer<rapidjson::StringBuffer, rapidjson::Document::EncodingType, rapidjson::UTF8<>> Writer(
                Buffer);
            Doc.Accept(Writer);
        }

        std::cout << Buffer.GetString() << "\n";
    }

    Res = dwarf_finish(Dbg, &Error);
    if (Res != DW_DLV_OK) {
        std::cerr << "dwarf_finish failed\n";
    }

    close(FD);

    return 0;
}
