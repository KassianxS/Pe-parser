#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <cstdint>
#include <cstring>
#include <ctime>

using namespace std;

// структуры PE файла

struct DosHeader {
    uint16_t e_magic;
    uint16_t e_cblp, e_cp, e_crlc, e_cparhdr;
    uint16_t e_minalloc, e_maxalloc;
    uint16_t e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid, e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
};

struct FileHeader {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
};

struct DataDirectory {
    uint32_t VirtualAddress;
    uint32_t Size;
};

struct OptionalHeader32 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode, BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint32_t SizeOfStackReserve, SizeOfStackCommit;
    uint32_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    DataDirectory Dirs[16];
};

struct OptionalHeader64 {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion, MinorLinkerVersion;
    uint32_t SizeOfCode, SizeOfInitializedData, SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint, BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment, FileAlignment;
    uint16_t MajorOSVersion, MinorOSVersion;
    uint16_t MajorImageVersion, MinorImageVersion;
    uint16_t MajorSubsystemVersion, MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage, SizeOfHeaders, CheckSum;
    uint16_t Subsystem, DllCharacteristics;
    uint64_t SizeOfStackReserve, SizeOfStackCommit;
    uint64_t SizeOfHeapReserve, SizeOfHeapCommit;
    uint32_t LoaderFlags, NumberOfRvaAndSizes;
    DataDirectory Dirs[16];
};

struct SectionHeader {
    uint8_t  Name[8];
    union { uint32_t PhysicalAddress; uint32_t VirtualSize; } Misc;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
};

struct ExportDirectory {
    uint32_t Characteristics, TimeDateStamp;
    uint16_t MajorVersion, MinorVersion;
    uint32_t Name, Base;
    uint32_t NumberOfFunctions, NumberOfNames;
    uint32_t AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals;
};

struct ImportDescriptor {
    union { uint32_t Characteristics; uint32_t OriginalFirstThunk; };
    uint32_t TimeDateStamp, ForwarderChain, Name, FirstThunk;
};

struct ImportByName {
    uint16_t Hint;
    char     Name[1];
};

// константы

const uint16_t MZ_MAGIC = 0x5A4D;
const uint32_t PE_SIG   = 0x00004550;

const uint16_t MACHINE_I386  = 0x014C;
const uint16_t MACHINE_AMD64 = 0x8664;
const uint16_t MACHINE_IA64  = 0x0200;

const uint16_t FC_RELOCS_STRIPPED         = 0x0001;
const uint16_t FC_EXECUTABLE_IMAGE        = 0x0002;
const uint16_t FC_LINE_NUMS_STRIPPED      = 0x0004;
const uint16_t FC_LOCAL_SYMS_STRIPPED     = 0x0008;
const uint16_t FC_AGGRESIVE_WS_TRIM       = 0x0010;
const uint16_t FC_LARGE_ADDRESS_AWARE     = 0x0020;
const uint16_t FC_32BIT_MACHINE           = 0x0100;
const uint16_t FC_DEBUG_STRIPPED          = 0x0200;
const uint16_t FC_REMOVABLE_RUN_FROM_SWAP = 0x0400;
const uint16_t FC_NET_RUN_FROM_SWAP       = 0x0800;
const uint16_t FC_SYSTEM                  = 0x1000;
const uint16_t FC_DLL                     = 0x2000;
const uint16_t FC_UP_SYSTEM_ONLY          = 0x4000;
const uint16_t FC_BYTES_REVERSED_HI       = 0x8000;

const uint16_t DLL_HIGH_ENTROPY_VA       = 0x0020;
const uint16_t DLL_DYNAMIC_BASE          = 0x0040;
const uint16_t DLL_FORCE_INTEGRITY       = 0x0080;
const uint16_t DLL_NX_COMPAT             = 0x0100;
const uint16_t DLL_NO_ISOLATION          = 0x0200;
const uint16_t DLL_NO_SEH                = 0x0400;
const uint16_t DLL_NO_BIND               = 0x0800;
const uint16_t DLL_APPCONTAINER          = 0x1000;
const uint16_t DLL_WDM_DRIVER            = 0x2000;
const uint16_t DLL_GUARD_CF              = 0x4000;
const uint16_t DLL_TERMINAL_SERVER_AWARE = 0x8000;

const uint32_t SCN_MEM_EXECUTE = 0x20000000;
const uint32_t SCN_MEM_READ    = 0x40000000;
const uint32_t SCN_MEM_WRITE   = 0x80000000;

const uint32_t ORDINAL_FLAG32 = 0x80000000;
const uint64_t ORDINAL_FLAG64 = 0x8000000000000000ULL;

// переводит RVA в смещение внутри файла
uint32_t rvaToOffset(uint32_t rva, SectionHeader* sections, int count)
{
    for (int i = 0; i < count; i++) {
        uint32_t va  = sections[i].VirtualAddress;
        uint32_t vsz = sections[i].Misc.VirtualSize;
        if (rva >= va && rva < va + vsz)
            return sections[i].PointerToRawData + (rva - va);
    }
    return 0;
}

void printFileCharacteristics(uint16_t ch)
{
    cout << "  Characteristics: 0x" << hex << ch << dec << endl;
    if (ch & FC_RELOCS_STRIPPED)         cout << "    IMAGE_FILE_RELOCS_STRIPPED" << endl;
    if (ch & FC_EXECUTABLE_IMAGE)        cout << "    IMAGE_FILE_EXECUTABLE_IMAGE" << endl;
    if (ch & FC_LINE_NUMS_STRIPPED)      cout << "    IMAGE_FILE_LINE_NUMS_STRIPPED" << endl;
    if (ch & FC_LOCAL_SYMS_STRIPPED)     cout << "    IMAGE_FILE_LOCAL_SYMS_STRIPPED" << endl;
    if (ch & FC_AGGRESIVE_WS_TRIM)       cout << "    IMAGE_FILE_AGGRESIVE_WS_TRIM" << endl;
    if (ch & FC_LARGE_ADDRESS_AWARE)     cout << "    IMAGE_FILE_LARGE_ADDRESS_AWARE" << endl;
    if (ch & FC_32BIT_MACHINE)           cout << "    IMAGE_FILE_32BIT_MACHINE" << endl;
    if (ch & FC_DEBUG_STRIPPED)          cout << "    IMAGE_FILE_DEBUG_STRIPPED" << endl;
    if (ch & FC_REMOVABLE_RUN_FROM_SWAP) cout << "    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP" << endl;
    if (ch & FC_NET_RUN_FROM_SWAP)       cout << "    IMAGE_FILE_NET_RUN_FROM_SWAP" << endl;
    if (ch & FC_SYSTEM)                  cout << "    IMAGE_FILE_SYSTEM" << endl;
    if (ch & FC_DLL)                     cout << "    IMAGE_FILE_DLL" << endl;
    if (ch & FC_UP_SYSTEM_ONLY)          cout << "    IMAGE_FILE_UP_SYSTEM_ONLY" << endl;
    if (ch & FC_BYTES_REVERSED_HI)       cout << "    IMAGE_FILE_BYTES_REVERSED_HI" << endl;
}

void printDllCharacteristics(uint16_t ch)
{
    cout << "  DllCharacteristics: 0x" << hex << ch << dec << endl;
    if (ch & DLL_HIGH_ENTROPY_VA)       cout << "    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA" << endl;
    if (ch & DLL_DYNAMIC_BASE)          cout << "    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE" << endl;
    if (ch & DLL_FORCE_INTEGRITY)       cout << "    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" << endl;
    if (ch & DLL_NX_COMPAT)             cout << "    IMAGE_DLLCHARACTERISTICS_NX_COMPAT" << endl;
    if (ch & DLL_NO_ISOLATION)          cout << "    IMAGE_DLLCHARACTERISTICS_NO_ISOLATION" << endl;
    if (ch & DLL_NO_SEH)                cout << "    IMAGE_DLLCHARACTERISTICS_NO_SEH" << endl;
    if (ch & DLL_NO_BIND)               cout << "    IMAGE_DLLCHARACTERISTICS_NO_BIND" << endl;
    if (ch & DLL_APPCONTAINER)          cout << "    IMAGE_DLLCHARACTERISTICS_APPCONTAINER" << endl;
    if (ch & DLL_WDM_DRIVER)            cout << "    IMAGE_DLLCHARACTERISTICS_WDM_DRIVER" << endl;
    if (ch & DLL_GUARD_CF)              cout << "    IMAGE_DLLCHARACTERISTICS_GUARD_CF" << endl;
    if (ch & DLL_TERMINAL_SERVER_AWARE) cout << "    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE" << endl;
}

void printSectionRights(uint32_t ch)
{
    string rights = "";
    if (ch & SCN_MEM_READ)    rights += "R";
    if (ch & SCN_MEM_WRITE)   rights += "W";
    if (ch & SCN_MEM_EXECUTE) rights += "X";
    if (rights.empty()) rights = "---";
    cout << "  Characteristics: " << rights << "  (0x" << hex << ch << dec << ")" << endl;
}

string timestampToString(uint32_t ts)
{
    time_t t = (time_t)ts;
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", gmtime(&t));
    return string(buf);
}

int main(int argc, char* argv[])
{
    if (argc != 2) {
        cout << "Usage: pe_parser <file>" << endl;
        return 1;
    }

    string filename = argv[1];

    cout << "====================================" << endl;
    cout << "File: " << filename << endl;
    cout << "====================================" << endl;

    // читаем файл
    ifstream f(filename, ios::binary);
    if (!f) {
        cout << "Cannot open file" << endl;
        return 1;
    }
    vector<uint8_t> buf((istreambuf_iterator<char>(f)), istreambuf_iterator<char>());
    f.close();

    // DOS заголовок
    DosHeader* dos = (DosHeader*)buf.data();
    if (dos->e_magic != MZ_MAGIC) {
        cout << "Not a PE file (no MZ signature)" << endl;
        return 1;
    }
    cout << "MZ signature OK, e_lfanew = 0x" << hex << dos->e_lfanew << dec << endl;

    // NT заголовок
    uint8_t* ntBase = buf.data() + dos->e_lfanew;
    uint32_t sig = *(uint32_t*)ntBase;
    if (sig != PE_SIG) {
        cout << "Invalid PE signature" << endl;
        return 1;
    }
    cout << "PE signature OK" << endl;

    FileHeader* fh = (FileHeader*)(ntBase + 4);

    bool is64 = (fh->Machine == MACHINE_AMD64 || fh->Machine == MACHINE_IA64);

    // секции находятся сразу после optional header
    uint8_t* optBase     = (uint8_t*)fh + sizeof(FileHeader);
    SectionHeader* sects = (SectionHeader*)(optBase + fh->SizeOfOptionalHeader);
    int numSects         = fh->NumberOfSections;

    // File Header
    cout << endl << "=== FILE HEADER ===" << endl;

    cout << "  Machine: ";
    if      (fh->Machine == MACHINE_I386)  cout << "x86 / i386 (0x014C)";
    else if (fh->Machine == MACHINE_AMD64) cout << "AMD64 / x64 (0x8664)";
    else if (fh->Machine == MACHINE_IA64)  cout << "Intel Itanium (0x0200)";
    else                                   cout << "Unknown (0x" << hex << fh->Machine << dec << ")";
    cout << endl;

    cout << "  NumberOfSections: " << fh->NumberOfSections << endl;
    cout << "  TimeDateStamp: 0x" << hex << fh->TimeDateStamp << dec
         << "  (" << timestampToString(fh->TimeDateStamp) << ")" << endl;
    cout << "  SizeOfOptionalHeader: 0x" << hex << fh->SizeOfOptionalHeader << dec << endl;
    printFileCharacteristics(fh->Characteristics);

    // Optional Header
    cout << endl << "=== OPTIONAL HEADER ===" << endl;

    uint16_t magic       = 0;
    uint32_t entryPoint  = 0;
    uint64_t imageBase   = 0;
    uint32_t secAlign    = 0;
    uint32_t fileAlign   = 0;
    uint32_t sizeOfImage = 0;
    uint16_t dllChars    = 0;

    uint32_t expRva = 0, impRva = 0, resRva = 0, resSz = 0, relRva = 0, relSz = 0;

    if (!is64) {
        OptionalHeader32* opt = (OptionalHeader32*)optBase;
        magic       = opt->Magic;
        entryPoint  = opt->AddressOfEntryPoint;
        imageBase   = opt->ImageBase;
        secAlign    = opt->SectionAlignment;
        fileAlign   = opt->FileAlignment;
        sizeOfImage = opt->SizeOfImage;
        dllChars    = opt->DllCharacteristics;

        if (opt->NumberOfRvaAndSizes > 0) expRva = opt->Dirs[0].VirtualAddress;
        if (opt->NumberOfRvaAndSizes > 1) impRva = opt->Dirs[1].VirtualAddress;
        if (opt->NumberOfRvaAndSizes > 2) { resRva = opt->Dirs[2].VirtualAddress; resSz = opt->Dirs[2].Size; }
        if (opt->NumberOfRvaAndSizes > 5) { relRva = opt->Dirs[5].VirtualAddress; relSz = opt->Dirs[5].Size; }
    } else {
        OptionalHeader64* opt = (OptionalHeader64*)optBase;
        magic       = opt->Magic;
        entryPoint  = opt->AddressOfEntryPoint;
        imageBase   = opt->ImageBase;
        secAlign    = opt->SectionAlignment;
        fileAlign   = opt->FileAlignment;
        sizeOfImage = opt->SizeOfImage;
        dllChars    = opt->DllCharacteristics;

        if (opt->NumberOfRvaAndSizes > 0) expRva = opt->Dirs[0].VirtualAddress;
        if (opt->NumberOfRvaAndSizes > 1) impRva = opt->Dirs[1].VirtualAddress;
        if (opt->NumberOfRvaAndSizes > 2) { resRva = opt->Dirs[2].VirtualAddress; resSz = opt->Dirs[2].Size; }
        if (opt->NumberOfRvaAndSizes > 5) { relRva = opt->Dirs[5].VirtualAddress; relSz = opt->Dirs[5].Size; }
    }

    string magicStr = "Unknown";
    if      (magic == 0x10B) magicStr = "PE32 (32-bit)";
    else if (magic == 0x20B) magicStr = "PE32+ (64-bit)";

    cout << "  Magic: 0x" << hex << magic << dec << "  (" << magicStr << ")" << endl;
    cout << "  AddressOfEntryPoint: 0x" << hex << entryPoint << dec << endl;
    cout << "  ImageBase: 0x" << hex << imageBase << dec << endl;
    cout << "  SectionAlignment: 0x" << hex << secAlign << dec << endl;
    cout << "  FileAlignment: 0x" << hex << fileAlign << dec << endl;
    cout << "  SizeOfImage: 0x" << hex << sizeOfImage << dec << "  (" << sizeOfImage << " bytes)" << endl;
    printDllCharacteristics(dllChars);

    // Export Table
    cout << endl << "=== EXPORT TABLE ===" << endl;
    if (expRva == 0) {
        cout << "  [no exports]" << endl;
    } else {
        uint32_t expOff = rvaToOffset(expRva, sects, numSects);
        if (expOff == 0) {
            cout << "  [cannot find section]" << endl;
        } else {
            ExportDirectory* expDir = (ExportDirectory*)(buf.data() + expOff);

            uint32_t dllNameOff = rvaToOffset(expDir->Name, sects, numSects);
            cout << "  DLL name: " << (char*)(buf.data() + dllNameOff) << endl;
            cout << "  NumberOfFunctions: " << expDir->NumberOfFunctions << endl;
            cout << "  NumberOfNames: " << expDir->NumberOfNames << endl;
            cout << "  Base: " << expDir->Base << endl << endl;

            uint32_t* nameArr = (uint32_t*)(buf.data() + rvaToOffset(expDir->AddressOfNames, sects, numSects));
            uint16_t* ordArr  = (uint16_t*)(buf.data() + rvaToOffset(expDir->AddressOfNameOrdinals, sects, numSects));
            uint32_t* funcArr = (uint32_t*)(buf.data() + rvaToOffset(expDir->AddressOfFunctions, sects, numSects));

            for (uint32_t i = 0; i < expDir->NumberOfNames; i++) {
                uint32_t nameOff = rvaToOffset(nameArr[i], sects, numSects);
                uint16_t ord     = ordArr[i];
                uint32_t funcRva = (ord < expDir->NumberOfFunctions) ? funcArr[ord] : 0;
                cout << "    ord=" << (expDir->Base + ord)
                     << "  RVA=0x" << hex << funcRva << dec
                     << "  " << (char*)(buf.data() + nameOff) << endl;
            }
        }
    }

    // Import Table
    cout << endl << "=== IMPORT TABLE ===" << endl;
    if (impRva == 0) {
        cout << "  [no imports]" << endl;
    } else {
        uint32_t impOff = rvaToOffset(impRva, sects, numSects);
        if (impOff == 0) {
            cout << "  [cannot find section]" << endl;
        } else {
            ImportDescriptor* imp = (ImportDescriptor*)(buf.data() + impOff);

            while (imp->Name != 0) {
                uint32_t dllNameOff = rvaToOffset(imp->Name, sects, numSects);
                cout << endl << "  " << (char*)(buf.data() + dllNameOff) << endl;

                uint32_t thunkRva = imp->OriginalFirstThunk ? imp->OriginalFirstThunk : imp->FirstThunk;
                uint32_t thunkOff = rvaToOffset(thunkRva, sects, numSects);

                if (thunkOff != 0) {
                    if (!is64) {
                        uint32_t* thunk = (uint32_t*)(buf.data() + thunkOff);
                        while (*thunk != 0) {
                            if (*thunk & ORDINAL_FLAG32) {
                                cout << "    [Ordinal " << (*thunk & 0xFFFF) << "]" << endl;
                            } else {
                                uint32_t ibnOff = rvaToOffset(*thunk, sects, numSects);
                                ImportByName* ibn = (ImportByName*)(buf.data() + ibnOff);
                                cout << "    " << ibn->Name << endl;
                            }
                            thunk++;
                        }
                    } else {
                        uint64_t* thunk = (uint64_t*)(buf.data() + thunkOff);
                        while (*thunk != 0) {
                            if (*thunk & ORDINAL_FLAG64) {
                                cout << "    [Ordinal " << (*thunk & 0xFFFF) << "]" << endl;
                            } else {
                                uint32_t ibnOff = rvaToOffset((uint32_t)*thunk, sects, numSects);
                                ImportByName* ibn = (ImportByName*)(buf.data() + ibnOff);
                                cout << "    " << ibn->Name << endl;
                            }
                            thunk++;
                        }
                    }
                }

                imp++;
            }
        }
    }

    // Relocations
    cout << endl << "=== RELOCATIONS ===" << endl;
    if (relRva != 0 && relSz != 0)
        cout << "  [!] Relocation table present"
             << "  (RVA=0x" << hex << relRva << "  Size=0x" << relSz << dec << ")" << endl;
    else
        cout << "  [none]" << endl;

    // Resources
    cout << endl << "=== RESOURCES ===" << endl;
    if (resRva != 0 && resSz != 0)
        cout << "  [!] Resource section present"
             << "  (RVA=0x" << hex << resRva << "  Size=0x" << resSz << dec << ")" << endl;
    else
        cout << "  [none]" << endl;

    // Sections
    cout << endl << "=== SECTIONS (" << numSects << ") ===" << endl;
    for (int i = 0; i < numSects; i++) {
        char name[9] = {};
        memcpy(name, sects[i].Name, 8);

        cout << endl;
        cout << "  [" << (i + 1) << "] " << name << endl;
        cout << "  VirtualSize:    0x" << hex << sects[i].Misc.VirtualSize << dec << endl;
        cout << "  VirtualAddress: 0x" << hex << sects[i].VirtualAddress << dec << endl;
        cout << "  SizeOfRawData:  0x" << hex << sects[i].SizeOfRawData << dec << endl;
        cout << "  PointerToRaw:   0x" << hex << sects[i].PointerToRawData << dec << endl;
        printSectionRights(sects[i].Characteristics);
    }

    cout << endl << "====================================" << endl;
    cout << "Done." << endl;

    return 0;
}
