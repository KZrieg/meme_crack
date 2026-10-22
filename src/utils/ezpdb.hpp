#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <objbase.h>  
#include <urlmon.h>   
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem> 
#include <memory>

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "Ole32.lib")

namespace ez
{
#pragma warning(push,1)
    namespace md5
    {
        const UINT32 k[64] = {
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

        const UINT32 r[] = { 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                              5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                              4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                              6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };

#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

        void to_bytes(UINT32 val, UINT8* bytes) {
            bytes[0] = (UINT8)val; bytes[1] = (UINT8)(val >> 8);
            bytes[2] = (UINT8)(val >> 16); bytes[3] = (UINT8)(val >> 24);
        }

        UINT32 to_int32(const UINT8* bytes) {
            return (UINT32)bytes[0] | ((UINT32)bytes[1] << 8) | ((UINT32)bytes[2] << 16) | ((UINT32)bytes[3] << 24);
        }

        void md5(const UINT8* initial_msg, UINT32 initial_len, UINT8* digest) {
            UINT32 h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476;
            UINT32 new_len, offset;
            UINT32 w[16];

            for (new_len = initial_len + 1; new_len % (512 / 8) != 448 / 8; new_len++);

            std::vector<UINT8> msg(new_len + 8, 0);
            memcpy(msg.data(), initial_msg, initial_len);
            msg[initial_len] = 0x80;
            to_bytes(initial_len * 8, msg.data() + new_len);
            to_bytes(initial_len >> 29, msg.data() + new_len + 4);

            for (offset = 0; offset < new_len; offset += (512 / 8)) {
                for (UINT32 i = 0; i < 16; i++) w[i] = to_int32(msg.data() + offset + i * 4);
                UINT32 a = h0, b = h1, c = h2, d = h3;
                for (UINT32 i = 0; i < 64; i++) {
                    UINT32 f, g;
                    if (i < 16) { f = (b & c) | ((~b) & d); g = i; }
                    else if (i < 32) { f = (d & b) | ((~d) & c); g = (5 * i + 1) % 16; }
                    else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
                    else { f = c ^ (b | (~d)); g = (7 * i) % 16; }
                    UINT32 temp = d; d = c; c = b;
                    b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
                    a = temp;
                }
                h0 += a; h1 += b; h2 += c; h3 += d;
            }
            to_bytes(h0, digest); to_bytes(h1, digest + 4);
            to_bytes(h2, digest + 8); to_bytes(h3, digest + 12);
        }

        std::string Md5(PVOID buffer, ULONG bufferLen) {
            UINT8 raw[16]; std::string res;
            md5((const UINT8*)buffer, bufferLen, raw);
            for (size_t i = 0; i < 16; i++) {
                char ch[4] = { 0 };
                snprintf(ch, ARRAYSIZE(ch), "%02x", raw[i]);
                res += ch;
            }
            return res;
        }

        std::string Md5(std::string filePath) {
            std::ifstream file(filePath, std::ios::binary | std::ios::ate);
            if (!file) return "";
            std::streamsize fileSize = file.tellg();
            file.seekg(0, std::ios::beg);
            std::vector<char> fileData(fileSize);
            if (file.read(fileData.data(), fileSize)) {
                return Md5(fileData.data(), (ULONG)fileSize);
            }
            return "";
        }
    }
#pragma warning(pop)

    class pdb
    {
    private:
        struct PdbInfo { DWORD Signature; GUID Guid; DWORD Age; char PdbFileName[1]; };
#define EZ_PDB_BASE_OF_DLL (DWORD64)0x10000000

        std::string _pe_path;
        std::string _symbol_server;
        bool pdb_downloaded = false;
        bool pdb_loaded = false;
        HANDLE _hPdbFile = NULL;
        HANDLE _hProcess = NULL;

        std::string download(std::string pe_path, bool bRedownload = false) {
            std::string pdbDownloadPath;
            wchar_t wszCurrentDir[MAX_PATH] = { 0 };
            GetModuleFileNameW(NULL, wszCurrentDir, _countof(wszCurrentDir));

            std::filesystem::path currentDirPath(wszCurrentDir);
            currentDirPath = currentDirPath.parent_path() / "symbols";
            pdbDownloadPath = currentDirPath.string() + "\\";

            if (!std::filesystem::exists(currentDirPath)) {
                std::error_code ec;
                std::filesystem::create_directories(currentDirPath, ec);
                if (ec) return "";
            }

            std::ifstream file(pe_path, std::ios::binary | std::ios::ate);
            if (!file) return "";
            std::streamsize size = file.tellg();
            file.seekg(0, std::ios::beg);
            std::vector<char> buffer(size);
            if (!file.read(buffer.data(), size) || size == 0) return "";

            std::string pdbPath = pdbDownloadPath + md5::Md5(buffer.data(), (ULONG)size) + ".pdb";
            std::string pdbHashCachePath = pdbPath + ".md5";

            if (!bRedownload && std::filesystem::exists(pdbPath) && std::filesystem::exists(pdbHashCachePath)) {
                std::ifstream ifs(pdbHashCachePath);
                std::string md5Cache;
                ifs >> md5Cache;
                if (md5::Md5(pdbPath) == md5Cache) return pdbPath;
            }

            IMAGE_DOS_HEADER* pDos = (IMAGE_DOS_HEADER*)buffer.data();
            IMAGE_NT_HEADERS* pNT = (IMAGE_NT_HEADERS*)(buffer.data() + pDos->e_lfanew);
            IMAGE_FILE_HEADER* pFile = &pNT->FileHeader;
            IMAGE_OPTIONAL_HEADER64* pOpt64 = NULL;
            IMAGE_OPTIONAL_HEADER32* pOpt32 = NULL;
            BOOL x86 = FALSE;

            if (pFile->Machine == IMAGE_FILE_MACHINE_AMD64) pOpt64 = (IMAGE_OPTIONAL_HEADER64*)(&pNT->OptionalHeader);
            else if (pFile->Machine == IMAGE_FILE_MACHINE_I386) { pOpt32 = (IMAGE_OPTIONAL_HEADER32*)(&pNT->OptionalHeader); x86 = TRUE; }
            else return "";

            DWORD ImageSize = x86 ? pOpt32->SizeOfImage : pOpt64->SizeOfImage;
            std::vector<BYTE> ImageBuffer(ImageSize, 0);

            memcpy(ImageBuffer.data(), buffer.data(), x86 ? pOpt32->SizeOfHeaders : pOpt64->SizeOfHeaders);
            IMAGE_SECTION_HEADER* pCurrentSectionHeader = IMAGE_FIRST_SECTION(pNT);
            for (UINT i = 0; i != pFile->NumberOfSections; ++i, ++pCurrentSectionHeader) {
                if (pCurrentSectionHeader->SizeOfRawData) {
                    memcpy(ImageBuffer.data() + pCurrentSectionHeader->VirtualAddress,
                        buffer.data() + pCurrentSectionHeader->PointerToRawData,
                        pCurrentSectionHeader->SizeOfRawData);
                }
            }

            IMAGE_DATA_DIRECTORY* pDataDir = x86 ? &pOpt32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG] : &pOpt64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
            IMAGE_DEBUG_DIRECTORY* pDebugDir = (IMAGE_DEBUG_DIRECTORY*)(ImageBuffer.data() + pDataDir->VirtualAddress);

            if (!pDataDir->Size || IMAGE_DEBUG_TYPE_CODEVIEW != pDebugDir->Type) return "";
            PdbInfo* pdb_info = (PdbInfo*)(ImageBuffer.data() + pDebugDir->AddressOfRawData);
            if (pdb_info->Signature != 0x53445352) return "";

            DeleteFileA(pdbPath.c_str());
            wchar_t w_GUID[100] = { 0 };
            if (!StringFromGUID2(pdb_info->Guid, w_GUID, 100)) return "";

            char a_GUID[100]{ 0 };
            size_t l_GUID = 0;
            if (wcstombs_s(&l_GUID, a_GUID, w_GUID, sizeof(a_GUID)) || !l_GUID) return "";

            char guid_filtered[256] = { 0 };
            for (UINT i = 0; i != l_GUID; ++i) {
                if ((a_GUID[i] >= '0' && a_GUID[i] <= '9') || (a_GUID[i] >= 'A' && a_GUID[i] <= 'F') || (a_GUID[i] >= 'a' && a_GUID[i] <= 'f')) {
                    guid_filtered[strlen(guid_filtered)] = a_GUID[i];
                }
            }

            char age[3] = { 0 };
            _itoa_s(pdb_info->Age, age, 10);

            std::string url = _symbol_server + pdb_info->PdbFileName + "/" + guid_filtered + age + "/" + pdb_info->PdbFileName;

            if (FAILED(URLDownloadToFileA(NULL, url.c_str(), pdbPath.c_str(), NULL, NULL))) return "";

            std::string pdbMd5 = md5::Md5(pdbPath);
            std::ofstream ofs(pdbHashCachePath);
            ofs << pdbMd5;

            return pdbPath;
        }

    public:
        pdb(std::string pe_path, std::string symbol_server = "https://msdl.microsoft.com/download/symbols/") {
            _pe_path = pe_path;
            _symbol_server = symbol_server;
        }

        bool init() {
            std::string pdb_path = download(_pe_path);
            if (pdb_path.empty()) return false;
            pdb_downloaded = true;

            _hPdbFile = CreateFileA(pdb_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL);
            if (_hPdbFile == INVALID_HANDLE_VALUE) return false;

            _hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GetCurrentProcessId());
            if (!_hProcess) { CloseHandle(_hPdbFile); return false; }

            if (!SymInitialize(_hProcess, pdb_path.c_str(), FALSE)) {
                CloseHandle(_hProcess); CloseHandle(_hPdbFile); return false;
            }

            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_AUTO_PUBLICS | SYMOPT_DEBUG | SYMOPT_LOAD_ANYTHING);

            DWORD64 SymbolTable = SymLoadModuleEx(_hProcess, NULL, pdb_path.c_str(), NULL, EZ_PDB_BASE_OF_DLL, 0, NULL, NULL);
            if (!SymbolTable) {
                SymCleanup(_hProcess); CloseHandle(_hProcess); CloseHandle(_hPdbFile); return false;
            }

            pdb_loaded = true;
            return true;
        }

        ~pdb() {
            if (pdb_loaded) {
                SymUnloadModule64(_hProcess, EZ_PDB_BASE_OF_DLL);
                SymCleanup(_hProcess);
                CloseHandle(_hProcess);
                CloseHandle(_hPdbFile);
            }
        }

        int get_rva(std::string SymName) {
            SYMBOL_INFO si = { 0 };
            si.SizeOfStruct = sizeof(SYMBOL_INFO);
            if (!SymFromName(_hProcess, SymName.c_str(), &si)) return -1;
            return (int)(si.Address - si.ModBase);
        }
    };
}