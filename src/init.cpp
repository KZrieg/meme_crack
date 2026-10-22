#include <winsock2.h>
#include <ws2tcpip.h>
#include "core/inject.h"
#include "core/vmp_fix.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <DbgHelp.h>
#include <Urlmon.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <vector>
#include <map>
#include <filesystem>
#include <fstream>
#include <iostream>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "Ole32.lib")

std::map<std::string, uint32_t> g_pdb_rva_map;

namespace {
    const wchar_t* const kTargetProcess = L"cs2.exe";
    HANDLE g_log_file = INVALID_HANDLE_VALUE;
    std::mutex g_log_mutex;

    void OpenLogFile() {
        wchar_t exe_path[MAX_PATH]{};
        const DWORD n = ::GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
        std::wstring path;
        if (n > 0 && n < MAX_PATH) {
            path = exe_path;
            const size_t slash = path.find_last_of(L"\\/");
            if (slash != std::wstring::npos) path = path.substr(0, slash + 1);
            else path.clear();
        }
        path += L"out.log";
        g_log_file = ::CreateFileW(path.c_str(), FILE_APPEND_DATA,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    void CloseLogFile() {
        if (g_log_file != INVALID_HANDLE_VALUE) { ::CloseHandle(g_log_file); g_log_file = INVALID_HANDLE_VALUE; }
    }

    void LogRaw(const char* text) {
        const std::lock_guard lock(g_log_mutex);
        HANDLE hOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            ::WriteFile(hOut, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        }
        if (g_log_file != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            ::WriteFile(g_log_file, text, static_cast<DWORD>(std::strlen(text)), &written, nullptr);
        }
    }

    template <class... Args>
    void Log(const char* fmt, Args... args) {
        char buf[1024];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, args...);
        LogRaw(buf);
        LogRaw("\n");
    }

    struct PdbInfo {
        DWORD Signature;
        GUID Guid;
        DWORD Age;
        char PdbFileName[1];
    };

    // Minimal RVA -> file-offset translation. The old code used
    // buffer.data() + VirtualAddress, which only works while a section happens
    // to have PointerToRawData == VirtualAddress; on this host ntdll's .rdata
    // does, so the bug stayed hidden.
    std::size_t RvaToFileOffset(const std::vector<char>& file,
                                const IMAGE_NT_HEADERS64* nt, std::uint32_t rva) {
        const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const std::uint32_t span = sec[i].Misc.VirtualSize
                                     ? sec[i].Misc.VirtualSize
                                     : sec[i].SizeOfRawData;
            if (rva >= sec[i].VirtualAddress && rva < sec[i].VirtualAddress + span) {
                const std::size_t off = sec[i].PointerToRawData + (rva - sec[i].VirtualAddress);
                return (off <= file.size()) ? off : 0;
            }
        }
        return 0;
    }

    // Locate the CodeView record and return the symbol-server identity.
    bool ReadCodeViewIdentity(std::wstring& outPdbName,
                              std::wstring& outSymbolKey) {
        wchar_t sysDir[MAX_PATH]{};
        if (::GetSystemDirectoryW(sysDir, MAX_PATH) == 0) return false;

        const std::wstring ntdllPath = std::wstring(sysDir) + L"\\ntdll.dll";
        std::ifstream file(ntdllPath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) return false;

        const std::streamsize size = file.tellg();
        if (size <= 0) return false;
        file.seekg(0, std::ios::beg);
        std::vector<char> buffer(static_cast<std::size_t>(size));
        if (!file.read(buffer.data(), size)) return false;

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        const IMAGE_DATA_DIRECTORY& dir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (dir.VirtualAddress == 0 || dir.Size < sizeof(IMAGE_DEBUG_DIRECTORY)) return false;

        const std::size_t debugOff = RvaToFileOffset(buffer, nt, dir.VirtualAddress);
        if (debugOff == 0) return false;

        IMAGE_DEBUG_DIRECTORY dbg{};
        std::memcpy(&dbg, buffer.data() + debugOff, sizeof(dbg));
        if (dbg.Type != IMAGE_DEBUG_TYPE_CODEVIEW) return false;

        // AddressOfRawData is an RVA; PointerToRawData is already a file offset.
        std::size_t cvOff = 0;
        if (dbg.AddressOfRawData != 0) {
            cvOff = RvaToFileOffset(buffer, nt, dbg.AddressOfRawData);
        }
        if (cvOff == 0 && dbg.PointerToRawData != 0) {
            cvOff = dbg.PointerToRawData;
        }
        if (cvOff == 0 || cvOff + 24 > buffer.size()) return false;

        if (std::memcmp(buffer.data() + cvOff, "RSDS", 4) != 0) return false;

        GUID guid{};
        std::memcpy(&guid, buffer.data() + cvOff + 4, sizeof(guid));
        std::uint32_t age = 0;
        std::memcpy(&age, buffer.data() + cvOff + 20, sizeof(age));

        const char* name = buffer.data() + cvOff + 24;
        const std::size_t maxName = buffer.size() - (cvOff + 24);
        const std::size_t nameLen = strnlen_s(name, maxName);
        if (nameLen == 0) return false;

        wchar_t wideName[MAX_PATH]{};
        if (::MultiByteToWideChar(CP_ACP, 0, name, static_cast<int>(nameLen),
                                  wideName, MAX_PATH) == 0) return false;
        outPdbName = wideName;

        // Symbol server key: %08X%04X%04X + remaining 8 bytes, then the age in
        // HEXADECIMAL. The old code formatted the age with base 10, which only
        // survives while the age happens to be a single digit.
        wchar_t key[64]{};
        _snwprintf_s(key, _countof(key), _TRUNCATE,
                     L"%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                     guid.Data1, guid.Data2, guid.Data3,
                     guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
                     guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7],
                     age);
        outSymbolKey = key;
        return true;
    }

    // Cache the PDB under a name derived from the CodeView identity, so a
    // Windows update produces a new file instead of silently reusing a symbol
    // file that no longer matches the loaded ntdll.
    bool EnsurePdbInTemp(std::wstring& outPdbPath) {
        std::wstring pdbName;
        std::wstring symbolKey;
        if (!ReadCodeViewIdentity(pdbName, symbolKey)) {
            Log("[-]无法读取 ntdll 的 CodeView 记录");
            return false;
        }

        wchar_t tempPath[MAX_PATH]{};
        ::GetTempPathW(MAX_PATH, tempPath);
        const std::filesystem::path targetDir =
            std::filesystem::path(tempPath) / "MemeSense_Symbols";
        std::error_code ec;
        std::filesystem::create_directories(targetDir, ec);

        // <dir>/<key>/<pdbname>. The key directory carries the GUID and age, so
        // a Windows update produces a new file instead of reusing a symbol file
        // that no longer matches the loaded ntdll. The pdb name is not used as a
        // directory level because the legacy cache already occupies that path
        // as a plain file.
        const std::filesystem::path keyDir = targetDir / symbolKey;
        std::filesystem::create_directories(keyDir, ec);
        outPdbPath = (keyDir / pdbName).wstring();

        if (std::filesystem::exists(outPdbPath, ec) &&
            std::filesystem::file_size(outPdbPath, ec) > 0) {
            Log("[+]复用已缓存的符号: %ls", outPdbPath.c_str());
            return true;
        }

        std::string url = "https://msdl.microsoft.com/download/symbols/";
        url += std::filesystem::path(pdbName).string();
        url += "/";
        url += std::filesystem::path(symbolKey).string();
        url += "/";
        url += std::filesystem::path(pdbName).string();

        Log("[+]正在下载符号...");
        Log("    %s", url.c_str());
        const std::string outPdbPathA = std::filesystem::path(outPdbPath).string();
        const HRESULT hr = ::URLDownloadToFileA(nullptr, url.c_str(), outPdbPathA.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            Log("[-]下载失败 hr=0x%lX", static_cast<unsigned long>(hr));
            return false;
        }
        return true;
    }

    void InitPdbMap() {
        std::wstring pdbPath;
        if (!EnsurePdbInTemp(pdbPath)) {
            Log("[-]无法获取符号文件，跳过 PDB 解析");
            return;
        }

        HANDLE hProcess = ::GetCurrentProcess();
        ::SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);

        // Symbol path is the directory that contains the cached PDB. The image
        // name passed to SymLoadModuleExW must be the PDB itself together with a
        // non-zero base, otherwise DbgHelp reports success but resolves nothing.
        const std::filesystem::path pdbDir = std::filesystem::path(pdbPath).parent_path();
        const std::wstring symPath = pdbDir.wstring();

        if (!::SymInitializeW(hProcess, symPath.c_str(), FALSE)) {
            Log("[-]SymInitialize 失败，跳过 PDB 解析");
            return;
        }

        const DWORD64 fakeBase = 0x10000000;
        const DWORD64 loaded = ::SymLoadModuleExW(hProcess, NULL, pdbPath.c_str(), NULL,
                                                  fakeBase, 0, NULL, NULL);
        if (loaded == 0) {
            Log("[-]SymLoadModuleEx 失败，跳过 PDB 解析");
            ::SymCleanup(hProcess);
            return;
        }

        for (int i = 0; i < kBrdataSlotCount; ++i) {
            const char* name = g_brdataSlots[i].symbol;
            if (!name) continue;
            if (g_pdb_rva_map.count(name)) continue;

            SYMBOL_INFO si = { 0 };
            si.SizeOfStruct = sizeof(SYMBOL_INFO);
            si.MaxNameLen   = 2000;
            if (::SymFromName(hProcess, name, &si)) {
                g_pdb_rva_map[name] = static_cast<uint32_t>(si.Address - si.ModBase);
                Log("[+]PDB Resolve: %s -> RVA 0x%X", name, g_pdb_rva_map[name]);
            }
            else {
                Log("[-]PDB Resolve FAILED: %s", name);
            }
        }

        // Symbols the loader itself calls back into. Without these the PEB->Ldr
        // registration cannot run, and its self-check is skipped silently.
        const char* const kLoaderSymbols[] = {
            "LdrFindEntryForAddress",
            "LdrpModuleBaseAddressIndex",
            "RtlRbInsertNodeEx",
            "RtlAddVectoredExceptionHandler",
        };
        for (const char* name : kLoaderSymbols) {
            if (g_pdb_rva_map.count(name)) continue;

            SYMBOL_INFO si = { 0 };
            si.SizeOfStruct = sizeof(SYMBOL_INFO);
            si.MaxNameLen   = 2000;
            if (::SymFromName(hProcess, name, &si)) {
                g_pdb_rva_map[name] = static_cast<uint32_t>(si.Address - si.ModBase);
                Log("[+]PDB Resolve: %s -> RVA 0x%X", name, g_pdb_rva_map[name]);
            }
            else {
                Log("[-]PDB Resolve FAILED: %s", name);
            }
        }

        for (int i = 0; i < kDiagSymbolCount; ++i) {
            const char* name = kDiagSymbols[i];
            if (g_pdb_rva_map.count(name)) continue;

            SYMBOL_INFO si = { 0 };
            si.SizeOfStruct = sizeof(SYMBOL_INFO);
            si.MaxNameLen   = 2000;
            if (::SymFromName(hProcess, name, &si)) {
                g_pdb_rva_map[name] = static_cast<uint32_t>(si.Address - si.ModBase);
                Log("[+]PDB Resolve: %s -> RVA 0x%X", name, g_pdb_rva_map[name]);
            }
            else {
                Log("[-]PDB Resolve FAILED: %s", name);
            }
        }

        ::SymUnloadModule64(hProcess, loaded);
        ::SymCleanup(hProcess);
    }
    BOOL IsRunAsAdmin() {
        BOOL isAdmin = FALSE; PSID administratorsGroup = nullptr; SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
        if (::AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
            if (!::CheckTokenMembership(nullptr, administratorsGroup, &isAdmin)) isAdmin = FALSE;
            ::FreeSid(administratorsGroup);
        }
        return isAdmin;
    }

    std::uint64_t GetFileSizeW(const wchar_t* path) {
        WIN32_FILE_ATTRIBUTE_DATA attr{};
        if (!::GetFileAttributesExW(path, GetFileExInfoStandard, &attr)) return 0;
        ULARGE_INTEGER size; size.LowPart = attr.nFileSizeLow; size.HighPart = attr.nFileSizeHigh;
        return size.QuadPart;
    }

    BOOL ExtractDeps() {
        const std::vector<std::uint8_t> data = ReadResource(IDR_RCDATA1);
        if (data.empty()) return FALSE;

        wchar_t tmpBuf[MAX_PATH]{};
        ::GetTempPathW(MAX_PATH, tmpBuf);
        std::wstring tmpPath = tmpBuf;
        tmpPath += L"ms_deps.zip";

        {
            HANDLE hFile = ::CreateFileW(tmpPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written = 0;
                ::WriteFile(hFile, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
                ::CloseHandle(hFile);
            }
        }

        wchar_t cmd[MAX_PATH * 2]{};
        swprintf_s(cmd, MAX_PATH * 2, L"tar.exe -xf \"%ls\" -C C:\\", tmpPath.c_str());

        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        BOOL ok = ::CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        if (ok) {
            ::WaitForSingleObject(pi.hProcess, 120000);
            ::CloseHandle(pi.hProcess); ::CloseHandle(pi.hThread);
        }
        ::DeleteFileW(tmpPath.c_str());
        return GetFileSizeW(L"C:\\MemeSense\\bin\\win64\\xldr.dll") > 0;
    }

    BOOL AreAllDllsLoaded(DWORD pid) {
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return FALSE;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        BOOL found[kReqDllCount] = {};
        int count = 0;

        if (::Module32FirstW(snap, &me)) {
            do {
                for (int i = 0; i < kReqDllCount; i++) {
                    if (!found[i] && _wcsicmp(me.szModule, kRequiredDlls[i]) == 0) {
                        found[i] = TRUE;
                        count++;
                    }
                }
            } while (::Module32NextW(snap, &me));
        }
        ::CloseHandle(snap);
        return (count == kReqDllCount);
    }
}

int main(int argc, char* argv[]) {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleTitleW(L"Memesense Loader");
    OpenLogFile();
    std::atexit(CloseLogFile);

    Log("\n===========================================================\n");
    Log("Memesense Loader");
    Log("Make in Krieg1337");
    Log("最后更新：2026/10/21");
    Log("感谢1048810292提供的dump文件");
    Log("公益制作，倒卖死冯");
    Log("\n===========================================================\n");

    std::uint32_t entryOverride = 0;
    if (argc >= 2 && argv[1] && argv[1][0]) {
        entryOverride = static_cast<std::uint32_t>(std::strtoul(argv[1], nullptr, 16));
        Log("[*]入口点覆盖 = 0x%X", entryOverride);
    }

    if (!IsRunAsAdmin()) {
        Log("[-]管理员权限缺失");
        return 1;
    }
    Log("[+]管理员权限存在");

    Log("[+]检查依赖项");
    if (GetFileSizeW(L"C:\\MemeSense\\bin\\win64\\xldr.dll") == 0) {
        Log("[-]依赖项不存在，进行修补");
        ExtractDeps();
    }
    Log("[+]依赖项存在");

    DWORD pid = GetProcessIdByName(kTargetProcess);
    if (pid == 0) {
        Log("[-]等待cs2...");
        ::ShellExecuteW(nullptr, L"open", L"steam://rungameid/730", nullptr, nullptr, SW_SHOWNORMAL);
        while ((pid = GetProcessIdByName(kTargetProcess)) == 0) ::Sleep(1000);
    }
    Log("[+]检测到cs2运行");

    Log("[+]异常处理捕获启动");
    ::Sleep(500);

    Log("[+]等待初始化");
    while (!AreAllDllsLoaded(pid)) ::Sleep(1000);

    InitPdbMap();

    Log("[+]开始直接注入Memesense");
    std::vector<std::uint8_t> payloadBuf = ReadResource(IDR_RCDATA3);
    if (!payloadBuf.empty()) {
        const MMapOptions mmOpts = MMapOptions::Defaults();
        Log("[*]DllMain 返回值强制 TRUE = %s，注入后诊断 = %s",
            mmOpts.forceDllMainTrue ? "ON" : "OFF",
            mmOpts.diagAfterEntry ? "ON" : "OFF");
        DWORD code = ManualMapBufferEx(pid, payloadBuf.data(), payloadBuf.size(), 0x666600000000ULL, entryOverride, mmOpts);
        if (code == 0) {
            Log("[+]注入成功，返回码：0");
        }
        else if (code == 259) {
            Log("[+]注入成功，返回码：259 (STILL_ACTIVE)");
        }
        else {
            Log("[-]注入失败，返回码：%lu", code);
        }
    }
    else {
        Log("[-]注入失败，读取资源错误");
    }

    Log("[+]操作完成，退出");

    // Deliberately no infinite wait here. The loader used to end with
    // `while (1) ::Sleep(INFINITE);`, which kept src.exe alive forever and
    // holding output\src.exe plus out.log. That blocked every rebuild
    // (LNK1104) and every log reset, so unattended runs were impossible.
    // cs2 keeps running on its own; the loader has nothing left to do.
    return 0;
}
