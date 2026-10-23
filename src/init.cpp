#include <winsock2.h>
#include <ws2tcpip.h>
#include "core/inject.h"
#include "core/vmp_fix.h"
#include "core/provenance.h"
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
    // Default target. Can be overridden on the command line
    // (src.exe [entryHex] [processName]) so one build works against a renamed
    // executable or a second install, instead of needing a rebuild.
    const wchar_t* kDefaultTargetProcess = L"cs2.exe";
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
            Log("[-] Could not read the CodeView record from ntdll");
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
            Log("[+] Reusing cached symbols: %ls", outPdbPath.c_str());
            return true;
        }

        std::string url = "https://msdl.microsoft.com/download/symbols/";
        url += std::filesystem::path(pdbName).string();
        url += "/";
        url += std::filesystem::path(symbolKey).string();
        url += "/";
        url += std::filesystem::path(pdbName).string();

        Log("[+] Downloading symbols...");
        Log("    %s", url.c_str());
        const std::string outPdbPathA = std::filesystem::path(outPdbPath).string();
        const HRESULT hr = ::URLDownloadToFileA(nullptr, url.c_str(), outPdbPathA.c_str(), 0, nullptr);
        if (FAILED(hr)) {
            Log("[-] Download failed, hr=0x%lX", static_cast<unsigned long>(hr));
            return false;
        }
        return true;
    }

    void InitPdbMap() {
        std::wstring pdbPath;
        if (!EnsurePdbInTemp(pdbPath)) {
            Log("[-] Symbol file unavailable, skipping PDB resolution");
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
            Log("[-] SymInitialize failed, skipping PDB resolution");
            return;
        }

        const DWORD64 fakeBase = 0x10000000;
        const DWORD64 loaded = ::SymLoadModuleExW(hProcess, NULL, pdbPath.c_str(), NULL,
                                                  fakeBase, 0, NULL, NULL);
        if (loaded == 0) {
            Log("[-] SymLoadModuleEx failed, skipping PDB resolution");
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
    // A second loader would race the first one for cs2.exe and for port 7531.
    // The mutex is the authority; the named event only exists so that a second
    // instance can tell an operator which one is already running.
    constexpr wchar_t kInstanceMutexName[] = L"Local\\MemeSense_Loader_Instance";
    constexpr wchar_t kServerReadyEvent[]  = L"Local\\MemeSense_ServerReady";
    constexpr wchar_t kHandshakeEvent[]    = L"Local\\MemeSense_Handshake";

    HANDLE g_instanceMutex = nullptr;

    bool AcquireSingleInstance() {
        g_instanceMutex = ::CreateMutexW(nullptr, TRUE, kInstanceMutexName);
        if (!g_instanceMutex) return true;   // cannot tell; do not block the run

        if (::GetLastError() == ERROR_ALREADY_EXISTS) {
            ::CloseHandle(g_instanceMutex);
            g_instanceMutex = nullptr;
            return false;
        }
        return true;
    }

    void ReleaseSingleInstance() {
        if (!g_instanceMutex) return;
        ::ReleaseMutex(g_instanceMutex);
        ::CloseHandle(g_instanceMutex);
        g_instanceMutex = nullptr;
    }

    // QuickEdit makes any click in the console a blocking selection. The loader
    // prints a lot and is often left running while cs2 starts, so an accidental
    // click would silently freeze it.
    void DisableQuickEdit() {
        for (DWORD which : { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE }) {
            HANDLE h = ::GetStdHandle(which);
            if (!h || h == INVALID_HANDLE_VALUE) continue;

            DWORD mode = 0;
            if (!::GetConsoleMode(h, &mode)) continue;

            mode &= ~ENABLE_QUICK_EDIT_MODE;
            mode |= ENABLE_EXTENDED_FLAGS;
            mode &= ~ENABLE_INSERT_MODE;
            ::SetConsoleMode(h, mode);
        }
    }

    // Keep the loader above cs2 so the progress log stays readable while the
    // game starts full screen.
    void ForceTopMost() {
        HWND wnd = ::GetConsoleWindow();
        if (!wnd) return;
        ::SetWindowPos(wnd, HWND_TOPMOST, 0, 0, 0, 0,
                       SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    }

    // Reset both events before mapping the service. The service opens them and
    // sets them; resetting here means a signalled handle can only come from this
    // run, never from a leftover process.
    bool PrepareServerEvents() {
        HANDLE ready = ::CreateEventW(nullptr, TRUE, FALSE, kServerReadyEvent);
        HANDLE handshake = ::CreateEventW(nullptr, TRUE, FALSE, kHandshakeEvent);
        if (!ready || !handshake) {
            if (ready) ::CloseHandle(ready);
            if (handshake) ::CloseHandle(handshake);
            return false;
        }
        ::ResetEvent(ready);
        ::ResetEvent(handshake);
        // The service holds its own handles; these are only for the reset, so
        // they can be closed immediately.
        ::CloseHandle(ready);
        ::CloseHandle(handshake);
        return true;
    }

    // Load binary/server.dll into the target and block until it reports that its
    // listener is up. Waiting forever is intentional: a payload injected before
    // the check service answers would fail its own startup, which is harder to
    // diagnose than a visibly stalled loader.
    bool StartCheckService(DWORD pid, const std::vector<std::uint8_t>& dll) {
        if (!PrepareServerEvents()) {
            Log("[-] Could not create the service events, err=%lu", ::GetLastError());
            return false;
        }

        Log("[+] Mapping the check service");
        const DWORD mapResult = ManualMapDll(pid, dll.data(), dll.size(), 60000);
        if (mapResult == WAIT_TIMEOUT) {
            // A service whose DllMain never returns is normal: it is a listener.
            Log("[*] Check service DllMain is still running (expected for a listener)");
        }
        else if (mapResult != 0) {
            Log("[-] Check service mapping failed, code %lu", mapResult);
            return false;
        }
        else {
            Log("[+] Check service mapped");
        }

        HANDLE handshake = ::OpenEventW(SYNCHRONIZE, FALSE, kHandshakeEvent);
        if (!handshake) {
            Log("[-] Handshake event unavailable, err=%lu", ::GetLastError());
            return false;
        }

        Log("[+] Waiting for the check service handshake");
        const DWORD wr = ::WaitForSingleObject(handshake, INFINITE);
        ::CloseHandle(handshake);

        if (wr != WAIT_OBJECT_0) {
            Log("[-] Handshake wait failed, code %lu", wr);
            return false;
        }
        Log("[+] Check service is up");
        return true;
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

    // Which of the required modules are not yet mapped into the target.
    //
    // The old version compared szModule with _wcsicmp, which is right, but it
    // returned a bare false and the caller spun forever with no output. This
    // version reports the missing names so a timeout can explain itself, and
    // treats an unreadable module list as "not ready yet" rather than a hard
    // failure, because a 32-bit target needs a different snapshot flag set.
    bool AreAllDllsLoaded(DWORD pid, std::vector<std::wstring>* outMissing = nullptr) {
        if (outMissing) outMissing->clear();

        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) {
            if (outMissing) {
                for (int i = 0; i < kReqDllCount; ++i) outMissing->emplace_back(kRequiredDlls[i]);
            }
            return false;
        }

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        BOOL found[kReqDllCount] = {};

        if (::Module32FirstW(snap, &me)) {
            do {
                for (int i = 0; i < kReqDllCount; i++) {
                    if (!found[i] && _wcsicmp(me.szModule, kRequiredDlls[i]) == 0)
                        found[i] = TRUE;
                }
            } while (::Module32NextW(snap, &me));
        }
        ::CloseHandle(snap);

        bool all = true;
        for (int i = 0; i < kReqDllCount; ++i) {
            if (!found[i]) {
                all = false;
                if (outMissing) outMissing->emplace_back(kRequiredDlls[i]);
            }
        }
        return all;
    }
}

int main(int argc, char* argv[]) {
    ::SetConsoleOutputCP(CP_UTF8);
    ::SetConsoleTitleW(L"Memesense Loader");

    if (!AcquireSingleInstance()) {
        ::MessageBoxW(nullptr,
                      L"Another Memesense Loader instance is already running.\n\n"
                      L"Close the existing window before starting a new one.",
                      L"Memesense Loader",
                      MB_OK | MB_ICONWARNING | MB_TOPMOST);
        return 1;
    }

    DisableQuickEdit();
    ForceTopMost();

    OpenLogFile();
    std::atexit(CloseLogFile);

    Log("===========================================================\n");
    Log(" Memesense Loader");
    Log( "Make in Krieg1337");
    Log(" GitHub: https://github.com/KZrieg/meme_crack");
    Log("===========================================================\n");

    std::uint32_t entryOverride = 0;
    if (argc >= 2 && argv[1] && argv[1][0]) {
        entryOverride = static_cast<std::uint32_t>(std::strtoul(argv[1], nullptr, 16));
        Log("[*] Entry point override = 0x%X", entryOverride);
    }

    // Optional third-party target name: src.exe [entryHex] [processName]
    // Kept as a raw UTF-16 conversion of the narrow argv so no wmain change is
    // needed and every existing invocation keeps its current meaning.
    std::wstring targetProcess = kDefaultTargetProcess;
    if (argc >= 3 && argv[2] && argv[2][0]) {
        wchar_t wide[MAX_PATH]{};
        if (::MultiByteToWideChar(CP_UTF8, 0, argv[2], -1, wide, MAX_PATH) > 0) {
            targetProcess = wide;
            Log("[*] Target process override = %ls", targetProcess.c_str());
        }
        else {
            Log("[-] Could not decode the target process name, using the default");
        }
    }

    if (!IsRunAsAdmin()) {
        Log("[-] Administrator privileges are required");
        return 1;
    }
    Log("[+] Administrator privileges confirmed");

    // Provenance: report only that the stamp is intact, never the tag itself.
    // Printing the value would defeat the point of encoding it.
    Log("[*] Build stamp: %s", prov::Verify() ? "verified" : "MISMATCH");

    Log("[+] Checking dependencies");
    if (GetFileSizeW(L"C:\\MemeSense\\bin\\win64\\xldr.dll") == 0) {
        Log("[-] Dependencies missing, extracting");
        ExtractDeps();
    }
    Log("[+] Dependencies present");

    DWORD pid = GetProcessIdByName(targetProcess.c_str());
    if (pid == 0) {
        Log("[-] Waiting for %ls...", targetProcess.c_str());
        // Only auto-launch the game when the default target is in use; a
        // custom target is the caller's business.
        if (_wcsicmp(targetProcess.c_str(), kDefaultTargetProcess) == 0)
            ::ShellExecuteW(nullptr, L"open", L"steam://rungameid/730", nullptr, nullptr, SW_SHOWNORMAL);
        while ((pid = GetProcessIdByName(targetProcess.c_str())) == 0) ::Sleep(1000);
    }

    // Several instances of one image can be running. Say which one was picked
    // so the operator can see it, and fail loudly instead of silently choosing
    // the wrong process.
    {
        const std::vector<DWORD> all = FindProcessIdsByName(targetProcess.c_str());
        if (all.size() > 1) {
            Log("[*] %zu matching processes; using pid %lu", all.size(), pid);
            for (DWORD other : all) {
                if (other != pid) Log("    also running: pid %lu", other);
            }
        }
    }
    Log("[+] %ls is running (pid %lu)", targetProcess.c_str(), pid);

    Log("[+] Starting exception capture");
    ::Sleep(500);

    Log("[+] Waiting for initialization");
    {
        // Bounded, but long enough for a slow game start. Prints what is
        // missing instead of spinning with no output, and gives up with an
        // actionable message rather than hanging forever.
        constexpr int kMaxWaitSeconds = 300;
        std::vector<std::wstring> missing;
        int waited = 0;
        while (!AreAllDllsLoaded(pid, &missing)) {
            if (waited % 10 == 0 && !missing.empty()) {
                std::wstring joined;
                for (const auto& m : missing) { if (!joined.empty()) joined += L", "; joined += m; }
                Log("[*] still waiting (%ds) for: %ls", waited, joined.c_str());
            }
            if (waited >= kMaxWaitSeconds) {
                Log("[-] Gave up after %d s waiting for the target's modules", kMaxWaitSeconds);
                ReleaseSingleInstance();
                return 1;
            }
            ::Sleep(1000);
            ++waited;
        }
        Log("[+] All required modules are loaded (%ds)", waited);
    }

    // The check service must be answering before the payload starts, so it is
    // mapped and confirmed here, between initialization and symbol resolution.
    {
        const std::vector<std::uint8_t> serverDll = ReadResource(IDR_RCDATA2);
        if (serverDll.empty()) {
            Log("[-] Embedded check service missing");
            ReleaseSingleInstance();
            return 1;
        }
        if (!StartCheckService(pid, serverDll)) {
            Log("[-] Check service did not come up, aborting");
            ReleaseSingleInstance();
            return 1;
        }
    }

    InitPdbMap();

    Log("[+] Injecting MemeSense payload");
    std::vector<std::uint8_t> payloadBuf = ReadResource(IDR_RCDATA3);
    if (!payloadBuf.empty()) {
        // Validate the embedded payload against this build's tables before a
        // single byte is written into the target. A payload whose .brdata slots
        // do not match the table is almost always the wrong dump (or a stale
        // payload_fix.bin), and that used to surface only as a crash inside
        // RtlAllocateHeap.
        {
            const PayloadReport rep = InspectPayloadForHost(payloadBuf.data(), payloadBuf.size());
            Log("[*] Payload self-test: file=0x%zX image=0x%X",
                rep.fileSize, rep.sizeOfImage);
            Log("[*] Payload self-test: brdata %d/%d slots match, IAT %d/%d slots in range",
                rep.slotsMatched, rep.slotsExpected, rep.importSlotsInRange, rep.importSlotsTotal);
            for (const auto& p : rep.problems) Log("    ! %s", p.c_str());
            if (!PayloadReportOk(rep)) {
                Log("[-] Payload self-test failed -- refusing to inject the wrong payload");
                ReleaseSingleInstance();
                return 1;
            }
            Log("[+] Payload self-test passed");
        }

        const MMapOptions mmOpts = MMapOptions::Defaults();
        Log("[*] Post-entry diagnostics = %s",
            mmOpts.diagAfterEntry ? "ON" : "OFF");
        DWORD code = ManualMapBufferEx(pid, payloadBuf.data(), payloadBuf.size(), 0x666600000000ULL, entryOverride, mmOpts);
        if (code == 0) {
            Log("[+] Injection succeeded, code 0");
        }
        else if (code == 259) {
            Log("[+] Injection succeeded, code 259 (STILL_ACTIVE)");
        }
        else {
            Log("[-] Injection failed, code %lu", code);
        }
    }
    else {
        Log("[-] Injection failed: could not read the embedded resource");
    }

    Log("[+] Done, exiting");
    ReleaseSingleInstance();

    // Deliberately no infinite wait here. The loader used to end with
    // `while (1) ::Sleep(INFINITE);`, which kept src.exe alive forever and
    // holding output\src.exe plus out.log. That blocked every rebuild
    // (LNK1104) and every log reset, so unattended runs were impossible.
    // cs2 keeps running on its own; the loader has nothing left to do.
    return 0;
}
