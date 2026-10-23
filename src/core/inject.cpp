#include "inject.h"
#include "common.h"
#include "imports_fix.h"
#include "vmp_fix.h"

#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>

#include <vector>
#include <string>
#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <map>
#include <mutex>

#pragma comment(lib, "psapi.lib")

extern std::map<std::string, uint32_t> g_pdb_rva_map;

const wchar_t* const kRequiredDlls[] = {
    L"ntdll.dll", L"ucrtbase.dll", L"msvcp_win.dll",
    L"v8.dll", L"sdl3.dll", L"libfreetype-6.dll",
    L"tier0.dll", L"v8_zlib.dll", L"Client.dll"
};

namespace {
    // Resolve the log path once, next to the loader executable. The previous
    // version hardcoded an absolute developer path, so every other machine
    // silently logged into a directory that did not exist and Diag() returned
    // before it could even echo to the console.
    const std::wstring& LogPath() {
        static const std::wstring path = []() {
            wchar_t exe[MAX_PATH]{};
            const DWORD n = ::GetModuleFileNameW(nullptr, exe, MAX_PATH);
            std::wstring dir;
            if (n > 0 && n < MAX_PATH) {
                dir.assign(exe, n);
                const std::size_t slash = dir.find_last_of(L"\\/");
                dir.resize(slash == std::wstring::npos ? 0 : slash + 1);
            }
            if (dir.empty()) {
                wchar_t tmp[MAX_PATH]{};
                ::GetTempPathW(MAX_PATH, tmp);
                dir = tmp;
            }
            return dir + L"out.log";
        }();
        return path;
    }

    void Diag(const char* fmt, ...) {
        char buf[1024]; va_list ap; va_start(ap, fmt);
        _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap); va_end(ap);

        static std::mutex s_logMutex;
        std::lock_guard<std::mutex> guard(s_logMutex);

        const std::string line = std::string("[D] ") + buf + "\n";

        // Append to the log, then always mirror to the console. The console
        // write must not depend on the file open succeeding.
        HANDLE f = ::CreateFileW(LogPath().c_str(), FILE_APPEND_DATA,
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                                 OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            DWORD w = 0;
            ::WriteFile(f, line.data(), (DWORD)line.size(), &w, nullptr);
            ::CloseHandle(f);
        }

        HANDLE hOut = ::GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut && hOut != INVALID_HANDLE_VALUE) {
            DWORD cw = 0;
            ::WriteConsoleA(hOut, line.data(), (DWORD)line.size(), &cw, nullptr);
        }
    }
}

namespace {
    std::uintptr_t ResolveNtdllSymbol(DWORD pid, HANDLE hProc, const char* name) {
        auto it = g_pdb_rva_map.find(name);
        if (it == g_pdb_rva_map.end()) return 0;
        const std::uintptr_t base = GetRemoteModuleBase(pid, "ntdll.dll");
        if (!base) return 0;
        return base + it->second;
    }
}

namespace {
    struct HandleCloser { void operator()(HANDLE h) const noexcept { if (h && h != INVALID_HANDLE_VALUE) ::CloseHandle(h); } };
    using UniqueHandle = std::unique_ptr<void, HandleCloser>;
    struct ProcessCloser { void operator()(HANDLE h) const noexcept { if (h) ::CloseHandle(h); } };
    using UniqueProcess = std::unique_ptr<void, ProcessCloser>;

    struct PEBDATA {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PVOID Ldr;
        PVOID ProcessParameters;
    };

    struct PEB_LDR_DATA_LOCAL {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
    };

    struct LDR_DATA_TABLE_ENTRY_LOCAL_BASE {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        PVOID DllBase;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    };

    typedef LONG(WINAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);

    // Disabled on purpose.
    //
    // This used to enable SeDebugPrivilege. VMProtect checks whether the
    // *injecting* process holds debug privilege, and the payload reacts to a
    // debugger / debug privilege by failing cleanly (no crash, no exception,
    // just FALSE from DllMain). Opening cs2 only needs
    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, which the
    // loader already has as administrator, so the privilege buys nothing here.
    bool EnableDebugPrivilegeOnce() {
        return true;
    }

    std::uintptr_t ModuleBaseViaPeb(HANDLE hProc, const wchar_t* dllNameW, std::uint32_t* outSize = nullptr) {
        HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return 0;
        auto pNtQIP = reinterpret_cast<NtQueryInformationProcess_t>(::GetProcAddress(ntdll, "NtQueryInformationProcess"));
        if (!pNtQIP) return 0;

        struct { PVOID Reserved1; PVOID PebBaseAddress; PVOID Reserved2[2]; ULONG_PTR UniqueProcessId; PVOID Reserved3; } pbi{};
        if (pNtQIP(hProc, 0, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress) return 0;

        PEBDATA peb{};
        if (!::ReadProcessMemory(hProc, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr) || !peb.Ldr) return 0;

        PEB_LDR_DATA_LOCAL ldr{};
        if (!::ReadProcessMemory(hProc, peb.Ldr, &ldr, sizeof(ldr), nullptr)) return 0;

        LIST_ENTRY* cur = ldr.InLoadOrderModuleList.Flink;
        const std::uintptr_t headAddr = reinterpret_cast<std::uintptr_t>(peb.Ldr) + offsetof(PEB_LDR_DATA_LOCAL, InLoadOrderModuleList);

        int guard = 0;
        while (cur && reinterpret_cast<std::uintptr_t>(cur) != headAddr && guard < 4096) {
            ++guard;
            LDR_DATA_TABLE_ENTRY_LOCAL_BASE ent{};
            if (!::ReadProcessMemory(hProc, cur, &ent, sizeof(ent), nullptr)) break;

            if (ent.BaseDllName.Buffer && ent.BaseDllName.Length > 0 && ent.BaseDllName.Length < 512) {
                wchar_t nameBuf[256] = {};
                const SIZE_T bytes = (ent.BaseDllName.Length < sizeof(nameBuf) - sizeof(wchar_t)) ? ent.BaseDllName.Length : (sizeof(nameBuf) - sizeof(wchar_t));
                if (::ReadProcessMemory(hProc, ent.BaseDllName.Buffer, nameBuf, bytes, nullptr)) {
                    if (_wcsicmp(nameBuf, dllNameW) == 0) {
                        if (outSize) *outSize = ent.SizeOfImage;
                        return reinterpret_cast<std::uintptr_t>(ent.DllBase);
                    }
                }
            }
            cur = ent.InLoadOrderLinks.Flink;
        }
        return 0;
    }
}

namespace {
    // Compare an image basename against a caller-supplied process name.
    //
    // The old code used wcsstr(), so "cs2" matched "cs2.exe" but also matched
    // any name merely *containing* it, and "cs2.exe" failed against "CS2.EXE".
    // Normalise both sides: strip any directory component, drop a trailing
    // ".exe", and compare case-insensitively.
    bool ProcessNameMatches(const wchar_t* exeFile, const wchar_t* wanted) {
        if (!exeFile || !wanted || !*wanted) return false;

        const auto basename = [](const wchar_t* path) -> const wchar_t* {
            const wchar_t* slash = wcsrchr(path, L'\\');
            return slash ? slash + 1 : path;
        };
        const auto stripExe = [](const wchar_t* name, wchar_t* out, std::size_t cap) {
            wcsncpy_s(out, cap, name, _TRUNCATE);
            const std::size_t n = wcslen(out);
            if (n > 4 && _wcsicmp(out + n - 4, L".exe") == 0) out[n - 4] = L'\0';
        };

        wchar_t have[MAX_PATH]{};
        wchar_t want[MAX_PATH]{};
        stripExe(basename(exeFile), have, _countof(have));
        stripExe(basename(wanted),  want, _countof(want));
        return *have && *want && _wcsicmp(have, want) == 0;
    }
}

std::vector<DWORD> FindProcessIdsByName(const wchar_t* processName) {
    std::vector<DWORD> pids;
    if (!processName || !*processName) return pids;

    UniqueHandle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snapshot.get(), &pe)) {
        do {
            if (ProcessNameMatches(pe.szExeFile, processName))
                pids.push_back(pe.th32ProcessID);
        } while (::Process32NextW(snapshot.get(), &pe));
    }
    return pids;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    const std::vector<DWORD> pids = FindProcessIdsByName(processName);
    return pids.empty() ? 0 : pids.front();
}

// Open the target with the least privilege that still allows mapping.
//
// PROCESS_ALL_ACCESS is often denied even to an administrator (protected
// processes, aggressive anti-cheat). Every operation the loader performs needs
// only QUERY_INFORMATION | VM_READ | VM_WRITE | VM_OPERATION | CREATE_THREAD.
HANDLE OpenTargetForMapping(DWORD pid, DWORD* outError) {
    if (pid == 0) { if (outError) *outError = ERROR_INVALID_PARAMETER; return nullptr; }

    const DWORD wanted = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                         PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD;

    static const DWORD attempts[] = {
        PROCESS_ALL_ACCESS,
        wanted,
        // Last resort: some hardened targets refuse CREATE_THREAD but still
        // allow writes, useful for diagnosis even if mapping cannot proceed.
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
    };

    DWORD lastError = ERROR_ACCESS_DENIED;
    for (DWORD access : attempts) {
        if (HANDLE h = ::OpenProcess(access, FALSE, pid)) {
            if (outError) *outError = 0;
            return h;
        }
        lastError = ::GetLastError();
        if (lastError == ERROR_INVALID_PARAMETER) break;   // pid gone
    }
    if (outError) *outError = lastError;
    return nullptr;
}

std::uintptr_t GetRemoteModuleBase(DWORD pid, const char* dllName) {
    if (!dllName || !dllName[0]) return 0;
    wchar_t dllNameW[MAX_PATH] = {};
    if (!::MultiByteToWideChar(CP_ACP, 0, dllName, -1, dllNameW, MAX_PATH)) return 0;
    EnableDebugPrivilegeOnce();
    UniqueProcess hProc(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (hProc.get()) {
        const std::uintptr_t viaPeb = ModuleBaseViaPeb(hProc.get(), dllNameW);
        if (viaPeb != 0) return viaPeb;
    }
    return 0;
}

std::uintptr_t GetRemoteModuleInfo(DWORD pid, const char* dllName, std::uint32_t* outSize) {
    if (outSize) *outSize = 0;
    if (!dllName || !dllName[0]) return 0;
    wchar_t dllNameW[MAX_PATH] = {};
    if (!::MultiByteToWideChar(CP_ACP, 0, dllName, -1, dllNameW, MAX_PATH)) return 0;
    EnableDebugPrivilegeOnce();
    UniqueProcess hProc(::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
    if (hProc.get()) {
        const std::uintptr_t viaPeb = ModuleBaseViaPeb(hProc.get(), dllNameW, outSize);
        if (viaPeb != 0) return viaPeb;
    }
    return 0;
}

std::vector<std::uint8_t> ReadResource(int resId) {
    HRSRC hrsrc = ::FindResourceW(nullptr, MAKEINTRESOURCEW(resId), RT_RCDATA);
    if (!hrsrc) return {};
    HGLOBAL hg = ::LoadResource(nullptr, hrsrc); if (!hg) return {};
    const DWORD size = ::SizeofResource(nullptr, hrsrc); void* ptr = ::LockResource(hg);
    if (!ptr || size == 0) return {};
    return std::vector<std::uint8_t>(static_cast<const std::uint8_t*>(ptr), static_cast<const std::uint8_t*>(ptr) + size);
}

namespace {
    bool IsForwardedExport(DWORD expRva, DWORD expSize, DWORD funcRva) {
        return funcRva >= expRva && funcRva < expRva + expSize;
    }

    bool ReadRemoteExportDir(HANDLE hProc, std::uintptr_t remoteModBase, IMAGE_EXPORT_DIRECTORY& expDir,
                             DWORD& expRva, DWORD& expSize) {
        IMAGE_DOS_HEADER dosHeader{};
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase), &dosHeader, sizeof(dosHeader), nullptr)) return false;
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;
        IMAGE_NT_HEADERS64 ntHeader{};
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + dosHeader.e_lfanew), &ntHeader, sizeof(ntHeader), nullptr)) return false;
        expRva  = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        expSize = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (!expRva) return false;
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + expRva), &expDir, sizeof(expDir), nullptr)) return false;
        if (expDir.NumberOfFunctions == 0 || expDir.NumberOfFunctions > 0x100000) return false;
        return true;
    }
}

namespace {
    // A forwarder string is "MODULE.Function" or "MODULE.#Ordinal". The old
    // code only understood the by-name form; the ordinal form fell through as a
    // raw RVA, which silently produced a wrong pointer.
    std::uintptr_t ResolveRemoteForwarder(HANDLE hProc, const char* forwarder) {
        char buf[256]{};
        strncpy_s(buf, sizeof(buf), forwarder, _TRUNCATE);
        char* dot = std::strchr(buf, '.');
        if (!dot || dot == buf || dot[1] == '\0') return 0;
        *dot = '\0';
        const char* fwdModule = buf;
        const char* fwdFunc   = dot + 1;

        char moduleFile[300] = {};
        _snprintf_s(moduleFile, sizeof(moduleFile), _TRUNCATE, "%s.dll", fwdModule);

        const std::uintptr_t fwdBase = GetRemoteModuleBase(::GetProcessId(hProc), moduleFile);
        if (!fwdBase) return 0;
        if (fwdFunc[0] == '#') {
            return GetRemoteProcAddressByOrdinal(
                hProc, fwdBase, static_cast<WORD>(std::strtoul(fwdFunc + 1, nullptr, 10)));
        }
        return GetRemoteProcAddressByName(hProc, fwdBase, fwdFunc);
    }
}

std::uintptr_t GetRemoteProcAddressByName(HANDLE hProc, std::uintptr_t remoteModBase, const char* funcName) {
    IMAGE_EXPORT_DIRECTORY expDir{}; DWORD expRva = 0, expSize = 0;
    if (!ReadRemoteExportDir(hProc, remoteModBase, expDir, expRva, expSize)) return 0;
    if (expDir.NumberOfNames == 0 || expDir.NumberOfNames > 0x100000) return 0;
    if (!expDir.AddressOfNames || !expDir.AddressOfNameOrdinals || !expDir.AddressOfFunctions) return 0;

    std::vector<DWORD> namesRva(expDir.NumberOfNames);
    std::vector<WORD>  nameOrdinals(expDir.NumberOfNames);
    if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + expDir.AddressOfNames),
                             namesRva.data(), expDir.NumberOfNames * sizeof(DWORD), nullptr)) return 0;
    if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + expDir.AddressOfNameOrdinals),
                             nameOrdinals.data(), expDir.NumberOfNames * sizeof(WORD), nullptr)) return 0;

    for (DWORD i = 0; i < expDir.NumberOfNames; i++) {
        char currentName[256] = {};
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + namesRva[i]),
                                 currentName, sizeof(currentName) - 1, nullptr)) continue;
        if (std::strcmp(currentName, funcName) != 0) continue;

        const WORD index = nameOrdinals[i];
        if (index >= expDir.NumberOfFunctions) return 0;
        DWORD funcRva = 0;
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + expDir.AddressOfFunctions
                                 + static_cast<std::uintptr_t>(index) * sizeof(DWORD)), &funcRva, sizeof(DWORD), nullptr)) return 0;

        if (!IsForwardedExport(expRva, expSize, funcRva)) return remoteModBase + funcRva;

        char forwarder[256] = {};
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + funcRva),
                                 forwarder, sizeof(forwarder) - 1, nullptr)) return 0;
        return ResolveRemoteForwarder(hProc, forwarder);
    }
    return 0;
}

std::uintptr_t GetRemoteProcAddressByOrdinal(HANDLE hProc, std::uintptr_t remoteModBase, WORD ordinal) {
    IMAGE_EXPORT_DIRECTORY expDir{}; DWORD expRva = 0, expSize = 0;
    if (!ReadRemoteExportDir(hProc, remoteModBase, expDir, expRva, expSize)) return 0;
    if (!expDir.AddressOfFunctions) return 0;
    if (ordinal < expDir.Base) return 0;
    if (static_cast<DWORD>(ordinal) >= expDir.Base + expDir.NumberOfFunctions) return 0;
    const DWORD index = static_cast<DWORD>(ordinal) - expDir.Base;
    DWORD funcRva = 0;
    if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + expDir.AddressOfFunctions + static_cast<std::uintptr_t>(index) * sizeof(DWORD)), &funcRva, sizeof(DWORD), nullptr)) return 0;
    if (funcRva == 0) return 0;
    if (!IsForwardedExport(expRva, expSize, funcRva)) return remoteModBase + funcRva;

    char forwarder[256] = {};
    if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(remoteModBase + funcRva),
                             forwarder, sizeof(forwarder) - 1, nullptr)) return 0;
    return ResolveRemoteForwarder(hProc, forwarder);
}

    struct LdrEntryLocal {
        LIST_ENTRY     InLoadOrderLinks;            // 0x00
        LIST_ENTRY     InMemoryOrderLinks;          // 0x10
        LIST_ENTRY     InInitializationOrderLinks;  // 0x20
        PVOID          DllBase;                     // 0x30
        PVOID          EntryPoint;                  // 0x38
        ULONG          SizeOfImage;                 // 0x40
        ULONG          Pad0;                        // 0x44
        UNICODE_STRING FullDllName;                 // 0x48
        UNICODE_STRING BaseDllName;                 // 0x58
        ULONG          Flags;                       // 0x68
        USHORT         ObsoleteLoadCount;           // 0x6C
        USHORT         TlsIndex;                    // 0x6E
        LIST_ENTRY     HashLinks;                   // 0x70
        ULONG          TimeDateStamp;               // 0x80
        ULONG          Pad1;                        // 0x84
        PVOID          EntryPointActivationContext; // 0x88
        PVOID          Lock;                        // 0x90
        PVOID          DdagNode;                    // 0x98
        LIST_ENTRY     NodeModuleLink;              // 0xA0
        PVOID          LoadContext;                 // 0xB0
        PVOID          ParentDllBase;               // 0xB8
        PVOID          SwitchBackContext;           // 0xC0
        PVOID          BaseAddressIndexNode[3];     // 0xC8  (RTL_BALANCED_NODE)
        PVOID          MappingInfoIndexNode[3];     // 0xE0
        ULONG64        OriginalBase;                // 0xF8
        LARGE_INTEGER  LoadTime;                    // 0x100
        ULONG          BaseNameHashValue;           // 0x108
        ULONG          Pad2;                        // 0x10C
    };
    static_assert(offsetof(LdrEntryLocal, DdagNode) == 0x98,
                  "DdagNode must sit at 0x98 or LdrpInitializeThread faults");
    static_assert(offsetof(LdrEntryLocal, Flags) == 0x68, "Flags offset");
    static_assert(offsetof(LdrEntryLocal, HashLinks) == 0x70, "HashLinks offset");

    // PEB->Ldr registration.
    //
    // The payload's own exception handler (RVA 0x5380) calls
    // LdrFindEntryForAddress and requires entry->DllBase == <payload base>;
    // on failure the SEH/CRT init path bails at 0x553d. LdrFindEntryForAddress
    // does NOT walk InLoadOrderLinks, it walks the RTL_RB_TREE at
    // LdrpModuleBaseAddressIndex, whose nodes are LDR_DATA_TABLE_ENTRY+0xC8.
    //
    // Verified against the live ntdll of this host (10.0.26100.9549) by
    // disassembly of LdrFindEntryForAddress (RVA 0x53EC0):
    //
    //   0x53EDD  lea  rdx, [rax+0x18]        ; out entry
    //   0x53EE1  call LdrpFindEntryForAddress (RVA 0x30740)
    //
    // and of LdrpFindEntryForAddress (RVA 0x30740):
    //
    //   0x307B9  mov  rax, [LdrpModuleBaseAddressIndex+0x00]   ; Root
    //   0x307C0  mov  rbx, [LdrpModuleBaseAddressIndex+0x08]   ; Min
    //   0x307C7  test al, 1                                    ; Root obfuscated?
    //   0x307C9  jne  encoded                                  ; rbx ^= &tree
    //   0x307E0  mov  rcx, [rbx-0x98]                          ; node -> DllBase
    //   0x307EC  mov  eax, [rbx-0x88]                          ; node -> SizeOfImage
    //   0x3080C  mov  rax, [rbx]                               ; left
    //   0x307FA  mov  rax, [rbx+8]                             ; right
    //   0x30820  mov  rax, [rbx-0x30]                          ; node -> DdagNode
    //   0x3082B  cmp  dword ptr [rax+0x18], -1                 ; DdagNode marker
    //
    // Two consequences drive this implementation:
    //   * inserting with Parent == NULL is only valid into an EMPTY tree. The
    //     real tree is already populated, so the insertion point must be found
    //     first, exactly like LdrpInsertModuleToIndex does. Passing NULL there
    //     overwrites Root and abandons every existing module.
    //   * the DdagNode must be a self-consistent structure; a zeroed block
    //     leaves null list heads that ntdll dereferences.
    bool RegisterModuleInLdr(HANDLE hProc, DWORD pid, std::uintptr_t imageBase,
                             std::uint32_t imageSize, std::uintptr_t entryPoint,
                             const wchar_t* dllName)
    {
        // LDR_DDAG_NODE. Only the marker at +0x18 is provable from the
        // disassembly above, so every LIST_ENTRY is self-linked: a self-linked
        // list terminates immediately, a zeroed one dereferences null.
        struct DdagNodeLocal {
            LIST_ENTRY    modules;   // +0x00, self-linked
            std::uint64_t unknown10; // +0x10
            std::uint32_t marker;    // +0x18, must read 0xFFFFFFFF
            std::uint32_t unknown1c; // +0x1C
            std::uint8_t  rest[0x40 - 0x20];
        };
        static_assert(offsetof(DdagNodeLocal, modules) == 0x00, "DdagNode modules offset");
        static_assert(offsetof(DdagNodeLocal, marker) == 0x18, "DdagNode marker offset");
        static_assert(sizeof(DdagNodeLocal) == 0x40, "DdagNode size");

        const std::uintptr_t ntdllBase = GetRemoteModuleBase(pid, "ntdll.dll");
        if (!ntdllBase) { Diag("Ldr: ntdll base unresolved"); return false; }

        // RtlRbInsertNodeEx and the tree address are private, so they come from
        // the PDB map; LdrFindEntryForAddress is a public export and is read
        // straight from the export directory.
        const auto rvaOf = [](const char* name) -> std::uint32_t {
            auto it = g_pdb_rva_map.find(name);
            return (it == g_pdb_rva_map.end()) ? 0u : it->second;
        };
        const std::uint32_t rvaRbInsert = rvaOf("RtlRbInsertNodeEx");
        if (!rvaRbInsert) { Diag("Ldr: RtlRbInsertNodeEx RVA unresolved"); return false; }
        const std::uintptr_t pRbInsert = ntdllBase + rvaRbInsert;

        const std::uint32_t rvaIndex = rvaOf("LdrpModuleBaseAddressIndex");
        if (!rvaIndex) { Diag("Ldr: LdrpModuleBaseAddressIndex RVA unresolved"); return false; }
        const std::uintptr_t addrIndex = ntdllBase + rvaIndex;

        const std::uintptr_t pFindEntry =
            GetRemoteProcAddressByName(hProc, ntdllBase, "LdrFindEntryForAddress");
        if (!pFindEntry) { Diag("Ldr: LdrFindEntryForAddress export not found"); return false; }

        using NtQIP_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        auto pNtQIP = reinterpret_cast<NtQIP_t>(
            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
        if (!pNtQIP) return false;
        struct { PVOID r1; PVOID PebBaseAddress; PVOID r2[2]; ULONG_PTR pid; PVOID r3; } pbi{};
        if (pNtQIP(hProc, 0, &pbi, sizeof(pbi), nullptr) != 0 || !pbi.PebBaseAddress) return false;

        std::uintptr_t ldrAddr = 0;
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(
                reinterpret_cast<std::uintptr_t>(pbi.PebBaseAddress) + 0x18),
                &ldrAddr, sizeof(ldrAddr), nullptr) || !ldrAddr) return false;

        // One allocation holds the entry, its name copies and the DdagNode, so
        // a single VirtualFreeEx would clean up if this ever needs undoing.
        const std::size_t nameChars = wcslen(dllName);
        const std::size_t nameBytes = (nameChars + 1) * sizeof(wchar_t);
        const std::size_t entryBytes = sizeof(LdrEntryLocal);
        const std::size_t blockBytes = entryBytes + nameBytes * 2 + sizeof(DdagNodeLocal) + 0x40;

        auto* block = static_cast<std::uint8_t*>(
            ::VirtualAllocEx(hProc, nullptr, blockBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!block) { Diag("Ldr: VirtualAllocEx failed"); return false; }

        const std::uintptr_t entryAddr = reinterpret_cast<std::uintptr_t>(block);
        const std::uintptr_t nameAddr  = entryAddr + entryBytes;
        const std::uintptr_t dagAddr   = nameAddr + nameBytes * 2;

        if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(nameAddr), dllName, nameBytes, nullptr))
            return false;

        LdrEntryLocal ent{};
        ent.DllBase     = reinterpret_cast<PVOID>(imageBase);
        ent.EntryPoint  = reinterpret_cast<PVOID>(entryPoint);
        ent.SizeOfImage = imageSize;

        ent.FullDllName.Buffer        = reinterpret_cast<PWSTR>(nameAddr);
        ent.FullDllName.Length        = static_cast<USHORT>(nameChars * sizeof(wchar_t));
        ent.FullDllName.MaximumLength = static_cast<USHORT>(nameBytes);
        ent.BaseDllName               = ent.FullDllName;

        // 0x84004 = IMAGE_DLL | PROCESS_ATTACH_CALLED, LOAD_IN_PROGRESS cleared.
        ent.Flags             = 0x00084004;
        ent.ObsoleteLoadCount = 1;
        ent.TlsIndex          = 0xFFFF;
        ent.DdagNode          = reinterpret_cast<PVOID>(dagAddr);
        ent.OriginalBase      = imageBase;
        ent.BaseNameHashValue = 0;   // 0 => ntdll treats the name as not-yet-hashed

        // Each list field must point at ITSELF, not at InLoadOrderLinks. The
        // previous version wrote the same +0x00 offset into all three lists,
        // which turns every InMemoryOrder / InInitializationOrder walk into a
        // self-loop on the wrong field.
        const std::uintptr_t loadLinks     = entryAddr + offsetof(LdrEntryLocal, InLoadOrderLinks);
        const std::uintptr_t memLinks      = entryAddr + offsetof(LdrEntryLocal, InMemoryOrderLinks);
        const std::uintptr_t initLinks     = entryAddr + offsetof(LdrEntryLocal, InInitializationOrderLinks);
        const auto selfLink = [](std::uintptr_t at) {
            LIST_ENTRY e{};
            e.Flink = reinterpret_cast<LIST_ENTRY*>(at);
            e.Blink = reinterpret_cast<LIST_ENTRY*>(at);
            return e;
        };
        ent.InLoadOrderLinks           = selfLink(loadLinks);
        ent.InMemoryOrderLinks         = selfLink(memLinks);
        ent.InInitializationOrderLinks = selfLink(initLinks);

        DdagNodeLocal dag{};
        dag.modules = selfLink(dagAddr + offsetof(DdagNodeLocal, modules));
        dag.marker  = 0xFFFFFFFFu;

        if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(entryAddr), &ent, sizeof(ent), nullptr))
            return false;
        if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(dagAddr), &dag, sizeof(dag), nullptr))
            return false;

        // Splice the load-order list, so tools that walk PEB->Ldr see the module.
        {
            const std::uintptr_t loadHead = ldrAddr + 0x10;
            LIST_ENTRY lh{};
            if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(loadHead), &lh, sizeof(lh), nullptr))
                return false;
            if (!lh.Flink || !lh.Blink) return false;

            ent.InLoadOrderLinks.Flink = lh.Flink;
            ent.InLoadOrderLinks.Blink = reinterpret_cast<LIST_ENTRY*>(loadHead);
            if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(loadLinks), &ent.InLoadOrderLinks,
                                      sizeof(LIST_ENTRY), nullptr)) return false;

            const auto linksPtr = reinterpret_cast<PVOID>(loadLinks);
            const std::uintptr_t oldFirst = reinterpret_cast<std::uintptr_t>(lh.Flink);
            if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(oldFirst + offsetof(LIST_ENTRY, Blink)),
                                      &linksPtr, sizeof(PVOID), nullptr)) return false;
            if (!::WriteProcessMemory(hProc, reinterpret_cast<LPVOID>(loadHead + offsetof(LIST_ENTRY, Flink)),
                                      &linksPtr, sizeof(PVOID), nullptr)) return false;
        }

        // Locate the insertion point in LdrpModuleBaseAddressIndex.
        //
        // Root is stored verbatim, except that bit 0 of the Root value marks a
        // per-tree XOR obfuscation of every node link with the tree address
        // (LdrpFindEntryForAddress at 0x307C7 and RtlRbInsertNodeEx at 0x440BC
        // both test exactly that bit).
        std::uint64_t root = 0;
        std::uint8_t  flagByte = 0;
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addrIndex), &root, sizeof(root), nullptr))
            return false;
        if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(addrIndex + 8), &flagByte, sizeof(flagByte), nullptr))
            return false;
        const bool encoded = (flagByte & 1) != 0;

        const auto decode = [&](std::uint64_t v) -> std::uint64_t {
            return encoded ? (v ^ addrIndex) : v;
        };

        const std::uintptr_t nodeAddr = entryAddr + offsetof(LdrEntryLocal, BaseAddressIndexNode);

        std::uint64_t parent = 0;
        bool insertRight = false;
        {
            std::uint64_t cur = decode(root);
            int guard = 0;
            while (cur != 0 && guard++ < 4096) {
                std::uint64_t dllBase = 0;
                std::uint32_t sizeOfImage = 0;
                if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(cur - 0x98), &dllBase, sizeof(dllBase), nullptr))
                    break;
                if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(cur - 0x88), &sizeOfImage, sizeof(sizeOfImage), nullptr))
                    break;

                parent = cur;
                const bool goRight = (imageBase >= dllBase + sizeOfImage);
                if (imageBase >= dllBase && imageBase < dllBase + sizeOfImage) {
                    Diag("Ldr: image range already present in the tree (base=0x%llX) -- aborting insert",
                         (unsigned long long)dllBase);
                    return false;
                }
                insertRight = goRight;

                std::uint64_t next = 0;
                if (!::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(cur + (goRight ? 8 : 0)),
                                         &next, sizeof(next), nullptr))
                    break;
                cur = decode(next);
            }
        }

        // RtlRbInsertNodeEx(Tree, Parent, RightChild, Node)
        //
        // Signature confirmed from the live ntdll body (RVA 0x440A0):
        //   movzx ebp, r8b        -> RightChild is r8b, not dl
        //   test  rdx, rdx        -> Parent in rdx
        //   mov   [r11], rax      -> Tree in rcx
        //   mov   [r9], rsi       -> Node in r9
        {
            std::uint8_t code[] = {
                0x48, 0x83, 0xEC, 0x28,                       // sub  rsp, 0x28
                0x48, 0xB9, 0,0,0,0,0,0,0,0,                  // mov  rcx, tree
                0x48, 0xBA, 0,0,0,0,0,0,0,0,                  // mov  rdx, parent
                0x41, 0xB0, 0x00,                             // mov  r8b, rightChild
                0x49, 0xB9, 0,0,0,0,0,0,0,0,                  // mov  r9, node
                0x48, 0xB8, 0,0,0,0,0,0,0,0,                  // mov  rax, RtlRbInsertNodeEx
                0xFF, 0xD0,                                   // call rax
                0x48, 0x89, 0x05, 0,0,0,0,                    // mov  [rip+disp32], rax
                0x48, 0x83, 0xC4, 0x28,                       // add  rsp, 0x28
                0xC3,                                         // ret
            };
            // Fixed offsets of the patched fields, asserted so a future edit
            // cannot silently shift them.
            constexpr std::size_t kOffTree   = 6;    // movabs rcx, imm64
            constexpr std::size_t kOffParent = 16;   // movabs rdx, imm64
            constexpr std::size_t kOffRight  = 26;   // mov    r8b, imm8
            constexpr std::size_t kOffNode   = 29;   // movabs r9,  imm64
            constexpr std::size_t kOffInsert = 39;   // movabs rax, imm64
            constexpr std::size_t kOffDisp   = 52;   // mov    [rip+disp32], rax

            std::memcpy(code + kOffTree,   &addrIndex, 8);
            std::memcpy(code + kOffParent, &parent,    8);
            std::memcpy(code + kOffNode,   &nodeAddr,  8);
            std::memcpy(code + kOffInsert, &pRbInsert, 8);
            code[kOffRight] = insertRight ? 1 : 0;

            auto* stub = static_cast<std::uint8_t*>(
                ::VirtualAllocEx(hProc, nullptr, sizeof(code) + 16, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE));
            if (!stub) { Diag("Ldr: tree stub alloc failed"); return false; }

            const std::uintptr_t retSlot = reinterpret_cast<std::uintptr_t>(stub) + sizeof(code);
            const std::int64_t disp =
                static_cast<std::int64_t>(retSlot) -
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(stub) + kOffDisp + 4);
            const auto disp32 = static_cast<std::int32_t>(disp);
            std::memcpy(code + kOffDisp, &disp32, 4);
            if (!::WriteProcessMemory(hProc, stub, code, sizeof(code), nullptr)) return false;

            UniqueHandle th(::CreateRemoteThread(hProc, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(stub), nullptr, 0, nullptr));
            if (th.get()) ::WaitForSingleObject(th.get(), 5000);

            std::uint64_t insertRet = 0;
            ::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(retSlot), &insertRet, sizeof(insertRet), nullptr);
            ::VirtualFreeEx(hProc, stub, 0, MEM_RELEASE);

            Diag("Ldr: RtlRbInsertNodeEx(tree=0x%llX, parent=0x%llX, right=%d, node=0x%llX) -> 0x%llX",
                 (unsigned long long)addrIndex, (unsigned long long)parent, insertRight ? 1 : 0,
                 (unsigned long long)nodeAddr, (unsigned long long)insertRet);
            if (insertRet != nodeAddr) {
                Diag("Ldr: insert did not return the node -- tree state is unknown");
                return false;
            }
        }

        // Verify the lookup the way the payload will, using the real export.
        {
            std::uint8_t code[] = {
                0x48, 0x83, 0xEC, 0x28,
                0x48, 0xB9, 0,0,0,0,0,0,0,0,                  // rcx = address to look up
                0x48, 0x8D, 0x54, 0x24, 0x30,                 // rdx = &out
                0x48, 0xB8, 0,0,0,0,0,0,0,0,                  // rax = LdrFindEntryForAddress
                0xFF, 0xD0,
                0x48, 0x89, 0x05, 0,0,0,0,                    // mov [rip+disp32], rax
                0x48, 0x83, 0xC4, 0x28,
                0xC3,
            };
            const std::uintptr_t probe = imageBase + 0x1000;
            std::memcpy(code + 6,  &probe,    8);
            std::memcpy(code + 21, &pFindEntry, 8);
            const std::size_t stOff = 29 + 3;

            auto* b2 = static_cast<std::uint8_t*>(
                ::VirtualAllocEx(hProc, nullptr, sizeof(code) + 16, MEM_COMMIT | MEM_RESERVE,
                                 PAGE_EXECUTE_READWRITE));
            if (!b2) return true;   // the module is registered; only the check failed

            const std::uintptr_t stSlot = reinterpret_cast<std::uintptr_t>(b2) + sizeof(code);
            const std::int64_t d2 =
                static_cast<std::int64_t>(stSlot) -
                static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(b2) + stOff + 4);
            std::memcpy(code + stOff, &d2, 4);
            ::WriteProcessMemory(hProc, b2, code, sizeof(code), nullptr);

            UniqueHandle th2(::CreateRemoteThread(hProc, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(b2), nullptr, 0, nullptr));
            if (th2.get()) ::WaitForSingleObject(th2.get(), 5000);

            std::uint64_t st = 0;
            ::ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(stSlot), &st, sizeof(st), nullptr);
            ::VirtualFreeEx(hProc, b2, 0, MEM_RELEASE);

            Diag("Ldr: self-check LdrFindEntryForAddress(0x%llX) -> 0x%llX %s",
                 (unsigned long long)probe, (unsigned long long)st,
                 (st == 0) ? "OK (payload SEH can resolve itself)"
                           : "FAILED (payload SEH will bail at 0x553d)");
            if (st != 0) return false;
        }

        return true;
    }

// ---------------------------------------------------------------------------
// Image layout detection
//
// payload.bin is a raw memory dump: bytes are already in VA order, so file
// offset == RVA. payload_fix.bin produced by tools/make.bat (pe_unmapper) is a
// conventional FILE-layout PE, where each section lives at PointerToRawData.
//
// The old loader blindly memcpy'd the buffer to the image vector, which only
// works for the VA-layout dump. Feeding it a pe_unmapper output copied the DOS
// header into .text and every section landed at the wrong offset, so the entry
// point decoded as garbage. Detect which layout a buffer is in, then build the
// image accordingly. This is what lets one binary accept either dump flavour,
// from any host, without a compile-time switch.
// Map a standard PE file into VA layout.
//
// This is deliberately NOT a heuristic. The build pipeline is:
//
//     memory dump  ->  tools/make.bat (pe_unmapper)  ->  binary/payload_fix.bin
//     (payload.bin, VA order)                            (ordinary PE file,
//                                                         sections at
//                                                         PointerToRawData)
//
// src.rc embeds payload_fix.bin, so the loader always receives an ordinary PE
// file and maps it exactly like the Windows loader does: headers at offset 0,
// each section copied from its file offset to its RVA. payload.bin is a raw
// dump and must be run through make.bat first; handing it to this function is a
// build mistake, and the section bounds check below reports it as one.
static bool BuildMappedImage(const std::uint8_t* data, std::size_t size,
                             const IMAGE_NT_HEADERS64* pNt,
                             std::vector<std::uint8_t>& outImage) {
    const std::uint32_t sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    if (sizeOfImage < sizeof(IMAGE_DOS_HEADER)) return false;

    // A file-layout PE must carry its own headers and every section's raw data
    // inside the buffer. A raw dump does not satisfy this for .reloc, which
    // sits past the dump's end -- that is the signal that make.bat was skipped.
    const std::size_t headerBytes = pNt->OptionalHeader.SizeOfHeaders;
    if (headerBytes == 0 || headerBytes > size) return false;

    outImage.assign(sizeOfImage, 0);
    std::memcpy(outImage.data(), data, (std::min<std::size_t>)(headerBytes, sizeOfImage));

    const auto* sec = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
        const std::size_t rawOff = sec[i].PointerToRawData;
        const std::size_t rawLen = sec[i].SizeOfRawData;
        const std::size_t dstOff = sec[i].VirtualAddress;
        const std::size_t want   = (std::min<std::size_t>)(rawLen, sec[i].Misc.VirtualSize);

        if (want == 0) continue;
        if (rawOff + want > size) return false;                 // not a file-layout PE
        if (dstOff + want > sizeOfImage) return false;          // corrupt section
        std::memcpy(outImage.data() + dstOff, data + rawOff, want);
    }
    return true;
}

struct TlsInfoLocal {
    uint64_t rawStartVa = 0, rawEndVa = 0, addrOfIndex = 0, addrOfCb = 0;
    uint32_t sizeOfZero = 0, characteristics = 0;
    std::size_t templateOffset = 0;   // rawStartVa translated into the file
    bool valid = false;
};

static TlsInfoLocal ParseTls(const std::uint8_t* data, std::size_t size,
                             const IMAGE_NT_HEADERS64* pNt) {
    TlsInfoLocal out;
    const std::uint32_t tlsRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    const std::uint32_t tlsSz  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    if (!tlsRva || tlsSz < 40) return out;

    // `data` is always the mapped VA-layout image here, so an RVA is a direct
    // index. The previous version translated through PointerToRawData, which is
    // right for a file but wrong once the caller already mapped the image.
    if (tlsRva + 40 > size) return out;
    const std::size_t off = tlsRva;

    std::memcpy(&out.rawStartVa, data + off + 0,  8);
    std::memcpy(&out.rawEndVa,   data + off + 8,  8);
    std::memcpy(&out.addrOfIndex,data + off + 16, 8);
    std::memcpy(&out.addrOfCb,   data + off + 24, 8);
    std::memcpy(&out.sizeOfZero, data + off + 32, 4);
    std::memcpy(&out.characteristics, data + off + 36, 4);

    // The TLS template address is an RVA in the mapped image, so it indexes
    // directly. Bounds checked; a bad value simply leaves templateOffset = 0.
    if (out.rawStartVa < size) {
        out.templateOffset = static_cast<std::size_t>(out.rawStartVa);
    }

    out.valid = true;
    return out;
}

static bool SetupTls(HANDLE h, DWORD pid, const std::uint8_t* data, std::size_t size,
                     const IMAGE_NT_HEADERS64* pNt, std::uintptr_t base,
                     std::int64_t delta, std::uintptr_t imageBase) {
    const TlsInfoLocal tls = ParseTls(data, size, pNt);
    if (!tls.valid) { Diag("TLS: no directory"); return true; }

    const std::uint32_t tmplSize = (tls.rawEndVa > tls.rawStartVa)
        ? static_cast<std::uint32_t>(tls.rawEndVa - tls.rawStartVa) + tls.sizeOfZero : 0;
    if (tmplSize == 0) { Diag("TLS: empty template"); return true; }

    Diag("TLS: tmplSize=0x%X indexAddr=0x%llX cbAddr=0x%llX",
        tmplSize, (unsigned long long)tls.addrOfIndex, (unsigned long long)tls.addrOfCb);

    const std::uintptr_t tlsData = reinterpret_cast<std::uintptr_t>(
        ::VirtualAllocEx(h, nullptr, tmplSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!tlsData) return false;

    const std::uintptr_t nt = GetRemoteModuleBase(pid, "ntdll.dll");
    if (!nt) return false;
    const std::uintptr_t pTlsAlloc = GetRemoteProcAddressByName(h, nt, "TlsAlloc");
    if (!pTlsAlloc) { Diag("TLS: TlsAlloc not found"); return false; }

    const std::uintptr_t scratch = reinterpret_cast<std::uintptr_t>(
        ::VirtualAllocEx(h, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!scratch) return false;

    std::vector<std::uint8_t> ts;
    auto ta = [&ts](std::initializer_list<std::uint8_t> b) { ts.insert(ts.end(), b.begin(), b.end()); };
    auto ta64 = [&ts](std::uint64_t v) { for (int i=0;i<8;i++) ts.push_back(static_cast<std::uint8_t>((v>>(i*8))&0xFF)); };
    ta({0x48,0x83,0xEC,0x28});
    ta({0x48,0xB8}); ta64(pTlsAlloc);
    ta({0xFF,0xD0});
    ta({0x89,0x04,0x25});
    for (int i=0;i<4;i++) ts.push_back(static_cast<std::uint8_t>((scratch>>(i*8))&0xFF));
    ta({0x48,0x83,0xC4,0x28});
    ta({0xC3});

    const std::uintptr_t tsMem = reinterpret_cast<std::uintptr_t>(
        ::VirtualAllocEx(h, nullptr, ts.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!tsMem) return false;
    if (!::WriteProcessMemory(h, reinterpret_cast<LPVOID>(tsMem), ts.data(), ts.size(), nullptr)) return false;

    UniqueHandle t1(::CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(tsMem), nullptr, 0, nullptr));
    if (t1.get()) { ::WaitForSingleObject(t1.get(), 5000); }
    ::VirtualFreeEx(h, reinterpret_cast<LPVOID>(tsMem), 0, MEM_RELEASE);

    std::uint32_t tlsIndex = 0;
    ::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(scratch), &tlsIndex, 4, nullptr);
    if (tlsIndex == 0xFFFFFFFF) { Diag("TLS: TlsAlloc failed"); return false; }
    Diag("TLS: index=%u", tlsIndex);

    const std::uintptr_t idxAddr = static_cast<std::uintptr_t>(tls.addrOfIndex) + delta;
    if (!::WriteProcessMemory(h, reinterpret_cast<LPVOID>(idxAddr), &tlsIndex, 4, nullptr)) {
        Diag("TLS: write index failed"); return false;
    }

    if (tls.rawEndVa > tls.rawStartVa) {
        // Copy the template out of the dumped image, not out of the target: the
        // preferred VA of the template was never mapped at that address.
        const std::size_t n = static_cast<std::size_t>(tls.rawEndVa - tls.rawStartVa);
        std::vector<std::uint8_t> tmpl(n, 0);
        if (tls.templateOffset != 0 && tls.templateOffset + n <= size) {
            std::memcpy(tmpl.data(), data + tls.templateOffset, n);
        }
        if (!::WriteProcessMemory(h, reinterpret_cast<LPVOID>(tlsData), tmpl.data(), n, nullptr)) {
            Diag("TLS: template write failed"); return false;
        }
    }

    if (tls.addrOfCb) {
        const std::uintptr_t cbArr = static_cast<std::uintptr_t>(tls.addrOfCb) + delta;
        for (int i = 0; i < 64; i++) {
            std::uint64_t cb = 0;
            if (!::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(cbArr + i*8), &cb, 8, nullptr)) break;
            if (cb == 0) break;
            const std::uint64_t cbActual = cb + static_cast<std::uint64_t>(delta);
            Diag("TLS: callback[%d] at 0x%llX", i, (unsigned long long)cbActual);

            std::vector<std::uint8_t> cs;
            auto ca = [&cs](std::initializer_list<std::uint8_t> b) { cs.insert(cs.end(), b.begin(), b.end()); };
            auto ca64 = [&cs](std::uint64_t v) { for (int j=0;j<8;j++) cs.push_back(static_cast<std::uint8_t>((v>>(j*8))&0xFF)); };
            ca({0x48,0x83,0xEC,0x28});
            ca({0x48,0xB9}); ca64(base);
            ca({0xBA,0x01,0x00,0x00,0x00});
            ca({0x41,0xB8,0x01,0x00,0x00,0x00});
            ca({0x48,0xB8}); ca64(cbActual);
            ca({0xFF,0xD0});
            ca({0x48,0x83,0xC4,0x28});
            ca({0xC3});

            const std::uintptr_t cm = reinterpret_cast<std::uintptr_t>(
                ::VirtualAllocEx(h, nullptr, cs.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
            if (!cm) continue;
            if (!::WriteProcessMemory(h, reinterpret_cast<LPVOID>(cm), cs.data(), cs.size(), nullptr)) continue;
            UniqueHandle t2(::CreateRemoteThread(h, nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(cm), nullptr, 0, nullptr));
            if (t2.get()) ::WaitForSingleObject(t2.get(), 10000);
            ::VirtualFreeEx(h, reinterpret_cast<LPVOID>(cm), 0, MEM_RELEASE);
        }
    }
    return true;
}

static bool RegisterExceptionTable(HANDLE h, DWORD pid, const IMAGE_NT_HEADERS64* pNt,
                                   std::uintptr_t base, std::int64_t delta) {
    const std::uint32_t excRva = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    const std::uint32_t excSz  = pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
    if (!excRva || excSz < 12) { Diag("EH: no exception directory"); return true; }
    const std::uint32_t count = excSz / 12;

    const std::uintptr_t nt = GetRemoteModuleBase(pid, "ntdll.dll");
    if (!nt) return false;
    const std::uintptr_t pAdd = GetRemoteProcAddressByName(h, nt, "RtlAddFunctionTable");
    if (!pAdd) { Diag("EH: RtlAddFunctionTable not found"); return false; }

    const std::uintptr_t tableAddr = base + excRva;

    std::vector<std::uint8_t> stub;
    auto a = [&stub](std::initializer_list<std::uint8_t> b) { stub.insert(stub.end(), b.begin(), b.end()); };
    auto a64 = [&stub](std::uint64_t v) { for (int i=0;i<8;i++) stub.push_back(static_cast<std::uint8_t>((v>>(i*8))&0xFF)); };
    a({0x48,0x83,0xEC,0x28});
    a({0x48,0xB9}); a64(tableAddr);
    a({0xBA}); for (int i=0;i<4;i++) stub.push_back(static_cast<std::uint8_t>((count>>(i*8))&0xFF));
    a({0x49,0xB8}); a64(base);
    a({0x48,0xB8}); a64(pAdd);
    a({0xFF,0xD0});
    a({0x48,0x83,0xC4,0x28});
    a({0xC3});

    const std::uintptr_t mem = reinterpret_cast<std::uintptr_t>(
        ::VirtualAllocEx(h, nullptr, stub.size(), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!mem) return false;
    if (!::WriteProcessMemory(h, reinterpret_cast<LPVOID>(mem), stub.data(), stub.size(), nullptr)) return false;

    UniqueHandle th(::CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(mem), nullptr, 0, nullptr));
    DWORD code = 0xFFFFFFFF;
    if (th.get()) {
        ::WaitForSingleObject(th.get(), 5000);
        ::GetExitCodeThread(th.get(), &code);
    }
    ::VirtualFreeEx(h, reinterpret_cast<LPVOID>(mem), 0, MEM_RELEASE);

    Diag("EH: RtlAddFunctionTable(table=0x%llX, count=%u) -> 0x%X",
        (unsigned long long)tableAddr, count, code);
    (void)delta;
    return code != 0;
}

// ---------------------------------------------------------------------------
// Multi-device support: recover the dump-host module bases from the payload.
//
// The .brdata slots hold absolute pointers captured on whichever machine the
// payload was dumped from. The old code hardcoded that machine's ntdll and
// sdl3 bases, so a dump from any other host silently produced wrong pointers
// and VMProtect either refused to decrypt or fed garbage to RtlAllocateHeap.
//
// Every IAT entry in imports_fix.h is the same kind of captured pointer, but
// each one names the module and export it came from. Resolving the same export
// in the live target gives the module's load delta directly:
//
//     delta = liveExport - capturedIat
//     dumpBase = liveModuleBase - delta
//
// IMPORTANT LIMIT: `liveExport - capturedIat` equals the module's load delta
// only when the export sits at the same RVA in both builds. Across Windows
// versions it does not (the IAT is dump-build-relative), so the deltas scatter.
// The mode test below therefore *refuses* to report a base unless one delta has
// a strict majority, which is exactly the same-build case (for example a payload
// re-dumped and reloaded on one machine). On a cross-build payload it returns
// the recorded constants and the caller logs that the bases are unverified.
//
// This is still worth doing: it is what makes a same-machine re-dump work with
// no edit, and it turns a silent wrong-pointer write into a logged fallback.
struct DumpBases {
    std::uint64_t ntdll = kDumpNtdllBase;
    std::uint64_t sdl3  = kDumpSdl3Base;
    bool ntdllDerived = false;
    bool sdl3Derived  = false;
    int  ntdllSamples = 0;
    int  sdl3Samples  = 0;
};

// Does `addr` fall inside a live module's mapped image?
//
// This is the cheap, build-independent guard that was missing: a wrong dump
// base used to produce a plausible-looking pointer into unmapped memory, and
// VMProtect only failed much later (inside RtlAllocateHeap). Checking the range
// at write time turns that into an immediate, named diagnostic.
static bool IsAddressInLiveModule(DWORD pid, const char* module, std::uint64_t addr,
                                  std::uint64_t* outBase = nullptr,
                                  std::uint32_t* outSize = nullptr) {
    std::uint32_t size = 0;
    const std::uintptr_t base = GetRemoteModuleInfo(pid, module, &size);
    if (outBase) *outBase = base;
    if (outSize) *outSize = size;
    if (base == 0 || size == 0) return false;
    return addr >= base && addr < static_cast<std::uint64_t>(base) + size;
}

// Read a hex override from the environment, e.g.
//   set MEMESENSE_DUMP_NTDLL=0x7FFCF2270000
// This is how a payload dumped on another machine is described without a
// rebuild: the operator supplies that machine's module bases once.
static bool ReadEnvHex64(const wchar_t* name, std::uint64_t& out) {
    wchar_t buf[64]{};
    const DWORD n = ::GetEnvironmentVariableW(name, buf, _countof(buf));
    if (n == 0 || n >= _countof(buf)) return false;
    wchar_t* end = nullptr;
    const unsigned long long v = wcstoull(buf, &end, 0);
    if (end == buf || v == 0) return false;
    out = static_cast<std::uint64_t>(v);
    return true;
}

static DumpBases DeriveDumpBases(HANDLE h, DWORD pid, const std::uint8_t* img,
                                 std::size_t imgSize) {
    DumpBases out;

    // Collect (module -> live base, mode delta).
    struct Acc {
        std::uint64_t liveBase = 0;
        std::map<std::uint64_t, int> deltas;   // delta -> vote count
        int samples = 0;
    };
    std::map<std::string, Acc> acc;

    const int total = static_cast<int>(sizeof(g_vmpBImportTable) / sizeof(VMP_ImportFix));
    for (int i = 0; i < total; ++i) {
        const auto& fix = g_vmpBImportTable[i];
        if (fix.rva + 8 > imgSize) continue;

        std::uint64_t captured = 0;
        std::memcpy(&captured, img + fix.rva, sizeof(captured));
        // An unrepaired dump pointer is a canonical user-mode address. Zero,
        // a tiny RVA, or a non-canonical value means this slot was already
        // rewritten (pe_unmapper) or is an ordinal stub, so skip it.
        if (captured < 0x10000ull || (captured >> 47) != 0x1FFFFull) continue;

        auto& a = acc[fix.module];
        if (a.liveBase == 0) {
            a.liveBase = GetRemoteModuleBase(pid, fix.module);
            if (a.liveBase == 0) continue;
        }
        const std::uintptr_t live = (fix.ordinal != 0)
            ? GetRemoteProcAddressByOrdinal(h, a.liveBase, fix.ordinal)
            : GetRemoteProcAddressByName(h, a.liveBase, fix.name);
        if (live == 0) continue;
        if (live < captured) continue;                  // same image never shrinks
        a.deltas[static_cast<std::uint64_t>(live) - captured] += 1;
        ++a.samples;
    }

    const auto pick = [](const Acc& a, std::uint64_t& dumpBase) -> bool {
        if (a.samples == 0 || a.deltas.empty()) return false;
        const auto best = std::max_element(
            a.deltas.begin(), a.deltas.end(),
            [](const auto& x, const auto& y) { return x.second < y.second; });
        // Require a clear winner; a tie means the IAT is mixed and the base
        // would be a guess.
        if (best->second * 2 <= a.samples) return false;
        if (a.liveBase < best->first) return false;
        dumpBase = a.liveBase - best->first;
        return true;
    };

    if (auto it = acc.find("ntdll.dll"); it != acc.end()) {
        out.ntdllSamples = it->second.samples;
        out.ntdllDerived = pick(it->second, out.ntdll);
    }
    if (auto it = acc.find("sdl3.dll"); it != acc.end()) {
        out.sdl3Samples = it->second.samples;
        out.sdl3Derived = pick(it->second, out.sdl3);
    }

    // Explicit operator overrides win over both the derived value and the
    // recorded constant. This is the supported path for a payload dumped on a
    // different machine, where derivation cannot work because import RVAs
    // differ between Windows builds.
    std::uint64_t envValue = 0;
    if (ReadEnvHex64(L"MEMESENSE_DUMP_NTDLL", envValue)) {
        out.ntdll = envValue;
        out.ntdllDerived = false;
    }
    if (ReadEnvHex64(L"MEMESENSE_DUMP_SDL3", envValue)) {
        out.sdl3 = envValue;
        out.sdl3Derived = false;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Offline payload self-test.
//
// Validates, with no target process and no execution, that a payload buffer is
// something this build can actually map: PE shape, layout detection, section
// coverage, and whether every .brdata slot still holds the value the table
// expects. Called by init.cpp before injection so a mismatched payload is
// reported as a named problem instead of a crash inside the target.
static PayloadReport InspectPayload(const std::uint8_t* buffer, std::size_t size) {
    PayloadReport rep;
    rep.fileSize = size;
    rep.ok = false;

    if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
        rep.problems.emplace_back("buffer smaller than a DOS header");
        return rep;
    }
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        rep.problems.emplace_back("bad MZ signature");
        return rep;
    }
    if (dos->e_lfanew < 0 || static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > size) {
        rep.problems.emplace_back("e_lfanew points outside the buffer");
        return rep;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        rep.problems.emplace_back("not a PE32+ image");
        return rep;
    }

    rep.sizeOfImage = nt->OptionalHeader.SizeOfImage;

    std::vector<std::uint8_t> image;
    if (!BuildMappedImage(buffer, size, nt, image)) {
        rep.problems.emplace_back(
            "not a file-layout PE (sections fall outside the buffer); "
            "run tools/make.bat on the raw dump first");
        return rep;
    }

    // .brdata must exist and every slot must still hold its captured value.
    std::uint32_t brdataVa = 0;
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (std::strncmp(reinterpret_cast<const char*>(sec[i].Name), ".brdata", 7) == 0) {
            brdataVa = sec[i].VirtualAddress;
            break;
        }
    }
    if (brdataVa == 0) {
        rep.problems.emplace_back(".brdata section missing");
    }
    else {
        for (int i = 0; i < kBrdataSlotCount; ++i) {
            const auto& slot = g_brdataSlots[i];
            const std::size_t off = static_cast<std::size_t>(brdataVa) + slot.rva;
            ++rep.slotsExpected;
            if (off + slot.width > image.size()) {
                rep.problems.emplace_back("brdata slot " + std::to_string(i) + " is out of range");
                continue;
            }
            std::uint64_t current = 0;
            std::memcpy(&current, image.data() + off, slot.width);
            if (current == slot.captured) ++rep.slotsMatched;
            else rep.problems.emplace_back(
                "brdata slot " + std::to_string(i) + " holds 0x" +
                [&] { char b[32]{}; _snprintf_s(b, sizeof(b), _TRUNCATE, "%llX",
                        (unsigned long long)current); return std::string(b); }());
        }
    }

    // Every IAT fixup must target a slot inside the image.
    const int total = static_cast<int>(sizeof(g_vmpBImportTable) / sizeof(VMP_ImportFix));
    rep.importSlotsTotal = total;
    for (int i = 0; i < total; ++i) {
        const auto& fix = g_vmpBImportTable[i];
        if (fix.rva + 8 <= image.size()) ++rep.importSlotsInRange;
        else rep.problems.emplace_back(
            "IAT slot " + std::to_string(i) + " RVA outside the image");
    }

    rep.ok = rep.problems.empty();
    return rep;
}

DWORD ManualMapBufferEx(DWORD pid, std::uint8_t* buffer, std::size_t size, std::uintptr_t forceBase,
                        std::uint32_t entryOverride, const MMapOptions& opts) {
    Diag("MMB: enter pid=%lu buf=%p size=%zX base=0x%llX",
         pid, (void*)buffer, size, (unsigned long long)forceBase);
    if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
        Diag("MMB: ERROR_BAD_FORMAT (buffer=%p size=%zX)", (void*)buffer, size);
        return ERROR_BAD_FORMAT;
    }
    auto* pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer);
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return ERROR_BAD_FORMAT;
    auto* pNt = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) {
        Diag("MMB: bad NT signature 0x%lX", pNt->Signature);
        return ERROR_BAD_FORMAT;
    }

    std::uintptr_t preferredBase = forceBase ? forceBase : pNt->OptionalHeader.ImageBase;
    const std::uint32_t sizeOfImage = pNt->OptionalHeader.SizeOfImage;
    const std::uint32_t entry = entryOverride ? entryOverride : pNt->OptionalHeader.AddressOfEntryPoint;

    PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);

    // The embedded resource is payload_fix.bin: an ordinary PE file produced
    // by tools/make.bat. Map it by section table, never by assuming the bytes
    // are already in VA order.
    std::vector<std::uint8_t> image;
    if (!BuildMappedImage(buffer, size, pNt, image)) {
        Diag("Map: not a file-layout PE (size=0x%zX, SizeOfImage=0x%X) -- "
             "run tools/make.bat on the raw dump first", size, sizeOfImage);
        return ERROR_BAD_FORMAT;
    }
    Diag("Map: file=0x%zX image=0x%X", size, sizeOfImage);

    std::uint8_t* const img = image.data();
    DWORD openErr = 0;
    UniqueProcess hProc(OpenTargetForMapping(pid, &openErr));
    if (!hProc.get()) {
        Diag("MMB: OpenProcess(pid=%lu) FAILED err=0x%lX (%lu)", pid, openErr, openErr);
        return openErr;
    }
    const HANDLE h = hProc.get();

    // Commit the whole image, not a hardcoded 0x302000. The previous version
    // dropped the tail of every image larger than that, which silently lost the
    // .reloc directory of this payload (RVA 0x302000, SizeOfImage 0x309000).
    const std::size_t commitSize = sizeOfImage;
    const std::size_t totalSize  = commitSize;   // no reserve-only tail needed

    LPVOID remoteBase = ::VirtualAllocEx(h, reinterpret_cast<LPVOID>(preferredBase), totalSize,
                                         MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remoteBase && preferredBase != 0) {
        // The preferred base is occupied. Fall back to anywhere, then apply the
        // relocation directory so absolute addresses still point at this image.
        Diag("Map: reserve at 0x%llX failed err=%lu, retrying anywhere",
             (unsigned long long)preferredBase, ::GetLastError());
        remoteBase = ::VirtualAllocEx(h, nullptr, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!remoteBase) {
        Diag("Map: VirtualAllocEx failed err=%lu", ::GetLastError());
        return ::GetLastError();
    }
    const auto remoteBaseAddr = reinterpret_cast<std::uintptr_t>(remoteBase);
    const std::intptr_t loadDelta =
        static_cast<std::intptr_t>(remoteBaseAddr) - static_cast<std::intptr_t>(preferredBase);
    Diag("Map: base=0x%llX size=0x%zX delta=%+lld",
        (unsigned long long)remoteBaseAddr, commitSize, (long long)loadDelta);

    // Apply IMAGE_REL_BASED_DIR64 entries when the image did not land at the
    // address it was linked for. The .reloc directory of this dump sits exactly
    // at the end of the file, so a file shorter than SizeOfImage has none.
    if (loadDelta != 0) {
        const std::uint32_t relocRva =
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        const std::uint32_t relocSize =
            pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        if (relocRva == 0 || relocSize == 0 || relocRva >= image.size()) {
            Diag("Reloc: image moved by %+lld but no usable .reloc in the dumped image",
                 (long long)loadDelta);
            return ERROR_INVALID_ADDRESS;
        }
        const std::size_t relocEnd = std::min<std::size_t>(
            static_cast<std::size_t>(relocRva) + relocSize, image.size());
        std::size_t at = relocRva;
        std::size_t applied = 0;
        while (at + sizeof(IMAGE_BASE_RELOCATION) <= relocEnd) {
            IMAGE_BASE_RELOCATION block{};
            std::memcpy(&block, img + at, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;

            const std::size_t count =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
            const auto* entries = reinterpret_cast<const std::uint16_t*>(
                img + at + sizeof(IMAGE_BASE_RELOCATION));
            for (std::size_t n = 0; n < count; ++n) {
                const std::uint16_t type = static_cast<std::uint16_t>(entries[n] >> 12);
                const std::uint16_t off  = static_cast<std::uint16_t>(entries[n] & 0x0FFF);
                if (type != IMAGE_REL_BASED_DIR64) continue;
                const std::size_t target = static_cast<std::size_t>(block.VirtualAddress) + off;
                if (target + sizeof(std::uint64_t) > image.size()) continue;
                std::uint64_t value = 0;
                std::memcpy(&value, img + target, sizeof(value));
                value += static_cast<std::uint64_t>(loadDelta);
                std::memcpy(img + target, &value, sizeof(value));
                ++applied;
            }
            at += block.SizeOfBlock;
        }
        Diag("Reloc: applied %zu IMAGE_REL_BASED_DIR64 entries", applied);
    }

    int fix_count = 0;
    int total_count = sizeof(g_vmpBImportTable) / sizeof(VMP_ImportFix);
#if MS_FIX_IAT
    for (int i = 0; i < total_count; ++i) {
        const auto& fix = g_vmpBImportTable[i];
        if (fix.rva + 8 > image.size()) continue;
        std::uintptr_t modBase = GetRemoteModuleBase(pid, fix.module);
        if (!modBase) continue;
        std::uintptr_t funcAddr = (fix.ordinal != 0) ? GetRemoteProcAddressByOrdinal(h, modBase, fix.ordinal) : GetRemoteProcAddressByName(h, modBase, fix.name);
        if (funcAddr != 0) {
            *reinterpret_cast<uint64_t*>(img + fix.rva) = funcAddr;
            fix_count++;
        }
    }
#endif  // MS_FIX_IAT

    Diag("IAT Fix: repaired %d/%d", fix_count, total_count);

#if MS_FIX_BRDATA
    {
        std::uint32_t brdataVa = 0;
        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
            if (std::strncmp(reinterpret_cast<const char*>(pSec[i].Name), ".brdata", 7) == 0) {
                brdataVa = pSec[i].VirtualAddress;
                break;
            }
        }

        if (brdataVa == 0) {
            Diag("BrdataFix: .brdata section not found -- slot repair skipped");
        }
        else {
            const uintptr_t ntdllBase = GetRemoteModuleBase(pid, "ntdll.dll");
            const uintptr_t sdl3Base  = GetRemoteModuleBase(pid, "sdl3.dll");

            // Recover the dump-host bases from this payload instead of trusting
            // the build-time constants, so a dump taken on a different machine
            // rebases correctly.
            const DumpBases dump = DeriveDumpBases(h, pid, img, image.size());
            Diag("BrdataFix: dump bases ntdll=0x%llX (%s, %d samples) sdl3=0x%llX (%s, %d samples)",
                 (unsigned long long)dump.ntdll, dump.ntdllDerived ? "derived" : "constant",
                 dump.ntdllSamples,
                 (unsigned long long)dump.sdl3, dump.sdl3Derived ? "derived" : "constant",
                 dump.sdl3Samples);

            Diag("BrdataFix: .brdata VA=0x%X ntdll=0x%llX sdl3=0x%llX",
                brdataVa, (unsigned long long)ntdllBase, (unsigned long long)sdl3Base);

            int repaired = 0;

            for (int i = 0; i < kBrdataSlotCount; ++i) {
                const auto& slot = g_brdataSlots[i];
                const std::size_t off = static_cast<std::size_t>(brdataVa) + slot.rva;

                if (off + slot.width > image.size()) {
                    Diag("BrdataFix[%d]: offset 0x%zX past end of image", i, off);
                    continue;
                }

                uint64_t current = 0;
                std::memcpy(&current, img + off, slot.width);
                if (current != slot.captured) {
                    Diag("BrdataFix[%d]: slot 0x%zX holds 0x%llX, expected 0x%llX -- skipped",
                        i, off, (unsigned long long)current, (unsigned long long)slot.captured);
                    continue;
                }

                uint64_t newAddr = 0;

                if (slot.module == SlotModule::Sdl3) {
                    if (!sdl3Base) {
                        Diag("BrdataFix[%d]: sdl3.dll not loaded -- skipped", i);
                        continue;
                    }
                    if (slot.captured < dump.sdl3) {
                        Diag("BrdataFix[%d]: captured 0x%llX below dump base 0x%llX -- skipped",
                             i, (unsigned long long)slot.captured,
                             (unsigned long long)dump.sdl3);
                        continue;
                    }
                    newAddr = static_cast<uint64_t>(sdl3Base) + (slot.captured - dump.sdl3);
                    Diag("BrdataFix[%d]: sdl3 rebase 0x%llX -> 0x%llX",
                        i, (unsigned long long)slot.captured, (unsigned long long)newAddr);
                }
                else {
                    if (!ntdllBase) {
                        Diag("BrdataFix[%d]: ntdll.dll not loaded -- skipped", i);
                        continue;
                    }

                    // Resolve the symbol in the LIVE ntdll.
                    //
                    // The captured slot value points into the dump host's
                    // ntdll, which is a different build. Its RVA cannot be
                    // reused: measured on this project, the dump build places
                    // RtlRegisterThreadWithCsrss at 0x54590 while 10.0.26100
                    // places it at 0xEF2E0. So the PDB (or the fallback table)
                    // must describe the host, and the captured value is only a
                    // sanity reference for "was this slot ever valid".
                    uint32_t symRva = 0;
                    bool haveRva = false;

                    auto it = g_pdb_rva_map.find(slot.symbol);
                    if (it != g_pdb_rva_map.end()) {
                        symRva = it->second;
                        haveRva = true;
                    }
                    else {
                        auto fb = g_manual_rva_fix.find(slot.symbol);
                        if (fb != g_manual_rva_fix.end()) {
                            symRva = fb->second;
                            haveRva = true;
                            Diag("BrdataFix[%d]: %s -> FALLBACK RVA 0x%X "
                                 "(no PDB; assumes an ntdll close to 10.0.26100)",
                                 i, slot.symbol, symRva);
                        }
                    }

                    if (!haveRva) {
                        Diag("BrdataFix[%d]: %s unresolved for this host -- slot left as dumped",
                             i, slot.symbol);
                        continue;
                    }

                    newAddr = static_cast<uint64_t>(ntdllBase) + symRva + slot.delta;
                    Diag("BrdataFix[%d]: %s+0x%X RVA 0x%X -> 0x%llX",
                        i, slot.symbol, slot.delta, symRva, (unsigned long long)newAddr);
                }

                // Never write a pointer that does not land in the module it
                // is supposed to point into. A stale dump base is the classic
                // cause of a silent corruption here.
                {
                    const char* targetModule =
                        (slot.module == SlotModule::Sdl3) ? "sdl3.dll" : "ntdll.dll";
                    if (!IsAddressInLiveModule(pid, targetModule, newAddr)) {
                        Diag("BrdataFix[%d]: computed 0x%llX is outside live %s -- "
                             "dump base looks wrong, slot left as dumped",
                             i, (unsigned long long)newAddr, targetModule);
                        continue;
                    }
                }

                std::memcpy(img + off, &newAddr, slot.width);
                ++repaired;
            }

            Diag("BrdataFix: repaired %d/%d slots", repaired, kBrdataSlotCount);
        }
    }
#else
    Diag("BrdataFix: SKIPPED (MS_FIX_BRDATA=0) -- .brdata left as dumped");
#endif  // MS_FIX_BRDATA
    if (!::WriteProcessMemory(h, remoteBase, img, commitSize, nullptr)) return ERROR_WRITE_FAULT;

    // Per-section protection. This used to be behind `if (false)`, leaving the
    // entire image PAGE_EXECUTE_READWRITE: a fixup written to .text then went
    // unnoticed, and an RWX image of this size is a loud VMProtect trigger.
    {
        auto sectionProtect = [](DWORD ch) -> DWORD {
            const bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            const bool read  = (ch & IMAGE_SCN_MEM_READ)    != 0;
            const bool write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;
            if (exec)  return write ? PAGE_EXECUTE_READWRITE : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
            if (write) return read  ? PAGE_READWRITE         : PAGE_WRITECOPY;
            return read ? PAGE_READONLY : PAGE_NOACCESS;
        };

        DWORD oldProt = 0;
        ::VirtualProtectEx(h, reinterpret_cast<LPVOID>(remoteBaseAddr),
                           (pNt->OptionalHeader.SizeOfHeaders + 0xFFF) & ~0xFFFu,
                           PAGE_READONLY, &oldProt);

        for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; ++i) {
            const std::uint32_t va  = pSec[i].VirtualAddress;
            const std::uint32_t vsz = pSec[i].Misc.VirtualSize;
            if (vsz == 0 || va + vsz > sizeOfImage) continue;
            ::VirtualProtectEx(h, reinterpret_cast<LPVOID>(remoteBaseAddr + va),
                               (vsz + 0xFFF) & ~0xFFFu,
                               sectionProtect(pSec[i].Characteristics), &oldProt);
            Diag("Protect: %-9s VA=0x%-7X size=0x%-7X -> 0x%X",
                 reinterpret_cast<const char*>(pSec[i].Name), va, vsz,
                 sectionProtect(pSec[i].Characteristics));
        }
    }

    // Exception table: OFF by default.
    //
    // The 12 RUNTIME_FUNCTION entries at RVA 0x301010 have plausible
    // begin/end ranges, but their UNWIND_INFO is not real. Decoding them:
    //
    //   entry[0]  (0x77860)  op=0x0d, 0x0b, 0x07, 0x0c, 0x0e ...
    //                        -> none of those are legal UWOP values, and the
    //                           code offsets are not strictly decreasing
    //   entry[10] (0x1F5000) five PUSH_NONVOL codes all at offset 0x00
    //
    // That is VMProtect's encrypted decoy, exactly as the .pdata section is.
    // Handing it to RtlAddFunctionTable makes every exception run through
    // RtlVirtualUnwind on garbage, which restores a bogus RIP/RSP -- the
    // observed 0x666600001001 (`in eax,dx`, never a real instruction
    // boundary) comes from here, and the thread never comes back.
    //
    // VMProtect installs its own table during VM init. Let it.
    if (opts.registerExceptionTable) {
        RegisterExceptionTable(h, pid, pNt, remoteBaseAddr,
            static_cast<std::int64_t>(remoteBaseAddr) - static_cast<std::int64_t>(pNt->OptionalHeader.ImageBase));
    }
    else {
        Diag("EH: skipped (MEMESENSE_EH=1 to enable; the .pdata unwind is a VMP decoy)");
    }

    SetupTls(h, pid, image.data(), image.size(), pNt, remoteBaseAddr,
             static_cast<std::int64_t>(remoteBaseAddr) - static_cast<std::int64_t>(pNt->OptionalHeader.ImageBase),
             pNt->OptionalHeader.ImageBase);

    DWORD exitCode = 0;
    bool ldrRegistered = false;
    if (entry != 0) {
        // PEB->Ldr registration now happens AFTER the READY prompt (option 'l'),
        // so the operator can choose it per run. The environment variable route
        // silently failed twice, so it is only the default, not the mechanism.
        const std::uintptr_t vehResult = reinterpret_cast<std::uintptr_t>(
            ::VirtualAllocEx(h, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        // The vectored exception handler that used to live here was dead code:
        // it sat behind `if (false && vehResult)` because capturing the handler's
        // arguments was never finished. Removed rather than left as a trap.
        // ---- one page for stub + scratch, allocated BEFORE the prompt ------
        // Allocating first means the READY banner can show the address, and the
        // force decision can be baked straight into the stub. The previous
        // version patched a flag slot at runtime and the flag silently did not
        // take effect (force=YES but the thread still exited with 0).
        const std::size_t kStubPage = 0x1000;
        const std::uintptr_t stubMem = reinterpret_cast<std::uintptr_t>(
            ::VirtualAllocEx(h, nullptr, kStubPage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (stubMem) {
            const std::uintptr_t scratchMem = stubMem + 0x800;   // raw DllMain eax

            // Interactive gate.
#if MS_INTERACTIVE
            char g_answerBuf[32]{}; int g_answerLen = 0;
            {
                Diag("=== READY ===");
                Diag("  image base  = 0x%llX", (unsigned long long)remoteBaseAddr);
                Diag("  entry point = 0x%llX  (RVA 0x%X)",
                     (unsigned long long)(remoteBaseAddr + entry), entry);
                Diag("  stub        = 0x%llX", (unsigned long long)stubMem);
                Diag("  SizeOfImage = 0x%X", sizeOfImage);
                Diag("  PEB->Ldr    = %s", ldrRegistered ? "registered" : "NOT registered");
                Diag("");
                Diag("  Enter = call DllMain as-is");
                Diag("  l     = register in PEB->Ldr first, then call DllMain");
                Diag("  q     = abort, do not call DllMain");
                Diag("");

                HANDLE hIn = ::GetStdHandle(STD_INPUT_HANDLE);
                DWORD mode = 0;
                const bool console = hIn && hIn != INVALID_HANDLE_VALUE && ::GetConsoleMode(hIn, &mode);

                char answer = 0;
                if (console) {
                    answer = static_cast<char>(std::getchar());
                    if (answer == '\n') answer = 0;
                    g_answerLen = 0;
                    if (answer) g_answerBuf[g_answerLen++] = answer;
                    int ch;
                    while (g_answerLen < (int)sizeof(g_answerBuf) - 1 &&
                           (ch = std::getchar()) != EOF && ch != '\n')
                        g_answerBuf[g_answerLen++] = (char)ch;
                }
                else {
                    // Non-console stdin (piped or redirected). Rather than a
                    // blind 60s wait, read the first byte from the stream: this
                    // is what makes `echo l | src.exe` and
                    // `src.exe < answer.txt` usable for unattended runs.
                    Diag("[READY] stdin is not a console -- reading answer from stdin");
                    // Read the WHOLE line here. The old code drained and threw
                    // the rest away, so "fl" only ever applied the 'f'.
                    char buf2[32]{}; int n2 = 0; int ch2;
                    while (n2 < (int)sizeof(buf2) - 1 && (ch2 = std::getchar()) != EOF && ch2 != '\n')
                        buf2[n2++] = (char)ch2;
                    if (n2 > 0) answer = buf2[0];
                    // park the remainder for the shared parser below
                    for (int i = 0; i < n2; ++i) g_answerBuf[i] = buf2[i];
                    g_answerLen = n2;
                }

                if (answer == 'q' || answer == 'Q') {
                    Diag("=== ABORTED BY OPERATOR ===");
                    return ERROR_CANCELLED;
                }
                // The line is already in g_answerBuf, either read from a pipe
                // above or by the console path, which fills it the same way.
                bool wantLdr = opts.registerInLdr;
                for (int i = 0; i < g_answerLen; ++i) {
                    if (g_answerBuf[i] == 'l' || g_answerBuf[i] == 'L') wantLdr = true;
                }
                Diag("=== CONTINUING (Ldr = %s) ===", wantLdr ? "YES" : "no");

                if (wantLdr) {
                    if (RegisterModuleInLdr(h, pid, remoteBaseAddr, sizeOfImage,
                                            remoteBaseAddr + entry, L"memesense.dll")) {
                        ldrRegistered = true;
                        Diag("Ldr: registered memesense.dll at 0x%llX", (unsigned long long)remoteBaseAddr);
                    }
                    else {
                        Diag("Ldr: registration FAILED -- continuing without it");
                    }
                }
            }

#else   // !MS_INTERACTIVE
            // Unattended run: use the compile-time defaults verbatim and skip
            // the prompt. This is what makes `src.exe` runnable from a script
            // with no stdin at all.
            const bool wantLdr = opts.registerInLdr;
            Diag("=== NON-INTERACTIVE (Ldr = %s) ===", wantLdr ? "YES" : "no");
            if (wantLdr) {
                if (RegisterModuleInLdr(h, pid, remoteBaseAddr, sizeOfImage,
                                        remoteBaseAddr + entry, L"memesense.dll")) {
                    ldrRegistered = true;
                    Diag("Ldr: registered memesense.dll at 0x%llX", (unsigned long long)remoteBaseAddr);
                }
                else {
                    Diag("Ldr: registration FAILED -- continuing without it");
                }
            }
#endif  // MS_INTERACTIVE

            // ---- build the stub with the decision already baked in ---------
            std::vector<std::uint8_t> stub;
            auto add = [&stub](std::initializer_list<uint8_t> b) { stub.insert(stub.end(), b.begin(), b.end()); };
            auto add64 = [&stub](std::uint64_t v) { for (int i = 0; i < 8; ++i) stub.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF)); };

            add({ 0x48, 0x83, 0xEC, 0x28 });                 // sub rsp,0x28
            add({ 0x48, 0xB9 }); add64(remoteBaseAddr);       // mov rcx,base
            add({ 0xBA, 0x01, 0x00, 0x00, 0x00 });            // mov edx,1
            add({ 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00 });      // mov r8d,1
            add({ 0x48, 0xB8 }); add64(remoteBaseAddr + entry + MS_ENTRY_SKIP); // mov rax,entry
            add({ 0xFF, 0xD0 });                              // call rax

            // The stub returns whatever DllMain returned. It is not forced.
            const std::size_t captureOff = stub.size();
            add({ 0x48, 0x89, 0x05 });                        // mov [rip+disp32], rax
            add({ 0x00, 0x00, 0x00, 0x00 });                  //   disp32 patched below

            add({ 0x48, 0x83, 0xC4, 0x28 });                  // add rsp,0x28
            add({ 0xC3 });                                    // ret

            {
                const std::size_t dispOff = captureOff + 3;
                const std::int64_t disp =
                    static_cast<std::int64_t>(scratchMem) -
                    static_cast<std::int64_t>(stubMem + dispOff + 4);
                const auto d32 = static_cast<std::int32_t>(disp);
                std::memcpy(stub.data() + dispOff, &d32, sizeof(d32));
            }

            if (stub.size() >= 0x800) {
                Diag("Stub: %zu bytes does not fit before the capture slot", stub.size());
                return ERROR_BUFFER_OVERFLOW;
            }

            ::WriteProcessMemory(h, reinterpret_cast<LPVOID>(stubMem), stub.data(), stub.size(), nullptr);
            // Seed the slot with a sentinel, NOT zero. If the slot still holds
            // the sentinel afterwards, `call rax` never returned -- which is a
            // completely different failure from "DllMain returned FALSE".
            const std::uint64_t kSentinel = 0xDEADBEEFDEADBEEFull;
            ::WriteProcessMemory(h, reinterpret_cast<LPVOID>(scratchMem), &kSentinel, sizeof(kSentinel), nullptr);

            Diag("Stub: %zu bytes, entry skip %u, capture slot 0x%llX",
                 stub.size(), (unsigned)MS_ENTRY_SKIP, (unsigned long long)scratchMem);

            UniqueHandle hThread(::CreateRemoteThread(h, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(stubMem), nullptr, 0, nullptr));
            bool threadRan = false;
            if (hThread.get()) {
                const DWORD wr = ::WaitForSingleObject(hThread.get(), 60000);
                threadRan = (wr == WAIT_OBJECT_0);
                ::GetExitCodeThread(hThread.get(), &exitCode);
                if (!threadRan) {
                    Diag("=== ENTRY TIMEOUT ===");
                    Diag("  WaitForSingleObject -> 0x%lX after 60000 ms", wr);
                    Diag("  DllMain never returned; exitCode is NOT a DllMain result");
                }
            }

            // ---- post-entry diagnostics -------------------------------------
            // These read the live target. They exist because the previous
            // failure mode was a bare `return 0` with no way to tell a crash
            // apart from a designed FALSE, from a silently failed thread.
            if (opts.diagAfterEntry) {
                std::uint64_t rawRet = 0;
                const bool haveRaw = threadRan &&
                    ::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(scratchMem), &rawRet, sizeof(rawRet), nullptr);

                Diag("=== ENTRY RESULT ===");
                const bool neverReturned = haveRaw && (rawRet == 0xDEADBEEFDEADBEEFull);
                if (haveRaw && !neverReturned)
                    Diag("  DllMain raw eax = 0x%llX  (%s)", (unsigned long long)rawRet,
                         (rawRet & 0xFFFFFFFFull) ? "TRUE" : "FALSE");
                else if (neverReturned)
                    Diag("  DllMain raw eax = <NEVER RETURNED> (slot still holds the sentinel)");
                else
                    Diag("  DllMain raw eax = <unavailable>");
                Diag("  thread exit code = 0x%lX", exitCode);

                // Thread still alive after DllMain returned => the payload
                // handed work off to a worker, which is what a cheat needs.
                if (threadRan) {
                    // ---- what pid are we even looking at? -----------------
                    {
                        wchar_t exe[MAX_PATH]{};
                        DWORD sz2 = MAX_PATH;
                        ::QueryFullProcessImageNameW(h, 0, exe, &sz2);
                        HMODULE mods[1024]{}; DWORD cbNeeded = 0;
                        ::EnumProcessModules(h, mods, sizeof(mods), &cbNeeded);
                        Diag("  pid                  = %lu", pid);
                        Diag("  image                = %ls", exe[0] ? exe : L"<unknown>");
                        Diag("  modules visible      = %lu", cbNeeded / sizeof(HMODULE));

                        // How many threads does the system say EVERY process has?
                        // If the total is tiny, the snapshot itself is restricted.
                        int sysTotal = 0, sysProcs = 0;
                        HANDLE all = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                        if (all != INVALID_HANDLE_VALUE) {
                            THREADENTRY32 t2{}; t2.dwSize = sizeof(t2);
                            if (::Thread32First(all, &t2)) {
                                do { ++sysTotal; } while (::Thread32Next(all, &t2));
                            }
                            ::CloseHandle(all);
                        }
                        HANDLE ps = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                        if (ps != INVALID_HANDLE_VALUE) {
                            PROCESSENTRY32W pe2{}; pe2.dwSize = sizeof(pe2);
                            if (::Process32FirstW(ps, &pe2)) {
                                do { ++sysProcs; } while (::Process32NextW(ps, &pe2));
                            }
                            ::CloseHandle(ps);
                        }
                        Diag("  system threads total = %d across %d processes", sysTotal, sysProcs);

                        // ---- is cs2 being debugged? ---------------------
                        // This is the single most likely reason a VMProtect
                        // payload returns FALSE without crashing: the VM detects
                        // the debugger and bails out cleanly.
                        using NtQIP2_t = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
                        auto pQIP = reinterpret_cast<NtQIP2_t>(
                            ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"),
                                             "NtQueryInformationProcess"));
                        if (pQIP) {
                            ULONG_PTR dbgPort = 0, dbgObj = 0;
                            ULONG dbgFlags = 0xFFFFFFFF;
                            pQIP(h, 7,  &dbgPort,  sizeof(dbgPort),  nullptr);   // ProcessDebugPort
                            pQIP(h, 30, &dbgObj,   sizeof(dbgObj),   nullptr);   // ProcessDebugObjectHandle
                            pQIP(h, 31, &dbgFlags, sizeof(dbgFlags), nullptr);   // ProcessDebugFlags
                            Diag("  ProcessDebugPort     = 0x%llX", (unsigned long long)dbgPort);
                            Diag("  ProcessDebugObject   = 0x%llX", (unsigned long long)dbgObj);
                            Diag("  ProcessDebugFlags    = 0x%lX %s", dbgFlags,
                                 (dbgFlags == 0) ? "(0 = BEING DEBUGGED)" : "(non-zero = clean)");
                            const bool dbg = (dbgPort != 0) || (dbgObj != 0) || (dbgFlags == 0);
                            if (dbg)
                                Diag("  !! cs2 IS UNDER A DEBUGGER -- VMProtect will very likely refuse to initialise");
                            else
                                Diag("  cs2 is NOT under a debugger");
                        }

                        // ---- who actually owns the threads we can see? ---
                        // cs2 shows 64+ threads in x64dbg but the census above
                        // reported 1, so print the owner histogram to find out
                        // whether the snapshot simply does not contain cs2.
                        {
                            std::map<DWORD,int> owner;
                            HANDLE a2 = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                            if (a2 != INVALID_HANDLE_VALUE) {
                                THREADENTRY32 t3{}; t3.dwSize = sizeof(t3);
                                if (::Thread32First(a2, &t3)) {
                                    do { ++owner[t3.th32OwnerProcessID]; } while (::Thread32Next(a2, &t3));
                                }
                                ::CloseHandle(a2);
                            }
                            Diag("  distinct owner pids   = %zu", owner.size());
                            Diag("  this pid in snapshot  = %s", owner.count(pid) ? "YES" : "NO");
                            int shown = 0;
                            for (const auto& kv : owner) {
                                if (shown++ >= 5) break;
                                Diag("    owner %-8lu -> %d threads", kv.first, kv.second);
                            }
                        }
                    }

                    std::vector<DWORD> tids;
                    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
                    if (snap != INVALID_HANDLE_VALUE) {
                        THREADENTRY32 te{}; te.dwSize = sizeof(te);
                        if (::Thread32First(snap, &te)) {
                            do {
                                if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID);
                            } while (::Thread32Next(snap, &te));
                        }
                        ::CloseHandle(snap);
                    }

                    // NtQuerySystemInformation(SystemProcessInformation = 5)
                    struct SPI_Thread {
                        LARGE_INTEGER KernelTime, UserTime, CreateTime;
                        ULONG WaitTime; PVOID StartAddress; CLIENT_ID ClientId;
                        LONGLONG Priority, BasePriority;
                        ULONG ContextSwitches, ThreadState, WaitReason;
                    };
                    struct SPI_Process {
                        ULONG NextEntryOffset, ThreadCount;
                        LARGE_INTEGER WorkingSetPrivateSize;
                        ULONG HardFaultCount, NumberOfThreadsHighWatermark;
                        ULONGLONG CycleTime;
                        LARGE_INTEGER CreateTime, UserTime, KernelTime;
                        UNICODE_STRING ImageName;
                        LONG BasePriority; HANDLE UniqueProcessId; HANDLE InheritedFromUniqueProcessId;
                        ULONG HandleCount, SessionId; ULONG_PTR UniqueProcessKey;
                        SIZE_T PeakVirtualSize, VirtualSize;
                        ULONG PageFaultCount; SIZE_T PeakWorkingSetSize, WorkingSetSize;
                        SIZE_T QuotaPeakPagedPoolUsage, QuotaPagedPoolUsage;
                        SIZE_T QuotaPeakNonPagedPoolUsage, QuotaNonPagedPoolUsage;
                        SIZE_T PagefileUsage, PeakPagefileUsage;
                        SIZE_T PrivatePageCount;
                        LARGE_INTEGER ReadOperationCount, WriteOperationCount, OtherOperationCount;
                        LARGE_INTEGER ReadTransferCount, WriteTransferCount, OtherTransferCount;
                        SPI_Thread Threads[1];
                    };
                    using NtQSI_t = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);
                    auto pNtQSI = reinterpret_cast<NtQSI_t>(
                        ::GetProcAddress(::GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
                    ULONG spiThreads = 0;
                    if (pNtQSI) {
                        ULONG need = 1 << 20;
                        std::vector<std::uint8_t> buf;
                        LONG st = 0;
                        for (int attempt = 0; attempt < 6; ++attempt) {
                            buf.assign(need, 0);
                            st = pNtQSI(5, buf.data(), need, &need);
                            if (st != 0xC0000004L /*STATUS_INFO_LENGTH_MISMATCH*/) break;
                            need += 1 << 20;
                        }
                        if (st == 0) {
                            auto* p = reinterpret_cast<SPI_Process*>(buf.data());
                            while (p) {
                                if (reinterpret_cast<ULONG_PTR>(p->UniqueProcessId) == pid) {
                                    spiThreads = p->ThreadCount;
                                    break;
                                }
                                if (!p->NextEntryOffset) break;
                                p = reinterpret_cast<SPI_Process*>(
                                    reinterpret_cast<std::uint8_t*>(p) + p->NextEntryOffset);
                            }
                        }
                    }

                    int alive = 0;
                    for (DWORD tid : tids) {
                        UniqueHandle th(::OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid));
                        if (!th.get()) continue;
                        DWORD ec = 0;
                        if (::GetExitCodeThread(th.get(), &ec) && ec == STILL_ACTIVE) ++alive;
                    }
                    Diag("  threads (toolhelp)   = %zu enumerated, %d alive", tids.size(), alive);
                    Diag("  threads (NtQSI)      = %lu", spiThreads);
                    if (spiThreads != tids.size())
                        Diag("  !! toolhelp and NtQSI disagree -- toolhelp is truncated, trust NtQSI");
                    if (tids.size() <= 8) {
                        char ids[256]{}; int p = 0;
                        for (DWORD tid : tids)
                            p += _snprintf_s(ids + p, sizeof(ids) - p, _TRUNCATE, "%lu ", tid);
                        Diag("  thread ids           = %s", ids);
                    }
                }

                // Is the module actually in the PEB loader lists? The payload's
                // own exception handler at RVA 0x5380 calls LdrFindEntryForAddress
                // and gives up unless the returned DllBase equals its own base,
                // so a missing entry is fatal for its SEH/CRT init path.
                {
                    std::uint32_t sz = 0;
                    if (GetRemoteModuleInfo(pid, "memesense.dll", &sz) != 0)
                        Diag("  PEB->Ldr entry   = present (SizeOfImage 0x%X)", sz);
                    else
                        Diag("  PEB->Ldr entry   = ABSENT  <-- payload SEH init cannot resolve itself");
                }

                // First bytes of the mapped image: cheap integrity check that
                // the VA-layout copy landed where we think it did.
                std::uint8_t head[16]{};
                if (::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(remoteBaseAddr), head, sizeof(head), nullptr)) {
                    Diag("  image[0..16]     = %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X %02X%02X%02X%02X",
                         head[0], head[1], head[2], head[3], head[4], head[5], head[6], head[7],
                         head[8], head[9], head[10], head[11], head[12], head[13], head[14], head[15]);
                }
            }   // opts.diagAfterEntry

            ::VirtualFreeEx(h, reinterpret_cast<LPVOID>(stubMem), 0, MEM_RELEASE);
        }       // if (stubMem)
    }           // if (entry != 0)

    return exitCode;
}

// Backwards-compatible entry point. Behaviour is unchanged unless the
// MEMESENSE_* environment switches are set.
// Manual map an ordinary PE into a remote process.
//
// This is deliberately a separate implementation from ManualMapBufferEx:
// that one is bound to this payload, with a hardcoded 149-entry import table,
// the .brdata slots and the PEB->Ldr trick. A normal DLL needs none of that and
// does need a real import walk and real relocation processing.
// GetRemoteModuleBase only sees modules that are already in the PEB. An import
// from a DLL that cs2 has not loaded yet would otherwise fail, so fall back to
// calling LoadLibraryW inside the target.
static std::uintptr_t EnsureRemoteModule(HANDLE h, DWORD pid, const char* dllName) {
    const std::uintptr_t existing = GetRemoteModuleBase(pid, dllName);
    if (existing != 0) return existing;

    wchar_t wide[MAX_PATH]{};
    if (::MultiByteToWideChar(CP_ACP, 0, dllName, -1, wide, MAX_PATH) == 0) return 0;

    const std::uintptr_t pLoadLibrary =
        GetRemoteProcAddressByName(h, GetRemoteModuleBase(pid, "kernel32.dll"), "LoadLibraryW");
    if (pLoadLibrary == 0) {
        Diag("MapDll: LoadLibraryW unavailable in the target");
        return 0;
    }

    const std::size_t nameBytes = (wcslen(wide) + 1) * sizeof(wchar_t);
    void* remoteName = ::VirtualAllocEx(h, nullptr, nameBytes,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteName) return 0;
    if (!::WriteProcessMemory(h, remoteName, wide, nameBytes, nullptr)) {
        ::VirtualFreeEx(h, remoteName, 0, MEM_RELEASE);
        return 0;
    }

    // sub rsp,0x28 / mov rcx,name / mov rax,LoadLibraryW / call rax /
    // mov [rip+disp32],rax / add rsp,0x28 / ret
    std::vector<std::uint8_t> stub;
    auto a = [&stub](std::initializer_list<std::uint8_t> b) {
        stub.insert(stub.end(), b.begin(), b.end());
    };
    auto a64 = [&stub](std::uint64_t v) {
        for (int i = 0; i < 8; ++i)
            stub.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    };
    a({ 0x48, 0x83, 0xEC, 0x28 });
    a({ 0x48, 0xB9 }); a64(reinterpret_cast<std::uint64_t>(remoteName));
    a({ 0x48, 0xB8 }); a64(pLoadLibrary);
    a({ 0xFF, 0xD0 });
    const std::size_t captureOff = stub.size();
    a({ 0x48, 0x89, 0x05, 0x00, 0x00, 0x00, 0x00 });
    a({ 0x48, 0x83, 0xC4, 0x28 });
    a({ 0xC3 });

    void* code = ::VirtualAllocEx(h, nullptr, stub.size() + 16,
                                  MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!code) {
        ::VirtualFreeEx(h, remoteName, 0, MEM_RELEASE);
        return 0;
    }
    const auto codeBase = reinterpret_cast<std::uintptr_t>(code);
    const std::uintptr_t slot = codeBase + stub.size();
    const std::int64_t disp = static_cast<std::int64_t>(slot) -
                              static_cast<std::int64_t>(codeBase + captureOff + 3 + 4);
    const auto disp32 = static_cast<std::int32_t>(disp);
    std::memcpy(stub.data() + captureOff + 3, &disp32, sizeof(disp32));
    ::WriteProcessMemory(h, code, stub.data(), stub.size(), nullptr);

    UniqueHandle th(::CreateRemoteThread(h, nullptr, 0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(code), nullptr, 0, nullptr));
    std::uint64_t loaded = 0;
    if (th.get()) {
        ::WaitForSingleObject(th.get(), 10000);
        ::ReadProcessMemory(h, reinterpret_cast<LPCVOID>(slot), &loaded, sizeof(loaded), nullptr);
    }
    ::VirtualFreeEx(h, code, 0, MEM_RELEASE);
    ::VirtualFreeEx(h, remoteName, 0, MEM_RELEASE);

    if (loaded == 0) {
        Diag("MapDll: LoadLibraryW(%s) failed in the target", dllName);
        return 0;
    }
    Diag("MapDll: loaded %s via LoadLibraryW -> 0x%llX", dllName, (unsigned long long)loaded);
    return static_cast<std::uintptr_t>(loaded);
}

DWORD ManualMapDll(DWORD pid, const std::uint8_t* buffer, std::size_t size,
                   std::uint32_t timeoutMs) {
    if (!buffer || size < sizeof(IMAGE_DOS_HEADER)) {
        Diag("MapDll: buffer too small");
        return ERROR_BAD_FORMAT;
    }

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        Diag("MapDll: bad DOS signature");
        return ERROR_BAD_FORMAT;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(buffer + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        Diag("MapDll: not a PE32+ image");
        return ERROR_BAD_FORMAT;
    }

    const std::uint32_t sizeOfImage = nt->OptionalHeader.SizeOfImage;
    const std::uint32_t entryRva = nt->OptionalHeader.AddressOfEntryPoint;
    const std::uint64_t preferredBase = nt->OptionalHeader.ImageBase;
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    // Build the image in VA layout: headers first, then every section at its
    // virtual address. The file may be sparse, so the buffer starts zeroed.
    std::vector<std::uint8_t> image(sizeOfImage, 0);
    const std::size_t headerBytes = std::min<std::size_t>(
        nt->OptionalHeader.SizeOfHeaders, size);
    std::memcpy(image.data(), buffer, headerBytes);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const std::size_t rawLen = sec[i].SizeOfRawData;
        const std::size_t rawOff = sec[i].PointerToRawData;
        const std::size_t dstOff = sec[i].VirtualAddress;
        if (rawLen == 0 || rawOff + rawLen > size) continue;
        if (dstOff + rawLen > sizeOfImage) continue;
        std::memcpy(image.data() + dstOff, buffer + rawOff, rawLen);
    }

    DWORD openErr = 0;
    UniqueProcess hProc(OpenTargetForMapping(pid, &openErr));
    if (!hProc.get()) {
        Diag("MapDll: OpenProcess failed err=%lu", openErr);
        return openErr;
    }
    const HANDLE h = hProc.get();

    LPVOID remote = ::VirtualAllocEx(h, reinterpret_cast<LPVOID>(preferredBase), sizeOfImage,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote) {
        remote = ::VirtualAllocEx(h, nullptr, sizeOfImage,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (!remote) {
        const DWORD e = ::GetLastError();
        Diag("MapDll: VirtualAllocEx failed err=%lu", e);
        return e;
    }
    const auto remoteBase = reinterpret_cast<std::uintptr_t>(remote);
    const std::intptr_t delta = static_cast<std::intptr_t>(remoteBase) -
                                static_cast<std::intptr_t>(preferredBase);
    Diag("MapDll: base=0x%llX size=0x%X delta=%+lld",
         (unsigned long long)remoteBase, sizeOfImage, (long long)delta);

    // Apply base relocations when the image did not land where it was linked.
    if (delta != 0) {
        const IMAGE_DATA_DIRECTORY& rd =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (rd.VirtualAddress == 0 || rd.Size == 0) {
            Diag("MapDll: moved image has no .reloc");
            ::VirtualFreeEx(h, remote, 0, MEM_RELEASE);
            return ERROR_INVALID_ADDRESS;
        }
        const std::size_t end = std::min<std::size_t>(
            static_cast<std::size_t>(rd.VirtualAddress) + rd.Size, image.size());
        std::size_t at = rd.VirtualAddress;
        std::size_t applied = 0;
        while (at + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            IMAGE_BASE_RELOCATION block{};
            std::memcpy(&block, image.data() + at, sizeof(block));
            if (block.SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) break;
            const std::size_t count =
                (block.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
            const auto* items = reinterpret_cast<const std::uint16_t*>(
                image.data() + at + sizeof(IMAGE_BASE_RELOCATION));
            for (std::size_t n = 0; n < count; ++n) {
                if ((items[n] >> 12) != IMAGE_REL_BASED_DIR64) continue;
                const std::size_t target =
                    static_cast<std::size_t>(block.VirtualAddress) + (items[n] & 0x0FFF);
                if (target + sizeof(std::uint64_t) > image.size()) continue;
                std::uint64_t v = 0;
                std::memcpy(&v, image.data() + target, sizeof(v));
                v += static_cast<std::uint64_t>(delta);
                std::memcpy(image.data() + target, &v, sizeof(v));
                ++applied;
            }
            at += block.SizeOfBlock;
        }
        Diag("MapDll: applied %zu relocations", applied);
    }

    // Resolve the import table. Forwarded imports are followed one level, which
    // is all a loader for this DLL needs.
    {
        const IMAGE_DATA_DIRECTORY& id =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        std::size_t resolved = 0, failed = 0;

        if (id.VirtualAddress != 0 && id.Size != 0) {
            std::size_t descOff = id.VirtualAddress;
            while (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= image.size()) {
                IMAGE_IMPORT_DESCRIPTOR desc{};
                std::memcpy(&desc, image.data() + descOff, sizeof(desc));
                if (desc.Name == 0 && desc.FirstThunk == 0) break;

                const char* dllName = reinterpret_cast<const char*>(image.data() + desc.Name);
                wchar_t wideName[MAX_PATH]{};
                ::MultiByteToWideChar(CP_ACP, 0, dllName, -1, wideName, MAX_PATH);

                const std::uintptr_t modBase = EnsureRemoteModule(h, pid, dllName);
                if (modBase == 0) {
                    Diag("MapDll: import module %s unavailable", dllName);
                    failed += 16;
                    descOff += sizeof(desc);
                    continue;
                }

                std::size_t thunkOff = desc.FirstThunk != 0 ? desc.FirstThunk : desc.OriginalFirstThunk;
                std::size_t nameThunkOff = desc.OriginalFirstThunk != 0
                                         ? desc.OriginalFirstThunk : desc.FirstThunk;
                for (;;) {
                    if (thunkOff + 8 > image.size() || nameThunkOff + 8 > image.size()) break;
                    std::uint64_t entry = 0, nameEntry = 0;
                    std::memcpy(&entry, image.data() + thunkOff, sizeof(entry));
                    std::memcpy(&nameEntry, image.data() + nameThunkOff, sizeof(nameEntry));
                    if (nameEntry == 0) break;

                    std::uintptr_t target = 0;
                    if ((nameEntry & 0x8000000000000000ull) != 0) {
                        target = GetRemoteProcAddressByOrdinal(
                            h, modBase, static_cast<WORD>(nameEntry & 0xFFFF));
                    }
                    else {
                        const auto* hint = reinterpret_cast<const char*>(
                            image.data() + (nameEntry & 0x7FFFFFFF) + 2);
                        target = GetRemoteProcAddressByName(h, modBase, hint);
                    }

                    if (target != 0) {
                        std::memcpy(image.data() + thunkOff, &target, sizeof(target));
                        ++resolved;
                    }
                    else {
                        ++failed;
                    }
                    thunkOff += 8;
                    nameThunkOff += 8;
                }
                descOff += sizeof(desc);
            }
        }
        Diag("MapDll: imports resolved %zu, failed %zu", resolved, failed);
        if (failed != 0) {
            ::VirtualFreeEx(h, remote, 0, MEM_RELEASE);
            return ERROR_PROC_NOT_FOUND;
        }
    }

    if (!::WriteProcessMemory(h, remote, image.data(), image.size(), nullptr)) {
        const DWORD e = ::GetLastError();
        Diag("MapDll: WriteProcessMemory failed err=%lu", e);
        ::VirtualFreeEx(h, remote, 0, MEM_RELEASE);
        return e;
    }

    // Section protection. No section is written after this point.
    {
        DWORD oldProt = 0;
        ::VirtualProtectEx(h, remote, headerBytes,
                           PAGE_READONLY, &oldProt);
        for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const std::uint32_t vsz = sec[i].Misc.VirtualSize;
            if (vsz == 0 || sec[i].VirtualAddress + vsz > sizeOfImage) continue;

            const DWORD ch = sec[i].Characteristics;
            const bool exec  = (ch & IMAGE_SCN_MEM_EXECUTE) != 0;
            const bool read  = (ch & IMAGE_SCN_MEM_READ)    != 0;
            const bool write = (ch & IMAGE_SCN_MEM_WRITE)   != 0;

            DWORD prot = PAGE_NOACCESS;
            if (exec)       prot = write ? PAGE_EXECUTE_READWRITE
                                         : (read ? PAGE_EXECUTE_READ : PAGE_EXECUTE);
            else if (write) prot = read ? PAGE_READWRITE : PAGE_WRITECOPY;
            else            prot = read ? PAGE_READONLY  : PAGE_NOACCESS;

            ::VirtualProtectEx(h, reinterpret_cast<LPVOID>(remoteBase + sec[i].VirtualAddress),
                               (vsz + 0xFFF) & ~0xFFFu, prot, &oldProt);
        }
    }

    // A normal DLL's unwind table is real, so register it. Without this a
    // structured exception inside the DLL terminates the process instead of
    // unwinding.
    {
        const IMAGE_DATA_DIRECTORY& ed =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
        if (ed.VirtualAddress != 0 && ed.Size >= 12) {
            const std::uintptr_t pAdd =
                GetRemoteProcAddressByName(h, GetRemoteModuleBase(pid, "ntdll.dll"),
                                           "RtlAddFunctionTable");
            if (pAdd != 0) {
                std::vector<std::uint8_t> stub;
                auto a = [&stub](std::initializer_list<std::uint8_t> b) {
                    stub.insert(stub.end(), b.begin(), b.end());
                };
                auto a64 = [&stub](std::uint64_t v) {
                    for (int i = 0; i < 8; ++i)
                        stub.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
                };
                a({ 0x48, 0x83, 0xEC, 0x28 });
                a({ 0x48, 0xB9 }); a64(remoteBase + ed.VirtualAddress);
                a({ 0xBA }); for (int i = 0; i < 4; ++i)
                    stub.push_back(static_cast<std::uint8_t>((ed.Size / 12) >> (i * 8)));
                a({ 0x49, 0xB8 }); a64(remoteBase);
                a({ 0x48, 0xB8 }); a64(pAdd);
                a({ 0xFF, 0xD0 });
                a({ 0x48, 0x83, 0xC4, 0x28 });
                a({ 0xC3 });

                void* code = ::VirtualAllocEx(h, nullptr, stub.size(),
                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                if (code) {
                    ::WriteProcessMemory(h, code, stub.data(), stub.size(), nullptr);
                    UniqueHandle th(::CreateRemoteThread(
                        h, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(code),
                        nullptr, 0, nullptr));
                    if (th.get()) ::WaitForSingleObject(th.get(), 5000);
                    ::VirtualFreeEx(h, code, 0, MEM_RELEASE);
                    Diag("MapDll: RtlAddFunctionTable(%u entries) requested", ed.Size / 12);
                }
            }
        }
    }

    if (entryRva == 0) {
        Diag("MapDll: image has no entry point, mapped but not started");
        return 0;
    }

    // Call DllMain(base, DLL_PROCESS_ATTACH, 1) on a new thread, capture the
    // return value, then exit with it so the caller can observe it.
    std::vector<std::uint8_t> stub;
    auto a = [&stub](std::initializer_list<std::uint8_t> b) {
        stub.insert(stub.end(), b.begin(), b.end());
    };
    auto a64 = [&stub](std::uint64_t v) {
        for (int i = 0; i < 8; ++i)
            stub.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF));
    };
    a({ 0x48, 0x83, 0xEC, 0x28 });                 // sub  rsp, 0x28
    a({ 0x48, 0xB9 }); a64(remoteBase);            // mov  rcx, base
    a({ 0xBA, 0x01, 0x00, 0x00, 0x00 });           // mov  edx, DLL_PROCESS_ATTACH
    a({ 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00 });     // mov  r8d, 1
    a({ 0x48, 0xB8 }); a64(remoteBase + entryRva); // mov  rax, DllMain
    a({ 0xFF, 0xD0 });                             // call rax
    a({ 0x48, 0x83, 0xC4, 0x28 });                 // add  rsp, 0x28
    a({ 0xC3 });                                   // ret

    void* entryStub = ::VirtualAllocEx(h, nullptr, stub.size(),
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!entryStub) {
        const DWORD e = ::GetLastError();
        Diag("MapDll: entry stub alloc failed err=%lu", e);
        return e;
    }
    ::WriteProcessMemory(h, entryStub, stub.data(), stub.size(), nullptr);

    UniqueHandle th(::CreateRemoteThread(
        h, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entryStub),
        nullptr, 0, nullptr));
    if (!th.get()) {
        const DWORD e = ::GetLastError();
        Diag("MapDll: CreateRemoteThread failed err=%lu", e);
        ::VirtualFreeEx(h, entryStub, 0, MEM_RELEASE);
        return e;
    }

    const DWORD wr = ::WaitForSingleObject(th.get(), timeoutMs);
    DWORD exitCode = 0;
    ::GetExitCodeThread(th.get(), &exitCode);
    ::VirtualFreeEx(h, entryStub, 0, MEM_RELEASE);

    if (wr == WAIT_TIMEOUT) {
        Diag("MapDll: DllMain did not return within %u ms (still running)", timeoutMs);
        return WAIT_TIMEOUT;
    }
    Diag("MapDll: DllMain returned %lu", exitCode);
    return (exitCode != 0) ? 0 : ERROR_DLL_INIT_FAILED;
}

DWORD ManualMapBuffer(DWORD pid, std::uint8_t* buffer, std::size_t size,
                      std::uintptr_t forceBase, std::uint32_t entryOverride) {
    return ManualMapBufferEx(pid, buffer, size, forceBase, entryOverride,
                             MMapOptions::Defaults());
}

// Public wrappers so init.cpp does not need the anonymous-namespace types.
PayloadReport InspectPayloadForHost(const std::uint8_t* buffer, std::size_t size) {
    return InspectPayload(buffer, size);
}

bool PayloadReportOk(const PayloadReport& report) { return report.ok; }

MMapOptions MMapOptions::Defaults() {
    // Compile-time defaults from common.h. These are the source of truth; the
    // environment variables are only a fallback for one-off experiments and
    // were removed from the READY prompt entirely because they never took
    // effect reliably.
    MMapOptions o;
    o.registerInLdr          = (MS_REGISTER_LDR != 0);
    o.registerExceptionTable = (MS_REGISTER_EH != 0);
    o.diagAfterEntry         = (MS_DIAG_AFTER_ENTRY != 0);
    return o;
}
