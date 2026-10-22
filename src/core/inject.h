#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#define IDR_RCDATA1 101
#define IDR_RCDATA2 102
#define IDR_RCDATA3 103

extern const wchar_t* const kRequiredDlls[];
constexpr int kReqDllCount = 9;

DWORD GetProcessIdByName(const wchar_t* processName);
std::uintptr_t GetRemoteModuleBase(DWORD pid, const char* dllName);
std::uintptr_t GetRemoteModuleInfo(DWORD pid, const char* dllName, std::uint32_t* outSize);
std::vector<std::uint8_t> ReadResource(int resId);
std::uintptr_t GetRemoteProcAddressByName(HANDLE hProc, std::uintptr_t remoteModBase, const char* funcName);
std::uintptr_t GetRemoteProcAddressByOrdinal(HANDLE hProc, std::uintptr_t remoteModBase, WORD ordinal);

// ---- Manual map options -------------------------------------------------
// Runtime switches. Every field defaults to the previous (pre-2026-10-22)
// behaviour, so ManualMapBuffer(pid,buf,size,base,entry) still works.
struct MMapOptions {
    // Force the value returned by the payload's DllMain to TRUE.
    //
    // WHY: static analysis of payload.bin (sha 00DC0383) shows the import
    // table contains NO thread/APC creation primitive at all -- no
    // NtCreateThreadEx, RtlCreateUserThread, NtQueueApcThread, CreateThread,
    // CreateTimerQueueTimer or SetWindowsHookEx. The only ntdll imports are
    // CRT support (RtlAllocateHeap, strlen, RtlEnterCriticalSection, ...).
    // A DLL that owns no thread-creation import cannot leave anything behind
    // from DllMain, so returning FALSE there is the designed behaviour, not a
    // crash and not a failed check.
    //
    // Turning this on is a falsification test: if cs2 survives with TRUE and
    // still shows no menu, the payload was mapped correctly and simply has
    // nobody driving it -- which moves the problem from "fix the payload" to
    // "drive it after DllMain", i.e. into the loader.
    bool forceDllMainTrue = false;

    // Emit the post-DllMain state dump (TEB, PEB->Ldr entry, stack, exit code).
    bool diagAfterEntry = true;

    // Register the mapped image in PEB->Ldr, including a node in
    // LdrpModuleBaseAddressIndex (the RtlRBTree that LdrFindEntryForAddress
    // actually walks). Required by this payload SEI init, but it mutates the
    // target loader state, so it stays opt-in.
    bool registerInLdr = false;

    // Single-step the payload entry point in the target and record RIP plus
    // every general register after each instruction. 0 = off.
    // Set MEMESENSE_TRACE=<n>.
    std::uint32_t traceSteps = 0;

    // Register the payload .pdata with RtlAddFunctionTable. Off by default:
    // that table is a VMProtect decoy, see the comment at the call site.
    bool registerExceptionTable = false;

    // Compile-time defaults from common.h.
    static MMapOptions Defaults();
};

DWORD ManualMapBuffer(DWORD pid, std::uint8_t* buffer, std::size_t size,
    std::uintptr_t forceBase,
    std::uint32_t entryOverride = 0);

DWORD ManualMapBufferEx(DWORD pid, std::uint8_t* buffer, std::size_t size,
    std::uintptr_t forceBase,
    std::uint32_t entryOverride,
    const MMapOptions& opts);
