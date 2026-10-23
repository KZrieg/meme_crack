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

// Resolve a target process by image name. Matches the basename, case
// insensitively, and tolerates a name without ".exe". A caller-supplied
// process name is what makes the loader usable against a target other than the
// default cs2.exe, or against several instances on one machine.
DWORD GetProcessIdByName(const wchar_t* processName);

// Enumerate every live process matching a name, so a caller can pick one when
// several are running instead of silently taking the first.
std::vector<DWORD> FindProcessIdsByName(const wchar_t* processName);

// Open a target with the least privilege that still allows manual mapping.
// Falls back from PROCESS_ALL_ACCESS to the specific rights the loader needs,
// which matters on hardened targets where full access is denied even to an
// administrator.
HANDLE OpenTargetForMapping(DWORD pid, DWORD* outError = nullptr);
std::uintptr_t GetRemoteModuleBase(DWORD pid, const char* dllName);
std::uintptr_t GetRemoteModuleInfo(DWORD pid, const char* dllName, std::uint32_t* outSize);
std::vector<std::uint8_t> ReadResource(int resId);
std::uintptr_t GetRemoteProcAddressByName(HANDLE hProc, std::uintptr_t remoteModBase, const char* funcName);
std::uintptr_t GetRemoteProcAddressByOrdinal(HANDLE hProc, std::uintptr_t remoteModBase, WORD ordinal);

// ---- Manual map options -------------------------------------------------
// Runtime switches. Every field defaults to the previous (pre-2026-10-22)
// behaviour, so ManualMapBuffer(pid,buf,size,base,entry) still works.
struct MMapOptions {
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

// ---- Payload validation ------------------------------------------------
// The loader always consumes binary/payload_fix.bin, which tools/make.bat
// produces from a raw memory dump with pe_unmapper. That output is an ordinary
// PE file (sections live at PointerToRawData); it is NOT a VA-order dump.
//
// A failure here is a property of the payload and this build's tables, never of
// the target process, which is why it can run offline.
struct PayloadReport {
    bool          ok = false;
    std::uint32_t sizeOfImage = 0;
    std::size_t   fileSize = 0;
    int           slotsMatched = 0;
    int           slotsExpected = 0;
    int           importSlotsInRange = 0;
    int           importSlotsTotal = 0;
    std::vector<std::string> problems;
};

PayloadReport InspectPayloadForHost(const std::uint8_t* buffer, std::size_t size);
bool PayloadReportOk(const PayloadReport& report);

DWORD ManualMapBuffer(DWORD pid, std::uint8_t* buffer, std::size_t size,
    std::uintptr_t forceBase,
    std::uint32_t entryOverride = 0);

DWORD ManualMapBufferEx(DWORD pid, std::uint8_t* buffer, std::size_t size,
    std::uintptr_t forceBase,
    std::uint32_t entryOverride,
    const MMapOptions& opts);

// Manual map a conventional PE (an ordinary MSVC-built DLL) into a remote
// process. Unlike ManualMapBufferEx this does not know anything about this
// payload: the import table is walked generically, base relocations are applied
// when the image cannot land at its preferred base, and the real .pdata is
// registered because a normal DLL's unwind info is not a VMProtect decoy.
//
// The DLL's DllMain is invoked on a new thread and this call waits up to
// timeoutMs for it to return. Returns 0 when the thread completed, the Win32
// error otherwise, and WAIT_TIMEOUT (258) when DllMain did not return in time.
DWORD ManualMapDll(DWORD pid, const std::uint8_t* buffer, std::size_t size,
    std::uint32_t timeoutMs = 60000);
