#pragma once
#include <cstdint>
#include <map>
#include <string>

// ---------------------------------------------------------------------------
// Origin (dump-host) module bases.
//
// These are NOT constants that must hold on every machine. They are only the
// recorded values from the Win10 22H2 dump that produced payload.bin, kept as
// the last-resort fallback so a single-host build still behaves exactly as
// before.
//
// At load time the loader derives the real dump bases from the payload itself:
// every IAT slot in imports_fix.h still holds the *dump-time* resolved address
// of its export. Comparing that captured value against the same export in the
// live process gives
//
//     delta_module = liveExportAddress - capturedIatValue
//     dumpBase     = liveModuleBase   - delta_module
//
// which is exact and needs no PDB, no fixed OS build, and no assumption about
// where the dump came from. vmp_fix.cpp implements that derivation; these
// values are what it falls back to when the payload has no usable IAT (for
// example when the caller already pre-fixed it with pe_unmapper).
constexpr uint64_t kDumpNtdllBase = 0x00007FFCF2270000ULL;
constexpr uint64_t kDumpSdl3Base  = 0x00007FFC2B0E0000ULL;

enum class SlotModule : uint8_t {
    Sdl3,
    Ntdll
};

// One .brdata slot. `symbol` is resolved through ntdll's PDB; `delta` is added
// to the symbol RVA. A slot with `symbol == nullptr` is a plain module-relative
// pointer: its dump RVA is `captured - <dump base of module>` which the loader
// recomputes, so SDL3 needs no symbol table.
struct BrdataSlot {
    uint32_t    rva;
    uint64_t    captured;
    uint32_t    width;
    SlotModule  module;
    const char* symbol;
    uint32_t    delta;
};

const BrdataSlot g_brdataSlots[] = {
    { 0x259, 0x00007FFC2B379A78ULL, 8, SlotModule::Sdl3,  nullptr,                           0x00 },
    { 0x261, 0x00007FFC2B153A70ULL, 8, SlotModule::Sdl3,  nullptr,                           0x00 },
    { 0x269, 0x00007FFCF22C4590ULL, 8, SlotModule::Ntdll, "RtlRegisterThreadWithCsrss",     0x80 },
    { 0x271, 0x00007FFCF22808F0ULL, 8, SlotModule::Ntdll, "RtlInsertInvertedFunctionTable", 0x00 },
    { 0x279, 0x00007FFCF23DD4A8ULL, 8, SlotModule::Ntdll, "LdrpModuleBaseAddressIndex",     0x00 },
    { 0x281, 0x00007FFCF23DC520ULL, 8, SlotModule::Ntdll, "LdrpHeap",                       0x00 },
    { 0x289, 0x00007FFCF2297DC0ULL, 8, SlotModule::Ntdll, "RtlRbInsertNodeEx",              0x00 },
    { 0x291, 0x00007FFCF23F13F0ULL, 6, SlotModule::Ntdll, "LdrpVectorHandlerList",          0x08 },
};

constexpr int kBrdataSlotCount = sizeof(g_brdataSlots) / sizeof(g_brdataSlots[0]);

// Runtime view of one slot after the dump bases are known. `dumpRva` is the
// section-relative offset of the pointer inside its origin module, derived once
// per run, so the same payload binary works on hosts whose modules load at
// different addresses.
struct BrdataSlotResolved {
    std::uint64_t dumpRva;      // offset of the target inside its module
    std::uint32_t width;        // 6 for the last slot (see doc)
    SlotModule    module;
    const char*   symbol;       // ntdll only; null for sdl3
    std::uint32_t delta;
};

const char* const kDiagSymbols[] = {
    "RtlAddVectoredExceptionHandler",
    "RtlExitUserProcess",
    "NtTerminateProcess",
    "RtlAllocateHeap",
    "RtlFreeHeap",
    "LdrpInsertModuleToIndex",
    "LdrpFindLoadedDll",
    "LdrpLoadDll",
    "LdrpInitializeProcess",
};
constexpr int kDiagSymbolCount = sizeof(kDiagSymbols) / sizeof(kDiagSymbols[0]);

const std::map<std::string, uint32_t> g_manual_rva_fix = {
    { "RtlRegisterThreadWithCsrss",     0x0EF2E0 },
    { "RtlInsertInvertedFunctionTable", 0x05AEA4 },
    { "LdrpModuleBaseAddressIndex",     0x1D2450 },
    { "LdrpHeap",                       0x1D2860 },
    { "RtlRbInsertNodeEx",              0x0440A0 },
    { "LdrpVectorHandlerList",          0x1EA578 },
};
