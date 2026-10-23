#pragma once

// MemeSense loader -- compile-time switches
// Edit here and rebuild. These are the defaults for every run.
//
// The READY prompt can still override them at runtime, but only when
// MS_INTERACTIVE is 1. For unattended runs (no console, piped stdin) set
// MS_INTERACTIVE to 0 and everything below is used verbatim -- that removes
// the need to feed "f" / "l" through a pipe, which never worked reliably.
//
// History: the environment-variable route and the `echo l | src.exe` route both
// silently failed more than once, so the compile-time defaults are now the
// primary mechanism.

// ---- payload patching ----------------------------------------------------
#define MS_FIX_IAT           1   // repair the 149-entry import table
#define MS_FIX_BRDATA        1   // repair the 8 .brdata slots

// ---- loader behaviour -----------------------------------------------------
// Register the image in PEB->Ldr, including a node in LdrpModuleBaseAddressIndex
// (the RtlRBTree that LdrFindEntryForAddress actually walks) plus a DdagNode
// whose +0x18 is -1. The payload's own exception handler at RVA 0x5380 needs
// this to recognise its own module. Off by default because it mutates the
// target's loader state.
#define MS_REGISTER_LDR      1

// Hand the .pdata unwind table to RtlAddFunctionTable. OFF by default: those 12
// RUNTIME_FUNCTION entries have illegal UNWIND_INFO (op 0x0d/0x0b/0x07, offsets
// not decreasing), so registering them makes every exception unwind through
// garbage and restore a bogus RIP.
#define MS_REGISTER_EH       0

// ---- diagnostics ----------------------------------------------------------
#define MS_DIAG_AFTER_ENTRY  1
// Skip the first N bytes of the entry trampoline and start there instead.
// 0 = normal entry. Used to bisect which instruction of the VMP chain
// first goes wrong.
#define MS_ENTRY_SKIP        0  // start execution N bytes into the entry trampoline

// Show the READY prompt and wait for keyboard input. Set 0 for unattended runs.
#define MS_INTERACTIVE       0
