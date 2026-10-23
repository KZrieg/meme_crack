<div align="center">

# meme_crack

**Cross-build remapping loader for a VMProtect-protected payload**

Takes a payload dumped from memory on *another machine, another Windows build*
and re-maps it into a target process so its `DllMain` can actually run.

![Platform](https://img.shields.io/badge/platform-Windows%20x64-0078D4?logo=windows&logoColor=white)
![Toolset](https://img.shields.io/badge/MSVC-v145-5C2D91?logo=visualstudio&logoColor=white)
![C++](https://img.shields.io/badge/C%2B%2B-20-00599C?logo=cplusplus&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Table of contents

- [The problem](#the-problem)
- [How it works](#how-it-works)
- [Multi-device support](#multi-device-support)
- [Quick start](#quick-start)
- [Compile-time switches](#compile-time-switches)
- [Repository layout](#repository-layout)
- [Diagnostics](#diagnostics)
- [Known limitations](#known-limitations)
- [Artifact fingerprints](#artifact-fingerprints)
- [License](#license)

---

## The problem

The payload was dumped from the memory of a **different** machine. Its machine code
contains absolute addresses that were only valid *there*:

- The **import table (IAT)** holds the absolute address of every resolved export
  as it existed at dump time.
- The **`.brdata` section** holds absolute addresses of internal `ntdll` and `SDL3`
  structures, also as they existed at dump time.

Replaying those addresses on the current machine is guaranteed to be wrong. And the
payload is VMProtect-protected: it validates those pointers, and when they do not
check out it either refuses to decrypt or feeds garbage into `RtlAllocateHeap`,
which ends as `C0000005`.

**What this project does:** manual-map the image, then *recompute every cross-machine
absolute address into a local one* before a single byte is written, restore the loader
state VMProtect depends on, and finally call `DllMain`.

```
                    ┌───────────────────────────────────────────┐
   memory dump ────► │ payload.bin          (VA layout, evidence) │
                    └───────────────┬───────────────────────────┘
                                    │  tools/make.bat (pe_unmapper)
                                    ▼
                    ┌───────────────────────────────────────────┐
                    │ payload_fix.bin      (standard PE layout)  │
                    └───────────────┬───────────────────────────┘
                                    │  src.rc → RCDATA
                                    ▼
                    ┌───────────────────────────────────────────┐
                    │ src.exe  ── manual map + address rewrite ─┼──► target
                    └───────────────────────────────────────────┘
```

---

## How it works

### 1. Mapping: deterministic PE expansion

`payload_fix.bin` is a **standard PE file**, not a VA-layout memory image. The two
are told apart by the section table:

| Artifact | File offset | Layout |
|---|---|---|
| `payload.bin` | `== RVA` | VA layout (raw memory dump) |
| `payload_fix.bin` | `== PointerToRawData` | File layout (standard PE) |

`BuildMappedImage()` expands it by the section table: headers are copied to offset 0
using `SizeOfHeaders`, and each section is copied from `PointerToRawData` to
`VirtualAddress`. **There is no format sniffing** — the buffer must be file-layout, and
if it is not, the mapper fails with an explicit message telling you to run `make.bat`
first.

Verified against the original dump: after mapping, `payload_fix.bin` matches
`payload.bin` byte-for-byte across **764 of 770** 4 KiB pages. The six differing pages
are the `.reloc` tail the dump never captured plus section-alignment padding.

### 2. Import table: 149 entries rebuilt

The IAT in the dump already holds absolute addresses, so the whole table is rebuilt
from scratch.

| Module | Entries | | Module | Entries |
|---|---:|---|---|---:|
| `tier0.dll` | 61 | | `sdl3.dll` | 6 |
| `ntdll.dll` | 34 | | `msvcp_win.dll` | 2 |
| `v8.dll` | 25 | | `ucrtbase.dll` | 1 |
| `libfreetype-6.dll` | 12 | | **Total** | **149** |
| `v8_zlib.dll` | 8 | | | |

Resolution supports both by-name and by-ordinal imports, and follows **export
forwarders recursively** in both forms — including the `MODULE.#Ordinal` shape that an
earlier revision silently mis-resolved as a bare RVA.

### 3. `.brdata`: 8 pointers relocated

| Offset | Width | Owner | Source |
|---|---:|---|---|
| `0x259` | 8 | SDL3 | rebased from the dump base |
| `0x261` | 8 | SDL3 | rebased from the dump base |
| `0x269` | 8 | ntdll | `RtlRegisterThreadWithCsrss` +0x80 |
| `0x271` | 8 | ntdll | `RtlInsertInvertedFunctionTable` |
| `0x279` | 8 | ntdll | `LdrpModuleBaseAddressIndex` |
| `0x281` | 8 | ntdll | `LdrpHeap` |
| `0x289` | 8 | ntdll | `RtlRbInsertNodeEx` |
| `0x291` | **6** | ntdll | `LdrpVectorHandlerList` +0x08 |

> **Width 6 is deliberate.** The trailing `43 01` bytes belong to a different field;
> writing a full 8 bytes clobbers it. Reads and writes are both 6-byte with the high
> bytes zeroed.

Two gates guard every write:

1. The slot's current value must equal the recorded `captured` value. A mismatch is
   skipped and logged — never overwritten blindly.
2. The computed address must fall inside the **live image of the corresponding module**
   in the target process. Otherwise the slot is skipped. This is what turns "wrong dump
   base" from silent corruption into a named diagnostic.

### 4. PEB->Ldr: making the payload recognise itself

The payload's own exception handler calls `LdrFindEntryForAddress` and compares the
returned `DllBase` against its own base. That function does **not** walk
`InLoadOrderLinks` — it walks the `LdrpModuleBaseAddressIndex` red-black tree, whose
nodes live at `LDR_DATA_TABLE_ENTRY + 0xC8`.

Implementation notes:

- All three list fields are **self-linked** (`+0x00`, `+0x10`, `+0x20`). Pointing all
  three at `+0x00` turns any `InMemoryOrder` walk into a self-loop on the wrong field.
- `DdagNode.Modules` is self-linked and `+0x18` is set to `0xFFFFFFFF`. A zeroed block
  hands `ntdll` a null list head.
- The insertion point is found by **binary search on `DllBase`/`SizeOfImage`** before
  calling `RtlRbInsertNodeEx` with the real parent. Passing `Parent = NULL` overwrites
  the root and abandons every module already in the index.
- The stub matches the real signature: `Tree=rcx`, `Parent=rdx`, `RightChild=r8b`,
  `Node=r9`.
- The return value is checked against `Node`, then the real export is called once as a
  self-check.

The whole step mutates the target's loader state, so it is a switch
(`MS_REGISTER_LDR`). For bisecting a crash, run once with it disabled.

### 5. `.pdata` is a decoy — do not register it

The table holds 12 `RUNTIME_FUNCTION` entries with plausible ranges, but the
`UNWIND_INFO` is fake: illegal `UWOP` codes and non-decreasing code offsets. Handing it
to `RtlAddFunctionTable` makes every exception unwind through garbage and restore a
bogus RIP/RSP — observed as a jump to `0x666600001001` (`in eax, dx`, not an instruction
boundary) after which the thread never returns.

**Keep `MS_REGISTER_EH = 0`** and let VMProtect install its own table during VM init.

Quick triage for any `.pdata`: for each entry, require `BeginAddress < EndAddress <=
SizeOfImage`, `UnwindData` inside the image, `UNWIND_INFO.Version` of 1 or 2, and
strictly decreasing `UWOP` code offsets. Any violation means decoy or corruption.

---

## Multi-device support

The goal: **one `src.exe` handles payloads dumped on different machines.**

| Dimension | Approach |
|---|---|
| **Image layout** | Fixed file-PE expansion. No heuristics. |
| **Process matching** | Strip directory, strip `.exe`, case-insensitive. Every instance is enumerated and the chosen pid is logged. |
| **Process access** | `ALL_ACCESS` → minimal rights → read-only diagnostic, a three-tier fallback. |
| **Dump bases** | Derived from leftover IAT values (`liveExport - capturedIat`), mode over all imports with a strict-majority requirement. |
| **Manual override** | `MEMESENSE_DUMP_NTDLL` / `MEMESENSE_DUMP_SDL3` environment variables. |
| **Write guard** | Every pointer must land inside the live image of its target module. |
| **Pre-flight** | Offline validation of PE shape, section coverage, slot matches and IAT ranges. Failure refuses injection. |

### ⚠️ The limits of derivation

`liveExport - capturedIat` equals the module's load delta **only when the export sits
at the same RVA in both builds**. That is the same-machine re-dump case. Across Windows
versions import RVAs move, the deltas scatter, and the mode test **refuses to report a
base** rather than guessing.

This is by design: turn "silently wrote a wrong pointer" into "one clear fallback log
line". When derivation is refused, supply the dump host's bases explicitly.

A concrete measurement that shapes all of this — the same symbol in two builds:

```
RtlRegisterThreadWithCsrss
    dump host (Win10 22H2) : 0x54590
    local       (26100.9549): 0xEF2E0
```

Cross-build RVAs differ, so a captured slot value may **never** be used to validate a
translated symbol RVA.

---

## Quick start

### Requirements

| | Requirement |
|---|---|
| OS | Windows x64 |
| Compiler | MSVC v145 (Visual Studio 2026) |
| Standard | C++20 |
| Privilege | Administrator (UAC manifest already requests `RequireAdministrator`) |

### Build

```powershell
# both projects
msbuild meme_crack.slnx /p:Configuration=Release /p:Platform=x64

# loader only
msbuild src\src.vcxproj /p:Configuration=Release /p:Platform=x64
# → src\output\src.exe
```

`server_src` emits to `src\binary\server.dll` automatically.

### Run

```powershell
# default target: cs2.exe
.\src.exe

# override the entry point RVA (hex)
.\src.exe 1000

# override the target process name
.\src.exe 1000 notepad.exe
```

Startup order: UAC check → dependency extraction → wait for the target → wait for all
nine required modules → map the check service and wait for its handshake → resolve PDB
symbols → **payload self-test** → map the payload.

The log is written to `out.log` next to the executable.

### Environment variables

| Variable | Purpose |
|---|---|
| `MEMESENSE_DUMP_NTDLL` | Dump host's ntdll base, e.g. `0x7FFCF2270000` |
| `MEMESENSE_DUMP_SDL3` | Dump host's SDL3 base, e.g. `0x7FFC2B0E0000` |

Use these when derivation is refused, i.e. a cross-build dump.

---

## Compile-time switches

Edit `src/core/common.h` and **rebuild**; these are not runtime flags.

| Switch | Default | Meaning |
|---|---:|---|
| `MS_FIX_IAT` | 1 | Repair the 149-entry import table |
| `MS_FIX_BRDATA` | 1 | Repair the 8 `.brdata` slots |
| `MS_REGISTER_LDR` | 1 | Register in PEB->Ldr (needed by the payload's SEH init) |
| `MS_REGISTER_EH` | **0** | Register `.pdata`. **Do not enable** — the table is a VMP decoy |
| `MS_DIAG_AFTER_ENTRY` | 1 | Dump TEB / PEB / thread / debugger state after entry |
| `MS_ENTRY_SKIP` | 0 | Start N bytes into the entry stub, for bisecting crashes |
| `MS_INTERACTIVE` | 0 | Show the READY prompt. Keep 0 for unattended runs |

---

## Repository layout

```
meme_crack/
├── meme_crack.slnx              solution (src + server_src)
├── src/
│   ├── init.cpp                 entry: resource extraction / PDB / orchestration
│   ├── core/
│   │   ├── common.h             compile-time switches
│   │   ├── inject.h             public interface and data types
│   │   ├── inject.cpp           map / IAT / .brdata / PEB->Ldr / diagnostics
│   │   ├── imports_fix.h        149 import-table fixups
│   │   ├── vmp_fix.h            .brdata slots + RVA fallback table
│   │   └── README.txt           per-module deep dive
│   ├── binary/
│   │   ├── payload.bin          raw memory dump (VA layout, original evidence)
│   │   ├── payload_fix.bin      pe_unmapper output (standard PE, embedded)
│   │   ├── deps.bin             dependency archive (zip)
│   │   └── server.dll           local check service
│   ├── tools/
│   │   ├── make.bat             dump → standard PE
│   │   └── pe_unmapper.exe
│   ├── utils/
│   │   └── ezpdb.hpp            DbgHelp wrapper (currently unused)
│   ├── 开发技术文档.md            engineering status and fixed-defect log
│   └── 逆向帮助文档.md            how to recompute the hardcoded values
└── server_src/
    └── server.cpp               local check service source
```

---

## Diagnostics

Key log lines, in triage order:

| Log line | Meaning |
|---|---|
| `Payload self-test: ...` | Pre-flight. If it fails, stop — the payload is wrong, not the target |
| `Map: base=... delta=...` | `delta` should be `0`; non-zero means the preferred base was taken and `.reloc` had to apply |
| `IAT Fix: repaired N/149` | Anything below 149 points at missing modules |
| `BrdataFix: repaired N/8` | Per-slot skip reasons are logged individually |
| `=== ENTRY RESULT ===` | See the three-state table below |
| `PEB->Ldr entry = present/ABSENT` | `ABSENT` means the payload's SEH cannot resolve itself |

The entry result is **three distinct outcomes**; do not conflate them:

| Captured value | Meaning |
|---|---|
| `0xDEADBEEFDEADBEEF` (sentinel) | The `call` **never returned** — it crashed |
| `0` | `DllMain` returned `FALSE` on purpose |
| Non-zero | Returned normally |

---

## Known limitations

- **Cross-build dump bases cannot be derived automatically.** Supply them via the
  environment variables (see [the limits of derivation](#-the-limits-of-derivation)).
- **The payload may still end in `C0000005` during VM init**, at a crash site involving
  `RtlAllocateHeap`. Symbol resolution and loader-state corruption have been ruled out
  as causes.
- **`utils/ezpdb.hpp` is not included by any translation unit** and overlaps with the
  PDB logic in `init.cpp`. Merging it requires fixing three defects it carries: decimal
  `Age` in the symbol-server key, a missing RVA→file-offset translation for the
  CodeView record, and `SymSetOptions` called after `SymInitialize`.
- **`RtlInsertInvertedFunctionTable` is not an exported symbol**, so its RVA can only
  come from the PDB. The value is cross-validated but the function's runtime behaviour
  is not verified.
- **`Ldrp*` offsets are build-private.** `+0xC8`, `-0x98`, `-0x88` and `-0x30` are
  ntdll internals with no stability guarantee; re-derive them by disassembly on any
  major Windows change.

---

## Artifact fingerprints

| File | Size | SHA-256 (first 16) |
|---|---:|---|
| `payload.bin` | 3,153,920 | `00DC0383D0B0049F` |
| `payload_fix.bin` | 3,121,152 | `232E445EB53B6617` |
| `server.dll` | 22,528 | `1A8785CF0723CE5E` |
| `deps.bin` | 7,559,314 | `A5B12A0775B3A887` |

Target image facts: base `0x666600000000`, `SizeOfImage` `0x309000`, entry RVA `0x1000`.

---
### Why did you make this half-finished product public?

Because when I was using MemeSense normally, MemeSense detected that there was related source code on my computer. Although I don't know how they scan, official support claimed that bans are automated. But this time, when I changed my HWID, the official side banned my account. Before that, I had already run MemeSense multiple times, and there were also MemeSense crack files on my computer.
<img width="929" height="898" alt="image" src="https://github.com/user-attachments/assets/42c031d7-91a3-4c5f-8fa6-39d5faea0ebf" />


## License

[MIT](LICENSE.txt)
