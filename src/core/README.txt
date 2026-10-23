================================================================================
 core/  --  MemeSense payload 手工映射核心
================================================================================

本目录只做一件事: 把一个已经由 pe_unmapper 处理过的 PE 文件, 手工映射进
cs2.exe (或其它目标进程), 修好 VMP 需要的导入表与 .brdata 指针, 然后调用它的
DllMain。它不读盘上的 payload, 资源由 init.cpp 从 exe 内嵌 RCDATA 取出后传进来。

    common.h        编译期开关 (改完必须重编)
    inject.h        对外接口与数据结构
    inject.cpp      全部实现: 映射 / IAT / .brdata / PEB->Ldr / 诊断 / 自检
    imports_fix.h   149 项导入表修复数据 (payload 自带 IAT 的 RVA 与来源)
    vmp_fix.h       .brdata 8 个槽位定义 + 本机 RVA 兜底表

--------------------------------------------------------------------------------
 1. 输入格式: 只有一种, 不要搞混
--------------------------------------------------------------------------------

    payload.bin        内存 dump 产物。文件偏移 == RVA (VA 布局)。
                       这是"原始证据", 只用于 IDA 分析和重新生成 payload_fix.bin。
                       直接喂给本目录的映射器是错的。

    payload_fix.bin    tools/make.bat 用 pe_unmapper 从 payload.bin 转出的
                       **标准 PE 文件**。每个节的原始数据在 PointerToRawData。
                       src.rc 里 IDR_RCDATA3 嵌的就是它, 也就是运行期唯一的输入。

BuildMappedImage() 按节表把它摊成 SizeOfImage 大小的 VA 布局镜像:
头按 SizeOfHeaders 拷到 0, 每个节从 PointerToRawData 拷到 VirtualAddress。
这是确定行为, 没有任何格式探测。如果传进来的不是文件布局 (节的 raw 范围超出
缓冲区), 函数直接返回 false, 映射器报:
    "not a file-layout PE ... run tools/make.bat on the raw dump first"

实测校验 (2026-10-23):
    payload_fix.bin 映射后与 payload.bin 的 VA 布局逐 4K 页比对, 764/770 页
    完全相同; 差异的 6 页是 dump 未覆盖的 .reloc 尾部和节对齐零页。
    入口 0x1000 处字节完全一致: e8 ed 83 27 00 9c 48 81 ...

--------------------------------------------------------------------------------
 2. 映射流程 (ManualMapBufferEx)
--------------------------------------------------------------------------------

  1) 校验 MZ / PE32+ 头, 取 SizeOfImage 与入口 RVA。
  2) BuildMappedImage() 摊成 VA 镜像 (见上)。
  3) VirtualAllocEx 在首选基址 0x666600000000 保留并提交整个 SizeOfImage。
     首选地址被占则回退到任意地址, 并按 .reloc 修正 DIR64 项。没有可用
     .reloc 时明确返回 ERROR_INVALID_ADDRESS, 不带坏地址继续。
  4) 修 149 项链式 IAT (imports_fix.h), 在目标进程里按名字或序号解析,
     并跟随 forwarder (含 "MODULE.#Ordinal" 形式, 见第 4 节)。
  5) 修 .brdata 8 个槽位 (见第 5 节)。
  6) 整块写进目标, 再按各节 Characteristics 逐节 VirtualProtectEx。
  7) .pdata 默认不注册 (那是 VMP 诱饵 unwind 表, 见 common.h)。
  8) TLS 目录 (本 payload 没有, 实际不执行)。
  9) 分配一页放调用桩, call DllMain(base, DLL_PROCESS_ATTACH, 1),
     返回值写进同页捕获槽, 然后 ret。
 10) CreateRemoteThread 起桩, 最多等 60 秒, 结束后读捕获槽做诊断。

诊断要点: 捕获槽预置哨兵 0xDEADBEEFDEADBEEF。结束后仍是哨兵 => call 没返回,
这是"崩了"; 返回 0 => DllMain 主动返回 FALSE; 非 0 => 正常。三者含义完全不同,
不要混着看。

--------------------------------------------------------------------------------
 3. 编译期开关 (common.h)
--------------------------------------------------------------------------------

    MS_FIX_IAT            1   修 149 项导入表
    MS_FIX_BRDATA         1   修 .brdata 8 个槽位
    MS_REGISTER_LDR       1   把镜像注册进 PEB->Ldr (payload 的 SEH 需要)
    MS_REGISTER_EH        0   注册 .pdata。保持 0: 那张 unwind 表是 VMP 诱饵,
                              注册后任何异常都会用垃圾 UNWIND_INFO 恢复坏 RIP。
    MS_DIAG_AFTER_ENTRY   1   入口返回后打印 TEB/PEB/线程/调试器状态
    MS_ENTRY_SKIP         0   跳过入口桩前 N 字节再执行, 用于二分定位
    MS_INTERACTIVE        0   是否显示 READY 交互提示。无人值守保持 0。

--------------------------------------------------------------------------------
 4. 导入表修复 (imports_fix.h)
--------------------------------------------------------------------------------

payload 的原始 IAT 在 dump 里仍然是 dump 机器的绝对地址, 必须整表重建。
g_vmpBImportTable[] 每项是 { IAT 所在 RVA, 模块名, 序号(0=按名), 函数名 }。

    共 149 项, 分布:
      ntdll.dll           34
      tier0.dll           61
      v8.dll              25
      libfreetype-6.dll   12
      v8_zlib.dll          8
      sdl3.dll             6
      msvcp_win.dll        2
      ucrtbase.dll         1

解析规则:
  * 先 GetRemoteModuleBase 找目标进程里该模块的基址; 模块没加载就跳过该项。
  * 序号非 0 走导出序号, 否则走导出名。两者都支持 forwarder 递归。
  * 目标模块尚未加载时, ManualMapDll 路径会退化为在目标里 LoadLibraryW。

失败处理: 修不上的项只少不崩, 但日志会打印 "IAT Fix: repaired N/149"。
            不是 149/149 就说明目标环境缺模块或版本差太多, 先看这一行。

--------------------------------------------------------------------------------
 5. .brdata 槽位 (vmp_fix.h)
--------------------------------------------------------------------------------

.brdata 节 VA 0x1F3000, 8 个槽位存的是 dump 时刻的绝对指针:

    偏移    宽度  归属    来源
    0x259   8     sdl3    按 dump 基址平移
    0x261   8     sdl3    按 dump 基址平移
    0x269   8     ntdll   RtlRegisterThreadWithCsrss        +0x80
    0x271   8     ntdll   RtlInsertInvertedFunctionTable
    0x279   8     ntdll   LdrpModuleBaseAddressIndex
    0x281   8     ntdll   LdrpHeap
    0x289   8     ntdll   RtlRbInsertNodeEx
    0x291   6     ntdll   LdrpVectorHandlerList              +0x08

关于宽度 6: 紧随其后的 "43 01" 属于另一个字段, 写满 8 字节会踩掉它。
读写都按 6 字节且高位补零, 自洽。

写入前有两道保护:
  a) 槽位当前值必须等于表中的 captured, 不匹配就跳过并记日志, 绝不盲写。
  b) 算出的新地址必须落在目标进程对应模块的映射范围内 (IsAddressInLiveModule),
     否则跳过。这道检查专门拦"dump 基址不对导致指针算飞"的情况。

符号 RVA 从哪来:
  * 优先 PDB (init.cpp 解析 %TEMP%\MemeSense_Symbols\<key>\ntdll.pdb)。
  * PDB 不可用时退到 g_manual_rva_fix。该表是 10.0.26100 的本机值,
    换 ntdll 大版本后可能失效, 日志会打印 "FALLBACK RVA" 提醒。

【重要】captured 值与当前 ntdll 的 RVA 不能互相验证。实测同一个
RtlRegisterThreadWithCsrss: dump (Win10) 在 0x54590, 本机 26100 在 0xEF2E0。
跨版本 RVA 本来就会变, 所以 captured 只当"这个槽位原始值是否完好"的判据,
不能用它去校验符号表。

--------------------------------------------------------------------------------
 6. 多设备适配 (2026-10-23 新增)
--------------------------------------------------------------------------------

目标: 同一个 src.exe 要能对付不同机器上 dump 出来的 payload, 而不是把
"dump 机器的模块基址"写死。

  a) 布局: 固定按文件 PE 映射, 不再猜。见第 1 节。
  b) 进程: GetProcessIdByName 现在去路径、去 .exe、不区分大小写
     (旧 wcsstr 实现会误匹配); 新增 FindProcessIdsByName 枚举所有实例,
     init.cpp 会把全部 pid 打出来并说明用了哪个。目标进程名可用命令行
     第 3 个参数覆盖: src.exe [entryHex] [processName]。
  c) 权限: OpenTargetForMapping 先试 PROCESS_ALL_ACCESS, 失败降级到
     QUERY|VM_READ|VM_WRITE|VM_OPERATION|CREATE_THREAD, 最后再降一档只读诊断。
     加固目标上管理员也会被拒 ALL_ACCESS, 这个降级是必要的。
  d) dump 基址反推: DeriveDumpBases() 拿 IAT 里残留的 dump 地址与目标进程
     中同一导出的实际地址相减:
         delta      = liveExport - capturedIat
         dumpBase   = liveModuleBase - delta
     对同一模块所有导入取众数, 要求严格多数才采用。
     【限制】这个等式只在导出 RVA 相同时成立, 也就是"同一台机器重新 dump 再
     加载"的场景。跨 Windows 版本时导入 RVA 会变, delta 会散开, 众数检测
     会拒绝采用并回落到常量。这是设计如此, 目的是把"静默写错指针"变成
     "记录一条回退日志"。
  e) 手动指定: 反推不成立时用环境变量显式给 dump 机器的基址
         set MEMESENSE_DUMP_NTDLL=0x7FFCF2270000
         set MEMESENSE_DUMP_SDL3=0x7FFC2B0E0000
     这两个值会覆盖反推结果与常量。
  f) 离线自检: InspectPayloadForHost() 在注入前验证 PE 形状、节覆盖、
     .brdata 槽位是否与表匹配、IAT 槽位是否都在镜像内。失败就拒绝注入并
     列出具体问题。它不需要目标进程, 也不会执行 payload。

--------------------------------------------------------------------------------
 7. PEB->Ldr 注册 (MS_REGISTER_LDR)
--------------------------------------------------------------------------------

payload 自己的异常处理器 (RVA 0x5380) 调 LdrFindEntryForAddress, 要求返回项的
DllBase 等于自身基址, 否则 SEH/CRT 初始化在 0x553D 放弃。

LdrFindEntryForAddress 不遍历 InLoadOrderLinks, 它走 LdrpModuleBaseAddressIndex
这棵 RTL_RB_TREE, 节点是 LDR_DATA_TABLE_ENTRY + 0xC8。据此实现的注册:

  * 三条链表字段各自指向自己 (+0x00 / +0x10 / +0x20)。
  * DdagNode 的 Modules 自连接, +0x18 写 0xFFFFFFFF。
  * 插入前先按 DllBase/SizeOfImage 二分走到插入点, 再以真实 parent 调
    RtlRbInsertNodeEx。传 Parent=NULL 只会覆盖 Root, 丢掉所有已存在模块。
  * 桩按真实签名构造: Tree=rcx, Parent=rdx, RightChild=r8b, Node=r9。
  * 插入后校验返回值 == Node, 再用真实导出 LdrFindEntryForAddress 自检。

这一段会改动目标进程的 loader 状态。排查时先设 MS_REGISTER_LDR=0 做对照。

--------------------------------------------------------------------------------
 8. 公共接口 (inject.h)
--------------------------------------------------------------------------------

    DWORD GetProcessIdByName(name)                  单个 pid, 0 表示没有
    std::vector<DWORD> FindProcessIdsByName(name)   全部匹配
    HANDLE OpenTargetForMapping(pid, &err)          带权限降级
    uintptr_t GetRemoteModuleBase(pid, dll)         走 PEB->Ldr
    uintptr_t GetRemoteModuleInfo(pid, dll, &size)  同上, 额外给 SizeOfImage
    uintptr_t GetRemoteProcAddressByName/ByOrdinal  远程导出解析, 跟 forwarder
    std::vector<uint8_t> ReadResource(resId)        读 exe 内嵌 RCDATA
    PayloadReport InspectPayloadForHost(buf,size)   离线自检
    DWORD ManualMapBufferEx(pid,buf,size,base,entry,opts)  主映射入口
    DWORD ManualMapBuffer(...)                      兼容旧签名
    DWORD ManualMapDll(pid,buf,size,timeout)        映普通 DLL (校验服务用)

返回值约定: 0 = 成功; 否则是 Win32 错误码。WAIT_TIMEOUT(258) 表示 DllMain
在超时内没返回, 对监听型 DLL 是正常现象。

--------------------------------------------------------------------------------
 9. 排查顺序
--------------------------------------------------------------------------------

  1) 先看 out.log 的 "Payload self-test" 段。失败就别往下走, 是 payload 不对。
  2) 看 "Map: file=... image=..." 与 "Map: base=... delta=..."。delta 应为 0;
     非 0 说明首选基址被占, 需要 .reloc 生效。
  3) 看 "IAT Fix: repaired N/149"。不是 149 先解决模块缺失。
  4) 看 "BrdataFix: repaired N/8" 以及每个槽位的跳过原因。
  5) 看 "=== ENTRY RESULT ==="。哨兵 / FALSE / 非 0 三种含义不同。
  6) 看 "PEB->Ldr entry = present/ABSENT" 与调试器状态。

================================================================================
