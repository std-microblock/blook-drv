# blook-drv 开发与测试指南

[返回首页](<../README.md>) · [用户态 SDK](<../sdk/README.md>) · [架构与边界](<architecture.md>)

本文规定 blook-drv 系统的编译构建、自动化脚本流程、测试分层体系以及命令行配置与诊断机制，适用于开发调试与系统验证。

## 工具链与编译目标

### 环境依赖

构建完整系统需要满足以下环境依赖：

- **操作系统**：Windows 10 或 Windows 11 x64 版本。
- **编译器**：支持 C++23 标准特性的 MSVC 编译器（Visual Studio 2022，19.3x 及以上版本），开启 `/permissive-`、`/utf-8` 与 `/W4`。
- **开发包与汇编器**：
  - Windows SDK（包含用户态头文件与静态库）。
  - Windows Driver Kit（WDK，提供内核头文件、驱动库与链接配置，使用 `win10_vb` 环境定义）。
  - Microsoft Macro Assembler（MASM，即 `ml64.exe`，负责编译 VMX 与 VM-exit 汇编模块）。
- **构建系统**：xmake。
- **签名工具**：签名套件位于仓库 [signer/](<../signer>) 目录，其中 [spcsign.exe](<../signer/spcsign/spcsign.exe>) 为随仓库分发的本地 Authenticode PKCS#7 签名程序（源码独立开源于外部仓库，仓库内只保存已编译产物），SPC 模板与本地时间戳机构分别位于 `signer/spc-templates` 与 `signer/tsa`。

### 构建目标列表

项目构建目标在 [xmake.lua](<../xmake.lua>) 中定义，默认构建架构为 `x64`，编译模式为 `releasedbg`，输出目录为 `build/windows/x64/releasedbg`。

| 目标名称 | 产物类型 | 输出二进制 | 说明 |
| --- | --- | --- | --- |
| `blook-drv` | 内核驱动 | `blook-drv.sys` | 包含 VMX 核心、EPT 引擎与会话管理的 WDK 驱动二进制 |
| `blook-loader` | 命令行工具 | `blook-loader.exe` | 服务控制、配置管理与诊断命令行程序 |
| `blook-tests` | 宿主机测试 | `blook-tests.exe` | 纯用户态运行的 EPT 引擎与页表转换模型验证程序 |
| `blook-protocol-tests` | 单元测试 | `blook-protocol-tests.exe` | ABI v4 协议结构体尺寸、对齐与序列化静态测试 |
| `blook-client-tests` | 单元测试 | `blook-client-tests.exe` | 用户态 SDK 句柄管理与 IOCTL 调用的模拟测试 |
| `blook-loader-tests` | 单元测试 | `blook-loader-tests.exe` | CLI 参数解析与 INI 配置文件词法解析测试 |
| `blook-terminal-fixture` | 诊断固件 | `blook-terminal-fixture.exe` | 终端色彩与格式化输出检查程序（非默认构建目标） |
| `blook-ept-smoke` | 冒烟测试 | `blook-ept-smoke.exe` | 在实际驱动设备上执行的 EPT 补丁与撤销冒烟测试 |
| `blook-session-smoke` | 会话回归测试 | `blook-session-smoke.exe` | 按需在实际驱动上验证临时诊断句柄、多会话同页 hook、跨进程会话关闭与目标退出清理；不属于默认构建或宿主机测试 |
| `blook-bench` | 性能测试 | `blook-bench.exe` | 评估 VMX 虚拟化与系统调用拦截开销的基准测试程序 |

## 开发与构建工作流

在未配置测试签名证书或仅验证逻辑的开发阶段，通过编译宿主机测试与命令行工具开展工作。

### 逐步编译与执行

在仓库根目录下运行以下命令：

```powershell
xmake f -p windows -a x64 -m releasedbg -y

# 编译四组宿主机测试与加载器
xmake build blook-tests
xmake build blook-protocol-tests
xmake build blook-client-tests
xmake build blook-loader-tests
xmake build blook-loader

# 执行全部宿主机测试
xmake run blook-tests
xmake run blook-protocol-tests
xmake run blook-client-tests
xmake run blook-loader-tests

$loader = ".\build\windows\x64\releasedbg\blook-loader.exe"
& $loader --help
```

### 输出隔离构建

若已有驱动镜像处于加载状态导致链接器报错（`LNK1104` 无法写入文件），可通过指定独立输出目录进行隔离编译：

```powershell
xmake f -p windows -a x64 -m releasedbg -o build/refactor-check -y
xmake build -a
```

## 自动化脚本体系

仓库在 [scripts/](<../scripts>) 目录下提供了用于构建、基准测试、服务清理与代码格式化的 PowerShell 脚本。

### 构建脚本 Build.ps1

构建脚本 [Build.ps1](<../scripts/Build.ps1>) 串联了工程配置、编译、宿主机测试与签名的标准流水线：

1. **配置与编译**：调用 `xmake f` 与 `xmake build -a` 编译工程内全部目标。
2. **宿主机测试**：依次执行 `blook-tests`、`blook-protocol-tests`、`blook-client-tests` 与 `blook-loader-tests` 四组测试。
3. **数字签名**：调用仓库内预编译的 [spcsign.exe](<../signer/spcsign/spcsign.exe>) 对驱动程序实施测试签名（无需现场编译，仅要求系统已安装 .NET 10 运行时）。签名会原地重写驱动镜像的签名块，因此重复构建直接重签同一文件；签名是否可用由内核加载驱动时自然判定，脚本不再单独执行验签。
4. **服务部署（可选）**：根据输入参数向系统服务控制管理器（SCM）注册或启动驱动服务。

脚本运行参数如下：

| 参数 | 默认行为 | 指定该参数时的行为 |
| --- | --- | --- |
| `-NoSign` | 执行数字签名流程 | 跳过数字签名阶段，编译完成后直接进入测试 |
| `-NoTests` | 运行全部四组宿主机测试 | 跳过宿主机测试执行 |
| `-Deploy` | 不注册服务 | 停止现有服务、注销并重新向 SCM 注册驱动服务 |
| `-Start` | 不启动服务 | 部署驱动服务并立即启动，接管处理器进入虚拟化执行 |

### 清理脚本 Cleanup.ps1

清理脚本 [Cleanup.ps1](<../scripts/Cleanup.ps1>) 执行服务卸载：

1. 调用 `blook-loader stop` 请求停止内核驱动服务，退出各 CPU 的 VMX 模式。
2. 调用 `blook-loader uninstall` 从系统 SCM 数据库中移除服务注册项。

该脚本仅变更系统服务状态，保留磁盘上的二进制文件与配置文件。

### 基准测试脚本 Bench.ps1

基准测试脚本 [Bench.ps1](<../scripts/Bench.ps1>) 测量驱动对系统调用的延迟影响，分别采集三种状态下的性能数据：

1. **裸机基准（bare）**：驱动停止状态下的原生系统调用延迟。
2. **虚拟化基准（vmx）**：驱动已启动但在无活动 profile 时的系统调用延迟（评估基础 VM-exit 开销）。
3. **拦截基准（hooks）**：全局内核隐匿 profile 与 win32k 窗口拦截开启时的延迟数据。

基准测试结果追加记录至 `.cache/bench.log` 文件中。

### 源码格式化与 pre-commit 钩子

代码格式由仓库根目录的 [.clang-format](<../.clang-format>) 规则统一约束，格式化工具为 `clang-format`（本仓库以 LLVM 20.1.0 验证）。该程序需位于 `PATH`，或通过 `CLANG_FORMAT` 环境变量指定可执行文件路径。

全量格式化与格式检查通过 [Reformat.ps1](<../scripts/Reformat.ps1>) 执行：

```powershell
# 原地格式化源码
.\scripts\Reformat.ps1

# 仅检查代码格式是否合规
.\scripts\Reformat.ps1 -Check
```

脚本根据 [.clang-format](<../.clang-format>) 规则遍历 `src/` 与 `tests/` 目录下的所有 C/C++ 源码、头文件与 `.inl` 内联片段。

[.clang-format](<../.clang-format>) 显式关闭 `SortIncludes`：Windows SDK 与 WDK 头文件存在顺序依赖（例如 `<windows.h>` 必须先于 `<bcrypt.h>`），字母序重排会导致编译失败，因此 include 顺序由人工维护，格式化过程不重排。

[pre-commit](<../.githooks/pre-commit>) 钩子在每次提交时格式化本次暂存的 C/C++ 文件并将结果写回暂存区，因此提交内容始终保持格式合规，无需手工运行全量脚本。钩子路径记录在 `.git/config` 中、不随克隆分发，克隆后执行一次：

```powershell
git config core.hooksPath .githooks    # 启用钩子
git config --unset core.hooksPath      # 关闭，恢复使用默认的 .git/hooks
```

钩子行为如下：

| 项目 | 行为 |
| --- | --- |
| 覆盖范围 | 本次提交中暂存的 `.c`、`.cc`、`.cpp`、`.h`、`.hpp`、`.inl` 文件；`third_party/`、`build/`、`.cache/`、`.xmake/` 与 `packages/` 目录不参与重排 |
| 工作区同步 | 文件的工作区内容与暂存内容一致时，同步重写工作区文件；文件存在未暂存改动时仅重写暂存内容（`git add -p` 的部分暂存不会被覆盖），并在输出中列出该文件 |
| 工具缺失 | 无法定位 `clang-format` 时拒绝提交，并输出安装与绕过提示 |
| 跳过方式 | `git commit --no-verify` 跳过全部钩子；`BLOOK_SKIP_FORMAT=1 git commit` 仅跳过格式化 |

钩子只处理本次提交涉及的文件，因此在钩子启用前已存在的不合规历史文件仍由 `Reformat.ps1` 负责全量重排。

## 测试分层体系

系统通过四个相互独立的测试套件在宿主机用户态环境中覆盖各层逻辑，测试执行无需加载内核驱动或访问特权硬件。

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. 协议静态测试 (blook-protocol-tests)                         │
│    - 结构体内存对齐、字段偏移、标准布局及平凡可复制性静态断言           │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. SDK 接口模拟测试 (blook-client-tests)                     │
│    - 模拟设备句柄打开、拦截错误码映射、IOCTL 数据包边界校验           │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. CLI 与配置解析测试 (blook-loader-tests)                    │
│    - 命令行语法校验、Unicode 路径处理、PID 数值界限、INI 词法状态机    │
└─────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. EPT 引擎模型测试 (blook-tests)                            │
│    - 模拟物理内存与 VMX 指令，验证双 EPT 视图映射、拆分合并与页表恢复  │
└─────────────────────────────────────────────────────────────┘
```

### 1. 协议静态测试（blook-protocol-tests）

- 测试入口为 [protocol.cc](<../tests/protocol.cc>)。
- 采用静态断言（`static_assert`）验证通信协议类型均满足标准布局（`std::is_standard_layout_v`）与平凡可复制（`std::is_trivially_copyable_v`）特性。
- 逐项校验 `ipc::Header`、`ipc::InstallRequest`、`ipc::QueryResponse` 等定长结构体的字节尺寸与关键字段对齐偏移。

### 2. SDK 接口测试（blook-client-tests）

- 测试入口为 [client.cc](<../tests/client.cc>)。
- 利用宏拦截 `CreateFileW` 与 `DeviceIoControl` API，创建标准无信号事件句柄替代驱动设备句柄。
- 模拟内核返回定长响应或异常状态码，验证 SDK 内部的连接所有权转移、异常句柄回收与 Win32 错误码转换逻辑。

### 3. CLI 与配置解析测试（blook-loader-tests）

- 测试入口为 [loader.cc](<../tests/loader.cc>)。
- 验证命令行参数解析器（[cli.hpp](<../src/loader/cli.hpp>)）对输入边界的处理，包括十六进制地址格式、带空格与引号的 Unicode 文件路径、十进制有效范围内的 PID 以及畸变参数。
- 验证 INI 配置文件解析器（[config.hpp](<../src/loader/config.hpp>)）对空行、注释行、畸变数值及行尾空格的容错性与行号上报。

### 4. EPT 引擎模型测试（blook-tests）

已迁移到 GoogleTest 1.17.0（xmake 管理依赖），不再用自定义 `require` / 进程退出作为 EPT 测试框架。策略测试位于 [unit.cc](<../tests/unit.cc>)，EPT 用例按主题拆分在 [ept](<../tests/ept>) 和 [ept_edges](<../tests/ept_edges>)。

- [fixture.hpp](<../tests/ept/fixture.hpp>)：每例独立分配 EPT、原始页，重置 CR3、物理映射、MTRR、MTF、统计与诊断；支持 shuffle/repeat，不依赖前一用例残留状态。
- [hooks.cc](<../tests/ept/hooks.cc>)、[watch.cc](<../tests/ept/watch.cc>)、[memory_types.cc](<../tests/ept/memory_types.cc>)：保留原安装/撤销、进程隔离、同页多 hook、watch 互斥/跨页 dump、MTRR 等覆盖。
- [jit_write.cc](<../tests/ept_edges/jit_write.cc>)：hook 后写入页首/页尾/patch 内外，整页 oracle 比较，固定随机种子的多轮重写、多 vCPU 显式发布。
- [boundaries.cc](<../tests/ept_edges/boundaries.cc>)、[resources.cc](<../tests/ept_edges/resources.cc>)、[windows.cc](<../tests/ept_edges/windows.cc>)：patch 长度/跨页、内部入口逐字节测试、容量耗尽、拆页池耗尽及回收、未知 ID、嵌套及同页 call-original 窗口。
- [regression.cc](<../tests/ept/regression.cc>)：遵循真实 VM-exit dispatcher 在非 EPT exit 前 rearm 的约束，验证撤销后的 split 复用；不把违反上层调用约束的序列当成生产 bug。

这些模型测试通过 `BLOOK_EPT_TEST` 编译真实的 [ept.cpp](<../src/driver/hv/ept.cpp>)，并用 platform mock 替换平台操作；这**不是在用户态运行驱动**，不会加载 `.sys`、执行真实 VMX 或访问真实 EPT 硬件，也不会执行测试代码页中的机器码或真实 INVEPT/MTF。因此不能证明硬件缓存、跨核同步、指令跨页重启或任意并发自修改代码完全透明。下述 live 测试则由用户态 GoogleTest 通过 SDK IOCTL 调用**已加载的内核驱动**，两者的执行路径与验证边界不同。

```powershell
xmake build blook-tests
xmake run blook-tests
xmake run blook-tests --gtest_shuffle --gtest_random_seed=455 --gtest_repeat=20
xmake run blook-tests --gtest_filter=*Jit*:*Write* --gtest_output=xml:build/ept-jit-results.xml
```

### GoogleTest 真实 JIT / 写后执行测试

非默认目标 `blook-ept-live-tests` 通过用户态 SDK 的 IOCTL 接口访问已加载驱动，不是在用户态运行驱动实现。默认运行全部跳过，且在检查 opt-in 前不会打开驱动。只有在已加载匹配驱动的隔离 Intel x64 测试机上显式设置 `BLOOK_EPT_LIVE=1` 才进行实际安装/执行；opt-in 后环境不可用算失败，不伪装成通过。不会自动安装或启动驱动服务。

```powershell
xmake build blook-ept-live-tests
# 安全检查：不访问驱动，预期 SKIPPED
$env:BLOOK_EPT_LIVE = '0'
xmake run blook-ept-live-tests
# 仅在隔离、可恢复的硬件测试机上：
$env:BLOOK_EPT_LIVE = '1'
xmake run blook-ept-live-tests --gtest_output=xml:build/ept-live-results.xml
Remove-Item Env:BLOOK_EPT_LIVE
```

真实测试使用自行分配的代码页，覆盖 RW→RX JIT 发布、执行 patch/数据读原字节、同页代码重写、显式 refresh、撤销后保留最新写入以及跨页拒绝。**写入与 refresh 期间必须停止执行该代码页**；宿主模型中自动 resync 使用的 backing 指针，不等同于真实驱动用户代码快照会自动同步。模型层 CoW / remap 的 PFN 变化须重新绑定；真实驱动保护维护路径的自动 rebind 由 [live_cow.cc](<../tests/live_cow.cc>) 的独立 GoogleTest 验证。任意跨核无同步自修改、GC 搬迁、异常重启、别名映射并不因此获得完整保证。

### 其余旧测试统一迁移 GoogleTest

原有自定义 `check/finish` 框架已移除。以下目标现在均支持 `--gtest_list_tests`、`--gtest_filter`、`--gtest_shuffle` 和 XML 报告：

| 目标 | 独立用例 | 类型 |
| --- | ---: | --- |
| `blook-client-tests` | 20 | SDK mock；每例重置假 IOCTL 状态 |
| `blook-loader-tests` | 20 | CLI / INI 解析 |
| `blook-protocol-tests` | 10 | 保留编译期 ABI 断言并拆分运行期契约 |
| `blook-terminal-fixture` | 3 | 捕获 stdout/stderr，验证正常、降级及 Unicode 错误输出 |
| `blook-ept-smoke` | 2 | 实际并发执行与写后 refresh/撤销 |
| `blook-live-watch` | 3 | pending、精确 dump、one-shot 执行与清理 |
| `blook-live-cow` | 1 | 真实 image 页保护变化后的 hook rebind |
| `blook-live-dormant` | 3 | 非可执行（RW）页上 hook/watch 的休眠注册、RX 变更时武装、休眠期撤销 |
| `blook-session-smoke` | 6 | 句柄生命周期、所有权隔离、远程目标退出 |
| `blook-image-page-tests` | 2 | 无驱动 BCrypt baseline + opt-in 同页双 hook |

后五个目标中的真实驱动用例都要求 `BLOOK_EPT_LIVE=1`；默认跳过，不参与普通宿主 `xmake test`。直接使用 `xmake run <target>` 加 GoogleTest flags 运行，不使用隔离 runner，也不为每个用例另启子进程。可通过 `--gtest_list_tests` 查看用例、`--gtest_filter` 选择用例、`--gtest_output=xml:...` 保存报告；需要核对产物时使用 `xmake show -t <target>` 查看当前配置的 targetfile。按 GoogleTest 输出及 XML 区分 PASS、FAIL 与 SKIPPED，不将平台布局不匹配的跳过误报为通过。

```powershell
xmake build blook-live-watch
$env:BLOOK_EPT_LIVE = '1'
xmake run blook-live-watch --gtest_list_tests
xmake run blook-live-watch --gtest_filter=* --gtest_output=xml:build/ept-live-watch-results.xml
Remove-Item Env:BLOOK_EPT_LIVE
```

GoogleTest flags 本身不提供挂起超时保护。若实际测试挂起，停止该次运行并检查驱动及机器状态；终止用户态测试进程不代表内核状态已恢复，不应据此连续重跑。

[image_page.cc](<../tests/image_page.cc>) 还修复了原复现程序的 BCrypt handler 参数数量及 CBC IV 重用错误；只有系统函数同页且已知 prologue 精确匹配时才安装 hook。保留 [bench.cc](<../tests/bench.cc>) 为独立性能测量工具，不把计时输出冒充 GoogleTest 正确性断言，现有 Bench 脚本接口不变。

历史实测记录：宿主新增迁移 53 项随机顺序重复 3 轮通过；真实新套件 16 项中 15 项通过、1 项同页自读取挂起，已实际复现，并非 SKIPPED；此前确认挂起的测试进程已终止，但这不证明挂起原因已修复或内核状态已恢复。此前采用隔离执行方式时，上表后五个目标合计 14 项曾在本机实际执行通过（含 BCrypt baseline，真实驱动项未跳过）；该历史结果不代表本轮直接执行结果。

同页自读取挂起的修复记录：根因是 EPT 数据违例路径只切「原始页 RW 无执行」视图——若访存指令本身就在被挂钩页上，其取指在数据视图下违例、访存在影子视图下违例，指令永远无法完成，形成退出乒乓死循环。修复为单步回退（与 HyperDbg 一致）：同页访存违例时切「原始页 RWX」单步一条指令，MTF 退出后重新武装。由此引入**文档化限制**：补丁自身不得包含读写本页的指令（如 RIP 相对自读），此类指令会以原始字节单步执行、该次执行补丁被绕过；回归用例 [jit_test.cc](<../tests/ept_live/jit_test.cc>) 的 `SamePageSelfReadRunsOriginalBytesWithoutHanging` 覆盖「不挂起 + 回退原始字节」语义。修复后 `blook-ept-live-tests` 16 项全过（不再需要排除过滤器），`blook-live-watch` 3 项、`blook-live-cow` 1 项、`blook-ept-smoke` 2 项、`blook-session-smoke` 6 项、新增的 `blook-live-dormant` 3 项（非可执行页休眠注册 → 保护变更武装 → 休眠期撤销）全部通过。

最新使用 `xmake run <target>` 直接执行的记录：宿主 5 个目标通过；`blook-ept-smoke` 2 项、`blook-live-watch` 3 项、`blook-live-cow` 1 项、`blook-session-smoke` 6 项通过；`blook-image-page-tests` 的 BCrypt baseline 1 项通过，live image 用例因 `Unsupported bcrypt prologue` **SKIPPED**，不是通过，也未绕过 prologue 检查。`blook-ept-live-tests` 使用过滤器排除已知挂起用例后，其余 15 项通过；被排除的挂起用例未在本轮验证，不能计为通过或 GoogleTest SKIPPED。此前 image live 通过、本轮跳过的差异须保留，不能写成本轮全部 14 项通过。

### 实际驱动会话生命周期回归

这组测试必须在隔离的、已加载测试驱动的受支持 Intel 机器上显式运行；不会修改驱动服务配置，也不会注入任何已有进程。测试在自身分配的代码页以及它创建的独立子进程中安装补丁，并直接关闭原始设备句柄，避免 SDK 的 hook 析构先发送 REMOVE 而掩盖驱动清理错误。

```powershell
xmake build blook-session-smoke
$env:BLOOK_EPT_LIVE = '1'
xmake run blook-session-smoke
# 仅验证跨进程所有权 / 目标退出清理（--remote 别名也保留）
xmake run blook-session-smoke --gtest_filter=SessionSmoke.Remote*
Remove-Item Env:BLOOK_EPT_LIVE
```

覆盖临时只读查询、统计、地址探测及空的已使能会话关闭后原 hook 仍生效；不同会话同页 hook 的独立清理与令牌鉴权；关闭创建会话后远程目标恢复原值；目标进程退出后跨会话 hook 全部失效。

## 命令行交互与诊断

命令行工具 [main.cc](<../src/loader/main.cc>) 负责接收用户指令、管理服务状态并输出诊断信息。

### 参数解析规则

- **帮助指令**：无参数执行、`help`、`--help` 以及在已知命令后追加 `--help` 均输出标准帮助文本。
- **PID 参数**：必须为十进制非零整数，取值范围为 `1` 至 `4294967295`。命令行中的 `hook self` 映射为 SDK 中表示当前进程的数值 `0`。
- **地址与字节参数**：虚拟地址按指针宽度的十六进制整数解析（可选带 `0x` 前缀）；补丁字节串要求为长度在 1 至 64 对之间的无分隔十六进制字符序列。
- **路径参数**：包含空格的路径必须使用双引号包裹，相对路径基于调用进程的当前工作目录解析。

### 仪表盘与状态展示

执行 `blook-loader status` 时，程序通过只读模式打开设备并格式化展示运行状态：

1. **连接与版本**：显示通信句柄建立结果、客户端 ABI 与驱动 ABI 版本号及匹配状态。
2. **虚拟化运行标志（running）**：显示全局 Intel VT-x 引擎是否处于活动状态。
3. **会话使能标志（enabled）**：显示当前连接是否持有修改授权。
4. **活动拦截计数（hooks）**：统计以当前调用进程为目标的活动拦截数量。
5. **系统隐匿状态（hidden / window_hooks）**：显示内核反分析策略使能状态与 win32k 窗口拦截实际生效数量。
6. **内核状态码（backend_status）**：输出驱动底层记录的原始 `NTSTATUS` 状态码。

### 退出码契约

命令行工具的进程退出码定义如下：

| 退出码 | 语义 | 说明 |
| --- | --- | --- |
| `0` | 执行成功 | 帮助显示完成，或请求操作成功执行；对于状态查询命令，要求 `running` 标志为 `1` |
| `1` | 操作失败 | 包含命令行语法错误、配置文件校验失败、文件未找到、权限被拒绝或服务调用失败 |
| `2` | 后端未就绪 | 设备查询成功完成，但内核虚拟化引擎未运行（`running` 为 `0`） |

### 终端控制台色彩输出

终端格式化模块（[terminal.cc](<../src/loader/terminal.cc>)）独立检测标准输出（stdout）与标准错误（stderr）的控制台虚拟终端处理能力（VT Mode）：

- 当检测到控制台支持 VT 序列时，输出带颜色的高亮状态；当输出流被重定向至管道或文件时，自动输出纯文本。
- 若环境中存在名为 `NO_COLOR` 的环境变量（无论其值是否为空），程序全局禁用色彩高亮输出。

## 配置规范与错误语义

命令 `blook-loader apply [path]` 用于解析配置文件并将设置注入系统，默认配置文件路径为当前工作目录下的 [blook.ini](<../blook.ini>)。

### 语法定义

- **编码格式**：配置文件必须采用 UTF-8 编码，支持可选的 UTF-8 BOM。
- **节与键**：遵循标准 INI 语法 `[section]` 与 `key = value`。节名称与键名称均按 ASCII 大小写无关方式处理，首尾空白字符自动裁剪。
- **注释规则**：以 `#` 或 `;` 开头的整行视作注释；不支持在值后追加的行尾注释。
- **节与配置项定义**：
  - `[device] allow_users`：布尔值，接受 `true`/`false`、`yes`/`no`、`1`/`0`。配置写入驱动服务注册表项 `AllowUsers`，控制下次设备创建时的 ACL。
  - `[hooks] hook_mask`：32 位无符号整数，写入注册表项 `HookMask`，控制内核系统服务的拦截范围。
  - `[hooks] window_hook_mask`：32 位无符号整数，写入注册表项 `WindowHookMask`，控制 win32k 服务的拦截范围。
  - `[roles] tool` / `target`：以逗号或分号分隔的进程镜像名或十进制 PID。

### 错误定位与部分应用语义

1. **语法校验阶段**：程序先完整读取并解析整个文件。若发现未知格式、语法畸变或非法数值，解析器终止处理并通过 `config_error` 输出具体行号与错误描述，此时不修改注册表亦不打开驱动设备。
2. **注册表写入阶段**：当配置中存在 `[device]` 或 `[hooks]` 项时，程序打开驱动服务的注册表键并逐项写入。此操作要求驱动服务已注册，但驱动不必须处于运行状态。
3. **角色应用阶段**：当配置中包含非空的 `[roles]` 项时，程序枚举当前系统进程快照，建立驱动连接并下发角色绑定指令。若驱动未运行，角色应用阶段将报告失败。
4. **部分应用语义**：注册表项写入成功后，若后续的角色下发操作发生错误，已写入注册表的配置不会自动回滚。重新加载驱动服务即可使已写入注册表的设置生效。
