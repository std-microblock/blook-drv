# blook-drv 开发与测试指南

[返回首页](<../README.md>) · [用户态 SDK](<../sdk/README.md>) · [架构与边界](<architecture.md>)

本文规定 blook-drv 系统的编译构建、自动化脚本流程、测试分层体系以及命令行配置与诊断机制，适用于开发调试与系统验证。

## 工具链与编译目标

### 环境依赖

构建完整系统需要满足以下环境依赖：

- **操作系统**：Windows 10 或 Windows 11 x64 版本。
- **编译器**：支持 C++23 标准特性的 MSVC 编译器（Visual Studio 2022，19.3x 及以上版本），开启 `/permissive-`、`/utf-8` 与 `/W4`。
- **开发包与汇编器**：
  - Windows SDK（包含用户态头文件、静态库与 `signtool.exe`）。
  - Windows Driver Kit（WDK，提供内核头文件、驱动库与链接配置，使用 `win10_vb` 环境定义）。
  - Microsoft Macro Assembler（MASM，即 `ml64.exe`，负责编译 VMX 与 VM-exit 汇编模块）。
- **构建系统**：xmake。
- **签名工具**：签名套件位于仓库 [signer/](<../signer>) 目录，包含驱动测试签名程序 [CSignTool.exe](<../signer/CSignTool.exe>) 与规则文件 [hook.ini](<../signer/hook.ini>)。

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

构建脚本 [Build.ps1](<../scripts/Build.ps1>) 串联了工程配置、编译、宿主机测试、签名与校验的标准流水线：

1. **配置与编译**：调用 `xmake f` 与 `xmake build -a` 编译工程内全部目标。
2. **宿主机测试**：依次执行 `blook-tests`、`blook-protocol-tests`、`blook-client-tests` 与 `blook-loader-tests` 四组测试。
3. **数字签名与验签**：调用 [CSignTool.exe](<../signer/CSignTool.exe>) 对驱动程序实施测试签名，并调用系统的 `signtool.exe verify /kp` 校验签名有效性。
4. **服务部署（可选）**：根据输入参数向系统服务控制管理器（SCM）注册或启动驱动服务。

脚本运行参数如下：

| 参数 | 默认行为 | 指定该参数时的行为 |
| --- | --- | --- |
| `-NoSign` | 执行签名与验签流程 | 跳过数字签名阶段，编译完成后直接进入测试 |
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

### 源码格式化脚本 Reformat.ps1

代码格式化通过 [Reformat.ps1](<../scripts/Reformat.ps1>) 维护：

```powershell
# 原地格式化源码
.\scripts\Reformat.ps1

# 仅检查代码格式是否合规
.\scripts\Reformat.ps1 -Check
```

脚本根据仓库根目录下的 [.clang-format](<../.clang-format>) 规则遍历 `src/` 与 `tests/` 目录下的所有 C++ 源码与头文件。

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

- 测试入口为 [unit.cc](<../tests/unit.cc>) 与 [ept_model.cc](<../tests/ept_model.cc>)。
- 引入经过模拟桩替换的物理内存分配器与 VMX 特权指令（如 `invept`），直接运行内核 [ept.cpp](<../src/driver/hv/ept.cpp>) 的真实代码。
- 验证 EPT 4 级页表的构建、页面分割（2 MiB 页拆分为 4 KiB 页）、影子页映射写入、执行权限与读写权限分离以及 hook 撤销时的页表结构复原。

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
