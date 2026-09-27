# blook-drv 系统概述

blook-drv 是面向 Windows x64 平台的 Intel VT-x 与扩展页表（Extended Page Tables, EPT）分析辅助驱动系统，包含内核驱动程序、用户态控制接口、命令行管理工具及宿主机验证测试套件。系统通过硬件辅助虚拟化技术在指定目标进程中建立影子执行视图，实现对用户态指令的无侵入拦截与内核行为监控。

## 文档索引

- [用户态 SDK](<sdk/README.md>)：C++23 头文件集成方式、只读状态查询、拦截接口与所有权生命周期。
- [架构与边界](<docs/architecture.md>)：分层架构、执行环境约束、IPC ABI v4 协议规范与 EPT 视图隔离机制。
- [开发与测试指南](<docs/development.md>)：工具链依赖、构建流水线、宿主机测试分层与配置文件规格。

## 快速上手

运行宿主机模型测试与构建命令行工具需要准备 Windows x64 操作系统、支持 C++23 标准的 MSVC 编译器、Windows SDK 与 xmake。在仓库根目录的 PowerShell 终端中执行以下构建命令：

```powershell
xmake f -p windows -a x64 -m releasedbg -y
xmake build blook-tests
xmake run blook-tests
xmake build blook-loader

$loader = ".\build\windows\x64\releasedbg\blook-loader.exe"
& $loader --help
```

宿主机测试（`blook-tests`）在模拟环境中验证 EPT 引擎的页表映射与地址转换逻辑，执行过程中不访问物理虚拟化硬件，亦不调用内核驱动接口。

### 自动化构建脚本

自动化构建脚本 [Build.ps1](<scripts/Build.ps1>) 集中管理配置、编译、测试与签名流程。在未配置测试签名证书的环境中，指定 `-NoSign` 参数完成编译并执行宿主机测试：

```powershell
.\scripts\Build.ps1 -NoSign
```

脚本支持以下运行参数：

| 参数 | 执行行为 |
| --- | --- |
| `-NoSign` | 跳过内核驱动的数字签名阶段 |
| `-NoTests` | 跳过宿主机单元测试套件的执行 |
| `-Deploy` | 编译后向系统服务控制管理器（SCM）注册驱动服务 |
| `-Start` | 注册并启动驱动服务，激活所有逻辑处理器的虚拟化监控 |

### 服务状态查询

在驱动已安装并运行的环境中，通过命令行工具执行状态查询：

```powershell
& $loader status
```

查询操作通过只读方式打开设备符号链接 `\\.\BlookDrv`，不修改系统服务配置，亦不改变内核运行状态。输出中的 `running` 指示全局虚拟化引擎的运行状态，`enabled` 指示当前打开会话的修改授权状态。

用户态应用程序建立连接时，若仅需读取状态，可调用 `blook::client::session::open(blook::client::open_mode::read_only)` 创建只读会话，具体流程见 [用户态 SDK](<sdk/README.md#只读状态查询>)。

## 命令行接口

命令行工具 [main.cc](<src/loader/main.cc>) 提供服务生命周期控制、配置管理与动态分析接口。

| 功能类别 | 命令格式 | 说明 |
| --- | --- | --- |
| 帮助与诊断 | `blook-loader help` / `--help` | 显示命令用法说明 |
| | `blook-loader status` | 查询全局虚拟化状态、会话使能状态及当前拦截计数 |
| | `blook-loader ping` | 向驱动发送探测数据包，验证通信通道是否正常 |
| | `blook-loader version` | 查询内核驱动的版本信息 |
| 服务管理 | `blook-loader install <path>` | 向 SCM 注册驱动内核服务（要求指定驱动文件完整路径） |
| | `blook-loader start` | 启动驱动服务并在各逻辑处理器上初始化 VMX 架构 |
| | `blook-loader stop` | 停止驱动服务并退出虚拟化执行模式 |
| | `blook-loader uninstall` | 从 SCM 中注销驱动服务（要求服务处于停止状态） |
| 配置应用 | `blook-loader apply [path]` | 解析 INI 配置文件，将设备项写入注册表并即时应用进程角色 |
| 分析干预 | `blook-loader hook <self|pid> <address> <bytes>` | 在目标进程的指定虚拟地址处安装 EPT 拦截补丁 |
| | `blook-loader hide [windows] <on|off>` | 启用或停用内核隐匿策略，可选附加 win32k 窗口过滤 |
| | `blook-loader pin <tool|target> <pid>` | 将指定进程绑定为分析工具角色或被分析目标角色 |
| | `blook-loader unpin <pid>` | 解除指定进程的角色绑定 |
| | `blook-loader scrub <pid>` | 清除目标进程 PEB 与堆结构中的调试器特征标志 |

卸载驱动服务前必须先停止驱动服务。若存在未关闭的设备句柄，服务停止将处于挂起状态，直至所有句柄完全释放。

## 配置体系

系统支持通过 INI 配置文件管理设备权限与过滤规则，基线配置定义于 [blook.ini](<blook.ini>)。

```ini
[device]
allow_users = false

[hooks]
hook_mask = 0x1ff
window_hook_mask = 0xffffffff

[roles]
tool = x64dbg.exe, x32dbg.exe, windbg.exe, frida.exe
target =
```

配置项按作用范围划分为三类：

1. **设备访问控制（`[device]`）**：`allow_users` 控制设备对象 `\Device\BlookDrv` 的访问控制列表（ACL）。默认值为 `false`，仅授予 SYSTEM 与 Administrators 组访问权限；设置为 `true` 时，额外向交互式登录用户授予读写访问权限。
2. **拦截掩码（`[hooks]`）**：`hook_mask` 与 `window_hook_mask` 分别通过 32 位位掩码指定内核服务与 win32k 窗口服务的拦截范围。
3. **进程角色（`[roles]`）**：定义分析工具进程（`tool`）与目标进程（`target`）。支持以逗号分隔的镜像名称或十进制 PID。

执行 `blook-loader apply [path]` 时，程序解析指定配置文件（缺省为当前工作目录下的 [blook.ini](<blook.ini>)）。设备控制与拦截掩码写入驱动服务注册表项并在驱动启动时加载；进程角色项通过 IOCTL 接口即时下发至正在运行的驱动实例中生效。

## 源码组织

系统源码按职责划分为驱动内核、通信协议、策略计算、用户接口与宿主机测试五个层次：

| 模块路径 | 职责范围 |
| --- | --- |
| [main.cc](<src/driver/main.cc>) / [session.cc](<src/driver/session.cc>) | 驱动入口点、设备对象创建、IRP 分派、会话管理与系统电源/进程事件通知 |
| [hooks.cc](<src/driver/hooks.cc>) / [hooks.hpp](<src/driver/hooks.hpp>) | EPT hook 注册表、物理页锁定、所有权校验与拦截发布 |
| [hv.cpp](<src/driver/hv/hv.cpp>) / [ept.cpp](<src/driver/hv/ept.cpp>) | VMX 状态初始化、VMCS 配置、EPT 双层页表构建与 VM-exit 处理 |
| [hide.cc](<src/driver/hide/hide.cc>) | 内核系统服务过滤、win32k 窗口隐藏及进程角色匹配逻辑 |
| [protocol.hpp](<src/ipc/protocol.hpp>) | 全局 `ipc` 命名空间定义、定长通信结构体与 ABI v4 控制码 |
| [hook.hpp](<src/policy/hook.hpp>) / [x86_length.hpp](<src/policy/x86_length.hpp>) | 无系统依赖的策略逻辑，包括页边界计算与 x86_64 指令长度解码 |
| [ept.hpp](<src/client/ept.hpp>) | 用户态 C++23 API，提供 `session` 与 `hook` 抽象封装 |
| [main.cc](<src/loader/main.cc>) | 命令行管理程序，提供服务控制、配置解析与诊断操作 |
| [unit.cc](<tests/unit.cc>) / [ept](<tests/ept>) / [ept_edges](<tests/ept_edges>) | GoogleTest 宿主机测试，验证策略、EPT 映射、JIT 写后同步与边界状态 |
| [ept_live](<tests/ept_live>) | 显式 opt-in 的 GoogleTest 真实 JIT、透明读写与撤销回归，默认安全跳过 |
