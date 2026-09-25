# blook-drv

基于自研 Intel VT-x / EPT 虚拟机的分析辅助驱动。

## 目录

| 路径 | 内容 |
| --- | --- |
| `src/driver/hv/` | hypervisor：VMX、VMCS、EPT、vm-exit 处理、时间隐藏 |
| `src/driver/hide/` | 迁移过来的隐藏实现（nt / win32k 服务、PEB、角色策略） |
| `src/driver/` | 设备、会话、IOCTL、EPT hook 注册表 |
| `src/client/` | 用户态客户端（session / hook / hide / scrub） |
| `src/policy/` | 纯策略：hook 规格、镜像名分类表（宿主机可测） |
| `src/loader/` | 命令行工具 `blook-loader.exe` |
| `tests/` | 宿主机上的 EPT 引擎模型测试与策略测试 |

## 构建

一个脚本搞定全部构建步骤：配置 → 编译 → 宿主机测试 → 签名 → 验签。

```powershell
.scriptsBuild.ps1              # 配置 + 编译 + 测试 + 签名 + 验签
.scriptsBuild.ps1 -NoTests     # 跳过宿主机测试
.scriptsBuild.ps1 -NoSign      # 只编译（bring-up 用）
.scriptsBuild.ps1 -Deploy      # 顺便安装服务
.scriptsBuild.ps1 -Start       # 顺便安装并启动（会接管所有逻辑处理器）
```

产物在 `build\windows\x64\releasedbg\`：`blook-drv.sys`、`blook-loader.exe`、
`blook-ept-smoke.exe`、`blook-bench.exe`。

签名由 `signer\CSignTool.exe` 静默完成，签完立刻 `signtool verify /kp` 校验；验签不过脚本
直接失败，不会放出一个起不来的驱动。

## 部署与检查

```powershell
.scriptsBuild.ps1 -Start       # 编译 + 签名 + 安装 + 启动
.scriptsLabTest.ps1            # hook 往返 + 隐藏 profile + 窗口 hook
.scriptsCleanup.ps1            # 停止并卸载服务（不动驱动文件）
```

性能基线（未 hook 的代码 / 被拦截的指令 / 被 hook 的页，三态对比，写 `.cache\bench.log`）：

```powershell
.scriptsBench.ps1
```

## 用户态 SDK

用户态 API（`src/client`）连同 ABI（`src/ipc`）和纯策略头（`src/policy`）直接当 xmake 包用，
仓库本身就是 package repository，不放任何源码副本：

```lua
add_repositories("blook-repo https://github.com/std-microblock/blook-drv.git")
add_requires("blook-client")

target("mytool")
    set_kind("binary")
    add_packages("blook-client")
```

```cpp
#include <client/ept.hpp>
```

API 说明与示例见 [sdk/README.md](sdk/README.md)。

## 使用

```powershell
blook-loader status                       # VMX 是否在跑、当前 hook 数
blook-loader hide on                      # 打开反反调试 profile
blook-loader hide windows on              # 额外打开 win32k 窗口隐藏（可选）
blook-loader pin tool 1234                # 把某个进程固定成“分析工具”角色
blook-loader pin target 4321              # 固定成“被分析目标”角色
blook-loader scrub 4321                   # 清掉目标 PEB / 堆里的调试痕迹
blook-loader hook 4321 7FF6ABCD0000 C3    # 在 4321 进程里给该地址装 EPT hook
blook-loader hook self 7FF6ABCD0000 C3    # 在自己进程里装
```

`hook` 地址是十六进制，字节串是无分隔的十六进制对（上面 `C3` 就是 `ret`）。

### 用户态 EPT hook

一个会话属于打开设备的进程，但 `patch(pid, ...)` 可以给**任意进程**装 hook：只
需要目标页在该进程里已提交且可执行。hook 不会写进目标内存，跨进程共享的镜像页
（比如 ntdll 的代码页）也只有属主进程会走到影子页。

```cpp
#include "client/ept.hpp"

auto session = blook::client::session::open();
if (!session) return;

// 1) 直接给一段字节
auto installed = session->patch(target_pid, address, {0xC3});

// 2) 或者把入口重定向到自己写好的处理函数
auto jumped = session->redirect(target_pid, address, &my_handler);

// 3) 也可以只改自己
auto mine = session->redirect(address, &my_handler);
```

`entry_jump()` 生成的 13 字节入口跳转（`mov r11, imm64; jmp r11`）不会破坏 x64
前四个参数寄存器，也不依赖从影子页里读回字面量（影子页只有执行权限）。

### 隐藏实现

`hide on` 之后安装的 kernel 侧 EPT hook：

| 服务 | 处理 |
| --- | --- |
| `NtQuerySystemInformation` | 从进程列表里摘掉工具进程、从模块列表里摘掉本驱动、系统调试器信息恒为未启用 |
| `NtQueryInformationProcess` | `ProcessDebugPort` / `ProcessDebugObjectHandle` / `ProcessDebugFlags` 一律回答“没被调试” |
| `NtSetInformationThread` | 吞掉目标的 `ThreadHideFromDebugger`，保证线程对调试器可见 |
| `NtQueryInformationThread` | 同上，查询结果恒为未隐藏 |
| `NtGetContextThread` | 目标读自己的线程上下文时清零 `Dr0..Dr3` / `Dr6` / `Dr7` |
| `NtOpenProcess` / `NtOpenThread` | 目标不能打开工具进程及其线程 |
| `NtDebugActiveProcess` | 挂接成功后立刻清掉被调试进程的 PEB 调试痕迹 |
| `NtWriteVirtualMemory` | 工具再次写 `PEB->BeingDebugged` 时把该字节中和掉，其余字节照常写入 |
| win32k `NtUser*` | 工具进程的窗口对样本不可见：`FindWindowEx` / `BuildHwndList` / `GetForegroundWindow` / `WindowFromPoint`，并且 `QueryWindow` 不再暴露窗口属主的 PID（`hide windows on`，见下） |

角色判定是“当前调用者”：只有 `target`（被分析样本）会被过滤，`tool`（调试器、
扫描器、监控器）永远看到真实系统。名单在 `src/policy/names.hpp`，也可以用
`blook-loader pin` 按 PID 固定。`scrub` 负责清 PEB 的 `BeingDebugged`、
`NtGlobalFlag` 调试位和堆的 `Flags` / `ForceFlags`。
