# blook-drv 用户态 SDK

[返回首页](<../README.md>) · [架构与边界](<../docs/architecture.md>) · [开发与测试指南](<../docs/development.md>)

blook-drv 用户态 SDK 提供基于 C++23 标准的头文件库接口，供分析工具、自动化组件与宿主程序同内核驱动建立通信。SDK 封装了设备连接建立、状态查询、双 EPT 视图拦截、内核服务隐匿与调试标记清除等功能。

SDK 主入口头文件为 [ept.hpp](<../src/client/ept.hpp>)，核心类型位于 `blook::client` 命名空间；底层通信协议与常数定义位于全局 `ipc` 命名空间（[protocol.hpp](<../src/ipc/protocol.hpp>)）。

## 工程集成

### 环境依赖

集成 SDK 需要满足以下编译与运行环境：

- **编译器**：支持 C++23 标准的 MSVC 编译器，要求完整支持 `std::expected` 与 concept 约束。
- **平台与架构**：Windows 10/11 x64 操作系统。
- **系统链接库**：链接 `advapi32.lib`。

SDK 采用头文件库（header-only）组织，接口依赖仓库 `src` 目录下的 `client/`、`ipc/` 与 `policy/` 模块。调用工程应将仓库的 `src` 根目录添加至包含路径中。

### 构建配置示例

使用 xmake 构建的项目可通过以下配置引入源码树：

```lua
set_languages("cxx23")
set_arch("x64")

target("blook-client-tool")
    set_kind("binary")
    add_files("src/main.cpp")
    add_includedirs("deps/blook-drv/src")
    add_defines("NOMINMAX", "UNICODE", "_UNICODE")
    add_syslinks("advapi32")
```

对于使用 CMake 的项目，添加对应的包含路径与链接依赖：

```cmake
cmake_minimum_required(VERSION 3.20)
project(blook-client-tool CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(blook-client-tool src/main.cpp)
target_include_directories(blook-client-tool PRIVATE deps/blook-drv/src)
target_link_libraries(blook-client-tool PRIVATE advapi32)
```

仓库同时提供了独立的包定义文件：位于仓库根目录的 [xmake.lua](<../packages/b/blook-client/xmake.lua>) 与 [blook-drv-sdk.lua](<blook-drv-sdk.lua>)。包定义将 master 版本固定到特定 commit，通过包管理器集成时仅拉取头文件，不触发驱动编译。

## 只读状态查询

应用程序通过 `blook::client::session::open(blook::client::open_mode::read_only)` 创建只读连接。只读连接打开设备符号链接 `\\.\BlookDrv`，但不向驱动发送使能指令（`IOCTL_BLOOK_ENABLE`），适用于系统状态诊断与监控场景。

```cpp
#include <client/ept.hpp>
#include <cstdio>

int main() {
    // 建立未使能修改能力的只读会话
    auto session = blook::client::session::open(blook::client::open_mode::read_only);
    if (!session) {
        std::fprintf(stderr, "打开驱动设备失败，Win32 错误码: %lu\n",
                     session.error().value());
        return 1;
    }

    // 执行状态查询
    const auto info = session->query();
    if (!info) {
        std::fprintf(stderr, "查询状态失败，Win32 错误码: %lu\n",
                     info.error().value());
        return 1;
    }

    // 校验通信协议 ABI 版本
    if (info->abi != ipc::abi_version) {
        std::fprintf(stderr, "协议 ABI 不匹配: 客户端=%u, 驱动=%u\n",
                     ipc::abi_version, info->abi);
        return 2;
    }

    std::printf("驱动 ABI: %u\n", info->abi);
    std::printf("虚拟化引擎运行状态: %s\n", info->running ? "已启动" : "已停止");
    std::printf("当前会话使能状态: %s\n", info->enabled ? "已使能" : "只读");
    std::printf("作用于当前进程的拦截数: %u\n", info->hooks);
    std::printf("内核隐匿状态: %s\n", info->hidden ? "已启用" : "已停用");
    std::printf("已安装的窗口服务拦截数: %u\n", info->window_hooks);
    std::printf("后端状态码 (NTSTATUS): 0x%08X\n",
                static_cast<unsigned>(info->backend_status));

    return 0;
}
```

### 查询协议与 ABI v4

查询接口调用成功后返回 `blook::client::session_info`：它是 32 字节固定布局的 `ipc::QueryResponse` _wire 结构体的解码视图，整型标志已转换为 `bool`。

| 字段 | 类型 | 说明与口径 |
| --- | --- | --- |
| `abi` | `uint32_t` | 驱动通信协议版本，现行为 `4`；调用方应与 `ipc::abi_version` 比较校验 |
| `version` | `uint32_t` | 驱动协议兼容标识，当前实现同 `abi_version`；产品语义版本通过版本 IOCTL 查询 |
| `running` | `uint32_t` | 全局 Intel VT-x 虚拟化引擎运行标志；`1` 表示已启动，`0` 表示已停止 |
| `enabled` | `uint32_t` | 当前会话是否获得修改授权；通过 `open(true)` 打开的会话置为 `1`，只读会话置为 `0` |
| `hooks` | `uint32_t` | 作用于**调用方进程**的活动用户态拦截总数，不包含针对其他进程的拦截计数 |
| `hidden` | `uint32_t` | 全局内核反分析策略使能状态；`1` 为开启，`0` 为关闭 |
| `window_hooks` | `uint32_t` | win32k 全局窗口函数当前实际生效的拦截计数 |
| `backend_status` | `int32_t` | 驱动底层记录的原始内核 `NTSTATUS` 状态码（如 `STATUS_SUCCESS`） |

## API 接口参考

SDK 核心操作集中于 `blook::client::session` 与 `blook::client::hook` 两个类型。

### 会话生命周期与配置

| 接口方法 | 说明 |
| --- | --- |
| `session::open(open_mode mode = open_mode::read_write)` | 打开驱动设备句柄。`read_write` 模式会同时向驱动请求会话使能，允许执行后续修改操作；`read_only` 仅建立只读连接 |
| `session::query()` | 发起只读查询，返回解码后的 `session_info`（布尔标志已转换为 `bool`） |
| `session::hide(bool enable)` | 启用或停用全局内核服务隐匿策略 |
| `session::hide_windows(bool enable)` | 启用或停用全局 win32k 窗口隐藏策略 |
| `session::pin(pid process, process_role role)` | 将指定进程绑定为指定角色（`process_role::tool` 或 `process_role::target`） |
| `session::unpin(pid process)` | 解除指定进程的角色绑定 |
| `session::scrub(pid process, scrub flags = scrub::all)` | 清除指定目标进程内存中的调试器特征标志（支持 `scrub::peb`、`scrub::heap` 组合） |

### EPT 拦截与重定向

| 接口方法 | 说明 |
| --- | --- |
| `session::patch(void* address, byte_range auto&& bytes, pid target = pid::current())` | 在指定进程的虚拟地址处安装二进制补丁，返回 `hook` 对象；字节序列接受任何 1 字节连续范围（`std::byte`/`uint8_t` 数组、`std::vector`、`std::span` 等） |
| `session::redirect(void* target, void* replacement, pid owner = pid::current())` | 在目标进程中分配跳转字面量并安装 6 字节间接跳转，将目标函数执行导向替代函数 |
| `hook::id()` | 读取当前拦截项的全局唯一 64 位标识符 |
| `hook::refresh()` | 在目标模块代码重新加载或发生修改后，重新同步 EPT 影子页的快照数据（同页所有拦截项的补丁会一并重新合并） |
| `hook::remove()` | 显式撤销拦截项；同页其余拦截项不受影响，其影子页会被重建。成功撤销后清空本地 ID |

`pid` 是强类型进程标识：`pid::current()` 表示当前进程，默认构造的 `pid{}`（值为 0）在驱动侧同样表示调用进程自身。

## 拦截机制与约束条件

### 页内边界与指令长度对齐

安装补丁时，SDK 校验补丁字节长度必须位于 `1` 至 `64` 字节之间，且 `[address, address + bytes.size())` 必须完整落在单个 4 KiB 物理页内，不支持跨页补丁。

驱动内核在接收到补丁请求后，利用内建的轻量级 x86_64 指令解码器校验目标地址代码。若传入的补丁长度截断了某条完整指令，内核将自动扩展覆盖范围至该完整指令的边界，并使用 `0x90`（NOP）填充尾部未覆盖的字节。若目标指令无法被解码器正确识别，驱动将拒绝安装请求并返回错误。

### 同一物理页上的多个拦截

同一进程在同一 4 KiB 页内可以安装任意多个互不重叠的拦截项：驱动会将它们合并进该进程独立的影子页，每个补丁按各自的指令覆盖区间写入。数据读操作仍然返回原始字节，执行时由 EPT 按需切换合并后的影子视图。撤销其中一个拦截项只会从影子页重建中移除对应补丁，其余拦截项保持生效。

合并规则：

- 同进程（同一身份页作用域）的拦截项要求覆盖区间互不重叠；重叠或完全相同的区间会被拒绝（`ERROR_OBJECT_NAME_COLLISION` 对应的驱动状态）。
- 内核（全局作用域）拦截项之间可以共页，但同样不允许区间重叠。
- 内核拦截项与用户拦截项永不共页：全局作用域与进程作用域在同一物理页上会互相冲突。
- 多个进程共享同一物理镜像页时（如系统 DLL），每个进程各自持有独立的影子页与补丁集。

### 入口重定向机制

`session::redirect` 用于将函数入口拦截并跳转至替代函数。函数内部调用 [ept.hpp](<../src/client/ept.hpp>) 中的 `entry_jump` 辅助函数，构造 6 字节的 RIP 相对间接跳转指令：

```text
ff 25 xx xx xx xx    ; jmp qword ptr [rip + rel32]
```

重定向过程要求如下约束：

1. **字面量（Literal）存储**：跳转目标绝对地址（64 位指针）存储于独立的 8 字节内存空间中。`redirect` 通过 `VirtualAlloc` 或 `VirtualAllocEx` 在进程地址空间中分配该页面。
2. **相对位移范围**：字面量存储地址相对跳转指令下一条指令的位移必须处于带符号 32 位整数范围内（即 `[-2 GiB, +2 GiB]`）。若寻址超出该范围，`entry_jump` 返回空 `std::optional`，`redirect` 终止安装并返回 `ERROR_INVALID_PARAMETER`。
3. **内存生命周期**：分配的字面量页面在拦截生效期间必须保持可读。为了避免替代函数返回时出现非法内存访问，SDK 当前不自动释放已分配的字面量内存。

## 对象生命周期与所有权

### 连接共享与 RAII 设计

`session` 结构管理与驱动设备的底层通信，内部持有共享连接结构 `std::shared_ptr<detail::connection>`。

1. **会话对象**：`session` 采用仅移动（move-only）语义，禁止拷贝。
2. **拦截对象**：由 `session::patch` 或 `session::redirect` 返回的 `hook` 对象同样持有底层连接的 `shared_ptr` 引用。只要仍有 `hook` 实例处于存活状态，底层驱动句柄将保持开启。
3. **析构与撤销**：`hook` 的析构函数尝试调用 `remove()` 撤销内核拦截；由于析构函数无法传递返回值，若需要确保拦截已撤销并获取明确状态，应显式调用 `hook::remove()`。

### 内核所有权与进程级清理

驱动内部通过三层维度管理资源所有权：

1. **会话令牌（Session Token）**：每个打开设备的会话分配独立的 64 位令牌。安装拦截时，拦截项记录创建该拦截的会话令牌。`remove()` 与 `refresh()` 操作要求调用方会话令牌与记录严格一致，其他会话无法修改该拦截。
2. **目标进程生命周期**：内核注册进程创建与退出通知回调。当被拦截的目标进程终止时，驱动自动定位并回收所有绑定到该目标 PID 的拦截项与角色标记，避免孤儿拦截残留。
3. **调用进程会话清理**：关闭连接时，驱动按该连接的会话令牌撤销它创建的全部拦截，包括针对其他进程的拦截；不会撤销同一进程中其他连接创建的拦截。临时只读查询或统计句柄的关闭不影响正在工作的 hook。调用进程退出时，驱动撤销其所有会话创建的拦截，并独立清理以该进程为目标的拦截。

## 错误处理规范

SDK 接口统一采用 `blook::client::result<T>`（即 `std::expected<T, std::error_code>`）作为返回类型，错误值来自 `std::system_category()`：

- 操作成功时，通过解引用或箭头运算符访问数据。
- 操作失败时，通过 `.error()` 获取 `std::error_code`，以 `.error().value()` 取得原始 Win32 错误码；`std::error_code` 可直接与 `std::format`、条件判断及标准库错误设施协作。

| 错误码 | 对应场景 | 处理方式 |
| --- | --- | --- |
| `ERROR_FILE_NOT_FOUND` / `ERROR_PATH_NOT_FOUND` | 设备符号链接 `\\.\BlookDrv` 不存在 | 确认驱动服务已注册并成功启动 |
| `ERROR_ACCESS_DENIED` | 设备访问被拒绝，或操作不具备会话所有权 | 以管理员权限运行程序，或在 `blook.ini` 中配置 `allow_users = true` |
| `ERROR_INVALID_HANDLE` | 设备连接未建立或已被释放 | 检查 `session` 对象是否已析构或移动 |
| `ERROR_INVALID_PARAMETER` | 补丁长度超出范围、跨越 4 KiB 页边界、指令无法解码或重定向位移越界 | 检查目标虚拟地址、补丁长度及汇编指令合法性 |
| `ERROR_INVALID_DATA` | 内核返回的响应包尺寸与协议定义不匹配 | 检查客户端 SDK 与内核驱动的 ABI 版本一致性 |
| `ERROR_NOT_READY` | 内核虚拟化引擎未处于运行状态 | 确认驱动加载时硬件虚拟化初始化成功 |
