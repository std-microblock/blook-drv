# blook-drv SDK

## 引入

```lua
add_repositories("blook-repo https://github.com/std-microblock/blook-drv.git")
add_requires("blook-client")

target("mytool")
    set_kind("binary")
    set_languages("cxx23")
    add_files("src/*.cpp")
    add_packages("blook-client")
```

```cpp
#include <client/ept.hpp>
```


## 运行前提

1. 驱动已安装并启动：`blook-loader install blook-drv.sys` + `blook-loader start`，设备
   `\.BlookDrv` 存在。ACL 只允许 SYSTEM 和管理员，所以你的进程需要管理员权限。
2. `session::open()` 默认会启用 hook 后端（在所有逻辑处理器上开 VMX）；只查询状态用
   `session::open(false)`，它不会启动后端。

## API 速查

返回值都是 `std::expected`（`result<T>` / `result<void>`），失败时 `error()` 是 Win32 错误码。

| 调用 | 作用 |
| --- | --- |
| `session::open(enable_hooks = true)` | 打开设备，可选启用后端 |
| `session->query()` | 状态：`running / enabled / hooks / hidden / window_hooks / abi / backend_status` |
| `session->patch(pid, address, bytes)` | 在目标地址装字节补丁（pid 0 = 当前进程） |
| `session->redirect(pid, target, replacement)` | 把入口跳到你自己的处理函数 |
| `hook::refresh()` | 重新发布快照（目标自改了代码 / 数据视图写过之后） |
| `hook::remove()` | 撤销这个 hook（析构也会撤销） |
| `session->hide(true/false)` | 开关隐藏 profile（Nt* 服务） |
| `session->pin(pid, role)` / `unpin(pid)` | 固定进程角色：`hide_role_tool` / `hide_role_target` |
| `session->scrub(pid, flags)` | 清目标 PEB / 堆里的调试痕迹 |

### patch：原始字节补丁

```cpp
#include <client/ept.hpp>

auto session = blook::client::session::open();
if (!session) return;                                  // session.error() 是 Win32 错误码

const uint8_t code[] = {0xb8, 42, 0, 0, 0, 0xc3};      // mov eax,42; ret
auto hook = session->patch(target_pid, address, code);  // pid 0 = 当前进程
if (!hook) return;

hook->refresh();   // 需要重新同步快照时
hook->remove();    // 也可以交给析构
```

- 补丁最多 64 字节，且必须完全落在目标页内（`address & 0xfff` + 长度 ≤ 4096）。
- 目标必须已提交且可执行（`PAGE_EXECUTE*`），否则装不上。
- **执行看 shadow、数据看原始页**：目标执行时看到打补丁的副本，读写自己的代码看到原始字节，
  所以目标的自校验代码不会被补丁本身戳穿。

### redirect：入口跳转到自己的处理函数

```cpp
extern "C" int my_handler();
auto hook = session->redirect(target_pid, entry_point, &my_handler);
```

入口补丁是 `jmp qword ptr [rip+rel32]`；literal 放在**目标页之外**独立分配的一页里，并保持
存活到 hook 撤销。不能把 literal 放进被 hook 的页里：执行视图是只读-执行的 shadow 页，
页内读会被"数据视图"接回原始页，读到的是原字节。

### hide / pin / scrub

```cpp
session->pin(debugger_pid, blook::ipc::hide_role_tool);
session->pin(sample_pid,   blook::ipc::hide_role_target);
session->hide(true);        // 打开 hidden profile
session->scrub(sample_pid, blook::ipc::scrub_all);
session->hide(false);
```

- `query().hidden` 和 `query().window_hooks` 能看到当前状态（窗口 hook 在部分 build 上少于 5 个，
  属于导出解析不到，不是失败）。

## 行为与坑

- **撤销**：hook 析构 / `remove()` 撤销；目标进程退出时驱动也会回收它名下的 hook。
- **刷新**：`refresh()` 用在目标自改代码或数据视图写过之后；执行中调用要自己保证目标静止。
- **同一物理页**只允许一个 hook 的 shadow，重复装同一页会返回冲突。
- **内核 hook vs 用户 hook**：`pid != 0` 的 hook 只在属主进程的地址空间生效（用 PEB 的物理页做
  属主判断），共享镜像页（如 ntdll）对其它进程完全无感；`blook-loader hide` 那套是内核级 hook，
  对所有进程生效。
- **性能**：执行被 hook 的页会付一次 VM-exit，数据访问同样；未 hook 的代码不会被拦截，但
  CPUID / RDTSC / RDMSR / WRMSR / MOV CR 这类指令是全局拦截的（隐藏 VM 存在的代价）。
  用仓库里的 `scripts/Bench.ps1` 可以在本机量三态基线。

## 完整例子

```cpp
#include <client/ept.hpp>
#include <cstdio>

int main() {
    auto session = blook::client::session::open();
    if (!session) {
        std::printf("open failed: %lu\n", session.error());
        return 1;
    }
    if (auto info = session->query())
        std::printf("ABI %u running=%u hooks=%u hidden=%u\n", info->abi,
                    info->running, info->hooks, info->hidden);

    const uint8_t patch[] = {0xc3};   // ret
    if (auto hooked = session->patch(0, target, patch)) {
        // ...
        hooked->remove();
    }
    return 0;
}
```
