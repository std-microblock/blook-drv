# signer/

驱动测试签名需要的全部材料，由 [scripts/Build.ps1](<../scripts/Build.ps1>) 的签名阶段使用。
这里没有任何东西会在普通构建中被编译：签名器是预编译产物，直接执行。

| 路径 | 作用 |
| --- | --- |
| `spcsign/` | Authenticode PKCS#7 签名器（`spcsign.exe` + .NET 程序集）。源码独立开源于外部仓库，本仓库只保留产物。运行需要系统安装 .NET 10 运行时。 |
| `certs/` | 随签名一同嵌入的交叉 / 中间 CA 证书，对应 `--chain`。 |
| `spc-templates/` | 从已知能通过内核策略校验的签名中提取的 SPC 模板：`spc_data.bin`（SpcPeImageData）与 `spc_attrs.bin`（statementType / opusInfo）。 |
| `tsa/` | 本地时间戳机构：`tsa-leaf.pfx`（含私钥，口令 `spcsign`）与 `tsa-root.cer`。 |

签名器按 `signer\spc-templates` 与 `signer\tsa` 的固定布局定位模板和时间戳材料，因此
`Build.ps1` 只需传入证书与时间参数。

## 重新编译签名器

仅当签名器自身需要更新时执行（需要 .NET 10 SDK）：

```powershell
dotnet publish <spcsign 源码仓库>\src\spcsign -c Release -r win-x64 --self-contained false -o signer\spcsign
```

## 时间戳根证书

`tsa/tsa-root.cer` 需要被安装到 `CurrentUser\Root` 才能让校验方认可时间戳链：

```powershell
signer\spcsign\spcsign.exe trust-tsa --dir signer\tsa
```
