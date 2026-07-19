# Windows 安装

管理员 PowerShell 执行：

```powershell
$env:SNW_AGENT_LINKD_BIN = "$PWD\snw-agent-linkd.exe"
$env:SNW_AGENT_LINK_BIN = "$PWD\snw-agent-link.exe"
.\install.ps1
```

服务启动前会调用 `tailscale ip -1` 获取绑定地址；也可以显式设置
`TAILSCALE_BIND_IP`。服务只绑定 Tailnet 地址，不开放公网监听。

安装脚本把 CLI 和 daemon 复制到 `%ProgramFiles%\snw-agent-link`，使用
原生 Windows Service 运行 `snw-agent-linkd.exe`，不依赖 NSSM、WinSW 或
PowerShell 常驻包装器。`%ProgramData%\snw-agent-link`
关闭继承并只允许 LocalSystem 与本机 Administrators 完全控制。

安装后确认：

```powershell
Get-Service snw-agent-linkd
sc.exe query snw-agent-linkd
```

Windows 默认管理接口为 `\\.\pipe\snw-agent-link`，只允许 LocalSystem 与本机
Administrators 访问，因此管理 CLI 必须从管理员终端执行。Tailscale LocalAPI 使用官方
`\\.\pipe\ProtectedPrefix\Administrators\Tailscale\tailscaled` 管道；不应额外开启管理
TCP 端口。网关仍只绑定 Tailscale IP。
