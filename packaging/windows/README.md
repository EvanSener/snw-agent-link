# Windows 安装

管理员 PowerShell 执行：

```powershell
$env:SNW_AGENT_LINKD_BIN = "$PWD\snw-agent-linkd.exe"
$env:SNW_AGENT_LINK_BIN = "$PWD\snw-agent-link.exe"
.\install.ps1
```

服务启动前会调用 `tailscale ip -1` 获取绑定地址；也可以显式设置
`TAILSCALE_BIND_IP`。服务只绑定 Tailnet 地址，不开放公网监听。

安装脚本把 CLI、daemon 和 wrapper 复制到 `%ProgramFiles%\snw-agent-link`，使用 Windows Service 运行 `snw-agent-linkd.exe`。服务账号只授予数据目录和 Named Pipe 所需权限。

安装后确认：

```powershell
Get-Service snw-agent-linkd
sc.exe query snw-agent-linkd
```

Windows 默认管理接口为 `\\.\pipe\snw-agent-link`，不应额外开启管理 TCP 端口。网关仍只绑定 Tailscale IP。
