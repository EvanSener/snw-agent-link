$ErrorActionPreference = 'Stop'
$serviceName = 'snw-agent-linkd'
$sourceDaemon = if ($env:SNW_AGENT_LINKD_BIN) { $env:SNW_AGENT_LINKD_BIN } else { Join-Path $PSScriptRoot 'snw-agent-linkd.exe' }
$sourceCli = if ($env:SNW_AGENT_LINK_BIN) { $env:SNW_AGENT_LINK_BIN } else { Join-Path $PSScriptRoot 'snw-agent-link.exe' }
$installDir = if ($env:SNW_AGENT_LINK_INSTALL_DIR) { $env:SNW_AGENT_LINK_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'snw-agent-link' }
$dataDir = if ($env:SNW_AGENT_LINK_DATA_DIR) { $env:SNW_AGENT_LINK_DATA_DIR } else { Join-Path $env:ProgramData 'snw-agent-link' }
if (-not (Test-Path $sourceDaemon)) { throw "找不到可执行文件: $sourceDaemon" }
if (-not (Test-Path $sourceCli)) { throw "找不到可执行文件: $sourceCli" }
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null
& icacls.exe $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "无法保护数据目录 ACL: $dataDir" }
Copy-Item -Force $sourceDaemon (Join-Path $installDir 'snw-agent-linkd.exe')
Copy-Item -Force $sourceCli (Join-Path $installDir 'snw-agent-link.exe')
$tailscale = if ($env:TAILSCALE_BIN) {
  $env:TAILSCALE_BIN
} elseif (Test-Path (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe')) {
  Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
} else {
  (Get-Command tailscale.exe).Source
}
$tailscaleIp = if ($env:TAILSCALE_BIND_IP) { $env:TAILSCALE_BIND_IP } else { (& $tailscale ip -1 | Select-Object -First 1).Trim() }
if ([string]::IsNullOrWhiteSpace($tailscaleIp)) { throw '未检测到 Tailscale 地址，请设置 TAILSCALE_BIND_IP' }
$daemon = Join-Path $installDir 'snw-agent-linkd.exe'
$quoted = '"' + $daemon + '" --data-dir "' + $dataDir + '" --tailscale-bind-ip "' + $tailscaleIp + '" --gateway-port 7443'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $serviceName | Out-Null
}
New-Service -Name $serviceName -BinaryPathName $quoted -DisplayName 'snw-agent-linkd' -StartupType Automatic -Description 'Tailnet-only peer Agent gateway'
Start-Service -Name $serviceName
Write-Host "snw-agent-link 与原生 Windows Service 已安装到 $installDir；数据目录已保护: $dataDir；服务已启动: Get-Service $serviceName"
