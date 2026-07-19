$ErrorActionPreference = 'Stop'
$serviceName = 'snw-agent-linkd'
$sourceDaemon = if ($env:SNW_AGENT_LINKD_BIN) { $env:SNW_AGENT_LINKD_BIN } else { Join-Path $PSScriptRoot 'snw-agent-linkd.exe' }
$sourceCli = if ($env:SNW_AGENT_LINK_BIN) { $env:SNW_AGENT_LINK_BIN } else { Join-Path $PSScriptRoot 'snw-agent-link.exe' }
$installDir = if ($env:SNW_AGENT_LINK_INSTALL_DIR) { $env:SNW_AGENT_LINK_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'snw-agent-link' }
if (-not (Test-Path $sourceDaemon)) { throw "找不到可执行文件: $sourceDaemon" }
if (-not (Test-Path $sourceCli)) { throw "找不到可执行文件: $sourceCli" }
New-Item -ItemType Directory -Force -Path $installDir | Out-Null
Copy-Item -Force $sourceDaemon (Join-Path $installDir 'snw-agent-linkd.exe')
Copy-Item -Force $sourceCli (Join-Path $installDir 'snw-agent-link.exe')
Copy-Item -Force (Join-Path $PSScriptRoot 'snw-agent-linkd-wrapper.ps1') (Join-Path $installDir 'snw-agent-linkd-wrapper.ps1')
$wrapper = Join-Path $installDir 'snw-agent-linkd-wrapper.ps1'
$quoted = '"' + (Get-Command powershell.exe).Source + '" -NoProfile -ExecutionPolicy Bypass -File "' + $wrapper + '"'
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
  Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
  sc.exe delete $serviceName | Out-Null
}
New-Service -Name $serviceName -BinaryPathName $quoted -DisplayName 'snw-agent-linkd' -StartupType Automatic -Description 'Tailnet-only peer Agent gateway'
Start-Service -Name $serviceName
Write-Host "snw-agent-link 与 snw-agent-linkd 已安装到 $installDir；服务已启动: Get-Service $serviceName"
