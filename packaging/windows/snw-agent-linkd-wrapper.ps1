$ErrorActionPreference = 'Stop'
$binary = Join-Path $PSScriptRoot 'snw-agent-linkd.exe'
$dataDir = if ($env:SNW_AGENT_LINK_DATA_DIR) { $env:SNW_AGENT_LINK_DATA_DIR } else { Join-Path $env:ProgramData 'snw-agent-link' }
$tailscale = if ($env:TAILSCALE_BIN) {
  $env:TAILSCALE_BIN
} elseif (Test-Path (Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe')) {
  Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
} else {
  (Get-Command tailscale.exe).Source
}
$tailscaleIp = if ($env:TAILSCALE_BIND_IP) { $env:TAILSCALE_BIND_IP } else { (& $tailscale ip -1 | Select-Object -First 1).Trim() }
if ([string]::IsNullOrWhiteSpace($tailscaleIp)) { throw '未检测到 Tailscale 地址，请设置 TAILSCALE_BIND_IP' }
& $binary '--data-dir' $dataDir '--tailscale-bind-ip' $tailscaleIp '--gateway-port' '7443'
exit $LASTEXITCODE
