$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'build.ps1')
if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
# EventLogTest reads docs/examples, so every test runs from the repo root.
Set-Location (Join-Path $PSScriptRoot '..')
foreach($t in 'SmokeTest','monitor.EventLogTest','monitor.DashboardServerTest','proxy.ForwardProxyServerTest'){
  Write-Host "== $t"
  & java -cp 'build/main;build/test' "com.demo.netguard.$t"
  if($LASTEXITCODE -ne 0){exit $LASTEXITCODE}
}
