param(
    [string]$VmName = "EWS-WIN11",
    [string]$OutputPath = ".\vagrant\boxes\ews-win11.box",
    [string]$VBoxManagePath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $VBoxManagePath)) {
    throw "VBoxManage not found at $VBoxManagePath"
}

$resolvedOutput = [System.IO.Path]::GetFullPath($OutputPath)
$outputDir = Split-Path -Parent $resolvedOutput
$stagingRoot = Join-Path $outputDir "ews-win11-box-staging"

New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
if (Test-Path $stagingRoot) {
    Remove-Item -Recurse -Force $stagingRoot
}
New-Item -ItemType Directory -Force -Path $stagingRoot | Out-Null

$ovfPath = Join-Path $stagingRoot "box.ovf"

Write-Host "Exporting VM '$VmName' with VBoxManage..."
& $VBoxManagePath export $VmName --output $ovfPath

$metadata = @{
    provider = "virtualbox"
} | ConvertTo-Json -Compress
$metadata | Set-Content -Path (Join-Path $stagingRoot "metadata.json") -Encoding ascii

@'
Vagrant.configure("2") do |config|
  config.vm.communicator = "winrm"
  config.winrm.username = ENV.fetch("HONEYPOT_EWS_WINRM_USER", "vagrant")
  config.winrm.password = ENV.fetch("HONEYPOT_EWS_WINRM_PASSWORD", "vagrant")
  config.vm.guest = :windows
end
'@ | Set-Content -Path (Join-Path $stagingRoot "Vagrantfile") -Encoding ascii

if (Test-Path $resolvedOutput) {
    Remove-Item -Force $resolvedOutput
}

Write-Host "Packing box archive '$resolvedOutput'..."
tar.exe -a -c -f $resolvedOutput -C $stagingRoot .

Remove-Item -Recurse -Force $stagingRoot

Write-Host ""
Write-Host "Package complete."
Write-Host "Register it on Linux with:"
Write-Host "  bash scripts/register_ews_windows_box.sh"
