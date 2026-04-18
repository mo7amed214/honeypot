$ErrorActionPreference = "Stop"

$transcriptDir = "C:\ProgramData\Honeypot\PowerShellTranscripts"
$wazuhConfig = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$backupSuffix = Get-Date -Format "yyyyMMdd-HHmmss"

New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockInvocationLogging" -Value 1 -PropertyType DWord -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "EnableModuleLogging" -Value 1 -PropertyType DWord -Force | Out-Null
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -Name "*" -Value "*" -PropertyType String -Force | Out-Null

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableInvocationHeader" -Value 1 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Value $transcriptDir -PropertyType String -Force | Out-Null

if (Test-Path $wazuhConfig) {
    Copy-Item $wazuhConfig "$wazuhConfig.pre-codex-$backupSuffix" -Force

    [xml]$xml = Get-Content $wazuhConfig
    $ossec = $xml.ossec_config

    $existing = @($ossec.localfile | Where-Object { $_.location -eq "Microsoft-Windows-PowerShell/Operational" })
    if ($existing.Count -eq 0) {
        $localfile = $xml.CreateElement("localfile")
        $location = $xml.CreateElement("location")
        $location.InnerText = "Microsoft-Windows-PowerShell/Operational"
        $format = $xml.CreateElement("log_format")
        $format.InnerText = "eventchannel"
        [void]$localfile.AppendChild($location)
        [void]$localfile.AppendChild($format)
        [void]$ossec.AppendChild($localfile)
        $xml.Save($wazuhConfig)
    }
}

Restart-Service WazuhSvc -Force
Write-Output "PowerShell logging and Wazuh collection configured."
Write-Output "Transcript directory: $transcriptDir"
Write-Output "Wazuh config backup suffix: $backupSuffix"
