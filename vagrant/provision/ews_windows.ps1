param(
    [string]$UserName = "john",
    [string]$UserPassword = "Cisco"
)

$ErrorActionPreference = "Stop"

function Ensure-LocalUser {
    param(
        [string]$Name,
        [string]$Password
    )

    $existing = Get-LocalUser -Name $Name -ErrorAction SilentlyContinue
    if (-not $existing) {
        $secure = ConvertTo-SecureString $Password -AsPlainText -Force
        New-LocalUser -Name $Name -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
    } else {
        net user $Name $Password | Out-Null
    }

    try {
        Add-LocalGroupMember -Group "Administrators" -Member $Name -ErrorAction Stop
    } catch {
    }
}

function Ensure-OpenSSH {
    $sshd = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $sshd) {
        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
    }

    Set-Service -Name sshd -StartupType Automatic
    Start-Service sshd

    $configPath = "C:\ProgramData\ssh\sshd_config"
    if (Test-Path $configPath) {
        $cfg = Get-Content $configPath -Raw
        if ($cfg -notmatch "(?m)^\s*PasswordAuthentication\s+yes\s*$") {
            Add-Content -Path $configPath -Value "`r`nPasswordAuthentication yes"
        }
        Restart-Service sshd
    }

    $fwRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
    if ($fwRule) {
        Enable-NetFirewallRule -Name "OpenSSH-Server-In-TCP" | Out-Null
    }
}

function Copy-RepoArtifacts {
    param(
        [string]$Name
    )

    $downloads = "C:\Users\$Name\Downloads"
    $diagDownloads = "C:\Users\$Name\AppData\Local\Microsoft\Diagnosis\Downloads"
    New-Item -ItemType Directory -Force -Path $downloads | Out-Null
    New-Item -ItemType Directory -Force -Path $diagDownloads | Out-Null

    $repoRoot = "C:\vagrant\honeypot"
    $assetRoot = Join-Path $repoRoot "vagrant\assets\ews"
    $telemetryScript = Join-Path $repoRoot "scripts\windows\enable_ews_host_telemetry.ps1"

    if (Test-Path $telemetryScript) {
        Copy-Item -Force $telemetryScript (Join-Path $downloads "enable_ews_host_telemetry.ps1")
    }

    if (Test-Path $assetRoot) {
        Get-ChildItem -Path $assetRoot -File -ErrorAction SilentlyContinue | ForEach-Object {
            Copy-Item -Force $_.FullName (Join-Path $downloads $_.Name)
        }
    }
}

function Install-OptionalArtifacts {
    param(
        [string]$Name
    )

    $downloads = "C:\Users\$Name\Downloads"

    $pythonInstaller = Get-ChildItem -Path $downloads -Filter "python-3.11*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($pythonInstaller) {
        Start-Process -FilePath $pythonInstaller.FullName -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_launcher=1" -Wait -NoNewWindow
    }

    $nmapInstaller = Get-ChildItem -Path $downloads -Filter "nmap-*-setup.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($nmapInstaller) {
        Start-Process -FilePath $nmapInstaller.FullName -ArgumentList "/S" -Wait -NoNewWindow
    }

    $wazuhInstaller = Get-ChildItem -Path $downloads -Filter "wazuh-agent-*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($wazuhInstaller -and $env:HONEYPOT_EWS_WAZUH_MANAGER) {
        Start-Process msiexec.exe -ArgumentList "/i `"$($wazuhInstaller.FullName)`" /qn WAZUH_MANAGER=$($env:HONEYPOT_EWS_WAZUH_MANAGER) WAZUH_AGENT_NAME=EWS-WIN11" -Wait -NoNewWindow
    }
}

function Get-Ipv4AddressString {
    param(
        $Config
    )

    if ($null -eq $Config.IPv4Address) {
        return $null
    }

    if ($Config.IPv4Address -is [System.Array]) {
        return ($Config.IPv4Address | Select-Object -First 1).IPAddress
    }

    return $Config.IPv4Address.IPAddress
}

function Ensure-StaticIpv4 {
    param(
        [int]$InterfaceIndex,
        [string]$IpAddress,
        [int]$PrefixLength = 24
    )

    if ([string]::IsNullOrWhiteSpace($IpAddress)) {
        return
    }

    $current = Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -eq $IpAddress -and $_.PrefixLength -eq $PrefixLength }
    if ($current) {
        return
    }

    Get-NetRoute -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -eq "0.0.0.0/0" } |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

    Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne "127.0.0.1" } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -Dhcp Disabled -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $InterfaceIndex -IPAddress $IpAddress -PrefixLength $PrefixLength -AddressFamily IPv4 | Out-Null
}

function Ensure-DhcpIpv4 {
    param(
        [int]$InterfaceIndex,
        [string]$InterfaceAlias
    )

    Set-NetIPInterface -InterfaceIndex $InterfaceIndex -Dhcp Enabled -ErrorAction SilentlyContinue

    Get-NetIPAddress -InterfaceIndex $InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -ne "127.0.0.1" } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue

    if (-not [string]::IsNullOrWhiteSpace($InterfaceAlias)) {
        Start-Process -FilePath "netsh.exe" -ArgumentList "interface ip set address name=`"$InterfaceAlias`" source=dhcp" -WindowStyle Hidden -Wait -ErrorAction SilentlyContinue
    }
}

function Configure-LabNetwork {
    $serviceIp = $env:HONEYPOT_EWS_SERVICE_IP
    $integrationIp = $env:HONEYPOT_EWS_INTEGRATION_IP
    $integrationEnabled = $env:HONEYPOT_ENABLE_INTEGRATION_NIC -eq "1"

    if ([string]::IsNullOrWhiteSpace($serviceIp)) {
        return
    }

    $configs = Get-NetIPConfiguration |
        Where-Object { $_.NetAdapter.Status -eq "Up" -and $_.NetAdapter.HardwareInterface } |
        Sort-Object InterfaceIndex

    if (-not $configs) {
        return
    }

    $primary = $configs | Where-Object { $_.IPv4DefaultGateway -ne $null } | Select-Object -First 1
    if ($null -ne $primary) {
        Ensure-DhcpIpv4 -InterfaceIndex $primary.InterfaceIndex -InterfaceAlias $primary.InterfaceAlias
    }

    $candidates = @($configs | Where-Object {
        if ($null -eq $primary) { return $true }
        $_.InterfaceIndex -ne $primary.InterfaceIndex
    })

    if ($candidates.Count -lt 1) {
        return
    }

    $servicePrefix = ($serviceIp -split '\.')[0..2] -join '.'
    $integrationPrefix = if (-not [string]::IsNullOrWhiteSpace($integrationIp)) { ($integrationIp -split '\.')[0..2] -join '.' } else { "" }

    $serviceConfig = $candidates | Where-Object {
        $ip = Get-Ipv4AddressString $_
        $null -ne $ip -and $ip.StartsWith("$servicePrefix.")
    } | Select-Object -First 1

    if ($null -eq $serviceConfig) {
        $serviceConfig = $candidates | Where-Object {
            $ip = Get-Ipv4AddressString $_
            $null -ne $ip -and -not $ip.StartsWith("169.254.")
        } | Select-Object -First 1
    }

    if ($null -eq $serviceConfig) {
        $serviceConfig = $candidates | Select-Object -First 1
    }

    Ensure-StaticIpv4 -InterfaceIndex $serviceConfig.InterfaceIndex -IpAddress $serviceIp

    if (-not $integrationEnabled -or [string]::IsNullOrWhiteSpace($integrationIp)) {
        return
    }

    $integrationConfig = $candidates | Where-Object { $_.InterfaceIndex -ne $serviceConfig.InterfaceIndex } | ForEach-Object { $_ } | Select-Object -First 1
    if ($null -eq $integrationConfig) {
        return
    }

    Ensure-StaticIpv4 -InterfaceIndex $integrationConfig.InterfaceIndex -IpAddress $integrationIp
}

Ensure-LocalUser -Name $UserName -Password $UserPassword
Ensure-OpenSSH
Configure-LabNetwork
Copy-RepoArtifacts -Name $UserName
Install-OptionalArtifacts -Name $UserName
