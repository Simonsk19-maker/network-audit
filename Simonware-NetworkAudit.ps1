<#
    Simonware Network Audit
    ------------------------
    Run from your own PC or laptop. Finds the Windows devices on a network and reports:
      - Windows version, build, and whether Microsoft still supports it
      - Chrome, Edge, Firefox, Brave and Opera versions, and whether they're up to date
      - Hardware: make, model, serial number, CPU, RAM, disk size and free space
      - Security: antivirus, firewall, BitLocker encryption, TPM, Secure Boot, local admins
      - Windows Update: last update date and whether a restart is pending
      - Network: IP and MAC address, wired or Wi-Fi, and whether Remote Desktop is on

    Results: a table on screen, plus a spreadsheet (CSV) and a web-page report.

    Works on both kinds of network:
      - Domain networks: use a domain admin account. Devices can come from Active Directory.
      - Networks without a domain (workgroups): use a local admin account that has the
        same username and password on each PC. Run option 5 ("Prepare this PC") once on
        each PC first, because Windows blocks remote checks by default.

    Devices are checked with PowerShell Remoting (WinRM) if it's on, otherwise WMI.
#>

# =====================================================================
#  SETTINGS
# =====================================================================

# Where each browser installs. Paths: under Program Files. UserPath: under each user's AppData\Local.
$SwBrowsers = @(
    @{ Name = 'Chrome';  Paths = @('Google\Chrome\Application\chrome.exe');              UserPath = 'Google\Chrome\Application\chrome.exe' }
    @{ Name = 'Edge';    Paths = @('Microsoft\Edge\Application\msedge.exe');             UserPath = $null }
    @{ Name = 'Firefox'; Paths = @('Mozilla Firefox\firefox.exe');                       UserPath = 'Mozilla Firefox\firefox.exe' }
    @{ Name = 'Brave';   Paths = @('BraveSoftware\Brave-Browser\Application\brave.exe'); UserPath = 'BraveSoftware\Brave-Browser\Application\brave.exe' }
    @{ Name = 'Opera';   Paths = @();                                                    UserPath = 'Programs\Opera\opera.exe' }
)

# Windows build number -> version name and end of support for Home/Pro.
# Enterprise/Education editions of Windows 11 get an extra 12 months.
# Check Microsoft's lifecycle pages now and then, and add new versions here.
$SwWindowsLifecycle = @{
    '19045' = @{ Name = 'Windows 10 22H2'; End = '2025-10-14' }
    '22000' = @{ Name = 'Windows 11 21H2'; End = '2023-10-10' }
    '22621' = @{ Name = 'Windows 11 22H2'; End = '2024-10-08' }
    '22631' = @{ Name = 'Windows 11 23H2'; End = '2025-11-11' }
    '26100' = @{ Name = 'Windows 11 24H2'; End = '2026-10-13' }
    '26200' = @{ Name = 'Windows 11 25H2'; End = '2027-10-12' }
}

$SwThrottle = 16   # how many devices to check at the same time

# =====================================================================
#  WHAT RUNS ON EACH DEVICE (through PowerShell Remoting)
# =====================================================================

$SwCollect = {
    param($Browsers)
    # Each piece is wrapped so one failure can't stop the whole check.
    function TryGet($block) { try { & $block } catch { $null } }

    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $bios = TryGet { Get-CimInstance Win32_BIOS }
    $cpu  = TryGet { Get-CimInstance Win32_Processor | Select-Object -First 1 }
    $sys  = TryGet { Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($os.SystemDrive)'" }
    $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) | Where-Object { $_ } | Select-Object -Unique
    $profiles = @(Get-CimInstance Win32_UserProfile -Filter 'Special=False' | ForEach-Object { $_.LocalPath })

    # ---- Security ----
    $av = TryGet { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop }
    $avName = (@($av) | ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
    $avOn = ''
    if ($av) {
        $avOn = 'Off'
        foreach ($p in @($av)) {
            $hex = ('{0:x6}' -f [int]$p.productState)
            $enabled   = [Convert]::ToInt32($hex.Substring(2, 2), 16)  # 10/11 = on
            $outOfDate = [Convert]::ToInt32($hex.Substring(4, 2), 16)  # 00 = up to date
            if ($enabled -ge 16) { $avOn = if ($outOfDate -ne 0) { 'On (out of date)' } else { 'On' }; break }
        }
    }
    $fw = TryGet { Get-NetFirewallProfile -ErrorAction Stop }
    $fwState = if ($fw) { $off = @($fw | Where-Object { -not $_.Enabled }).Name; if ($off) { "Off: $($off -join ',')" } else { 'On' } } else { '' }
    $enc = TryGet { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$($os.SystemDrive)'" -ErrorAction Stop }
    $encState = if ($enc) { switch ([int]$enc.ProtectionStatus) { 1 { 'On' } 0 { 'Off' } default { 'Unknown' } } } else { '' }
    $tpm = TryGet { Get-CimInstance -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop }
    $tpmState = if ($tpm) { if ($tpm.IsEnabled_InitialValue) { 'Yes' } else { 'Present, off' } } else { 'None' }
    $secureBoot = TryGet { if (Confirm-SecureBootUEFI) { 'On' } else { 'Off' } }
    if (-not $secureBoot) { $secureBoot = 'N/A (older BIOS)' }
    $admins = TryGet { (Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop | ForEach-Object { ($_.Name -split '\\')[-1] }) -join ', ' }

    # ---- Windows Update ----
    $lastHotfix = TryGet { Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1 }
    $lastUpdate = if ($lastHotfix) { $lastHotfix.InstalledOn.ToString('yyyy-MM-dd') } else { '' }
    $rebootPending = TryGet {
        $pending = $false
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending = $true }
        if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending = $true }
        if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations) { $pending = $true }
        $pending
    }
    $rebootPending = if ($rebootPending) { 'Yes' } else { 'No' }

    # ---- Network ----
    $nic = TryGet { Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Select-Object -First 1 }
    $ip  = if ($nic) { (@($nic.IPAddress) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ', ' } else { '' }
    $mac = if ($nic) { $nic.MACAddress } else { '' }
    $adapter = TryGet { Get-CimInstance Win32_NetworkAdapter -Filter 'NetConnectionStatus=2' | Where-Object { $_.PhysicalAdapter } | Select-Object -First 1 }
    $conn = if ($adapter) { if ("$($adapter.Name) $($adapter.NetConnectionID)" -match 'Wi-?Fi|Wireless|WLAN|802\.11') { 'Wi-Fi' } else { 'Wired' } } else { '' }
    $rdp = TryGet { if ((Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -ErrorAction Stop).fDenyTSConnections -eq 0) { 'On' } else { 'Off' } }

    $info = [ordered]@{
        ComputerName  = $env:COMPUTERNAME
        OS            = $os.Caption -replace '^Microsoft ', ''
        Version       = if ($cv.DisplayVersion) { $cv.DisplayVersion } else { $cv.ReleaseId }
        Build         = "$($cv.CurrentBuild).$($cv.UBR)"
        LoggedOnUser  = $cs.UserName
        LastRestart   = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
        Make          = $cs.Manufacturer
        Model         = $cs.Model
        Serial        = if ($bios) { $bios.SerialNumber } else { '' }
        Cpu           = if ($cpu) { ($cpu.Name -replace '\s+', ' ').Trim() } else { '' }
        RamGB         = [math]::Round($cs.TotalPhysicalMemory / 1GB)
        DiskGB        = if ($sys) { [math]::Round($sys.Size / 1GB) } else { '' }
        DiskFreeGB    = if ($sys) { [math]::Round($sys.FreeSpace / 1GB) } else { '' }
        Antivirus     = $avName
        AvOn          = $avOn
        Firewall      = $fwState
        Encrypted     = $encState
        Tpm           = $tpmState
        SecureBoot    = $secureBoot
        LocalAdmins   = $admins
        LastUpdate    = $lastUpdate
        RebootPending = $rebootPending
        Ip            = $ip
        Mac           = $mac
        Connection    = $conn
        Rdp           = $rdp
    }
    foreach ($browser in $Browsers) {
        $files = @()
        foreach ($root in $roots) { foreach ($path in $browser.Paths) { $files += Join-Path $root $path } }
        if ($browser.UserPath) { foreach ($profile in $profiles) { $files += Join-Path $profile ('AppData\Local\' + $browser.UserPath) } }
        $versions = $files | Where-Object { Test-Path -LiteralPath $_ } |
            ForEach-Object { (Get-Item -LiteralPath $_).VersionInfo.ProductVersion } | Where-Object { $_ } | Sort-Object -Unique
        $info[$browser.Name] = ($versions -join ', ')
    }
    [pscustomobject]$info
}

# =====================================================================
#  CHECKS ONE DEVICE (runs in parallel on your PC)
# =====================================================================

$SwWorker = {
    param($Target, $Credential, $Browsers, $CollectText)

    function Get-ViaWmi {
        # Backup method when PowerShell Remoting isn't turned on: WMI over DCOM.
        param($Name, $Credential, $Browsers)
        $options = @{ ComputerName = $Name; SessionOption = (New-CimSessionOption -Protocol Dcom); OperationTimeoutSec = 30; ErrorAction = 'Stop' }
        if ($Credential) { $options.Credential = $Credential }
        $session = New-CimSession @options
        try {
            function TryGet($block) { try { & $block } catch { $null } }
            $os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem -ErrorAction Stop
            $cs = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem
            $bios = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_BIOS }
            $cpu  = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_Processor | Select-Object -First 1 }
            $drive = $os.SystemDrive
            $sys  = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_LogicalDisk -Filter "DeviceID='$drive'" }
            $regArgs = @{ hDefKey = [uint32]2147483650; sSubKeyName = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion' }
            $display = (Invoke-CimMethod -CimSession $session -Namespace root/default -ClassName StdRegProv -MethodName GetStringValue -Arguments ($regArgs + @{ sValueName = 'DisplayVersion' })).sValue
            $ubr     = (Invoke-CimMethod -CimSession $session -Namespace root/default -ClassName StdRegProv -MethodName GetDWORDValue  -Arguments ($regArgs + @{ sValueName = 'UBR' })).uValue
            $roots    = @("$drive\Program Files", "$drive\Program Files (x86)")
            $profiles = @(Get-CimInstance -CimSession $session -ClassName Win32_UserProfile -Filter 'Special=False' | ForEach-Object { $_.LocalPath })

            # Read a registry DWORD/string through WMI (for firewall + RDP)
            function RegDword($hive, $key, $value) {
                (Invoke-CimMethod -CimSession $session -Namespace root/default -ClassName StdRegProv -MethodName GetDWORDValue -Arguments @{ hDefKey = [uint32]$hive; sSubKeyName = $key; sValueName = $value }).uValue
            }

            # Security (best effort over WMI)
            $av = TryGet { Get-CimInstance -CimSession $session -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop }
            $avName = (@($av) | ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            $avOn = ''
            if ($av) {
                $avOn = 'Off'
                foreach ($p in @($av)) {
                    $hex = ('{0:x6}' -f [int]$p.productState)
                    if ([Convert]::ToInt32($hex.Substring(2, 2), 16) -ge 16) {
                        $avOn = if ([Convert]::ToInt32($hex.Substring(4, 2), 16) -ne 0) { 'On (out of date)' } else { 'On' }; break
                    }
                }
            }
            $fwOn = TryGet {
                $p = 'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy'
                $vals = 'DomainProfile', 'StandardProfile', 'PublicProfile' | ForEach-Object { RegDword 2147483650 "$p\$_" 'EnableFirewall' }
                if (($vals | Where-Object { $_ -eq 0 }).Count) { 'Some off' } else { 'On' }
            }
            $enc = TryGet { Get-CimInstance -CimSession $session -Namespace root/cimv2/Security/MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction Stop }
            $encState = if ($enc) { switch ([int]$enc.ProtectionStatus) { 1 { 'On' } 0 { 'Off' } default { 'Unknown' } } } else { '' }
            $tpm = TryGet { Get-CimInstance -CimSession $session -Namespace root/cimv2/Security/MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop }
            $tpmState = if ($tpm) { if ($tpm.IsEnabled_InitialValue) { 'Yes' } else { 'Present, off' } } else { 'None' }
            $lastHotfix = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_QuickFixEngineering | Where-Object InstalledOn | Sort-Object { [datetime]$_.InstalledOn } -Descending | Select-Object -First 1 }
            $lastUpdate = if ($lastHotfix -and $lastHotfix.InstalledOn) { ([datetime]$lastHotfix.InstalledOn).ToString('yyyy-MM-dd') } else { '' }
            $nic = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' | Select-Object -First 1 }
            $ip  = if ($nic) { (@($nic.IPAddress) | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+$' }) -join ', ' } else { '' }
            $mac = if ($nic) { $nic.MACAddress } else { '' }
            $adapter = TryGet { Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapter -Filter 'NetConnectionStatus=2' | Where-Object { $_.PhysicalAdapter } | Select-Object -First 1 }
            $conn = if ($adapter) { if ("$($adapter.Name) $($adapter.NetConnectionID)" -match 'Wi-?Fi|Wireless|WLAN|802\.11') { 'Wi-Fi' } else { 'Wired' } } else { '' }
            $rdp = TryGet { if ((RegDword 2147483650 'System\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections') -eq 0) { 'On' } else { 'Off' } }

            $info = [ordered]@{
                ComputerName  = $cs.Name
                OS            = $os.Caption -replace '^Microsoft ', ''
                Version       = $display
                Build         = "$($os.BuildNumber).$ubr"
                LoggedOnUser  = $cs.UserName
                LastRestart   = $os.LastBootUpTime.ToString('yyyy-MM-dd HH:mm')
                Make          = $cs.Manufacturer
                Model         = $cs.Model
                Serial        = if ($bios) { $bios.SerialNumber } else { '' }
                Cpu           = if ($cpu) { ($cpu.Name -replace '\s+', ' ').Trim() } else { '' }
                RamGB         = [math]::Round($cs.TotalPhysicalMemory / 1GB)
                DiskGB        = if ($sys) { [math]::Round($sys.Size / 1GB) } else { '' }
                DiskFreeGB    = if ($sys) { [math]::Round($sys.FreeSpace / 1GB) } else { '' }
                Antivirus     = $avName
                AvOn          = $avOn
                Firewall      = $fwOn
                Encrypted     = $encState
                Tpm           = $tpmState
                SecureBoot    = ''   # not available over WMI
                LocalAdmins   = ''   # not available over WMI
                LastUpdate    = $lastUpdate
                RebootPending = ''   # not available over WMI
                Ip            = $ip
                Mac           = $mac
                Connection    = $conn
                Rdp           = $rdp
            }
            foreach ($browser in $Browsers) {
                $files = @()
                foreach ($root in $roots) { foreach ($path in $browser.Paths) { $files += "$root\$path" } }
                if ($browser.UserPath) { foreach ($profile in $profiles) { $files += "$profile\AppData\Local\$($browser.UserPath)" } }
                $versions = foreach ($file in $files) {
                    $wql = $file.Replace('\', '\\').Replace("'", "\'")
                    (Get-CimInstance -CimSession $session -ClassName CIM_DataFile -Filter "Name='$wql'" -ErrorAction SilentlyContinue).Version
                }
                $info[$browser.Name] = (($versions | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
            }
            [pscustomobject]$info
        }
        finally { Remove-CimSession $session }
    }

    $row = [ordered]@{ Device = $Target.Name; Address = $Target.Address; Status = 'OK'; Method = ''; Note = ''; Data = $null }

    # Use the device's name if we only have its IP address (needed for PowerShell Remoting on a domain)
    $name = $Target.Name
    if ($name -match '^\d{1,3}(\.\d{1,3}){3}$') {
        try { $name = [Net.Dns]::GetHostEntry($name).HostName; $row.Device = $name } catch { }
    }

    try {
        if ($Target.IsLocal) {
            $row.Data = & ([scriptblock]::Create($CollectText)) -Browsers $Browsers
            $row.Method = 'This PC'
        } else {
            $remote = @{
                ComputerName  = $name
                ScriptBlock   = [scriptblock]::Create($CollectText)
                ArgumentList  = @(, $Browsers)
                SessionOption = (New-PSSessionOption -OpenTimeout 8000 -OperationTimeout 90000)
                ErrorAction   = 'Stop'
            }
            if ($Credential) { $remote.Credential = $Credential }
            $row.Data = Invoke-Command @remote
            $row.Method = 'PowerShell Remoting'
        }
    }
    catch {
        $remotingError = $_.Exception.Message
        try {
            $address = if ($Target.Address) { $Target.Address } else { $name }
            $row.Data = Get-ViaWmi -Name $address -Credential $Credential -Browsers $Browsers
            $row.Method = 'WMI'
        }
        catch {
            $row.Status = 'Not checked'
            $message = "$($_.Exception.Message) $remotingError"
            $row.Note = switch -Regex ($message) {
                'Access is denied|Access denied|0x80070005' { 'Access denied: use an admin account for this device. No domain? Run option 5 on it, or use its built-in Administrator account'; break }
                'RPC server is unavailable|0x800706BA'      { 'No answer: not Windows, switched off, or remote checks blocked. Run option 5 on it'; break }
                'TrustedHosts'                              { 'Use the device name instead of its IP, or allow WMI through its firewall'; break }
                default                                     { ($_.Exception.Message -split "`n")[0].Trim() }
            }
            if ($Target.AdOs) { $row.Note += " (Active Directory says: $($Target.AdOs))" }
        }
    }
    [pscustomobject]$row
}

# =====================================================================
#  HELPERS (on your PC)
# =====================================================================

function Write-SwGood { param([string]$Text) Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-SwWarn { param([string]$Text) Write-Host "  [!]  $Text" -ForegroundColor Yellow }

function Get-SwIpRange {
    # "192.168.1.0/24" -> every usable address in that range
    param([string]$Cidr)
    if ($Cidr -notmatch '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') { throw "Use the form 192.168.1.0/24" }
    $bits = [int]$Matches[2]
    if ($bits -lt 22 -or $bits -gt 30) { throw 'Please use a range between /22 (1,022 addresses) and /30.' }
    $bytes = [Net.IPAddress]::Parse($Matches[1]).GetAddressBytes()
    [Array]::Reverse($bytes)
    $start = [uint64][BitConverter]::ToUInt32($bytes, 0)
    $all   = [uint64]4294967295   # 255.255.255.255
    $mask  = ($all -shl (32 - $bits)) -band $all
    $network = $start -band $mask
    $size = [uint64][math]::Pow(2, 32 - $bits)
    for ($i = [uint64]1; $i -lt $size - 1; $i++) {
        $b = [BitConverter]::GetBytes([uint32]($network + $i))
        [Array]::Reverse($b)
        ([Net.IPAddress]::new($b)).ToString()
    }
}

function Get-SwLocalSubnet {
    $config = Get-NetIPConfiguration -ErrorAction SilentlyContinue |
        Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' } | Select-Object -First 1
    if (-not $config) { return $null }
    $address = $config.IPv4Address | Select-Object -First 1
    $prefix = [math]::Max([int]$address.PrefixLength, 22)
    "$($address.IPAddress)/$prefix"
}

function Find-SwLiveDevices {
    # A device counts as "there" if it answers a ping or one of the usual Windows ports.
    # (Windows blocks ping by default, so the port check matters.)
    param([string[]]$Addresses, [int]$TimeoutMs = 800)
    $ports = 445, 135, 5985, 3389
    $live = [System.Collections.Generic.List[string]]::new()
    $batchSize = 64
    for ($i = 0; $i -lt $Addresses.Count; $i += $batchSize) {
        Write-Progress -Activity 'Looking for devices' -Status "$i of $($Addresses.Count) addresses" -PercentComplete ($i / $Addresses.Count * 100)
        $batch = $Addresses[$i..([math]::Min($i + $batchSize, $Addresses.Count) - 1)]
        $probes = foreach ($address in $batch) {
            $ping = [Net.NetworkInformation.Ping]::new()
            $pingTask = try { $ping.SendPingAsync($address, $TimeoutMs) } catch { $null }
            $tcp = foreach ($port in $ports) {
                $client = [Net.Sockets.TcpClient]::new()
                [pscustomobject]@{ Client = $client; Task = $client.ConnectAsync($address, $port) }
            }
            [pscustomobject]@{ Address = $address; Ping = $ping; PingTask = $pingTask; Tcp = $tcp }
        }
        Start-Sleep -Milliseconds ($TimeoutMs + 150)
        foreach ($probe in $probes) {
            $alive = $probe.PingTask -and $probe.PingTask.Status -eq 'RanToCompletion' -and $probe.PingTask.Result.Status -eq 'Success'
            foreach ($t in $probe.Tcp) {
                if ($t.Task.Status -eq 'RanToCompletion' -and $t.Client.Connected) { $alive = $true }
                try { $t.Client.Dispose() } catch { }
            }
            try { $probe.Ping.Dispose() } catch { }
            if ($alive) { $live.Add($probe.Address) }
        }
    }
    Write-Progress -Activity 'Looking for devices' -Completed
    $live
}

function Get-SwAdComputers {
    $searcher = [adsisearcher]'(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $searcher.PageSize = 500
    'dnshostname', 'name', 'operatingsystem' | ForEach-Object { [void]$searcher.PropertiesToLoad.Add($_) }
    foreach ($entry in $searcher.FindAll()) {
        $p = $entry.Properties
        $name = if ($p['dnshostname'].Count) { $p['dnshostname'][0] } else { $p['name'][0] }
        [pscustomobject]@{ Name = $name; Address = $null; AdOs = ($p['operatingsystem'] | Select-Object -First 1); IsLocal = $false }
    }
}

function Get-SwLatestBrowsers {
    # Latest stable versions, straight from Google, Microsoft and Mozilla.
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $latest = @{}
    try {
        $latest.Chrome = (Invoke-RestMethod 'https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions' -TimeoutSec 15).versions[0].version
    } catch { }
    try {
        $edge = Invoke-RestMethod 'https://edgeupdates.microsoft.com/api/products' -TimeoutSec 15
        $latest.Edge = ($edge | Where-Object Product -eq 'Stable').Releases |
            Where-Object { $_.Platform -eq 'Windows' -and $_.Architecture -eq 'x64' } |
            Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1 -ExpandProperty ProductVersion
    } catch { }
    try {
        $latest.Firefox = (Invoke-RestMethod 'https://product-details.mozilla.org/1.0/firefox_versions.json' -TimeoutSec 15).LATEST_FIREFOX_VERSION
    } catch { }
    $latest
}

function ConvertTo-SwVersion {
    param([string]$Text)
    if ($Text -match '^\d+(\.\d+){1,3}') { try { return [version]$Matches[0] } catch { } }
    return $null
}

function Get-SwBrowserStatus {
    # Compares the newest copy on the device with the latest release.
    param([string]$Installed, [string]$Latest)
    if (-not $Installed) { return '' }
    if ($Installed -match 'esr') { return 'ESR: check' }   # Firefox long-term business version
    if (-not $Latest) { return '' }
    $newest = $Installed -split ',\s*' | ForEach-Object { ConvertTo-SwVersion $_ } | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
    $target = ConvertTo-SwVersion $Latest
    if (-not $newest -or -not $target) { return '' }
    if ($newest -ge $target) { 'Up to date' } else { 'Update due' }
}

function Get-SwWindowsSupport {
    param([string]$OS, [string]$Build)
    if (-not $Build) { return '' }
    if ($OS -match 'Server') { return 'Server: check lifecycle' }
    if ($OS -match 'LTSC|LTSB') { return 'LTSC: check lifecycle' }
    $number = ($Build -split '\.')[0]
    $entry = $SwWindowsLifecycle[$number]
    if (-not $entry) {
        if ([int]$number -lt 19045) { return 'Out of support' }
        return 'Unknown: check'
    }
    $end = [datetime]$entry.End
    if ($OS -match 'Windows 11' -and $OS -match 'Enterprise|Education') { $end = $end.AddYears(1) }
    $today = (Get-Date).Date
    if ($end -lt $today) { 'Out of support' }
    elseif ($end -lt $today.AddDays(90)) { "Support ends $($end.ToString('dd MMM yyyy'))" }
    else { "Supported until $($end.ToString('MMM yyyy'))" }
}

function Enable-SwAuditAccess {
    # Run ON a PC you want to audit (mainly for networks without a domain).
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) { Write-SwWarn 'Please open PowerShell as Administrator on this PC and run it again.'; return }

    Write-Host "`n  Preparing $env:COMPUTERNAME so the Network Audit can check it..." -ForegroundColor Cyan

    # 1. PowerShell Remoting (also opens its firewall rule for the local network)
    try { Enable-PSRemoting -SkipNetworkProfileCheck -Force -ErrorAction Stop | Out-Null; Write-SwGood 'PowerShell Remoting turned on.' }
    catch { Write-SwWarn "PowerShell Remoting: $($_.Exception.Message)" }

    # 2. WMI through the firewall (the backup method). Group name works on every Windows language.
    try { Enable-NetFirewallRule -Group '@FirewallAPI.dll,-34251' -ErrorAction Stop; Write-SwGood 'WMI allowed through the firewall.' }
    catch { Write-SwWarn "WMI firewall rule: $($_.Exception.Message)" }

    # 3. Local admin accounts over the network (only needed without a domain)
    $onDomain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if (-not $onDomain) {
        Write-Host ''
        Write-Host '  On networks without a domain, Windows only lets the built-in "Administrator"' -ForegroundColor Gray
        Write-Host '  account check a PC remotely. To use a different local admin account, this' -ForegroundColor Gray
        Write-Host '  setting must be turned on. It makes remote admin logins more powerful, so' -ForegroundColor Gray
        Write-Host '  only do it on networks you manage, with strong admin passwords.' -ForegroundColor Gray
        if ((Read-Host '  Allow other local admin accounts to check this PC? [y/N]').Trim().ToLower() -in @('y', 'yes')) {
            $key = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            New-ItemProperty -Path $key -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null
            Write-SwGood 'Other local admin accounts can now check this PC.'
        }
    }

    Write-Host ''
    Write-SwGood "$env:COMPUTERNAME is ready. Admin accounts on this PC:"
    Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | ForEach-Object { Write-Host "       $($_.Name)" }
    Write-Host '  Tip: use an admin account with the same username and password on every PC.' -ForegroundColor Gray
}

function Show-SwConsoleResults {
    # The list on screen: one line per device, then a coloured "needs attention" list.
    param($Rows)
    $tag = {
        param($version, $status)
        if (-not $version) { return '-' }
        $newest = (($version -split ',\s*')[-1] -split '\.')[0]   # main version number, e.g. 156
        switch -Regex ($status) {
            '^Up to date' { "$newest OK" }
            '^Update due' { "$newest OLD" }
            '^ESR'        { "$newest ESR" }
            default       { $newest }
        }
    }
    $Rows | ForEach-Object {
        [pscustomobject][ordered]@{
            Device  = $_.Device
            Windows = if ($_.Windows) { (($_.Windows -replace '^Windows ', 'Win ') + " $($_.Version)").Trim() } else { $_.Status }
            Support = $_.Support -replace '^Supported until ', 'OK until ' -replace '^Support ends ', 'Ends '
            Chrome  = & $tag $_.Chrome  $_.'Chrome status'
            Edge    = & $tag $_.Edge    $_.'Edge status'
            Firefox = & $tag $_.Firefox $_.'Firefox status'
            Brave   = if ($_.Brave) { (($_.Brave -split ',\s*')[-1] -split '\.')[0] } else { '-' }
            Opera   = if ($_.Opera) { (($_.Opera -split ',\s*')[-1] -split '\.')[0] } else { '-' }
        }
    } | Format-Table -AutoSize | Out-Host
    Write-Host '  Browser numbers are the main version (full versions are in the report).' -ForegroundColor DarkGray
    Write-Host '  OK = up to date   OLD = update due   ESR = Firefox business version' -ForegroundColor DarkGray

    Write-Host "`n  NEEDS ATTENTION" -ForegroundColor Yellow
    $any = $false
    foreach ($r in $Rows) {
        $issues = @()
        if ($r.Status -ne 'OK')                 { $issues += @{ Text = "Not checked. $($r.Note)"; Colour = 'Red' } }
        if ($r.Support -eq 'Out of support')    { $issues += @{ Text = "$($r.Windows) $($r.Version) is out of support"; Colour = 'Red' } }
        elseif ($r.Support -like 'Support ends*') { $issues += @{ Text = "Windows $($r.Support -replace '^Support', 'support')"; Colour = 'Yellow' } }
        foreach ($b in 'Chrome', 'Edge', 'Firefox') {
            if ($r."$b status" -eq 'Update due') { $issues += @{ Text = "$b needs updating ($((($r.$b) -split ',\s*')[-1]))"; Colour = 'Yellow' } }
        }
        if ($r.Status -eq 'OK') {
            if (-not $r.Antivirus)              { $issues += @{ Text = 'No antivirus found'; Colour = 'Red' } }
            elseif ($r.'AV on' -eq 'Off')       { $issues += @{ Text = "Antivirus is OFF ($($r.Antivirus))"; Colour = 'Red' } }
            elseif ($r.'AV on' -like '*out of date*') { $issues += @{ Text = "Antivirus out of date ($($r.Antivirus))"; Colour = 'Yellow' } }
            if ($r.Firewall -like 'Off*' -or $r.Firewall -like 'Some off*') { $issues += @{ Text = "Firewall: $($r.Firewall)"; Colour = 'Yellow' } }
            if ($r.Encrypted -eq 'Off')         { $issues += @{ Text = 'Drive not encrypted (no BitLocker)'; Colour = 'Yellow' } }
            if ($r.'Reboot pending' -eq 'Yes')  { $issues += @{ Text = 'Restart needed to finish updates'; Colour = 'Yellow' } }
        }
        if ($issues) {
            $any = $true
            Write-Host "  $($r.Device)" -ForegroundColor White
            foreach ($i in $issues) { Write-Host "     - $($i.Text)" -ForegroundColor $i.Colour }
        }
    }
    if (-not $any) { Write-SwGood 'Nothing needs attention.' }
    Write-Host ''
}

function Read-SwChoice {
    param([string]$Question, [string[]]$Allowed)
    while ($true) {
        $answer = (Read-Host "  $Question").Trim().ToUpper()
        if ($answer -in $Allowed) { return $answer }
        Write-SwWarn "Please type one of: $($Allowed -join ', ')"
    }
}

function New-SwHtmlReport {
    param($Rows, $Latest, [string]$Title)
    $encode = { param($t) [Net.WebUtility]::HtmlEncode([string]$t) }
    $badge = {
        param($text)
        $class = switch -Regex ($text) {
            '^(Up to date|Supported)' { 'good' }
            '^(Update due|Support ends|Unknown|ESR)' { 'warn' }
            '^(Out of support|Not checked)' { 'bad' }
            default { 'plain' }
        }
        if ($text) { "<span class=""badge $class"">$(& $encode $text)</span>" } else { '' }
    }
    $checked = @($Rows | Where-Object Status -eq 'OK')
    $cards = @(
        @('Devices found', $Rows.Count), @('Checked', $checked.Count),
        @('Not checked', @($Rows | Where-Object Status -ne 'OK').Count),
        @('Windows out of support', @($checked | Where-Object Support -eq 'Out of support').Count),
        @('Browsers needing update', @($checked | ForEach-Object { $_.'Chrome status', $_.'Edge status', $_.'Firefox status' } | Where-Object { $_ -eq 'Update due' }).Count),
        @('Antivirus off or missing', @($checked | Where-Object { -not $_.Antivirus -or $_.'AV on' -eq 'Off' }).Count),
        @('Drives not encrypted', @($checked | Where-Object Encrypted -eq 'Off').Count),
        @('Restart needed', @($checked | Where-Object 'Reboot pending' -eq 'Yes').Count)
    ) | ForEach-Object { "<div class=""card""><b>$($_[1])</b><span>$($_[0])</span></div>" }

    $rowsHtml = foreach ($r in $Rows) {
        $browserCell = {
            param($name)
            $v = $r.$name; $s = $r."$name status"
            if (-not $v) { '<span class="none">-</span>' } else { "$(& $encode $v)<br>$(& $badge $s)" }
        }
        "<tr><td><b>$(& $encode $r.Device)</b><br><small>$(& $encode $r.Address)</small></td>" +
        "<td>$(if ($r.Windows) { "$(& $encode $r.Windows)<br><small>$(& $encode $r.Version) &middot; build $(& $encode $r.Build)</small>" })</td>" +
        "<td>$(& $badge $r.Support)$(if ($r.Status -ne 'OK') { & $badge 'Not checked' })</td>" +
        "<td>$(& $browserCell 'Chrome')</td><td>$(& $browserCell 'Edge')</td><td>$(& $browserCell 'Firefox')</td>" +
        "<td>$(if ($r.Brave) { & $encode $r.Brave } else { '<span class=""none"">-</span>' })</td>" +
        "<td>$(if ($r.Opera) { & $encode $r.Opera } else { '<span class=""none"">-</span>' })</td>" +
        "<td><small>$(& $encode $r.'Logged on user')</small></td><td><small>$(& $encode $r.Note)</small></td></tr>"
    }
    # Second table: hardware, security and network
    $yesno = { param($text, $goodWhen) if (-not $text) { '<span class="none">-</span>' } elseif ($text -match $goodWhen) { & $badge $text } else { "<span class=""badge bad"">$(& $encode $text)</span>" } }
    $rows2Html = foreach ($r in $Rows) {
        if ($r.Status -ne 'OK') {
            "<tr><td><b>$(& $encode $r.Device)</b></td><td colspan=""13""><small>$(& $encode $r.Note)</small></td></tr>"
            continue
        }
        $av = if (-not $r.Antivirus) { '<span class="badge bad">None found</span>' }
              else { "$(& $encode $r.Antivirus)<br>" + $(if ($r.'AV on' -eq 'On') { '<span class="badge good">On</span>' } elseif ($r.'AV on' -like '*out of date*') { '<span class="badge warn">Out of date</span>' } else { '<span class="badge bad">Off</span>' }) }
        "<tr><td><b>$(& $encode $r.Device)</b></td>" +
        "<td>$(& $encode $r.Make)<br><small>$(& $encode $r.Model)</small></td>" +
        "<td><small>$(& $encode $r.Serial)</small></td>" +
        "<td><small>$(& $encode $r.CPU)</small></td>" +
        "<td>$(& $encode $r.'RAM (GB)') GB</td>" +
        "<td>$(& $encode $r.'Disk free (GB)') / $(& $encode $r.'Disk (GB)') GB</td>" +
        "<td>$av</td>" +
        "<td>$(& $yesno $r.Firewall '^On$')</td>" +
        "<td>$(& $yesno $r.Encrypted '^On$')</td>" +
        "<td>$(& $yesno $r.TPM '^Yes$')</td>" +
        "<td>$(& $yesno $r.'Secure Boot' '^On|N/A')</td>" +
        "<td>$(& $encode $r.'Last update')$(if ($r.'Reboot pending' -eq 'Yes') { '<br><span class=""badge warn"">restart needed</span>' })</td>" +
        "<td><small>$(& $encode $r.IP)<br>$(& $encode $r.Connection)</small></td>" +
        "<td>$(if ($r.RDP -eq 'On') { '<span class=""badge warn"">On</span>' } elseif ($r.RDP) { '<span class=""badge good"">Off</span>' })</td></tr>"
    }

    $latestLine = ($('Chrome', 'Edge', 'Firefox') | ForEach-Object { "$_ $(if ($Latest[$_]) { $Latest[$_] } else { 'unknown' })" }) -join ' &middot; '

    @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>$(& $encode $Title)</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #eef1f5; color: #1d2733; }
  header { background: #13294b; color: #fff; padding: 22px 32px; }
  header h1 { margin: 0; font-size: 24px; } header p { margin: 4px 0 0; color: #b9c7dc; font-size: 14px; }
  main { max-width: 1400px; margin: 20px auto; padding: 0 16px; }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 18px; }
  .card { background: #fff; border-radius: 8px; padding: 14px 18px; min-width: 150px; box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  .card b { display: block; font-size: 26px; color: #13294b; } .card span { font-size: 13px; color: #5b6676; }
  .wrap { background: #fff; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,.08); overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #e3e8ef; vertical-align: top; }
  th { background: #f4f6f9; position: sticky; top: 0; }
  h2 { font-size: 17px; color: #13294b; margin: 22px 0 8px; }
  small { color: #5b6676; } .none { color: #b0b8c4; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; margin-top: 3px; }
  .good { background: #dff3e4; color: #1d6b34; } .warn { background: #fff1d6; color: #8a5a00; }
  .bad { background: #fde2e1; color: #a1231c; } .plain { background: #eef1f5; color: #3b4656; }
  footer { text-align: center; color: #7a8594; font-size: 12px; padding: 14px 0 30px; }
</style></head>
<body>
<header><h1>$(& $encode $Title)</h1><p>$(Get-Date -Format 'dd MMMM yyyy, HH:mm') &middot; Latest versions: $latestLine</p></header>
<main>
<div class="cards">$($cards -join '')</div>
<h2>Windows &amp; browsers</h2>
<div class="wrap"><table>
<tr><th>Device</th><th>Windows</th><th>Support</th><th>Chrome</th><th>Edge</th><th>Firefox</th><th>Brave</th><th>Opera</th><th>Signed in</th><th>Notes</th></tr>
$($rowsHtml -join "`n")
</table></div>
<h2>Hardware, security &amp; network</h2>
<div class="wrap"><table>
<tr><th>Device</th><th>Make / model</th><th>Serial</th><th>CPU</th><th>RAM</th><th>Disk free</th><th>Antivirus</th><th>Firewall</th><th>Encrypted</th><th>TPM</th><th>Secure Boot</th><th>Updates</th><th>Network</th><th>RDP</th></tr>
$($rows2Html -join "`n")
</table></div>
</main>
<footer>Made with Simonware Network Audit</footer>
</body></html>
"@
}

# =====================================================================
#  MAIN
# =====================================================================

function Invoke-SimonwareNetworkAudit {
    Write-Host ''
    Write-Host '  ================================================' -ForegroundColor Cyan
    Write-Host '         S I M O N W A R E   N E T W O R K   A U D I T' -ForegroundColor Cyan
    Write-Host '  ================================================' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  Which devices should I check?' -ForegroundColor Yellow
    Write-Host '   [1] Scan this network automatically'
    Write-Host '   [2] Scan an address range I type (e.g. 192.168.1.0/24)'
    Write-Host '   [3] All computers in Active Directory (domain networks)'
    Write-Host '   [4] Names or IP addresses I type, or a .txt file with one per line'
    Write-Host ''
    Write-Host '   [5] Prepare THIS PC so it can be audited (run once on each PC, mainly without a domain)' -ForegroundColor Gray
    $source = Read-SwChoice 'Choose 1-5' @('1', '2', '3', '4', '5')
    if ($source -eq '5') { Enable-SwAuditAccess; return }

    $onDomain = [bool](Get-CimInstance Win32_ComputerSystem).PartOfDomain
    if ($source -eq '3' -and -not $onDomain) {
        Write-SwWarn 'This PC is not on a domain, so there is no Active Directory. Choose 1, 2 or 4 instead.'
        return
    }

    $targets = @()
    switch ($source) {
        { $_ -in '1', '2' } {
            $range = if ($source -eq '1') { Get-SwLocalSubnet } else { (Read-Host '  Address range').Trim() }
            if (-not $range) { Write-SwWarn "Couldn't work out this network. Choose option 2 and type the range."; return }
            Write-Host "  Scanning $range ..." -ForegroundColor Cyan
            $addresses = @(Get-SwIpRange $range)
            $targets = Find-SwLiveDevices $addresses | ForEach-Object { [pscustomobject]@{ Name = $_; Address = $_; AdOs = $null; IsLocal = $false } }
        }
        '3' {
            try { $targets = @(Get-SwAdComputers) }
            catch { Write-SwWarn "Couldn't read Active Directory: $($_.Exception.Message)"; return }
        }
        '4' {
            $text = (Read-Host '  Names/IPs separated by commas, or the path to a .txt file').Trim().Trim('"')
            $names = if (Test-Path -LiteralPath $text -PathType Leaf) { Get-Content -LiteralPath $text } else { $text -split '[,;\s]+' }
            $targets = $names | Where-Object { $_.Trim() } | ForEach-Object { [pscustomobject]@{ Name = $_.Trim(); Address = $null; AdOs = $null; IsLocal = $false } }
        }
    }
    $targets = @($targets)
    if (-not $targets) { Write-SwWarn 'No devices found.'; return }

    # Mark this PC so it's checked directly, not over the network
    $myAddresses = @([Net.Dns]::GetHostAddresses($env:COMPUTERNAME) | ForEach-Object { $_.ToString() }) + '127.0.0.1'
    foreach ($t in $targets) {
        $short = ($t.Name -split '\.')[0]
        if ($short -eq $env:COMPUTERNAME -or $t.Name -eq 'localhost' -or $t.Address -in $myAddresses -or $t.Name -in $myAddresses) { $t.IsLocal = $true }
    }
    Write-SwGood "$($targets.Count) device(s) to check."

    $credential = $null
    if ($onDomain) {
        Write-Host "  Domain network ($((Get-CimInstance Win32_ComputerSystem).Domain))." -ForegroundColor Gray
        $answer = (Read-Host '  Use a different admin account than the one you are signed in with? [y/N]').Trim().ToLower()
        if ($answer -in @('y', 'yes')) { $credential = Get-Credential -Message 'Domain admin account, e.g. DOMAIN\admin' }
    } else {
        Write-Host '  No domain on this network, so I need a local admin account that is the same on each PC.' -ForegroundColor Gray
        Write-Host '  Type just the username (e.g. Administrator), not PCNAME\username.' -ForegroundColor Gray
        $credential = Get-Credential -Message 'Local admin account on the PCs, e.g. Administrator'
        if (-not $credential) { Write-SwWarn 'No account given, so I can only check this PC.' }
    }

    Write-Host '  Getting the latest browser versions...' -ForegroundColor Cyan
    $latest = Get-SwLatestBrowsers
    if (-not $latest.Count) { Write-SwWarn "Couldn't reach the browser websites, so 'up to date' won't be shown." }

    # Check every device, several at a time
    $pool = [runspacefactory]::CreateRunspacePool(1, $SwThrottle)
    $pool.Open()
    $jobs = foreach ($t in $targets) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($SwWorker).AddArgument($t).AddArgument($credential).AddArgument($SwBrowsers).AddArgument($SwCollect.ToString())
        [pscustomobject]@{ PS = $ps; Handle = $ps.BeginInvoke() }
    }
    while (@($jobs | Where-Object { -not $_.Handle.IsCompleted }).Count) {
        $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
        Write-Progress -Activity 'Checking devices' -Status "$done of $($jobs.Count) done" -PercentComplete ($done / $jobs.Count * 100)
        Start-Sleep -Milliseconds 400
    }
    Write-Progress -Activity 'Checking devices' -Completed
    $raw = foreach ($job in $jobs) { $job.PS.EndInvoke($job.Handle); $job.PS.Dispose() }
    $pool.Close()

    # Build the report rows
    $rows = foreach ($r in $raw) {
        $d = $r.Data
        $row = [ordered]@{
            Device  = if ($d -and $d.ComputerName) { $d.ComputerName } else { $r.Device }
            Address = $r.Address
            Status  = $r.Status
            Method  = $r.Method
            Windows = if ($d) { $d.OS } else { '' }
            Version = if ($d) { $d.Version } else { '' }
            Build   = if ($d) { $d.Build } else { '' }
            Support = if ($d) { Get-SwWindowsSupport $d.OS $d.Build } else { '' }
        }
        foreach ($b in $SwBrowsers) {
            $v = if ($d) { $d.($b.Name) } else { '' }
            $row[$b.Name] = $v
            if ($b.Name -in 'Chrome', 'Edge', 'Firefox') { $row["$($b.Name) status"] = Get-SwBrowserStatus $v $latest[$b.Name] }
        }
        # Hardware
        $row['Make']          = if ($d) { $d.Make } else { '' }
        $row['Model']         = if ($d) { $d.Model } else { '' }
        $row['Serial']        = if ($d) { $d.Serial } else { '' }
        $row['CPU']           = if ($d) { $d.Cpu } else { '' }
        $row['RAM (GB)']      = if ($d) { $d.RamGB } else { '' }
        $row['Disk (GB)']     = if ($d) { $d.DiskGB } else { '' }
        $row['Disk free (GB)'] = if ($d) { $d.DiskFreeGB } else { '' }
        # Security
        $row['Antivirus']     = if ($d) { $d.Antivirus } else { '' }
        $row['AV on']         = if ($d) { $d.AvOn } else { '' }
        $row['Firewall']      = if ($d) { $d.Firewall } else { '' }
        $row['Encrypted']     = if ($d) { $d.Encrypted } else { '' }
        $row['TPM']           = if ($d) { $d.Tpm } else { '' }
        $row['Secure Boot']   = if ($d) { $d.SecureBoot } else { '' }
        $row['Local admins']  = if ($d) { $d.LocalAdmins } else { '' }
        # Windows Update
        $row['Last update']   = if ($d) { $d.LastUpdate } else { '' }
        $row['Reboot pending'] = if ($d) { $d.RebootPending } else { '' }
        # Network
        $row['IP']            = if ($d) { $d.Ip } else { '' }
        $row['MAC']           = if ($d) { $d.Mac } else { '' }
        $row['Connection']    = if ($d) { $d.Connection } else { '' }
        $row['RDP']           = if ($d) { $d.Rdp } else { '' }
        $row['Logged on user'] = if ($d) { $d.LoggedOnUser } else { '' }
        $row['Last restart']   = if ($d) { $d.LastRestart } else { '' }
        $row['Note']           = $r.Note
        [pscustomobject]$row
    }
    $rows = @($rows | Sort-Object @{ e = { $_.Status -ne 'OK' } }, Device)

    # Show and save
    Show-SwConsoleResults $rows

    $folder = Join-Path ([Environment]::GetFolderPath('Desktop')) 'Simonware Reports'
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
    $stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
    $csvPath  = Join-Path $folder "Network Audit $stamp.csv"
    $htmlPath = Join-Path $folder "Network Audit $stamp.html"
    $rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    New-SwHtmlReport -Rows $rows -Latest $latest -Title 'Network Audit' | Out-File -FilePath $htmlPath -Encoding UTF8

    Write-SwGood "Spreadsheet: $csvPath"
    Write-SwGood "Report:      $htmlPath"
    if ((Read-Host '  Open the report now? [Y/n]').Trim().ToLower() -notin @('n', 'no')) { Start-Process $htmlPath }
}

Invoke-SimonwareNetworkAudit
