<#
.SYNOPSIS
    Report which vioscsi driver is installed and loaded on this machine.

.DESCRIPTION
    Collects everything needed to check that the vioscsi build you think you are running is the one
    Windows actually loaded: the service and its image path, the on-disk .sys (version, timestamp, SHA256,
    signature), every copy of the driver in the driver store with a hash comparison, the PnP devices
    bound to the service and the driver package they use, the Storport adapters that expose the telemetry
    IOCTL, and the last boot time. A summary at the end flags the usual mismatches, such as a driver file
    newer than the last boot (the old image is still loaded) or driver store copies that differ from the
    one in System32\drivers.

    Run from an elevated PowerShell. If the script itself is blocked by the execution policy, start it with
    powershell -ExecutionPolicy Bypass -File .\GetVioScsiDriverInfo.ps1

.PARAMETER OutFile
    Also write the output to this file (PowerShell transcript).

.EXAMPLE
    .\GetVioScsiDriverInfo.ps1

.EXAMPLE
    .\GetVioScsiDriverInfo.ps1 -OutFile C:\temp\vioscsi-driver.txt
#>

#  Copyright (c) 2026 Red Hat, Inc. and/or its affiliates. All rights reserved.

#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the names of the copyright holders nor the names of their contributors
#     may be used to endorse or promote products derived from this software
#     without specific prior written permission.
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  SUCH DAMAGE.

[CmdletBinding()]
param (
    [string]$OutFile
)

# Only affects this PowerShell process. It can fail if a policy is enforced by Group Policy, which is
# harmless here because the script is already running.
try {
    Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force -ErrorAction Stop
} catch {
    Write-Warning "Could not set the process execution policy: $($_.Exception.Message)"
}

$SERVICE_NAME = 'vioscsi'
$DRIVER_FILE  = 'vioscsi.sys'
$SERVICE_START_TYPES = @{ 0 = 'Boot'; 1 = 'System'; 2 = 'Automatic'; 3 = 'Manual'; 4 = 'Disabled' }

function Write-Section([string]$Title) {
    Write-Host ''
    Write-Host ('=== {0} ===' -f $Title)
}

function Invoke-Section([string]$Title, [scriptblock]$Body) {
    # A failure in one source (missing cmdlet, no admin rights) must not hide the others.
    Write-Section $Title
    try {
        & $Body
    } catch {
        Write-Warning ('{0}: {1}' -f $Title, $_.Exception.Message)
    }
}

function Get-DriverFileInfo([string]$Path) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        Path           = $item.FullName
        FileVersion    = $item.VersionInfo.FileVersion
        ProductVersion = $item.VersionInfo.ProductVersion
        Description    = $item.VersionInfo.FileDescription
        SizeBytes      = $item.Length
        LastWriteTime  = $item.LastWriteTime
        SHA256         = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
        Signature      = $(if ($sig) { $sig.Status } else { 'unknown' })
        Signer         = $(if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null })
    }
}

function ConvertTo-DriverPath([string]$ImagePath) {
    # ImagePath is usually System32\drivers\vioscsi.sys (relative to %SystemRoot%) but can also be
    # \SystemRoot\..., \??\C:\..., or a full path.
    if (-not $ImagePath) { return $null }
    $p = $ImagePath.Trim('"')
    if ($p -match '^\\SystemRoot\\(.*)$') { return Join-Path $env:SystemRoot $Matches[1] }
    if ($p -match '^\\\?\?\\(.*)$') { return $Matches[1] }
    if ($p -match '^[A-Za-z]:\\') { return $p }
    return Join-Path $env:SystemRoot $p
}

if ($OutFile) {
    Start-Transcript -Path $OutFile -Force | Out-Null
}

$notes = New-Object System.Collections.Generic.List[string]
$activeFile = $null
$lastBoot = $null
$service = $null

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'Not running as Administrator: the driver store and package queries may be incomplete.'
}

Invoke-Section 'Host' {
    $os = Get-CimInstance Win32_OperatingSystem
    $script:lastBoot = $os.LastBootUpTime
    [PSCustomObject]@{
        Computer     = $env:COMPUTERNAME
        OS           = $os.Caption
        Version      = $os.Version
        Architecture = $os.OSArchitecture
        LastBootTime = $os.LastBootUpTime
        Now          = Get-Date
    } | Format-List | Out-Host
}

Invoke-Section "Service '$SERVICE_NAME'" {
    $key = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$SERVICE_NAME" -ErrorAction Stop
    $sys = Get-CimInstance Win32_SystemDriver -Filter "Name='$SERVICE_NAME'" -ErrorAction SilentlyContinue
    $startValue = [int]$key.Start
    [PSCustomObject]@{
        DisplayName = $key.DisplayName
        ImagePath   = $key.ImagePath
        StartType   = $(if ($SERVICE_START_TYPES.ContainsKey($startValue)) { $SERVICE_START_TYPES[$startValue] } else { $startValue })
        State       = $(if ($sys) { $sys.State } else { 'unknown' })
        Status      = $(if ($sys) { $sys.Status } else { 'unknown' })
        PathName    = $(if ($sys) { $sys.PathName } else { $null })
        Group       = $key.Group
    } | Format-List | Out-Host
    $script:service = $key
    if ($sys -and $sys.State -ne 'Running') {
        $notes.Add("Service state is '$($sys.State)', not Running.")
    }
}

Invoke-Section 'Active driver file' {
    $path = $null
    if ($service) { $path = ConvertTo-DriverPath $service.ImagePath }
    if (-not $path) { $path = Join-Path $env:SystemRoot "System32\drivers\$DRIVER_FILE" }
    $script:activeFile = Get-DriverFileInfo $path
    $script:activeFile | Format-List | Out-Host
    if ($activeFile.Signature -ne 'Valid') {
        $notes.Add("Signature of $($activeFile.Path) is '$($activeFile.Signature)'. A test-signed build needs test signing enabled.")
    }
    if ($lastBoot -and $activeFile.LastWriteTime -gt $lastBoot) {
        $notes.Add(('{0} was modified at {1}, after the last boot at {2}. Windows may still be running the image it loaded earlier; reboot (or disable/enable the adapter, if it is not the boot disk) to load it.' -f
                    $DRIVER_FILE, $activeFile.LastWriteTime, $lastBoot))
    }
}

Invoke-Section "Copies of $DRIVER_FILE in the driver store" {
    $repo = Join-Path $env:SystemRoot 'System32\DriverStore\FileRepository'
    $copies = @(Get-ChildItem -Path $repo -Filter $DRIVER_FILE -Recurse -ErrorAction SilentlyContinue)
    if ($copies.Count -eq 0) {
        Write-Host 'None found.'
        return
    }
    $rows = foreach ($c in $copies) {
        $hash = (Get-FileHash -LiteralPath $c.FullName -Algorithm SHA256).Hash
        [PSCustomObject]@{
            Package       = $c.Directory.Name
            FileVersion   = $c.VersionInfo.FileVersion
            LastWriteTime = $c.LastWriteTime
            SHA256        = $hash
            MatchesActive = $(if ($activeFile) { $hash -eq $activeFile.SHA256 } else { $null })
        }
    }
    $rows | Format-Table -AutoSize -Wrap | Out-Host
    if ($activeFile -and -not @($rows | Where-Object { $_.MatchesActive }).Count) {
        $notes.Add("The active $DRIVER_FILE matches none of the driver store copies, so the installed package is not the one in use.")
    }
    $hashes = @($rows | Select-Object -ExpandProperty SHA256 -Unique)
    if ($hashes.Count -gt 1) {
        $notes.Add("The driver store holds $($copies.Count) different vioscsi packages ($($hashes.Count) distinct binaries). Check which one the device is bound to below.")
    }
}

Invoke-Section 'PnP devices bound to the service' {
    $devices = @(Get-CimInstance Win32_PnPEntity -ErrorAction Stop | Where-Object { $_.Service -eq $SERVICE_NAME })
    if ($devices.Count -eq 0) {
        Write-Host "No PnP device is bound to service '$SERVICE_NAME'."
        $notes.Add("No PnP device is bound to service '$SERVICE_NAME'.")
        return
    }
    $signed = @(Get-CimInstance Win32_PnPSignedDriver -ErrorAction SilentlyContinue)
    foreach ($d in $devices) {
        $drv = $signed | Where-Object { $_.DeviceID -eq $d.DeviceID } | Select-Object -First 1
        [PSCustomObject]@{
            Name          = $d.Name
            Status        = $d.Status
            ErrorCode     = $d.ConfigManagerErrorCode
            DeviceID      = $d.DeviceID
            HardwareID    = ($d.HardwareID -join '; ')
            DriverVersion = $(if ($drv) { $drv.DriverVersion } else { $null })
            DriverDate    = $(if ($drv) { $drv.DriverDate } else { $null })
            DriverProvider = $(if ($drv) { $drv.DriverProviderName } else { $null })
            InfName       = $(if ($drv) { $drv.InfName } else { $null })
            Signed        = $(if ($drv) { $drv.IsSigned } else { $null })
            Signer        = $(if ($drv) { $drv.Signer } else { $null })
        } | Format-List | Out-Host
        if ($d.ConfigManagerErrorCode) {
            $notes.Add("Device '$($d.Name)' reports problem code $($d.ConfigManagerErrorCode).")
        }
    }
}

Invoke-Section 'Installed vioscsi driver packages (pnputil)' {
    # pnputil output is localized, so match on the file name instead of on field labels. Each package
    # is a block of lines separated by a blank line.
    $text = (& pnputil.exe /enum-drivers 2>&1 | Out-String)
    $blocks = $text -split '(?:\r?\n){2,}'
    $mine = @($blocks | Where-Object { $_ -match 'vioscsi' })
    if ($mine.Count -eq 0) {
        Write-Host 'No package mentioning vioscsi was listed.'
        return
    }
    $mine | ForEach-Object { $_.Trim(); '' } | Out-Host
}

Invoke-Section 'Storport adapters using the driver' {
    $ports = @(Get-ChildItem 'HKLM:\HARDWARE\DEVICEMAP\Scsi' -ErrorAction SilentlyContinue |
               Where-Object { $_.GetValue('Driver') -eq $SERVICE_NAME })
    if ($ports.Count -eq 0) {
        Write-Host "No 'Scsi Port' key names driver '$SERVICE_NAME'."
        $notes.Add("No SCSI port is served by '$SERVICE_NAME', so the telemetry IOCTL has nothing to query.")
        return
    }
    $ports | ForEach-Object {
        [PSCustomObject]@{
            Port       = [int]($_.PSChildName -replace '^Scsi Port ', '')
            Device     = '\\.\Scsi{0}:' -f ($_.PSChildName -replace '^Scsi Port ', '')
            Driver     = $_.GetValue('Driver')
            Interrupt  = $_.GetValue('Interrupt')
        }
    } | Sort-Object Port | Format-Table -AutoSize | Out-Host
}

Invoke-Section 'Summary' {
    if ($activeFile) {
        Write-Host ('Active image : {0}' -f $activeFile.Path)
        Write-Host ('File version : {0}' -f $activeFile.FileVersion)
        Write-Host ('Modified     : {0}' -f $activeFile.LastWriteTime)
        Write-Host ('SHA256       : {0}' -f $activeFile.SHA256)
    }
    if ($lastBoot) {
        Write-Host ('Last boot    : {0}' -f $lastBoot)
    }
    Write-Host ''
    if ($notes.Count -eq 0) {
        Write-Host 'No mismatches found. Compare the SHA256 above with the .sys you built to confirm it is the same file.'
    } else {
        Write-Host 'Things to check:'
        $notes | ForEach-Object { Write-Host (' - {0}' -f $_) -ForegroundColor Yellow }
    }
}

if ($OutFile) {
    Stop-Transcript | Out-Null
}
