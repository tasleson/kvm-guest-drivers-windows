<#
.SYNOPSIS
    Read and summarize vioscsi per-queue I/O, latency and error telemetry.

.DESCRIPTION
    Queries every vioscsi adapter in the running system with an IOCTL_SCSI_MINIPORT
    request and prints a summary of the driver's STOR_TELEMETRY block: reset counts,
    then per-queue I/O counts, bytes, latency (avg/min/max and approximate p50/p99 from
    the log2 histogram), in-flight high-water mark and queue-full count, and a
    non-zero SRB status histogram. Counters are cumulative since the adapter was
    started; take two snapshots to compute rates.

    Requires Administrator rights and a vioscsi driver with telemetry version 3 or
    later. A blob saved with -SaveRaw can be parsed later, on any machine, with
    -InputFile.

.PARAMETER Port
    Query only these \\.\ScsiN: port numbers instead of every vioscsi adapter.

.PARAMETER All
    Also list queues that have not completed any request.

.PARAMETER PassThru
    Emit one object per adapter instead of printing a summary.

.PARAMETER SaveRaw
    Directory to write each adapter's raw telemetry blob to (as a .bin file).

.PARAMETER InputFile
    Parse a previously saved raw blob instead of querying the driver.

.EXAMPLE
    .\GetVioScsiTelemetry.ps1

.EXAMPLE
    .\GetVioScsiTelemetry.ps1 -SaveRaw C:\temp

.EXAMPLE
    (.\GetVioScsiTelemetry.ps1 -PassThru)[0].Queues | Format-Table
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
    [int[]]$Port,
    [switch]$All,
    [switch]$PassThru,
    [string]$SaveRaw,
    [string]$InputFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Mirrors vioscsi/vioscsi.h; keep in sync.
$VIOSCSI_IOCTL_SIGNATURE        = [byte[]]([Text.Encoding]::ASCII.GetBytes('VIOSCSI') + 0)
$VIOSCSI_IOCTL_QUERY_TELEMETRY  = [uint32]0x56530001
$VIOSCSI_TELEMETRY_RC_TRUNCATED = [uint32]1
$STOR_TELEMETRY_MAGIC           = [uint32]0x53505331
$STOR_TELEMETRY_MIN_VERSION     = 3
# Fixed STOR_TELEMETRY header: Magic, Version, HeaderSize, QueueSize, QueueCount,
# LatencyBuckets, StatusSlots, Reserved (8 ULONGs), then the adapter-wide ULONG64s.
$HEADER_FIXED_SIZE              = 32
$HEADER_V3_SIZE                 = 80
$INITIAL_QUERY_SIZE             = 4096
$IOCTL_TIMEOUT_SEC              = 10

# Indexed by SRB_STATUS_* with SRB_STATUS_QUEUE_FROZEN/AUTOSENSE_VALID masked off (srb.h).
$SrbStatusNames = @{
    0x00 = 'PENDING'; 0x01 = 'SUCCESS'; 0x02 = 'ABORTED'; 0x03 = 'ABORT_FAILED'; 0x04 = 'ERROR'
    0x05 = 'BUSY'; 0x06 = 'INVALID_REQUEST'; 0x07 = 'INVALID_PATH_ID'; 0x08 = 'NO_DEVICE'
    0x09 = 'TIMEOUT'; 0x0A = 'SELECTION_TIMEOUT'; 0x0B = 'COMMAND_TIMEOUT'; 0x0D = 'MESSAGE_REJECTED'
    0x0E = 'BUS_RESET'; 0x0F = 'PARITY_ERROR'; 0x10 = 'REQUEST_SENSE_FAILED'; 0x11 = 'NO_HBA'
    0x12 = 'DATA_OVERRUN'; 0x13 = 'UNEXPECTED_BUS_FREE'; 0x14 = 'PHASE_SEQUENCE_FAILURE'
    0x15 = 'BAD_SRB_BLOCK_LENGTH'; 0x16 = 'REQUEST_FLUSHED'; 0x20 = 'INVALID_LUN'
    0x21 = 'INVALID_TARGET_ID'; 0x22 = 'BAD_FUNCTION'; 0x23 = 'ERROR_RECOVERY'; 0x24 = 'NOT_POWERED'
    0x25 = 'LINK_DOWN'; 0x26 = 'INSUFFICIENT_RESOURCES'; 0x27 = 'THROTTLED_REQUEST'; 0x30 = 'INTERNAL_ERROR'
}

if (-not ('VioScsiTelemetryIoctl' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class VioScsiTelemetryIoctl
{
    const uint GENERIC_READ = 0x80000000;
    const uint GENERIC_WRITE = 0x40000000;
    const uint FILE_SHARE_READ = 1;
    const uint FILE_SHARE_WRITE = 2;
    const uint OPEN_EXISTING = 3;
    const uint IOCTL_SCSI_MINIPORT = 0x0004D008;
    // sizeof(SRB_IO_CONTROL): HeaderLength, Signature[8], Timeout, ControlCode, ReturnCode, Length
    const int SRB_IO_CONTROL_SIZE = 28;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
                                             uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool DeviceIoControl(SafeFileHandle device, uint code, byte[] inBuffer, int inSize,
                                       [Out] byte[] outBuffer, int outSize, out int returned, IntPtr overlapped);

    // Sends an IOCTL_SCSI_MINIPORT request with a payloadSize-byte payload and returns
    // the payload bytes the miniport reported in SRB_IO_CONTROL.Length.
    public static byte[] Query(string path, byte[] signature, uint controlCode, uint timeout,
                               int payloadSize, out uint returnCode)
    {
        using (SafeFileHandle device = CreateFileW(path, GENERIC_READ | GENERIC_WRITE,
                                                   FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero,
                                                   OPEN_EXISTING, 0, IntPtr.Zero))
        {
            if (device.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open " + path);
            }

            byte[] request = new byte[SRB_IO_CONTROL_SIZE + payloadSize];
            byte[] response = new byte[request.Length];
            BitConverter.GetBytes((uint)SRB_IO_CONTROL_SIZE).CopyTo(request, 0);
            Array.Copy(signature, 0, request, 4, 8);
            BitConverter.GetBytes(timeout).CopyTo(request, 12);
            BitConverter.GetBytes(controlCode).CopyTo(request, 16);
            BitConverter.GetBytes((uint)payloadSize).CopyTo(request, 24);

            int returned;
            if (!DeviceIoControl(device, IOCTL_SCSI_MINIPORT, request, request.Length, response,
                                 response.Length, out returned, IntPtr.Zero))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "IOCTL_SCSI_MINIPORT failed on " + path);
            }

            if (returned < SRB_IO_CONTROL_SIZE)
            {
                throw new InvalidOperationException("IOCTL_SCSI_MINIPORT on " + path + " returned only " +
                                                    returned + " bytes");
            }

            returnCode = BitConverter.ToUInt32(response, 20);
            int length = (int)Math.Min(BitConverter.ToUInt32(response, 24), (uint)payloadSize);
            byte[] payload = new byte[length];
            Array.Copy(response, SRB_IO_CONTROL_SIZE, payload, 0, length);
            return payload;
        }
    }
}
'@
}

function Get-VioScsiPorts {
    # HARDWARE\DEVICEMAP\Scsi has one "Scsi Port N" key per storage adapter, naming its driver.
    Get-ChildItem 'HKLM:\HARDWARE\DEVICEMAP\Scsi' -ErrorAction SilentlyContinue |
        Where-Object { $_.GetValue('Driver') -eq 'vioscsi' } |
        ForEach-Object { [int]($_.PSChildName -replace '^Scsi Port ', '') } |
        Sort-Object
}

function Get-ErrorText($ErrorRecord) {
    # Exceptions thrown from the C# helper arrive wrapped in a MethodInvocationException.
    $e = $ErrorRecord.Exception
    if ($e.InnerException) { $e = $e.InnerException }
    return $e.Message
}

function Invoke-TelemetryQuery([int]$PortNumber) {
    $path = "\\.\Scsi${PortNumber}:"
    $rc = [uint32]0
    $data = [VioScsiTelemetryIoctl]::Query($path, $VIOSCSI_IOCTL_SIGNATURE, $VIOSCSI_IOCTL_QUERY_TELEMETRY,
                                           $IOCTL_TIMEOUT_SEC, $INITIAL_QUERY_SIZE, [ref]$rc)
    if ($rc -eq $VIOSCSI_TELEMETRY_RC_TRUNCATED -and $data.Length -ge 20) {
        # The header tells us how large the full snapshot is; ask again with that size.
        $required = [BitConverter]::ToUInt32($data, 8) +
                    [uint64][BitConverter]::ToUInt32($data, 12) * [BitConverter]::ToUInt32($data, 16)
        try {
            $data = [VioScsiTelemetryIoctl]::Query($path, $VIOSCSI_IOCTL_SIGNATURE, $VIOSCSI_IOCTL_QUERY_TELEMETRY,
                                                   $IOCTL_TIMEOUT_SEC, [int]$required, [ref]$rc)
        } catch {
            # Keep the truncated first snapshot rather than losing everything.
            Write-Warning "${path}: full-size query of $required bytes failed: $(Get-ErrorText $_)"
        }
    }
    if ($rc -eq $VIOSCSI_TELEMETRY_RC_TRUNCATED) {
        Write-Warning "$path returned a truncated snapshot; showing the queues that fit"
    }
    return ,$data
}

function Get-HistogramPercentileUs([uint64[]]$Buckets, [double]$Fraction) {
    # Bucket N holds [2^N, 2^(N+1)) us (bucket 0 also holds 0), so report the upper bound.
    $total = [uint64]0
    foreach ($b in $Buckets) { $total += $b }
    if ($total -eq 0) { return $null }
    $target = [math]::Ceiling($total * $Fraction)
    $seen = [uint64]0
    for ($i = 0; $i -lt $Buckets.Length; $i++) {
        $seen += $Buckets[$i]
        if ($seen -ge $target) { return [math]::Pow(2, $i + 1) }
    }
    return [math]::Pow(2, $Buckets.Length)
}

function ConvertFrom-VioScsiTelemetry([byte[]]$Data, [string]$Source) {
    if ($Data.Length -lt $HEADER_FIXED_SIZE) {
        throw "${Source}: snapshot is only $($Data.Length) bytes, too short for a telemetry header"
    }
    $magic = [BitConverter]::ToUInt32($Data, 0)
    if ($magic -ne $STOR_TELEMETRY_MAGIC) {
        throw ("${Source}: bad telemetry magic 0x{0:X8}, expected 0x{1:X8}" -f $magic, $STOR_TELEMETRY_MAGIC)
    }
    $version = [BitConverter]::ToUInt32($Data, 4)
    if ($version -lt $STOR_TELEMETRY_MIN_VERSION) {
        throw "${Source}: telemetry version $version is not supported (need $STOR_TELEMETRY_MIN_VERSION or later)"
    }
    $headerSize = [BitConverter]::ToUInt32($Data, 8)
    $queueSize = [BitConverter]::ToUInt32($Data, 12)
    $queueCount = [BitConverter]::ToUInt32($Data, 16)
    $latencyBuckets = [int][BitConverter]::ToUInt32($Data, 20)
    $statusSlots = [int][BitConverter]::ToUInt32($Data, 24)

    # QUEUE_TELEMETRY field offsets; the arrays are sized by the header so these follow them.
    $offLatencyCount = 56 + 8 * $latencyBuckets
    $offStatus = $offLatencyCount + 32
    $offHwm = $offStatus + 8 * $statusSlots
    $offQueueFull = $offHwm + 8
    if ($headerSize -lt $HEADER_V3_SIZE -or $queueSize -lt ($offQueueFull + 8) -or $Data.Length -lt $headerSize) {
        throw "${Source}: inconsistent telemetry header (HeaderSize=$headerSize QueueSize=$queueSize, $($Data.Length) bytes)"
    }
    $available = [uint32][math]::Floor(($Data.Length - $headerSize) / $queueSize)
    if ($available -lt $queueCount) {
        Write-Warning "${Source}: snapshot holds $available of $queueCount queues"
        $queueCount = $available
    }

    $u64 = { param($Offset) [BitConverter]::ToUInt64($Data, $Offset) }
    $u64Array = {
        param($Offset, $Count)
        $a = New-Object 'uint64[]' $Count
        for ($i = 0; $i -lt $Count; $i++) { $a[$i] = [BitConverter]::ToUInt64($Data, $Offset + 8 * $i) }
        ,$a
    }

    $queues = for ($q = 0; $q -lt $queueCount; $q++) {
        $base = $headerSize + $q * $queueSize
        $buckets = & $u64Array ($base + 56) $latencyBuckets
        $count = & $u64 ($base + $offLatencyCount)
        $sum = & $u64 ($base + $offLatencyCount + 8)
        [PSCustomObject]@{
            Queue           = $q
            Reads           = & $u64 ($base + 0)
            Writes          = & $u64 ($base + 8)
            Flushes         = & $u64 ($base + 16)
            Unmaps          = & $u64 ($base + 24)
            Other           = & $u64 ($base + 32)
            ReadBytes       = & $u64 ($base + 40)
            WriteBytes      = & $u64 ($base + 48)
            Completions     = $count
            LatencySumUs    = $sum
            AvgUs           = $(if ($count) { [math]::Round($sum / $count, 1) } else { $null })
            MinUs           = & $u64 ($base + $offLatencyCount + 16)
            MaxUs           = & $u64 ($base + $offLatencyCount + 24)
            P50Us           = Get-HistogramPercentileUs $buckets 0.50
            P99Us           = Get-HistogramPercentileUs $buckets 0.99
            InFlightHwm     = [BitConverter]::ToUInt32($Data, $base + $offHwm)
            QueueFull       = & $u64 ($base + $offQueueFull)
            LatencyBuckets  = $buckets
            StatusHistogram = & $u64Array ($base + $offStatus) $statusSlots
        }
    }
    $queues = @($queues)

    # Totals across queues; histograms are summed so percentiles stay meaningful.
    $totalBuckets = New-Object 'uint64[]' $latencyBuckets
    $totalStatus = New-Object 'uint64[]' $statusSlots
    $total = [ordered]@{ Queue = 'Total'; Reads = [uint64]0; Writes = [uint64]0; Flushes = [uint64]0; Unmaps = [uint64]0
                         Other = [uint64]0; ReadBytes = [uint64]0; WriteBytes = [uint64]0; Completions = [uint64]0
                         LatencySumUs = [uint64]0; MinUs = [uint64]0; MaxUs = [uint64]0; InFlightHwm = [uint32]0
                         QueueFull = [uint64]0 }
    foreach ($q in $queues) {
        foreach ($f in 'Reads', 'Writes', 'Flushes', 'Unmaps', 'Other', 'ReadBytes', 'WriteBytes', 'Completions',
                       'LatencySumUs', 'QueueFull') {
            $total[$f] += $q.$f
        }
        if ($q.MinUs -and (-not $total.MinUs -or $q.MinUs -lt $total.MinUs)) { $total.MinUs = $q.MinUs }
        if ($q.MaxUs -gt $total.MaxUs) { $total.MaxUs = $q.MaxUs }
        if ($q.InFlightHwm -gt $total.InFlightHwm) { $total.InFlightHwm = $q.InFlightHwm }
        for ($i = 0; $i -lt $latencyBuckets; $i++) { $totalBuckets[$i] += $q.LatencyBuckets[$i] }
        for ($i = 0; $i -lt $statusSlots; $i++) { $totalStatus[$i] += $q.StatusHistogram[$i] }
    }
    $total.AvgUs = $(if ($total.Completions) { [math]::Round($total.LatencySumUs / $total.Completions, 1) } else { $null })
    $total.P50Us = Get-HistogramPercentileUs $totalBuckets 0.50
    $total.P99Us = Get-HistogramPercentileUs $totalBuckets 0.99
    $total.LatencyBuckets = $totalBuckets
    $total.StatusHistogram = $totalStatus

    $status = [ordered]@{}
    for ($i = 0; $i -lt $statusSlots; $i++) {
        if ($totalStatus[$i]) {
            $name = $(if ($SrbStatusNames.ContainsKey($i)) { $SrbStatusNames[$i] } else { '0x{0:X2}' -f $i })
            $status[$name] = $totalStatus[$i]
        }
    }

    [PSCustomObject]@{
        Source                      = $Source
        Version                     = $version
        QueueCount                  = $queueCount
        BusResetCount               = & $u64 32
        DeviceResetCount            = & $u64 40
        LogicalUnitResetCount       = & $u64 48
        LastResetDurationUs         = & $u64 56
        MaxResetDurationUs          = & $u64 64
        DeviceResetTmfInFlightCount = & $u64 72
        Queues                      = $queues
        Total                       = [PSCustomObject]$total
        Status                      = [PSCustomObject]$status
    }
}

function Format-Us($Us) {
    if ($null -eq $Us) { return '-' }
    if ($Us -ge 1000000) { return '{0:N1}s' -f ($Us / 1000000) }
    if ($Us -ge 1000) { return '{0:N1}ms' -f ($Us / 1000) }
    return '{0:N0}us' -f $Us
}

function Write-TelemetrySummary($T) {
    $rows = @($T.Queues | Where-Object { $All -or $_.Completions -or $_.QueueFull }) + $T.Total
    Write-Host ''
    Write-Host ("== {0}  (telemetry v{1}, {2} queues)" -f $T.Source, $T.Version, $T.QueueCount)
    Write-Host ("Resets: bus {0}, device {1}, LUN {2}; last {3}, max {4}; DeviceReset with TMF in flight {5}" -f
                $T.BusResetCount, $T.DeviceResetCount, $T.LogicalUnitResetCount,
                (Format-Us $T.LastResetDurationUs), (Format-Us $T.MaxResetDurationUs), $T.DeviceResetTmfInFlightCount)
    $rows | Format-Table -AutoSize -Property Queue, Reads, Writes, Flushes, Unmaps, Other,
        @{ n = 'ReadMB'; e = { '{0:N1}' -f ($_.ReadBytes / 1MB) }; a = 'right' },
        @{ n = 'WriteMB'; e = { '{0:N1}' -f ($_.WriteBytes / 1MB) }; a = 'right' },
        @{ n = 'Avg'; e = { Format-Us $_.AvgUs }; a = 'right' },
        @{ n = 'Min'; e = { Format-Us $(if ($_.Completions) { $_.MinUs }) }; a = 'right' },
        @{ n = 'Max'; e = { Format-Us $(if ($_.Completions) { $_.MaxUs }) }; a = 'right' },
        @{ n = 'p50<='; e = { Format-Us $_.P50Us }; a = 'right' },
        @{ n = 'p99<='; e = { Format-Us $_.P99Us }; a = 'right' },
        @{ n = 'HWM'; e = { $_.InFlightHwm } },
        @{ n = 'QFull'; e = { $_.QueueFull } } | Out-Host
    $statusText = ($T.Status.PSObject.Properties | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ', '
    Write-Host ("SRB status: {0}" -f $(if ($statusText) { $statusText } else { '(none)' }))
}

function Write-Result($Telemetry) {
    if ($PassThru) { $Telemetry } else { Write-TelemetrySummary $Telemetry }
}

if ($InputFile) {
    $path = (Resolve-Path $InputFile).Path
    Write-Result (ConvertFrom-VioScsiTelemetry ([IO.File]::ReadAllBytes($path)) $path)
    return
}

$ports = $(if ($Port) { $Port } else { @(Get-VioScsiPorts) })
if (-not $ports) {
    Write-Warning 'No vioscsi adapters found under HKLM:\HARDWARE\DEVICEMAP\Scsi'
    return
}
if ($SaveRaw) {
    # .NET file APIs resolve relative paths against the process directory, not $PWD.
    $SaveRaw = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SaveRaw)
    if (-not (Test-Path $SaveRaw)) {
        New-Item -ItemType Directory -Path $SaveRaw | Out-Null
    }
}

foreach ($p in $ports) {
    $source = "\\.\Scsi${p}:"
    try {
        $data = Invoke-TelemetryQuery $p
    } catch {
        Write-Warning "${source}: $(Get-ErrorText $_)"
        continue
    }
    # Save before parsing so the raw blob is still available when parsing fails.
    if ($SaveRaw) {
        $file = Join-Path $SaveRaw ("vioscsi-telemetry-scsi{0}-{1:yyyyMMdd-HHmmss}.bin" -f $p, (Get-Date))
        [IO.File]::WriteAllBytes($file, $data)
        Write-Verbose "Saved $file"
    }
    try {
        $telemetry = ConvertFrom-VioScsiTelemetry $data $source
    } catch {
        Write-Warning "${source}: $(Get-ErrorText $_)"
        continue
    }
    Write-Result $telemetry
}
