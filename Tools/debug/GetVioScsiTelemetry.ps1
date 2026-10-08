<#
.SYNOPSIS
    Read and summarize vioscsi per-queue and per-target I/O, latency and error telemetry.

.DESCRIPTION
    Queries every vioscsi adapter in the running system with an IOCTL_SCSI_MINIPORT
    request and prints a summary of the driver's STOR_TELEMETRY block: reset counts,
    then per-queue I/O counts, bytes, latency (avg/min/max and approximate p50/p99 from
    the log2 histogram), in-flight high-water mark and queue-full count, and a
    non-zero SRB status histogram. Stall indicators are the in-flight count, the age of
    the oldest in-flight request, the time since the last completion, counts of requests
    slower than 1s/5s/30s, and the time since the last reset. A request that never
    completes is not in the latency figures, so look at the oldest in-flight age when
    chasing storage timeouts.

    Requests of one SCSI target are spread over all queues, so on an adapter with several
    targets the per-queue view cannot say which disk has the problem. The per-target
    section lists each active target with its I/O counts, latency, stall indicators and
    error counters (BUSY, ABORTED/BUS_RESET, NO_DEVICE, other errors, INVALID_TARGET_ID),
    and flags a target that has requests in flight but none completing (STALLED: oldest
    request outstanding 5 seconds or more). Counters are cumulative since the adapter was
    started; take two snapshots to compute rates.

    From telemetry version 6 it also reports descriptor ownership: requests a reset completed
    while the device still held them, SRB extensions reused while the device still referenced
    them, requests the device returned that no request list held, and requests refused for a
    scatter/gather list that would have produced a zero-length or truncated descriptor chain.
    The individual occurrences are in the adapter's event ring, which only a kernel dump shows
    (Tools/debug/vioscsi_telemetry.js, !vioscsi_events).

    Requires Administrator rights and a vioscsi driver with telemetry version 5 or
    later. A blob saved with -SaveRaw can be parsed later, on any machine, with -InputFile.

.PARAMETER Port
    Query only these \\.\ScsiN: port numbers instead of every vioscsi adapter.

.PARAMETER All
    Also list queues that have not completed any request and targets with no activity.

.PARAMETER PassThru
    Emit one object per adapter instead of printing a summary. Its Queues and Targets
    properties hold one object per queue and per reported target.

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

.EXAMPLE
    (.\GetVioScsiTelemetry.ps1 -PassThru)[0].Targets | Where-Object Stalled
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
$STOR_TELEMETRY_MIN_VERSION     = 5
# STOR_TELEMETRY header: Magic, Version, HeaderSize, QueueSize, QueueCount, TargetSize,
# TargetCount, TargetsOffset, LatencyBuckets, StatusSlots, Reserved[2] (12 ULONGs), then the
# adapter-wide ULONG64s up to TargetScanTime. The first 28 bytes are enough to size a retry.
$HEADER_SIZE_FIELDS             = 28
$HEADER_MIN_SIZE                = 128
# Version 6 appends ten ULONG64s: EarlyCompletedCount, ExtReusedWhileOwnedCount,
# OrphanReturnCount, OrphanUnexplainedCount, OrphanIntoReusedExtCount, ZombieEvictedCount,
# SgZeroLengthCount, SgTooManyElementsCount, SgLengthMismatchCount, ZeroLengthDescCount.
$HEADER_V6_SIZE                 = 208
# QUEUE_TELEMETRY ends with 56 bytes after QueueFullCount: OldestInFlightTime,
# LastCompletionTime, MaxLatencyTime, Slow1s/5s/30sCount (ULONG64s), InFlightCount and a
# ULONG of padding.
$QUEUE_TAIL_SIZE                = 56
# TARGET_TELEMETRY: TargetId, InFlightCount (ULONGs), then 22 ULONG64s.
$TARGET_MIN_SIZE                = 184
# Timestamps are interrupt time in 100 ns units; ages are taken against SnapshotTime.
$HNS_PER_US                     = 10
# A request outstanding this long is flagged in the summary.
$STALL_WARN_US                  = 5000000
$INITIAL_QUERY_SIZE             = 4096
$MAX_QUERY_ATTEMPTS             = 3
# Upper bound for a retry: the header plus 256 queues plus 256 targets is well under this.
$MAX_SNAPSHOT_SIZE              = 1MB
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
    # The header tells us how large the full snapshot is; ask again with that size. The set of
    # active targets can grow between queries, so allow for a few retries.
    $attempt = 0
    while ($rc -eq $VIOSCSI_TELEMETRY_RC_TRUNCATED -and $data.Length -ge $HEADER_SIZE_FIELDS -and $attempt -lt $MAX_QUERY_ATTEMPTS) {
        $attempt++
        $required = [uint64][BitConverter]::ToUInt32($data, 8) +
                    [uint64][BitConverter]::ToUInt32($data, 12) * [BitConverter]::ToUInt32($data, 16) +
                    [uint64][BitConverter]::ToUInt32($data, 20) * [BitConverter]::ToUInt32($data, 24)
        # Leave room for a few more targets turning active between the two queries.
        $required += 4 * [uint64][BitConverter]::ToUInt32($data, 20)
        if ($required -le $data.Length -or $required -gt $MAX_SNAPSHOT_SIZE) { break }
        try {
            $data = [VioScsiTelemetryIoctl]::Query($path, $VIOSCSI_IOCTL_SIGNATURE, $VIOSCSI_IOCTL_QUERY_TELEMETRY,
                                                   $IOCTL_TIMEOUT_SEC, [int]$required, [ref]$rc)
        } catch {
            # Keep the truncated snapshot rather than losing everything.
            Write-Warning "${path}: full-size query of $required bytes failed: $(Get-ErrorText $_)"
            break
        }
    }
    if ($rc -eq $VIOSCSI_TELEMETRY_RC_TRUNCATED) {
        Write-Warning "$path returned a truncated snapshot; showing the queues and targets that fit"
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

function Get-AgeUs($Now, $Then) {
    # Timestamps are interrupt time in 100 ns units, 0 meaning never/none. A request queued just
    # after the snapshot time was taken can be slightly newer than it, so clamp to 0.
    if (-not $Now -or -not $Then) { return $null }
    if ($Then -ge $Now) { return [uint64]0 }
    return [uint64][math]::Floor(($Now - $Then) / $HNS_PER_US)
}

function ConvertFrom-VioScsiTelemetry([byte[]]$Data, [string]$Source) {
    if ($Data.Length -lt $HEADER_MIN_SIZE) {
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
    $targetSize = [BitConverter]::ToUInt32($Data, 20)
    $targetCount = [BitConverter]::ToUInt32($Data, 24)
    $targetsOffset = [BitConverter]::ToUInt32($Data, 28)
    $latencyBuckets = [int][BitConverter]::ToUInt32($Data, 32)
    $statusSlots = [int][BitConverter]::ToUInt32($Data, 36)

    # QUEUE_TELEMETRY field offsets; the arrays are sized by the header so these follow them.
    $offLatencyCount = 56 + 8 * $latencyBuckets
    $offStatus = $offLatencyCount + 32
    $offHwm = $offStatus + 8 * $statusSlots
    $offQueueFull = $offHwm + 8
    $offTail = $offQueueFull + 8
    $minQueue = $offTail + $QUEUE_TAIL_SIZE
    if ($headerSize -lt $HEADER_MIN_SIZE -or $queueSize -lt $minQueue -or $targetSize -lt $TARGET_MIN_SIZE -or
        $targetsOffset -lt $headerSize -or $Data.Length -lt $headerSize) {
        throw ("${Source}: inconsistent telemetry header (HeaderSize=$headerSize QueueSize=$queueSize " +
               "TargetSize=$targetSize TargetsOffset=$targetsOffset, $($Data.Length) bytes)")
    }
    $availableQueues = [uint32][math]::Floor(($Data.Length - $headerSize) / $queueSize)
    if ($availableQueues -lt $queueCount) {
        Write-Warning "${Source}: snapshot holds $availableQueues of $queueCount queues"
        $queueCount = $availableQueues
    }
    # The target table follows the queues in a snapshot, but is located by TargetsOffset so a
    # table that doesn't start right after them (the in-memory layout) reads correctly too.
    $availableTargets = $(if ($Data.Length -gt $targetsOffset) {
                              [uint32][math]::Floor(($Data.Length - $targetsOffset) / $targetSize)
                          } else { [uint32]0 })
    if ($availableTargets -lt $targetCount) {
        Write-Warning "${Source}: snapshot holds $availableTargets of $targetCount targets"
        $targetCount = $availableTargets
    }

    $u64 = { param($Offset) [BitConverter]::ToUInt64($Data, $Offset) }
    $u64Array = {
        param($Offset, $Count)
        $a = New-Object 'uint64[]' $Count
        for ($i = 0; $i -lt $Count; $i++) { $a[$i] = [BitConverter]::ToUInt64($Data, $Offset + 8 * $i) }
        ,$a
    }

    # Ages are relative to the time the driver took the snapshot (interrupt time, 100 ns units).
    $snapshotTime = & $u64 104
    $targetScanTime = & $u64 120

    $queues = for ($q = 0; $q -lt $queueCount; $q++) {
        $base = $headerSize + $q * $queueSize
        $buckets = & $u64Array ($base + 56) $latencyBuckets
        $count = & $u64 ($base + $offLatencyCount)
        $sum = & $u64 ($base + $offLatencyCount + 8)
        [PSCustomObject]@{
            Queue               = $q
            Reads               = & $u64 ($base + 0)
            Writes              = & $u64 ($base + 8)
            Flushes             = & $u64 ($base + 16)
            Unmaps              = & $u64 ($base + 24)
            Other               = & $u64 ($base + 32)
            ReadBytes           = & $u64 ($base + 40)
            WriteBytes          = & $u64 ($base + 48)
            Completions         = $count
            LatencySumUs        = $sum
            AvgUs               = $(if ($count) { [math]::Round($sum / $count, 1) } else { $null })
            MinUs               = & $u64 ($base + $offLatencyCount + 16)
            MaxUs               = & $u64 ($base + $offLatencyCount + 24)
            P50Us               = Get-HistogramPercentileUs $buckets 0.50
            P99Us               = Get-HistogramPercentileUs $buckets 0.99
            InFlightHwm         = [BitConverter]::ToUInt32($Data, $base + $offHwm)
            QueueFull           = & $u64 ($base + $offQueueFull)
            InFlight            = [BitConverter]::ToUInt32($Data, $base + $offTail + 48)
            OldestInFlightAgeUs = Get-AgeUs $snapshotTime (& $u64 ($base + $offTail))
            LastCompletionAgeUs = Get-AgeUs $snapshotTime (& $u64 ($base + $offTail + 8))
            MaxLatencyAgeUs     = Get-AgeUs $snapshotTime (& $u64 ($base + $offTail + 16))
            Slow1s              = & $u64 ($base + $offTail + 24)
            Slow5s              = & $u64 ($base + $offTail + 32)
            Slow30s             = & $u64 ($base + $offTail + 40)
            LatencyBuckets      = $buckets
            StatusHistogram     = & $u64Array ($base + $offStatus) $statusSlots
        }
    }
    $queues = @($queues)

    # TARGET_TELEMETRY: offsets are fixed (no variable-size arrays), see vioscsi.h.
    # @() around the loop: with no targets it must stay an empty array, not become @($null).
    $targets = @(for ($t = 0; $t -lt $targetCount; $t++) {
        $base = $targetsOffset + $t * $targetSize
        $inFlight = [BitConverter]::ToUInt32($Data, $base + 4)
        $reads = & $u64 ($base + 8)
        $writes = & $u64 ($base + 16)
        $other = & $u64 ($base + 24)
        $latencyCount = & $u64 ($base + 64)
        $latencySum = & $u64 ($base + 72)
        $oldestAge = $(if ($targetScanTime) { Get-AgeUs $snapshotTime (& $u64 ($base + 48)) } else { $null })
        $lastCompletionAge = Get-AgeUs $snapshotTime (& $u64 ($base + 56))
        # Stalled: requests are outstanding and the oldest has waited too long. A request that
        # arrived after the driver's scan has no oldest age yet and is too young to judge. Only a
        # blob that was never scanned has to fall back to the time since the last completion.
        $stallReason = $null
        if ($inFlight) {
            if ($targetScanTime) {
                if ($null -ne $oldestAge -and $oldestAge -ge $STALL_WARN_US) {
                    $stallReason = "oldest request outstanding $(Format-Us $oldestAge)"
                }
            } elseif ($null -ne $lastCompletionAge -and $lastCompletionAge -ge $STALL_WARN_US) {
                $stallReason = "no completion for $(Format-Us $lastCompletionAge)"
            }
        }
        [PSCustomObject]@{
            Target              = [BitConverter]::ToUInt32($Data, $base)
            InFlight            = $inFlight
            OldestInFlightAgeUs = $(if ($inFlight) { $oldestAge } else { $null })
            LastCompletionAgeUs = $lastCompletionAge
            Stalled             = [bool]$stallReason
            StallReason         = $stallReason
            Reads               = $reads
            Writes              = $writes
            Other               = $other
            ReadBytes           = & $u64 ($base + 32)
            WriteBytes          = & $u64 ($base + 40)
            Completions         = $latencyCount
            LatencySumUs        = $latencySum
            AvgUs               = $(if ($latencyCount) { [math]::Round($latencySum / $latencyCount, 1) } else { $null })
            MaxUs               = & $u64 ($base + 80)
            MaxLatencyAgeUs     = Get-AgeUs $snapshotTime (& $u64 ($base + 88))
            Slow1s              = & $u64 ($base + 96)
            Slow5s              = & $u64 ($base + 104)
            Slow30s             = & $u64 ($base + 112)
            Busy                = & $u64 ($base + 120)
            Aborted             = & $u64 ($base + 128)
            NoDevice            = & $u64 ($base + 136)
            Errors              = & $u64 ($base + 144)
            InvalidTarget       = & $u64 ($base + 152)
            DeviceResets        = & $u64 ($base + 160)
            LunResets           = & $u64 ($base + 168)
            LastResetAgeUs      = Get-AgeUs $snapshotTime (& $u64 ($base + 176))
        }
    })

    # Totals across queues; histograms are summed so percentiles stay meaningful.
    $totalBuckets = New-Object 'uint64[]' $latencyBuckets
    $totalStatus = New-Object 'uint64[]' $statusSlots
    $total = [ordered]@{ Queue = 'Total'; Reads = [uint64]0; Writes = [uint64]0; Flushes = [uint64]0; Unmaps = [uint64]0
                         Other = [uint64]0; ReadBytes = [uint64]0; WriteBytes = [uint64]0; Completions = [uint64]0
                         LatencySumUs = [uint64]0; MinUs = [uint64]0; MaxUs = [uint64]0; InFlightHwm = [uint32]0
                         QueueFull = [uint64]0; InFlight = [uint64]0; OldestInFlightAgeUs = $null
                         LastCompletionAgeUs = $null; MaxLatencyAgeUs = $null
                         Slow1s = [uint64]0; Slow5s = [uint64]0; Slow30s = [uint64]0 }
    foreach ($q in $queues) {
        foreach ($f in 'Reads', 'Writes', 'Flushes', 'Unmaps', 'Other', 'ReadBytes', 'WriteBytes', 'Completions',
                       'LatencySumUs', 'QueueFull', 'InFlight', 'Slow1s', 'Slow5s', 'Slow30s') {
            $total[$f] += $q.$f
        }
        # Oldest request: the largest age. Last completion: the smallest age (most recent).
        if ($null -ne $q.OldestInFlightAgeUs -and
            ($null -eq $total.OldestInFlightAgeUs -or $q.OldestInFlightAgeUs -gt $total.OldestInFlightAgeUs)) {
            $total.OldestInFlightAgeUs = $q.OldestInFlightAgeUs
        }
        if ($null -ne $q.LastCompletionAgeUs -and
            ($null -eq $total.LastCompletionAgeUs -or $q.LastCompletionAgeUs -lt $total.LastCompletionAgeUs)) {
            $total.LastCompletionAgeUs = $q.LastCompletionAgeUs
        }
        # The max latency time belongs to the queue holding the overall max.
        if ($q.MaxUs -gt $total.MaxUs) { $total.MaxLatencyAgeUs = $q.MaxLatencyAgeUs }
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

    # Descriptor ownership and request validation counters, $null before version 6.
    $v6 = ($version -ge 6 -and $headerSize -ge $HEADER_V6_SIZE -and $Data.Length -ge $HEADER_V6_SIZE)
    $v6u64 = { param($Offset) if ($v6) { & $u64 $Offset } else { $null } }

    [PSCustomObject]@{
        Source                      = $Source
        Version                     = $version
        QueueCount                  = $queueCount
        TargetCount                 = $targetCount
        BusResetCount               = & $u64 48
        DeviceResetCount            = & $u64 56
        LogicalUnitResetCount       = & $u64 64
        LastResetDurationUs         = & $u64 72
        MaxResetDurationUs          = & $u64 80
        DeviceResetTmfInFlightCount = & $u64 88
        LastResetTime               = & $u64 96
        LastResetAgeUs              = Get-AgeUs $snapshotTime (& $u64 96)
        OutOfRangeTargetCount       = & $u64 112
        EarlyCompletedCount         = & $v6u64 128
        ExtReusedWhileOwnedCount    = & $v6u64 136
        OrphanReturnCount           = & $v6u64 144
        OrphanUnexplainedCount      = & $v6u64 152
        OrphanIntoReusedExtCount    = & $v6u64 160
        ZombieEvictedCount          = & $v6u64 168
        SgZeroLengthCount           = & $v6u64 176
        SgTooManyElementsCount      = & $v6u64 184
        SgLengthMismatchCount       = & $v6u64 192
        ZeroLengthDescCount         = & $v6u64 200
        Queues                      = $queues
        Targets                     = $targets
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

function Format-Ago($Us) {
    if ($null -eq $Us) { return '-' }
    return "$(Format-Us $Us) ago"
}

function Test-TargetActive($Target) {
    # Deliberately narrower than StorPerfTargetActive() in the driver (which is what decides
    # whether a target is in the snapshot at all -- see vioscsi.c). That check also counts
    # Other/NoDevice/InvalidTarget/DeviceResets/LunResets, which a routine Windows bus rescan
    # trips for every unattached target ID it probes -- including InvalidTarget: the device
    # answers VIRTIO_SCSI_S_BAD_TARGET (-> SRB_STATUS_INVALID_TARGET_ID) for any in-range ID
    # with nothing behind it, so practically every unattached target racks one up during
    # enumeration. None of that means a real device, so a target only gets its own row here if
    # it did real I/O or is currently stuck in flight (so a stall with zero completions is still
    # visible). InvalidTarget still shows as a column for any row included for one of those
    # reasons; it just isn't a reason to include a row by itself.
    return [bool]($Target.Reads -or $Target.Writes -or $Target.InFlight)
}

function Write-TelemetrySummary($T) {
    $rows = @($T.Queues | Where-Object { $All -or $_.Completions -or $_.QueueFull -or $_.InFlight }) + $T.Total
    Write-Host ''
    Write-Host ("== {0}  (telemetry v{1}, {2} queues, {3} targets reported)" -f
                $T.Source, $T.Version, $T.QueueCount, $T.TargetCount)
    Write-Host ("Resets: bus {0}, device {1}, LUN {2}; last {3}, max {4}; DeviceReset with TMF in flight {5}" -f
                $T.BusResetCount, $T.DeviceResetCount, $T.LogicalUnitResetCount,
                (Format-Us $T.LastResetDurationUs), (Format-Us $T.MaxResetDurationUs), $T.DeviceResetTmfInFlightCount)
    # No age means either no reset yet (time 0) or no time reference to measure it against.
    $lastReset = $(if ($null -ne $T.LastResetAgeUs) { Format-Ago $T.LastResetAgeUs }
                   elseif ($T.LastResetTime) { 'unknown' } else { 'never' })
    Write-Host ("Last reset: {0}" -f $lastReset)
    if ($T.OutOfRangeTargetCount) {
        Write-Host ("Requests refused for a target ID beyond the device's maximum: {0}" -f $T.OutOfRangeTargetCount)
    }
    if ($null -ne $T.EarlyCompletedCount) {
        # Always shown from version 6: zeros here rule out early completion as the cause of a
        # broken virtqueue.
        Write-Host ("Descriptor ownership: completed while the device held them {0}; extension reused while still referenced {1}" -f
                    $T.EarlyCompletedCount, $T.ExtReusedWhileOwnedCount)
        Write-Host ("Returned by the device but on no request list: {0} (never completed early {1}, into a reused extension {2}; forgotten, table full {3})" -f
                    $T.OrphanReturnCount, $T.OrphanUnexplainedCount, $T.OrphanIntoReusedExtCount, $T.ZombieEvictedCount)
        if ($T.SgZeroLengthCount -or $T.SgTooManyElementsCount -or $T.SgLengthMismatchCount -or $T.ZeroLengthDescCount) {
            Write-Host ("Scatter/gather: refused zero-length element {0}, too many elements {1}; length mismatch {2}; zero-length descriptor published {3}" -f
                        $T.SgZeroLengthCount, $T.SgTooManyElementsCount, $T.SgLengthMismatchCount, $T.ZeroLengthDescCount)
        }
    }
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
    Write-Host ''
    Write-Host 'Stall indicators (ages are relative to the snapshot time):'
    $rows | Format-Table -AutoSize -Property Queue,
        @{ n = 'InFlight'; e = { $_.InFlight } },
        @{ n = 'OldestInFlight'; e = { Format-Us $_.OldestInFlightAgeUs }; a = 'right' },
        @{ n = 'LastCompletion'; e = { Format-Ago $_.LastCompletionAgeUs }; a = 'right' },
        @{ n = 'MaxLatencyAt'; e = { Format-Ago $_.MaxLatencyAgeUs }; a = 'right' },
        @{ n = '>1s'; e = { $_.Slow1s } },
        @{ n = '>5s'; e = { $_.Slow5s } },
        @{ n = '>30s'; e = { $_.Slow30s } } | Out-Host
    foreach ($q in $T.Queues) {
        if ($q.InFlight -and $null -ne $q.OldestInFlightAgeUs -and $q.OldestInFlightAgeUs -ge $STALL_WARN_US) {
            Write-Host ("WARNING: queue {0} has {1} request(s) in flight, the oldest for {2}" -f
                        $q.Queue, $q.InFlight, (Format-Us $q.OldestInFlightAgeUs)) -ForegroundColor Yellow
        }
    }

    $targetRows = @($T.Targets | Where-Object { $All -or (Test-TargetActive $_) })
    if ($targetRows.Count -gt 0) {
        Write-Host ''
        Write-Host 'Per target (a target spans all queues):'
        $targetRows | Format-Table -AutoSize -Property Target,
            @{ n = 'State'; e = { if ($_.Stalled) { 'STALLED' } else { '' } } },
            @{ n = 'InFlight'; e = { $_.InFlight } },
            @{ n = 'OldestInFlight'; e = { Format-Us $_.OldestInFlightAgeUs }; a = 'right' },
            @{ n = 'LastCompletion'; e = { Format-Ago $_.LastCompletionAgeUs }; a = 'right' },
            Reads, Writes, Other,
            @{ n = 'ReadMB'; e = { '{0:N1}' -f ($_.ReadBytes / 1MB) }; a = 'right' },
            @{ n = 'WriteMB'; e = { '{0:N1}' -f ($_.WriteBytes / 1MB) }; a = 'right' },
            @{ n = 'Avg'; e = { Format-Us $_.AvgUs }; a = 'right' },
            @{ n = 'Max'; e = { Format-Us $(if ($_.Completions) { $_.MaxUs }) }; a = 'right' },
            @{ n = '>1s'; e = { $_.Slow1s } },
            @{ n = '>5s'; e = { $_.Slow5s } },
            @{ n = '>30s'; e = { $_.Slow30s } } | Out-Host
        Write-Host 'Per target errors and resets:'
        $targetRows | Format-Table -AutoSize -Property Target,
            Busy, Aborted, NoDevice, Errors, InvalidTarget,
            @{ n = 'DevResets'; e = { $_.DeviceResets } },
            @{ n = 'LunResets'; e = { $_.LunResets } },
            @{ n = 'LastReset'; e = { Format-Ago $_.LastResetAgeUs }; a = 'right' } | Out-Host
        # Not $t: PowerShell variable names are case-insensitive and this function's parameter is $T.
        foreach ($tgt in $targetRows) {
            if ($tgt.Stalled) {
                Write-Host ("WARNING: target {0} has {1} request(s) in flight, {2}" -f
                            $tgt.Target, $tgt.InFlight, $tgt.StallReason) -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host ''
        Write-Host 'No target has seen any I/O yet.'
    }
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
