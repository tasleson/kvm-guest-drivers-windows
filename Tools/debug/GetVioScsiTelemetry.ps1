<#
.SYNOPSIS
    Read and summarize vioscsi per-queue and per-target I/O, latency and error telemetry.

.DESCRIPTION
    Queries every vioscsi adapter in the running system over WMI (the root\wmi class
    VioScsiTelemetryGuid, its GetChunk method hands out the driver's live STOR_TELEMETRY
    block in chunks) and prints a summary: reset counts,
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

    Requires Administrator rights and a vioscsi driver with telemetry version 1. A blob saved
    with -SaveRaw can be parsed later, on any machine, with -InputFile.

.PARAMETER InstanceName
    Query only WMI instances whose InstanceName matches this (wildcard) pattern,
    instead of every vioscsi adapter.

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
    .\GetVioScsiTelemetry.ps1 -InstanceName '*PCIID*'

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
    [string]$InstanceName,
    [switch]$All,
    [switch]$PassThru,
    [string]$SaveRaw,
    [string]$InputFile
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Mirrors vioscsi/vioscsi.h and vioscsi/vioscsidt.h; keep in sync.
$STOR_TELEMETRY_MAGIC           = [uint32]0x53505331
$STOR_TELEMETRY_VERSION         = 1
# STOR_TELEMETRY header: Magic, Version, HeaderSize, QueueSize, QueueCount, TargetSize,
# TargetCount, TargetsOffset, LatencyBuckets, StatusSlots, QueueCapacity and Reserved (12
# ULONGs), then the adapter-wide ULONG64s up to TargetScanTime, then StatusCodes[StatusSlots]
# (UCHARs, at offset 128), which makes HeaderSize 144.
$STATUS_CODES_OFFSET            = 128
# StatusCodes value of the catch-all last slot (STOR_TELEMETRY_STATUS_OTHER).
$STATUS_CODE_OTHER              = 0xFF
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
# VIOSCSI_TELEMETRY_MAX_CHUNK: the largest chunk the WMI GetChunk method returns.
$CHUNK_SIZE                     = 4096
# Upper bound for a full read: the header plus 256 queue slots (608 bytes each) plus 256 targets
# is about 200 KB, well under this.
$MAX_SNAPSHOT_SIZE              = 1MB

# Keyed by SRB_STATUS_* with SRB_STATUS_QUEUE_FROZEN/AUTOSENSE_VALID masked off (srb.h).
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

function Get-VioScsiTelemetryInstances {
    # One instance per vioscsi adapter that has WMI telemetry. Needs Administrator rights.
    $instances = @(Get-CimInstance -Namespace root\wmi -ClassName VioScsiTelemetryGuid -ErrorAction Stop)
    if ($InstanceName) {
        $instances = @($instances | Where-Object { $_.InstanceName -like $InstanceName })
    }
    return $instances
}

function Get-ErrorText($ErrorRecord) {
    # CIM errors can arrive wrapped in an inner exception; surface that message when present.
    $e = $ErrorRecord.Exception
    if ($e.InnerException) { $e = $e.InnerException }
    return $e.Message
}

function Invoke-TelemetryRead($Instance) {
    # Reads the adapter's full live STOR_TELEMETRY block through the WMI GetChunk method:
    # the first call (Offset 0) also refreshes SnapshotTime and per-target OldestInFlightTime
    # in the driver, then chunks are appended until ChunkLength comes back 0.
    $first = Invoke-CimMethod -InputObject $Instance -MethodName GetChunk `
                              -Arguments @{ Offset = [uint32]0; Length = [uint32]$CHUNK_SIZE } -ErrorAction Stop
    $total = [uint32]$first.TotalSize
    if ($total -gt $MAX_SNAPSHOT_SIZE) {
        throw "telemetry block of $total bytes exceeds the $($MAX_SNAPSHOT_SIZE) byte bound"
    }
    $blob = New-Object System.Collections.Generic.List[byte]
    $chunk = $first
    while ($true) {
        $length = [uint32]$chunk.ChunkLength
        if ($length -eq 0) { break }
        if ($null -ne $chunk.Data) {
            # Data is sized by WmiSizeIs("ChunkLength"), but never trust it past that.
            $take = [int][math]::Min($length, $chunk.Data.Length)
            for ($i = 0; $i -lt $take; $i++) { $blob.Add($chunk.Data[$i]) }
        }
        if ($blob.Count -ge $total) { break }
        $chunk = Invoke-CimMethod -InputObject $Instance -MethodName GetChunk `
                                  -Arguments @{ Offset = [uint32]$blob.Count; Length = [uint32]$CHUNK_SIZE } -ErrorAction Stop
    }
    if ($blob.Count -lt $total) {
        throw "telemetry read stopped at $($blob.Count) of $total bytes"
    }
    return ,$blob.ToArray()
}

function Get-HistogramPercentileUs([uint64[]]$Buckets, [double]$Fraction) {
    # Bucket N holds [2^N, 2^(N+1)) us (bucket 0 also holds 0), so report the upper bound. The last
    # bucket also holds everything above its range, so its bound is only a lower limit.
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
    # after the read was started can be slightly newer than it, so clamp to 0.
    if (-not $Now -or -not $Then) { return $null }
    if ($Then -ge $Now) { return [uint64]0 }
    return [uint64][math]::Floor(($Now - $Then) / $HNS_PER_US)
}

function ConvertFrom-VioScsiTelemetry([byte[]]$Data, [string]$Source) {
    if ($Data.Length -lt $STATUS_CODES_OFFSET) {
        throw "${Source}: blob is only $($Data.Length) bytes, too short for a telemetry header"
    }
    $magic = [BitConverter]::ToUInt32($Data, 0)
    if ($magic -ne $STOR_TELEMETRY_MAGIC) {
        throw ("${Source}: bad telemetry magic 0x{0:X8}, expected 0x{1:X8}" -f $magic, $STOR_TELEMETRY_MAGIC)
    }
    $version = [BitConverter]::ToUInt32($Data, 4)
    if ($version -ne $STOR_TELEMETRY_VERSION) {
        throw "${Source}: telemetry version $version is not supported (need $STOR_TELEMETRY_VERSION)"
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
    # StatusCodes[StatusSlots] follows the 128-byte fixed part of the header.
    $minHeader = $STATUS_CODES_OFFSET + $statusSlots
    if ($statusSlots -lt 1 -or $latencyBuckets -lt 1 -or $headerSize -lt $minHeader -or $queueSize -lt $minQueue -or $targetSize -lt $TARGET_MIN_SIZE -or
        $targetsOffset -lt $headerSize -or $Data.Length -lt $headerSize) {
        throw ("${Source}: inconsistent telemetry header (StatusSlots=$statusSlots LatencyBuckets=$latencyBuckets " +
               "HeaderSize=$headerSize QueueSize=$queueSize " +
               "TargetSize=$targetSize TargetsOffset=$targetsOffset, $($Data.Length) bytes)")
    }
    $statusCodes = [byte[]]$Data[$STATUS_CODES_OFFSET..($STATUS_CODES_OFFSET + $statusSlots - 1)]
    # QueueCapacity (offset 40) is the number of queue slots the block was sized for, so a larger
    # QueueCount means a corrupt header.
    $queueCapacity = [BitConverter]::ToUInt32($Data, 40)
    if ($queueCount -gt $queueCapacity) {
        Write-Warning "${Source}: QueueCount $queueCount exceeds QueueCapacity $queueCapacity"
        $queueCount = $queueCapacity
    }
    $availableQueues = [uint32][math]::Floor(($Data.Length - $headerSize) / $queueSize)
    if ($availableQueues -lt $queueCount) {
        Write-Warning "${Source}: blob holds $availableQueues of $queueCount queues"
        $queueCount = $availableQueues
    }
    # The queue table has QueueCapacity slots but only the first QueueCount are valid; the target
    # table is located by TargetsOffset (after the full queue table).
    $availableTargets = $(if ($Data.Length -gt $targetsOffset) {
                              [uint32][math]::Floor(($Data.Length - $targetsOffset) / $targetSize)
                          } else { [uint32]0 })
    if ($availableTargets -lt $targetCount) {
        Write-Warning "${Source}: blob holds $availableTargets of $targetCount targets"
        $targetCount = $availableTargets
    }

    $u64 = { param($Offset) [BitConverter]::ToUInt64($Data, $Offset) }
    $u64Array = {
        param($Offset, $Count)
        $a = New-Object 'uint64[]' $Count
        for ($i = 0; $i -lt $Count; $i++) { $a[$i] = [BitConverter]::ToUInt64($Data, $Offset + 8 * $i) }
        ,$a
    }

    # Ages are relative to the time the driver started the read (interrupt time, 100 ns units).
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
            $code = [int]$statusCodes[$i]
            $name = $(if ($code -eq $STATUS_CODE_OTHER) { 'OTHER' }
                      elseif ($SrbStatusNames.ContainsKey($code)) { $SrbStatusNames[$code] }
                      else { '0x{0:X2}' -f $code })
            $status[$name] = $totalStatus[$i]
        }
    }

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
    # Mirrors StorPerfTargetActive() in the driver. The live table holds all 256 target IDs, so
    # this decides which ones are reported.
    return [bool]($Target.InFlight -or $Target.Reads -or $Target.Writes -or $Target.Other -or $Target.NoDevice -or
                  $Target.DeviceResets -or $Target.LunResets)
}

function Write-TelemetrySummary($T) {
    $rows = @($T.Queues | Where-Object { $All -or $_.Completions -or $_.QueueFull -or $_.InFlight }) + $T.Total
    Write-Host ''
    Write-Host ("== {0}  (telemetry v{1}, {2} queues, {3} target table entries)" -f
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
    Write-Host 'Stall indicators (ages are relative to the start of the read):'
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

try {
    $instances = @(Get-VioScsiTelemetryInstances)
} catch {
    Write-Warning "Cannot enumerate root\wmi class VioScsiTelemetryGuid (is the driver loaded and are you Administrator?): $(Get-ErrorText $_)"
    return
}
if (-not $instances) {
    if ($InstanceName) {
        Write-Warning "No VioScsiTelemetryGuid instance matches '$InstanceName'"
    } else {
        Write-Warning 'No vioscsi adapters expose the VioScsiTelemetryGuid WMI class'
    }
    return
}
if ($SaveRaw) {
    # .NET file APIs resolve relative paths against the process directory, not $PWD.
    $SaveRaw = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($SaveRaw)
    if (-not (Test-Path $SaveRaw)) {
        New-Item -ItemType Directory -Path $SaveRaw | Out-Null
    }
}

foreach ($instance in $instances) {
    $source = $instance.InstanceName
    try {
        $data = Invoke-TelemetryRead $instance
    } catch {
        Write-Warning "${source}: $(Get-ErrorText $_)"
        continue
    }
    # Save before parsing so the raw blob is still available when parsing fails.
    if ($SaveRaw) {
        # Instance names can hold characters that are not valid in file names.
        $safeName = $source -replace '[^\w.-]', '_'
        $file = Join-Path $SaveRaw ("vioscsi-telemetry-{0}-{1:yyyyMMdd-HHmmss}.bin" -f $safeName, (Get-Date))
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
