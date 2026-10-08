// WinDbg script: summarize vioscsi STOR_TELEMETRY from a kernel dump or live kernel session.
//
// Usage:
//   .scriptload <path>\vioscsi_telemetry.js
//   !vioscsi_telemetry                     summary of every registered vioscsi adapter
//   !vioscsi_telemetry <adapter extension> summary of one adapter, by its miniport device extension
//   !vioscsi_telemetry 0 1                 all adapters, including queues and targets with no activity
//   !vioscsi_telemetry_at <address> [1]    parse a STOR_TELEMETRY at a known address (no symbols needed)
//   !vioscsi_telemetry_scan <start> <len> [1]
//                                          scan a memory range for STOR_TELEMETRY blocks (no symbols needed)
//   dx @$vioscsiTelemetry()                the same data as data model objects
//   dx -r3 @$vioscsiTelemetry()[0].Queues  drill into per-queue values and raw histograms
//   dx @$vioscsiTelemetry()[0].Targets     per-SCSI-target values (active targets only)
//   !vioscsi_events [adapter] [table PA] [count] [virtqueue] [avail pos]
//                                          the adapter's event ring: the last <count> events
//                                          (default 64), or every event of the request(s) whose
//                                          indirect descriptor table is at <table PA> or that were
//                                          published at <avail pos> of <virtqueue> (QEMU numbering)
//   !vioscsi_chain <table PA> <virtqueue> <avail pos>
//                                          the same for every adapter, taking the addr=, queue= and
//                                          pos= of a QEMU virtqueue_chain_error line
//   dx @$vioscsiEvents([adapter])          the decoded event rings and outstanding zombies
//
// With matching vioscsi symbols, !vioscsi_telemetry reads vioscsi!VioScsiTelemetryDirectory
// and the typed structures. Without them it finds the vioscsi image in the module list, scans
// its writable sections for the directory's magic, and parses each adapter's STOR_TELEMETRY
// from the raw layout described by the block's own header (see vioscsi/vioscsi.h).
//
// Besides the per-queue view the script prints each active SCSI target (a target's requests span
// all queues) with its in-flight count, last completion, latency, errors and resets, and flags
// a target whose oldest request was already 5 s old at the last scan as STALLED (or, without
// scan data, one that is in flight with no recent completion as a "possible stall"). Per-target oldest
// in-flight ages are only as fresh as the driver's last IOCTL snapshot (it is computed there,
// not on the I/O path), so a dump shows it "as of" that scan.
//
// Copyright (c) 2026 Red Hat, Inc. and/or its affiliates. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
// 3. Neither the names of the copyright holders nor the names of their contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
// SUCH DAMAGE.

"use strict";

// Mirrors vioscsi/vioscsi.h.
const MODULE = "vioscsi";
const DIRECTORY_SYMBOL = "VioScsiTelemetryDirectory";
const ADAPTER_POINTER_TYPE = "_ADAPTER_EXTENSION *";
const STOR_TELEMETRY_MAGIC = 0x53505331;
const STOR_TELEMETRY_MIN_VERSION = 5;
const MAX_CPU = 256; // length of STOR_TELEMETRY.Queues[]
const MAX_TARGETS = 256; // length of STOR_TELEMETRY.Targets[] (STOR_TELEMETRY_MAX_TARGETS)
const STOR_TELEMETRY_HISTOGRAM_BUCKETS = 64; // length of LATENCY_STATS.Buckets[]
const STOR_TELEMETRY_STATUS_SLOTS = 64; // length of QUEUE_TELEMETRY.StatusHistogram[]
const VIOSCSI_TELEMETRY_DIRECTORY_MAGIC = 0x44545356; // 'VSTD'

// Raw (symbol-free) layout, matching Tools/debug/GetVioScsiTelemetry.ps1.
// STOR_TELEMETRY header: Magic, Version, HeaderSize, QueueSize, QueueCount, TargetSize, TargetCount,
// TargetsOffset, LatencyBuckets, StatusSlots, Reserved[2] (12 ULONGs), then ten adapter-wide ULONG64s.
const HEADER_ULONGS = 12;
const HEADER_SIZE = 128;
const RESET_FIELDS = ["BusResetCount", "DeviceResetCount", "LogicalUnitResetCount", "LastResetDurationUs",
                      "MaxResetDurationUs", "DeviceResetTmfInFlightCount"];
// After RESET_FIELDS: LastResetTime, SnapshotTime, OutOfRangeTargetCount, TargetScanTime.
const HEADER_TAIL_FIELDS = ["LastResetTime", "SnapshotTime", "OutOfRangeTargetCount", "TargetScanTime"];
// Version 6 appends descriptor ownership and request validation counters at HEADER_SIZE.
const OWNERSHIP_FIELDS = ["EarlyCompletedCount", "ExtReusedWhileOwnedCount", "OrphanReturnCount",
                          "OrphanUnexplainedCount", "OrphanIntoReusedExtCount", "ZombieEvictedCount",
                          "SgZeroLengthCount", "SgTooManyElementsCount", "SgLengthMismatchCount",
                          "ZeroLengthDescCount"];
const OWNERSHIP_VERSION = 6;
const OWNERSHIP_HEADER_SIZE = HEADER_SIZE + OWNERSHIP_FIELDS.length * 8;
// QUEUE_TELEMETRY, in ULONG64 slots: 7 counters, Buckets[B], Count/SumUs/MinUs/MaxUs,
// StatusHistogram[S], InFlightHighWaterMark + Reserved (two ULONGs), QueueFullCount, then six
// ULONG64s (OldestInFlightTime, LastCompletionTime, MaxLatencyTime, Slow1sCount, Slow5sCount,
// Slow30sCount) and one slot of InFlightCount + Reserved2 (two ULONGs).
const QUEUE_COUNTER_SLOTS = 7;
const QUEUE_LATENCY_SLOTS = 4;
const QUEUE_TRAILER_SLOTS = 2;
const QUEUE_TAIL_SLOTS = 7;
// TARGET_TELEMETRY, in ULONG64 slots (184 bytes): TargetId + InFlightCount (two ULONGs), then
// Read/Write/OtherCount, Read/WriteBytes, OldestInFlightTime, LastCompletionTime, LatencyCount,
// LatencySumUs, MaxLatencyUs, MaxLatencyTime, Slow1s/5s/30sCount, Busy/Aborted/NoDevice/Error/
// InvalidTargetCount, DeviceResetCount, LogicalUnitResetCount and LastResetTime.
const TARGET_SLOTS = 23;
// Timestamps are interrupt time in 100 ns units. In a dump or live session "now" is that same
// clock read from KUSER_SHARED_DATA (InterruptTime is a KSYSTEM_TIME at offset 8).
const HNS_PER_US = 10;
const KUSER_SHARED_DATA_ADDRESSES = ["fffff78000000000", "ffdf0000"]; // x64/arm64, x86 (hex)
const KUSER_INTERRUPT_TIME_OFFSET = 8;
// A request outstanding this long is flagged in the summary.
const STALL_WARN_US = 5000000;
// Sanity bounds for header-described sizes in the raw path, so a corrupt header can't make
// the script read megabytes per queue. The driver's own values are HeaderSize 128, QueueSize 1184
// and TargetSize 184.
const RAW_MAX_ARRAY_SLOTS = 256;
const RAW_MAX_HEADER_SIZE = 4 * 1024;
const RAW_MAX_QUEUE_SIZE = 64 * 1024;
const RAW_MAX_TARGET_SIZE = 4 * 1024;
const RAW_MAX_TARGETS_OFFSET = 16 * 1024 * 1024;
// VIOSCSI_TELEMETRY_DIRECTORY: Magic, Version, PointerSize, MaxAdapters, TelemetryOffset,
// Reserved (6 ULONGs), then Adapters[MaxAdapters] of PointerSize each.
const DIRECTORY_ULONGS = 6;
const DIRECTORY_MAX_ADAPTERS = 64;
const DIRECTORY_MAX_TELEMETRY_OFFSET = 4 * 1024 * 1024;
// VIOSCSI_TELEMETRY_DIRECTORY version 2 appends EventRingOffset and ZombiesOffset (2 ULONGs)
// after Adapters[].
const DIRECTORY_EVENTS_VERSION = 2;
const DIRECTORY_MAX_EXTENSION_OFFSET = 16 * 1024 * 1024;
// VIOSCSI_EVENT_RING: Magic, Version, EntrySize, EntryCount (ULONGs), Next (ULONG64), from
// version 2 Flags and Reserved (ULONGs), then Entries[EntryCount]. VIOSCSI_EVENT: Sequence, Time,
// TablePa, Id, SrbExt, Srb, Value1, Value2 (ULONG64s), then Code, Queue (USHORTs), Target, Lun
// (UCHARs) and AvailPos (USHORT, version 2; padding before).
const VIOSCSI_EVENT_RING_MAGIC = 0x47525645; // 'EVRG'
const EVENT_RING_V1_HEADER_SIZE = 24;
const EVENT_RING_V2_HEADER_SIZE = 32;
const EVENT_RING_PACKED = 0x1; // Flags: packed virtqueues, no AvailPos recorded
const EVENT_SLOTS = 9;
const EVENT_RING_MAX_ENTRIES = 1 << 20;
// Entries read per memory request; the ring holds 32768 of them (2.3 MB).
const EVENT_READ_CHUNK = 2048;
const EVENT_NO_QUEUE = 0xFFFF;
const EVENTS_DEFAULT_COUNT = 64;
// QEMU numbers virtqueues from the control (0) and event (1) queues; the ring records request
// queue indexes, so request queue N is QEMU's virtqueue N + 2 (VIRTIO_SCSI_REQUEST_QUEUE_0).
const VIRTIO_SCSI_REQUEST_QUEUE_0 = 2;
// VIOSCSI_ZOMBIE[VIOSCSI_ZOMBIE_SLOTS]: Key, Id, SrbExt, Srb, TablePa, Time (ULONG64s), Reused and
// Queue (ULONGs), then AvailPos (USHORT) and padding to 64 bytes.
const VIOSCSI_ZOMBIE_SLOTS = 1024;
const ZOMBIE_SLOTS = 8;
// Events whose AvailPos names a request's avail entry. An OrphanReturn has one only when it
// matched an early-completed request (VIOSCSI_ORPHAN_EARLY_COMPLETED).
const EVENTS_WITH_POS = new Set([1, 2, 4, 12, 16]);
const EVENT_NAMES = {
    1: "Publish", 2: "DeviceComplete", 3: "OrphanReturn", 4: "EarlyComplete", 5: "ResetRequest",
    6: "ResetDone", 7: "TmfSent", 8: "TmfCoalesced", 9: "TmfComplete", 10: "Pause", 11: "Resume",
    12: "ExtReused", 13: "SgZeroLength", 14: "SgTooManyElements", 15: "SgLengthMismatch",
    16: "ZeroLengthDesc"
};
const EVENT_SITE_NAMES = {
    1: "CompletePendingRequestsOnReset", 2: "DeviceReset", 3: "ProcessTMFCompletion",
    4: "DeviceReset, TMF not posted"
};
const IMAGE_SCN_MEM_WRITE = 0x80000000;
const PAGE_SIZE = 4096;
const SCAN_WARN_BYTES = 256 * 1024 * 1024;
const SCAN_HINT = "use !vioscsi_telemetry_at <STOR_TELEMETRY address> or " +
                  "!vioscsi_telemetry_scan <start> <length> instead";

// Indexed by SRB_STATUS_* with SRB_STATUS_QUEUE_FROZEN/AUTOSENSE_VALID masked off (srb.h).
const SRB_STATUS_NAMES = {
    0x00: "PENDING", 0x01: "SUCCESS", 0x02: "ABORTED", 0x03: "ABORT_FAILED", 0x04: "ERROR",
    0x05: "BUSY", 0x06: "INVALID_REQUEST", 0x07: "INVALID_PATH_ID", 0x08: "NO_DEVICE",
    0x09: "TIMEOUT", 0x0A: "SELECTION_TIMEOUT", 0x0B: "COMMAND_TIMEOUT", 0x0D: "MESSAGE_REJECTED",
    0x0E: "BUS_RESET", 0x0F: "PARITY_ERROR", 0x10: "REQUEST_SENSE_FAILED", 0x11: "NO_HBA",
    0x12: "DATA_OVERRUN", 0x13: "UNEXPECTED_BUS_FREE", 0x14: "PHASE_SEQUENCE_FAILURE",
    0x15: "BAD_SRB_BLOCK_LENGTH", 0x16: "REQUEST_FLUSHED", 0x20: "INVALID_LUN",
    0x21: "INVALID_TARGET_ID", 0x22: "BAD_FUNCTION", 0x23: "ERROR_RECOVERY", 0x24: "NOT_POWERED",
    0x25: "LINK_DOWN", 0x26: "INSUFFICIENT_RESOURCES", 0x27: "THROTTLED_REQUEST", 0x30: "INTERNAL_ERROR"
};

const COUNTER_FIELDS = ["Reads", "Writes", "Flushes", "Unmaps", "Other", "ReadBytes", "WriteBytes",
                        "Completions", "LatencySumUs", "QueueFull", "InFlight", "Slow1s", "Slow5s", "Slow30s"];

function log(s) {
    host.diagnostics.debugLog(s + "\n");
}

// 64-bit fields arrive as host.Int64 objects (smaller ones may arrive as plain numbers).
// Counters are converted to JS numbers for arithmetic and display: exact up to 2^53,
// which no realistic counter (e.g. 8 PiB of I/O) reaches. Addresses are never converted:
// they stay host.Int64 and are offset with add().
function num(v) {
    return (typeof v === "number") ? v : v.convertToNumber();
}

function low32(v) {
    return (typeof v === "number") ? v % 4294967296 : v.getLowPart() >>> 0;
}

function high32(v) {
    return (typeof v === "number") ? Math.floor(v / 4294967296) : v.getHighPart() >>> 0;
}

function isZero(v) {
    return (typeof v === "number") ? v === 0 : (v.getLowPart() === 0 && v.getHighPart() === 0);
}

function toAddress(v) {
    return (typeof v === "number") ? new host.Int64(v) : v;
}

function hex(v) {
    return "0x" + ((typeof v === "number") ? v.toString(16) : v.toString(16).replace(/^0x/, ""));
}

function readValues(address, count, size) {
    const values = host.memory.readMemoryValues(address, count, size);
    return Array.isArray(values) ? values : Array.from(values);
}

// Bucket N holds [2^N, 2^(N+1)) us (bucket 0 also holds 0), so report the upper bound.
function percentileUs(buckets, fraction) {
    const total = buckets.reduce((a, b) => a + b, 0);
    if (total === 0) {
        return null;
    }
    const target = Math.ceil(total * fraction);
    let seen = 0;
    for (let i = 0; i < buckets.length; i++) {
        seen += buckets[i];
        if (seen >= target) {
            return Math.pow(2, i + 1);
        }
    }
    return Math.pow(2, buckets.length);
}

function readArray(arr, count) {
    const out = [];
    for (let i = 0; i < count; i++) {
        out.push(num(arr[i]));
    }
    return out;
}

// Current interrupt time (100 ns units) of the target, from KUSER_SHARED_DATA, or null if the
// page isn't available (e.g. not captured in the dump).
function readInterruptTimeHns() {
    for (const base of KUSER_SHARED_DATA_ADDRESSES) {
        try {
            const address = host.parseInt64(base, 16).add(KUSER_INTERRUPT_TIME_OFFSET);
            for (let attempt = 0; attempt < 3; attempt++) {
                // KSYSTEM_TIME: LowPart, High1Time, High2Time; equal highs mean a consistent read.
                const t = readValues(address, 3, 4).map(low32);
                if (t[1] === t[2]) {
                    return t[1] * 4294967296 + t[0];
                }
            }
        } catch (e) {
            // Try the next layout.
        }
    }
    return null;
}

// Microseconds from a timestamp to now; null if the timestamp is unset (0), clamped to 0 if it
// is slightly newer than now (a request queued just after the reference time was taken).
function ageUs(now, then) {
    if (!now || !then) {
        return null;
    }
    return then >= now ? 0 : Math.floor((now - then) / HNS_PER_US);
}

function addLatencyStats(row) {
    row.AvgUs = row.Completions ? Math.round((row.LatencySumUs / row.Completions) * 10) / 10 : null;
    row.P50Us = percentileUs(row.LatencyBuckets, 0.50);
    row.P99Us = percentileUs(row.LatencyBuckets, 0.99);
    return row;
}

// A target is reported (and shown by default) once it has seen any I/O, a refusal or a reset.
// Mirrors StorPerfTargetActive() in the driver.
function isTargetActive(t) {
    return !!(t.InFlight || t.Reads || t.Writes || t.Other || t.NoDevice || t.DeviceResets || t.LunResets);
}

// Adds ages and the stall verdict to each target. The oldest in-flight request is only computed
// when the driver takes an IOCTL snapshot, so it is reported as its age at that scan (scanTime),
// not against "now": in a dump the request may have completed since.
//
// Two levels of confidence, because "nothing completed for a while" alone proves little (the
// request in flight may have been submitted a moment before the dump):
//   Stalled       a request was already outstanding 5 s or more at the last scan (scan evidence).
//   PossibleStall no scan evidence for this target (never scanned, or its request arrived after
//                 the scan), and either nothing completed for 5 s or more, or nothing ever did.
// A target whose oldest request was young at the scan is not flagged, however long ago its last
// completion was. StallReason says which evidence was used.
function summarizeTargets(targets, now, scanTime) {
    for (const t of targets) {
        t.LastCompletionAgeUs = ageUs(now, t.LastCompletionTime);
        t.MaxLatencyAgeUs = ageUs(now, t.MaxLatencyTime);
        t.LastResetAgeUs = ageUs(now, t.LastResetTime);
        t.OldestAtScanUs = (t.InFlight && scanTime) ? ageUs(scanTime, t.OldestInFlightTime) : null;
        t.Stalled = false;
        t.PossibleStall = false;
        t.StallReason = "";
        if (!t.InFlight) {
            continue;
        }
        const idleFor = t.LastCompletionAgeUs !== null && t.LastCompletionAgeUs >= STALL_WARN_US;
        if (t.OldestAtScanUs !== null) {
            if (t.OldestAtScanUs >= STALL_WARN_US) {
                t.Stalled = true;
                t.StallReason = "oldest request outstanding " + fmtUs(t.OldestAtScanUs) + " at the last scan" +
                    (idleFor ? ", no completion for " + fmtUs(t.LastCompletionAgeUs) : "");
            }
        } else if (!t.LastCompletionTime) {
            t.PossibleStall = true;
            t.StallReason = "in flight, never completed (no scan data for its oldest request)";
        } else if (idleFor) {
            t.PossibleStall = true;
            t.StallReason = "no completion for " + fmtUs(t.LastCompletionAgeUs) +
                " (no scan data for its oldest request, so it may be recent)";
        }
    }
}

// Builds the normalized per-adapter result shared by the typed and raw paths.
// header: { Version, LatencyBuckets, StatusSlots, <RESET_FIELDS>, <HEADER_TAIL_FIELDS>,
//          <OWNERSHIP_FIELDS> (version 6 and later only) }
// targets: every entry read, active or not.
function summarize(source, header, queues, targets, typed) {
    const total = { Queue: "Total", MinUs: 0, MaxUs: 0, InFlightHwm: 0 };
    COUNTER_FIELDS.forEach(f => total[f] = 0);
    // "Now" is the target's current interrupt time when it can be read; otherwise the time of the
    // driver's last IOCTL snapshot, which may be long before a dump.
    let now = readInterruptTimeHns();
    let nowSource = null;
    if (now) {
        nowSource = "dump/session interrupt time";
    } else if (header.SnapshotTime) {
        now = header.SnapshotTime;
        nowSource = "last IOCTL snapshot time (current time unavailable, ages may be understated)";
    }
    total.OldestInFlightAgeUs = null;
    total.LastCompletionAgeUs = null;
    total.MaxLatencyAgeUs = null;
    total.LatencyBuckets = new Array(header.LatencyBuckets).fill(0);
    total.StatusHistogram = new Array(header.StatusSlots).fill(0);
    for (const q of queues) {
        COUNTER_FIELDS.forEach(f => total[f] += q[f]);
        q.OldestInFlightAgeUs = ageUs(now, q.OldestInFlightTime);
        q.LastCompletionAgeUs = ageUs(now, q.LastCompletionTime);
        q.MaxLatencyAgeUs = ageUs(now, q.MaxLatencyTime);
        // Oldest request: the largest age. Last completion: the smallest age (most recent).
        if (q.OldestInFlightAgeUs !== null &&
            (total.OldestInFlightAgeUs === null || q.OldestInFlightAgeUs > total.OldestInFlightAgeUs)) {
            total.OldestInFlightAgeUs = q.OldestInFlightAgeUs;
        }
        if (q.LastCompletionAgeUs !== null &&
            (total.LastCompletionAgeUs === null || q.LastCompletionAgeUs < total.LastCompletionAgeUs)) {
            total.LastCompletionAgeUs = q.LastCompletionAgeUs;
        }
        // The max latency time belongs to the queue holding the overall max.
        if (q.MaxUs > total.MaxUs) {
            total.MaxLatencyAgeUs = q.MaxLatencyAgeUs;
        }
        if (q.MinUs && (!total.MinUs || q.MinUs < total.MinUs)) {
            total.MinUs = q.MinUs;
        }
        total.MaxUs = Math.max(total.MaxUs, q.MaxUs);
        total.InFlightHwm = Math.max(total.InFlightHwm, q.InFlightHwm);
        q.LatencyBuckets.forEach((v, i) => total.LatencyBuckets[i] += v);
        q.StatusHistogram.forEach((v, i) => total.StatusHistogram[i] += v);
    }
    addLatencyStats(total);
    summarizeTargets(targets, now, header.TargetScanTime);

    const status = {};
    total.StatusHistogram.forEach((v, i) => {
        if (v) {
            status[SRB_STATUS_NAMES[i] || "0x" + (i < 16 ? "0" : "") + i.toString(16).toUpperCase()] = v;
        }
    });

    const result = { Source: source, Version: header.Version, QueueCount: queues.length };
    RESET_FIELDS.forEach(f => result[f] = header[f]);
    result.LastResetTime = header.LastResetTime;
    result.LastResetAgeUs = ageUs(now, header.LastResetTime);
    result.OutOfRangeTargetCount = header.OutOfRangeTargetCount;
    result.TargetScanTime = header.TargetScanTime;
    result.TargetScanAgeUs = ageUs(now, header.TargetScanTime);
    // Left undefined for older drivers, so the summary can tell "none" from "not counted".
    OWNERSHIP_FIELDS.forEach(f => {
        if (header[f] !== undefined) {
            result[f] = header[f];
        }
    });
    result.AgesRelativeTo = nowSource;
    result.Queues = queues;
    // Targets: the ones that have seen activity; AllTargets: every entry read (the in-memory table
    // has 256, the driver's IOCTL snapshot only the active ones).
    result.Targets = targets.filter(isTargetActive);
    result.AllTargets = targets;
    result.Total = total;
    result.Status = status;
    // The typed STOR_TELEMETRY object, for dx drill-down; null when read without symbols.
    result.Telemetry = typed;
    return result;
}

function checkMagicAndVersion(source, magic, version) {
    if (magic !== STOR_TELEMETRY_MAGIC) {
        throw new Error(source + ": bad telemetry magic " + hex(magic));
    }
    if (version < STOR_TELEMETRY_MIN_VERSION) {
        throw new Error(source + ": telemetry version " + version + " is not supported");
    }
}

// ---- Typed path: vioscsi symbols available ----

function readTypedQueue(q, index, latencyBuckets, statusSlots) {
    return addLatencyStats({
        Queue: index,
        Reads: num(q.ReadCount),
        Writes: num(q.WriteCount),
        Flushes: num(q.FlushCount),
        Unmaps: num(q.UnmapCount),
        Other: num(q.OtherCount),
        ReadBytes: num(q.ReadBytes),
        WriteBytes: num(q.WriteBytes),
        Completions: num(q.Latency.Count),
        LatencySumUs: num(q.Latency.SumUs),
        MinUs: num(q.Latency.MinUs),
        MaxUs: num(q.Latency.MaxUs),
        InFlightHwm: num(q.InFlightHighWaterMark),
        QueueFull: num(q.QueueFullCount),
        LatencyBuckets: readArray(q.Latency.Buckets, latencyBuckets),
        StatusHistogram: readArray(q.StatusHistogram, statusSlots),
        InFlight: num(q.InFlightCount),
        OldestInFlightTime: num(q.OldestInFlightTime),
        LastCompletionTime: num(q.LastCompletionTime),
        MaxLatencyTime: num(q.MaxLatencyTime),
        Slow1s: num(q.Slow1sCount),
        Slow5s: num(q.Slow5sCount),
        Slow30s: num(q.Slow30sCount)
    });
}

// An entry with nothing recorded, without reading its remaining members.
function idleTarget(id) {
    return {
        Target: id, InFlight: 0, Reads: 0, Writes: 0, Other: 0, ReadBytes: 0, WriteBytes: 0,
        OldestInFlightTime: 0, LastCompletionTime: 0, Completions: 0, LatencySumUs: 0, AvgUs: null, MaxUs: 0,
        MaxLatencyTime: 0, Slow1s: 0, Slow5s: 0, Slow30s: 0, Busy: 0, Aborted: 0, NoDevice: 0, Errors: 0,
        InvalidTarget: 0, DeviceResets: 0, LunResets: 0, LastResetTime: 0
    };
}

function finishTarget(row) {
    row.AvgUs = row.Completions ? Math.round((row.LatencySumUs / row.Completions) * 10) / 10 : null;
    return row;
}

function readTypedTarget(t, index) {
    // The 256-entry table is mostly idle; check the members that make a target active first so
    // an idle entry costs a handful of reads instead of the full set.
    const row = idleTarget(num(t.TargetId));
    row.InFlight = num(t.InFlightCount);
    row.Reads = num(t.ReadCount);
    row.Writes = num(t.WriteCount);
    row.Other = num(t.OtherCount);
    row.NoDevice = num(t.NoDeviceCount);
    row.DeviceResets = num(t.DeviceResetCount);
    row.LunResets = num(t.LogicalUnitResetCount);
    if (!isTargetActive(row)) {
        return row;
    }
    row.ReadBytes = num(t.ReadBytes);
    row.WriteBytes = num(t.WriteBytes);
    row.OldestInFlightTime = num(t.OldestInFlightTime);
    row.LastCompletionTime = num(t.LastCompletionTime);
    row.Completions = num(t.LatencyCount);
    row.LatencySumUs = num(t.LatencySumUs);
    row.MaxUs = num(t.MaxLatencyUs);
    row.MaxLatencyTime = num(t.MaxLatencyTime);
    row.Slow1s = num(t.Slow1sCount);
    row.Slow5s = num(t.Slow5sCount);
    row.Slow30s = num(t.Slow30sCount);
    row.Busy = num(t.BusyCount);
    row.Aborted = num(t.AbortedCount);
    row.Errors = num(t.ErrorCount);
    row.InvalidTarget = num(t.InvalidTargetCount);
    row.LastResetTime = num(t.LastResetTime);
    return finishTarget(row);
}

function readTypedAdapter(adapterPtr) {
    const t = adapterPtr.dereference().Telemetry;
    const source = MODULE + "!_ADAPTER_EXTENSION " + hex(adapterPtr.address);
    const version = num(t.Version);
    checkMagicAndVersion(source, num(t.Magic), version);

    // Clamp header-reported sizes to the compiled array lengths so a corrupt header can't
    // index past the arrays. This differs on purpose from the raw path, which has no PDB
    // array lengths and instead uses the header counts as-is (within sanity bounds),
    // because there they also determine the offsets of every later queue field.
    const header = {
        Version: version,
        LatencyBuckets: Math.min(num(t.LatencyBuckets), STOR_TELEMETRY_HISTOGRAM_BUCKETS),
        StatusSlots: Math.min(num(t.StatusSlots), STOR_TELEMETRY_STATUS_SLOTS)
    };
    RESET_FIELDS.forEach(f => header[f] = num(t[f]));
    HEADER_TAIL_FIELDS.forEach(f => header[f] = num(t[f]));
    if (version >= OWNERSHIP_VERSION) {
        OWNERSHIP_FIELDS.forEach(f => header[f] = num(t[f]));
    }
    const queueCount = Math.min(num(t.QueueCount), MAX_CPU);
    const queues = [];
    for (let i = 0; i < queueCount; i++) {
        queues.push(readTypedQueue(t.Queues[i], i, header.LatencyBuckets, header.StatusSlots));
    }
    const targetCount = Math.min(num(t.TargetCount), MAX_TARGETS);
    const targets = [];
    for (let i = 0; i < targetCount; i++) {
        targets.push(readTypedTarget(t.Targets[i], i));
    }
    return summarize(source, header, queues, targets, t);
}

// Returns the typed directory, or null when vioscsi symbols (or this symbol) aren't available.
function symbolDirectory() {
    try {
        const directory = host.getModuleSymbol(MODULE, DIRECTORY_SYMBOL);
        if (directory && directory.Adapters !== undefined) {
            return directory;
        }
    } catch (e) {
        // Fall through to the symbol-free path.
    }
    return null;
}

function typedTelemetry(directory, address) {
    if (address !== undefined && !isZero(address)) {
        return [readTypedAdapter(host.createPointerObject(toAddress(address), MODULE, ADAPTER_POINTER_TYPE))];
    }
    const result = [];
    for (const p of directory.Adapters) {
        if (p.isNull) {
            continue;
        }
        try {
            result.push(readTypedAdapter(p));
        } catch (e) {
            log("warning: " + e.message);
        }
    }
    return result;
}

// ---- Raw path: no symbols, layout taken from the in-memory headers ----

// Reads and validates a STOR_TELEMETRY header at address; throws if it doesn't look like one.
// strict additionally requires the header's Reserved to be zero, to weed out stray matches
// of the magic when scanning arbitrary memory.
function readRawHeader(address, source, strict) {
    const u = readValues(address, HEADER_ULONGS, 4).map(low32);
    const [magic, version, headerSize, queueSize, queueCount, targetSize, targetCount, targetsOffset,
           latencyBuckets, statusSlots, reserved0, reserved1] = u;
    checkMagicAndVersion(source, magic, version);
    if (strict && (reserved0 !== 0 || reserved1 !== 0)) {
        throw new Error(source + ": telemetry header Reserved is " + hex(reserved0) + ", " + hex(reserved1));
    }
    const implausible = what => new Error(source + ": implausible telemetry header: " + what);
    if (latencyBuckets < 1 || latencyBuckets > RAW_MAX_ARRAY_SLOTS) {
        throw implausible("LatencyBuckets " + latencyBuckets + " not in 1.." + RAW_MAX_ARRAY_SLOTS);
    }
    if (statusSlots < 1 || statusSlots > RAW_MAX_ARRAY_SLOTS) {
        throw implausible("StatusSlots " + statusSlots + " not in 1.." + RAW_MAX_ARRAY_SLOTS);
    }
    if (headerSize < HEADER_SIZE || headerSize > RAW_MAX_HEADER_SIZE || headerSize % 8 !== 0) {
        throw implausible("HeaderSize " + headerSize + " is not a multiple of 8 in " + HEADER_SIZE + ".." +
                          RAW_MAX_HEADER_SIZE);
    }
    // Only the fields this script knows are read from each queue/target; their sizes may be larger.
    const queueSlots = QUEUE_COUNTER_SLOTS + latencyBuckets + QUEUE_LATENCY_SLOTS + statusSlots +
                       QUEUE_TRAILER_SLOTS + QUEUE_TAIL_SLOTS;
    if (queueSize < queueSlots * 8 || queueSize > RAW_MAX_QUEUE_SIZE || queueSize % 8 !== 0) {
        throw implausible("QueueSize " + queueSize + " is not a multiple of 8 in " + queueSlots * 8 + ".." +
                          RAW_MAX_QUEUE_SIZE);
    }
    if (queueCount > MAX_CPU) {
        throw implausible("QueueCount " + queueCount + " exceeds " + MAX_CPU);
    }
    if (targetSize < TARGET_SLOTS * 8 || targetSize > RAW_MAX_TARGET_SIZE || targetSize % 8 !== 0) {
        throw implausible("TargetSize " + targetSize + " is not a multiple of 8 in " + TARGET_SLOTS * 8 + ".." +
                          RAW_MAX_TARGET_SIZE);
    }
    if (targetCount > MAX_TARGETS) {
        throw implausible("TargetCount " + targetCount + " exceeds " + MAX_TARGETS);
    }
    if (targetsOffset < headerSize || targetsOffset > RAW_MAX_TARGETS_OFFSET || targetsOffset % 8 !== 0) {
        throw implausible("TargetsOffset " + targetsOffset + " is not a multiple of 8 in " + headerSize + ".." +
                          RAW_MAX_TARGETS_OFFSET);
    }
    const header = {
        Version: version, HeaderSize: headerSize, QueueSize: queueSize, QueueCount: queueCount,
        TargetSize: targetSize, TargetCount: targetCount, TargetsOffset: targetsOffset,
        LatencyBuckets: latencyBuckets, StatusSlots: statusSlots, QueueSlots: queueSlots
    };
    const fields = RESET_FIELDS.concat(HEADER_TAIL_FIELDS);
    const values = readValues(address.add(HEADER_ULONGS * 4), fields.length, 8);
    fields.forEach((f, i) => header[f] = num(values[i]));
    if (version >= OWNERSHIP_VERSION && headerSize >= OWNERSHIP_HEADER_SIZE) {
        const ownership = readValues(address.add(HEADER_SIZE), OWNERSHIP_FIELDS.length, 8);
        OWNERSHIP_FIELDS.forEach((f, i) => header[f] = num(ownership[i]));
    }
    return header;
}

function readRawQueue(address, index, header) {
    const v = readValues(address, header.QueueSlots, 8);
    const buckets = QUEUE_COUNTER_SLOTS;
    const latency = buckets + header.LatencyBuckets;
    const status = latency + QUEUE_LATENCY_SLOTS;
    const trailer = status + header.StatusSlots;
    const tail = trailer + QUEUE_TRAILER_SLOTS;
    const slice = (from, count) => v.slice(from, from + count).map(num);
    return addLatencyStats({
        Queue: index,
        Reads: num(v[0]),
        Writes: num(v[1]),
        Flushes: num(v[2]),
        Unmaps: num(v[3]),
        Other: num(v[4]),
        ReadBytes: num(v[5]),
        WriteBytes: num(v[6]),
        Completions: num(v[latency]),
        LatencySumUs: num(v[latency + 1]),
        MinUs: num(v[latency + 2]),
        MaxUs: num(v[latency + 3]),
        InFlightHwm: low32(v[trailer]), // ULONG InFlightHighWaterMark, then ULONG Reserved
        QueueFull: num(v[trailer + 1]),
        LatencyBuckets: slice(buckets, header.LatencyBuckets),
        StatusHistogram: slice(status, header.StatusSlots),
        OldestInFlightTime: num(v[tail]),
        LastCompletionTime: num(v[tail + 1]),
        MaxLatencyTime: num(v[tail + 2]),
        Slow1s: num(v[tail + 3]),
        Slow5s: num(v[tail + 4]),
        Slow30s: num(v[tail + 5]),
        InFlight: low32(v[tail + 6]) // ULONG InFlightCount, then ULONG Reserved2
    });
}

// The entries are located by the header (TargetsOffset/TargetSize), and each says which target it
// is: the in-memory table has an entry per ID, an IOCTL snapshot only the active ones.
function readRawTarget(address) {
    const v = readValues(address, TARGET_SLOTS, 8);
    return finishTarget({
        Target: low32(v[0]), // ULONG TargetId, then ULONG InFlightCount
        InFlight: high32(v[0]),
        Reads: num(v[1]),
        Writes: num(v[2]),
        Other: num(v[3]),
        ReadBytes: num(v[4]),
        WriteBytes: num(v[5]),
        OldestInFlightTime: num(v[6]),
        LastCompletionTime: num(v[7]),
        Completions: num(v[8]),
        LatencySumUs: num(v[9]),
        MaxUs: num(v[10]),
        MaxLatencyTime: num(v[11]),
        Slow1s: num(v[12]),
        Slow5s: num(v[13]),
        Slow30s: num(v[14]),
        Busy: num(v[15]),
        Aborted: num(v[16]),
        NoDevice: num(v[17]),
        Errors: num(v[18]),
        InvalidTarget: num(v[19]),
        DeviceResets: num(v[20]),
        LunResets: num(v[21]),
        LastResetTime: num(v[22])
    });
}

function readRawTelemetry(address, source, strict) {
    const header = readRawHeader(address, source, strict);
    const queues = [];
    for (let i = 0; i < header.QueueCount; i++) {
        queues.push(readRawQueue(address.add(header.HeaderSize + i * header.QueueSize), i, header));
    }
    const targets = [];
    for (let i = 0; i < header.TargetCount; i++) {
        targets.push(readRawTarget(address.add(header.TargetsOffset + i * header.TargetSize)));
    }
    return summarize(source, header, queues, targets, null);
}

// Calls visit(pageAddress, ulongs) for each readable page overlapping [start, start + length).
function forEachPage(start, length, visit, progress) {
    const first = start.subtract(low32(start) % PAGE_SIZE);
    const end = (low32(start) % PAGE_SIZE) + length;
    const step = Math.max(PAGE_SIZE, Math.ceil(end / 10 / PAGE_SIZE) * PAGE_SIZE);
    for (let off = 0; off < end; off += PAGE_SIZE) {
        if (progress && off > 0 && off % step === 0) {
            log("  ... scanned " + Math.round(off / 1048576) + " MB of " + Math.round(end / 1048576) + " MB");
        }
        const page = first.add(off);
        let ulongs;
        try {
            ulongs = readValues(page, PAGE_SIZE / 4, 4);
        } catch (e) {
            continue; // not present in the dump
        }
        visit(page, ulongs);
    }
}

function findModule() {
    for (const m of host.currentSession.Modules) {
        const base = String(m.Name).split(/[\\/]/).pop().replace(/\.[^.]*$/, "").toLowerCase();
        if (base === MODULE) {
            return m;
        }
    }
    return null;
}

function readU16(address) {
    return low32(readValues(address, 1, 2)[0]);
}

function readU32(address) {
    return low32(readValues(address, 1, 4)[0]);
}

// Writable section ranges of the image as [{ start, length }], or the whole image if the
// PE headers can't be read.
function writableRanges(base, size) {
    try {
        if (readU16(base) !== 0x5A4D) { // "MZ"
            throw new Error("no MZ header");
        }
        const nt = base.add(readU32(base.add(0x3C)));
        if (readU32(nt) !== 0x00004550) { // "PE\0\0"
            throw new Error("no PE signature");
        }
        const sectionCount = readU16(nt.add(6));
        const sections = nt.add(24 + readU16(nt.add(20)));
        const ranges = [];
        for (let i = 0; i < sectionCount; i++) {
            const s = readValues(sections.add(i * 40), 10, 4).map(low32);
            const [virtualSize, virtualAddress, characteristics] = [s[2], s[3], s[9]];
            if ((characteristics & IMAGE_SCN_MEM_WRITE) && virtualSize) {
                ranges.push({ start: base.add(virtualAddress), length: virtualSize });
            }
        }
        if (ranges.length) {
            return ranges;
        }
    } catch (e) {
        log("warning: cannot parse " + MODULE + " PE headers (" + e.message + "), scanning the whole image");
    }
    return [{ start: base, length: size }];
}

// Validates a VIOSCSI_TELEMETRY_DIRECTORY candidate; returns it or null.
function readDirectoryAt(address) {
    try {
        const [magic, version, pointerSize, maxAdapters, telemetryOffset, reserved] =
            readValues(address, DIRECTORY_ULONGS, 4).map(low32);
        if (magic !== VIOSCSI_TELEMETRY_DIRECTORY_MAGIC || version < 1 || reserved !== 0 ||
            (pointerSize !== 4 && pointerSize !== 8) ||
            maxAdapters < 1 || maxAdapters > DIRECTORY_MAX_ADAPTERS || telemetryOffset % 8 !== 0 ||
            telemetryOffset >= DIRECTORY_MAX_TELEMETRY_OFFSET || low32(address) % pointerSize !== 0) {
            return null;
        }
        const adapters = readValues(address.add(DIRECTORY_ULONGS * 4), maxAdapters, pointerSize)
            .filter(p => !isZero(p))
            .map(toAddress);
        // 0 when the driver predates the event ring.
        let eventRingOffset = 0;
        let zombiesOffset = 0;
        if (version >= DIRECTORY_EVENTS_VERSION) {
            [eventRingOffset, zombiesOffset] =
                readValues(address.add(DIRECTORY_ULONGS * 4 + maxAdapters * pointerSize), 2, 4).map(low32);
            if (eventRingOffset % 8 !== 0 || eventRingOffset >= DIRECTORY_MAX_EXTENSION_OFFSET ||
                zombiesOffset % 8 !== 0 || zombiesOffset >= DIRECTORY_MAX_EXTENSION_OFFSET) {
                eventRingOffset = 0;
                zombiesOffset = 0;
            }
        }
        return {
            Address: address, TelemetryOffset: telemetryOffset, Adapters: adapters,
            EventRingOffset: eventRingOffset, ZombiesOffset: zombiesOffset
        };
    } catch (e) {
        return null;
    }
}

function scanDirectory() {
    const module = findModule();
    if (!module) {
        throw new Error(MODULE + ".sys is not in the module list");
    }
    const base = toAddress(module.BaseAddress);
    const found = [];
    for (const range of writableRanges(base, num(module.Size))) {
        forEachPage(range.start, range.length, (page, ulongs) => {
            for (let i = 0; i < ulongs.length; i++) {
                if (low32(ulongs[i]) === VIOSCSI_TELEMETRY_DIRECTORY_MAGIC) {
                    const d = readDirectoryAt(page.add(i * 4));
                    if (d) {
                        found.push(d);
                    }
                }
            }
        });
    }
    if (found.length === 0) {
        throw new Error("no telemetry directory found in " + MODULE + " at " + hex(base) +
                        " (driver predates it, or its data pages aren't in the dump); " + SCAN_HINT);
    }
    // Only one directory should exist; if stray data also validates, prefer one that
    // actually lists adapters.
    const chosen = found.find(d => d.Adapters.length > 0) || found[0];
    if (found.length > 1) {
        log("warning: " + found.length + " telemetry directories found, using the one at " + hex(chosen.Address));
    }
    return chosen;
}

// The "symbols unavailable" notice is logged once per script load for dx evaluations, and
// on every printing command.
let fallbackNoticeShown = false;
// Directory used by the most recent raw-path call, for the empty-result message.
let lastDirectory = null;

function rawTelemetry(address, printing) {
    if (printing || !fallbackNoticeShown) {
        log("vioscsi symbols unavailable; scanning the " + MODULE + " image for the telemetry directory");
        fallbackNoticeShown = true;
    }
    const directory = scanDirectory();
    lastDirectory = directory;
    const adapters = (address !== undefined && !isZero(address)) ? [toAddress(address)] : directory.Adapters;
    const result = [];
    for (const a of adapters) {
        const telemetry = a.add(directory.TelemetryOffset);
        try {
            result.push(readRawTelemetry(telemetry, MODULE + " adapter " + hex(a) + " (telemetry " + hex(telemetry) + ")"));
        } catch (e) {
            log("warning: " + e.message);
        }
    }
    return result;
}

// ---- Entry points ----

function collectTelemetry(address, printing) {
    const directory = symbolDirectory();
    if (directory) {
        return {
            adapters: typedTelemetry(directory, address),
            empty: "No vioscsi adapters registered in " + MODULE + "!" + DIRECTORY_SYMBOL
        };
    }
    const adapters = rawTelemetry(address, printing);
    return {
        adapters: adapters,
        empty: "No vioscsi adapters registered in the telemetry directory found at " + hex(lastDirectory.Address)
    };
}

// dx @$vioscsiTelemetry([adapter extension address])
function vioscsiTelemetry(address) {
    return collectTelemetry(address, false).adapters;
}

// dx @$vioscsiTelemetryAt(<STOR_TELEMETRY address>)
function vioscsiTelemetryAt(address) {
    const a = toAddress(address);
    return [readRawTelemetry(a, "STOR_TELEMETRY " + hex(a))];
}

// Parses "ffffa580`10008008  53505331 ..." style hit lines from the engine's "s -d" output.
// Returns the hit addresses, or null if the output contains anything unrecognized, so the
// caller can fall back to the script's own page loop rather than silently miss hits.
function parseSearchOutput(lines) {
    const hits = [];
    for (const raw of lines) {
        const line = String(raw).trim();
        if (line === "") {
            continue;
        }
        const m = /^([0-9a-f`]+)\s+53505331\b/i.exec(line);
        if (!m) {
            return null;
        }
        const digits = m[1].replace(/`/g, "");
        if (digits.length > 16) {
            return null;
        }
        const high = digits.length > 8 ? parseInt(digits.slice(0, -8), 16) : 0;
        hits.push(new host.Int64(parseInt(digits.slice(-8), 16), high));
    }
    return hits;
}

// Candidate magic addresses from the debugger engine's native memory search, or null if the
// command isn't available or its output can't be parsed.
function engineSearch(start, len) {
    try {
        const control = host.namespace.Debugger.Utility.Control;
        return parseSearchOutput(control.ExecuteCommand("s -d " + hex(start) + " L?" + hex(len) + " " +
                                                        STOR_TELEMETRY_MAGIC.toString(16)));
    } catch (e) {
        return null;
    }
}

// Candidate magic addresses from reading the range page by page in script.
function scriptSearch(start, len) {
    const hits = [];
    forEachPage(start, len, (page, ulongs) => {
        for (let i = 0; i < ulongs.length; i++) {
            if (low32(ulongs[i]) === STOR_TELEMETRY_MAGIC) {
                hits.push(page.add(i * 4));
            }
        }
    }, len > SCAN_WARN_BYTES);
    return hits;
}

// dx @$vioscsiTelemetryScan(<start>, <length>)
function vioscsiTelemetryScan(start, length) {
    const s = toAddress(start);
    const len = num(length);
    const end = s.add(len);
    if (len > SCAN_WARN_BYTES) {
        log("warning: scanning " + Math.round(len / 1048576) + " MB, this may take a while");
    }
    let hits = engineSearch(s, len);
    if (hits === null) {
        hits = scriptSearch(s, len);
    }
    const result = [];
    for (const a of hits) {
        // STOR_TELEMETRY is 8-byte aligned; the page loop also sees the partial pages around
        // the range, so clip to [start, start + length).
        if (low32(a) % 8 !== 0 || a.compareTo(s) < 0 || a.compareTo(end) >= 0) {
            continue;
        }
        try {
            result.push(readRawTelemetry(a, "STOR_TELEMETRY " + hex(a), true));
        } catch (e) {
            // Not a telemetry block, just the same 4 bytes.
        }
    }
    return result;
}

function fmtUs(us) {
    if (us === null || us === undefined) {
        return "-";
    }
    if (us >= 1000000) {
        return (us / 1000000).toFixed(1) + "s";
    }
    if (us >= 1000) {
        return (us / 1000).toFixed(1) + "ms";
    }
    return Math.round(us) + "us";
}

function pad(s, width, left) {
    const fill = " ".repeat(Math.max(0, width - s.length));
    return left ? s + fill : fill + s;
}

function fmtTable(columns, rows) {
    const cells = rows.map(r => columns.map(c => String(c.value(r))));
    const widths = columns.map((c, i) => Math.max(c.name.length, ...cells.map(r => r[i].length)));
    // The first column and any marked left (free text) are left-aligned, numbers right-aligned.
    const line = vals => vals.map((v, i) => pad(v, widths[i], i === 0 || columns[i].left === true))
                             .join("  ")
                             .replace(/\s+$/, "");
    log(line(columns.map(c => c.name)));
    log(line(widths.map(w => "-".repeat(w))));
    cells.forEach(r => log(line(r)));
}

const SUMMARY_COLUMNS = [
    { name: "Queue", value: r => r.Queue },
    { name: "Reads", value: r => r.Reads },
    { name: "Writes", value: r => r.Writes },
    { name: "Flushes", value: r => r.Flushes },
    { name: "Unmaps", value: r => r.Unmaps },
    { name: "Other", value: r => r.Other },
    { name: "ReadMB", value: r => (r.ReadBytes / 1048576).toFixed(1) },
    { name: "WriteMB", value: r => (r.WriteBytes / 1048576).toFixed(1) },
    { name: "Avg", value: r => fmtUs(r.AvgUs) },
    { name: "Min", value: r => fmtUs(r.Completions ? r.MinUs : null) },
    { name: "Max", value: r => fmtUs(r.Completions ? r.MaxUs : null) },
    { name: "p50<=", value: r => fmtUs(r.P50Us) },
    { name: "p99<=", value: r => fmtUs(r.P99Us) },
    { name: "HWM", value: r => r.InFlightHwm },
    { name: "QFull", value: r => r.QueueFull }
];

function fmtAgo(us) {
    return (us === null || us === undefined) ? "-" : fmtUs(us) + " ago";
}

const STALL_COLUMNS = [
    { name: "Queue", value: r => r.Queue },
    { name: "InFlight", value: r => r.InFlight },
    { name: "OldestInFlight", value: r => fmtUs(r.OldestInFlightAgeUs) },
    { name: "LastCompletion", value: r => fmtAgo(r.LastCompletionAgeUs) },
    { name: "MaxLatencyAt", value: r => fmtAgo(r.MaxLatencyAgeUs) },
    { name: ">1s", value: r => r.Slow1s },
    { name: ">5s", value: r => r.Slow5s },
    { name: ">30s", value: r => r.Slow30s }
];

const TARGET_COLUMNS = [
    { name: "Target", value: r => r.Target },
    { name: "State", value: r => r.Stalled ? "STALLED" : r.PossibleStall ? "possible stall" : "" },
    { name: "InFlight", value: r => r.InFlight },
    { name: "OldestAtScan", value: r => fmtUs(r.OldestAtScanUs) },
    { name: "LastCompletion", value: r => fmtAgo(r.LastCompletionAgeUs) },
    { name: "Reads", value: r => r.Reads },
    { name: "Writes", value: r => r.Writes },
    { name: "Other", value: r => r.Other },
    { name: "ReadMB", value: r => (r.ReadBytes / 1048576).toFixed(1) },
    { name: "WriteMB", value: r => (r.WriteBytes / 1048576).toFixed(1) },
    { name: "Avg", value: r => fmtUs(r.AvgUs) },
    { name: "Max", value: r => fmtUs(r.Completions ? r.MaxUs : null) },
    { name: ">1s", value: r => r.Slow1s },
    { name: ">5s", value: r => r.Slow5s },
    { name: ">30s", value: r => r.Slow30s }
];

const TARGET_ERROR_COLUMNS = [
    { name: "Target", value: r => r.Target },
    { name: "Busy", value: r => r.Busy },
    { name: "Aborted", value: r => r.Aborted },
    { name: "NoDevice", value: r => r.NoDevice },
    { name: "Errors", value: r => r.Errors },
    { name: "InvalidTarget", value: r => r.InvalidTarget },
    { name: "DevResets", value: r => r.DeviceResets },
    { name: "LunResets", value: r => r.LunResets },
    { name: "LastReset", value: r => fmtAgo(r.LastResetAgeUs) }
];

function printTargets(a, showAll) {
    const targets = showAll ? a.AllTargets : a.Targets;
    log("");
    if (targets.length === 0) {
        log("No target has seen any I/O yet.");
        return;
    }
    // The oldest in-flight request is computed when the driver takes an IOCTL snapshot.
    log("Per target (a target spans all queues). OldestAtScan is the age of the oldest in-flight request at " +
        "the driver's last scan: " +
        (!a.TargetScanTime ? "never scanned" : a.TargetScanAgeUs !== null ? fmtAgo(a.TargetScanAgeUs) : "time unknown") + ".");
    fmtTable(TARGET_COLUMNS, targets);
    log("");
    log("Per target errors and resets:");
    fmtTable(TARGET_ERROR_COLUMNS, targets);
    for (const t of targets) {
        if (t.Stalled || t.PossibleStall) {
            log("WARNING: target " + t.Target + " has " + t.InFlight + " request(s) in flight, " +
                (t.Stalled ? "STALLED: " : "possible stall (low confidence): ") + t.StallReason);
        }
    }
}

// Telemetry version 6 counters. The ownership lines are shown even when zero: a broken virtqueue
// with nothing completed early rules that explanation out. !vioscsi_events has the occurrences.
function printOwnership(a) {
    if (a.EarlyCompletedCount === undefined) {
        return;
    }
    log("Descriptor ownership: completed while the device held them " + a.EarlyCompletedCount +
        "; extension reused while still referenced " + a.ExtReusedWhileOwnedCount);
    log("Returned by the device but on no request list: " + a.OrphanReturnCount + " (never completed early " +
        a.OrphanUnexplainedCount + ", into a reused extension " + a.OrphanIntoReusedExtCount +
        "; forgotten, table full " + a.ZombieEvictedCount + ")");
    if (a.SgZeroLengthCount || a.SgTooManyElementsCount || a.SgLengthMismatchCount || a.ZeroLengthDescCount) {
        log("Scatter/gather: refused zero-length element " + a.SgZeroLengthCount + ", too many elements " +
            a.SgTooManyElementsCount + "; length mismatch " + a.SgLengthMismatchCount +
            "; zero-length descriptor published " + a.ZeroLengthDescCount);
    }
}

function printAdapters(adapters, all, emptyMessage) {
    const showAll = all !== undefined && !isZero(all);
    if (adapters.length === 0) {
        log(emptyMessage);
        return;
    }
    for (const a of adapters) {
        log("");
        log("== " + a.Source + "  (telemetry v" + a.Version + ", " + a.QueueCount + " queues, " +
            a.Targets.length + " active targets)");
        log("Resets: bus " + a.BusResetCount + ", device " + a.DeviceResetCount + ", LUN " +
            a.LogicalUnitResetCount + "; last " + fmtUs(a.LastResetDurationUs) + ", max " +
            fmtUs(a.MaxResetDurationUs) + "; DeviceReset with TMF in flight " + a.DeviceResetTmfInFlightCount);
        // No age means either no reset yet (time 0) or no time reference to measure it against.
        log("Last reset: " + (a.LastResetAgeUs !== null ? fmtAgo(a.LastResetAgeUs) :
                              (a.LastResetTime ? "unknown" : "never")));
        if (a.OutOfRangeTargetCount) {
            log("Requests refused for a target ID beyond the device's maximum: " + a.OutOfRangeTargetCount);
        }
        printOwnership(a);
        log("");
        const rows = a.Queues.filter(q => showAll || q.Completions || q.QueueFull || q.InFlight);
        rows.push(a.Total);
        fmtTable(SUMMARY_COLUMNS, rows);
        log("");
        log("Stall indicators (ages relative to " + (a.AgesRelativeTo || "an unknown time") + "):");
        fmtTable(STALL_COLUMNS, rows);
        for (const q of a.Queues) {
            if (q.InFlight && q.OldestInFlightAgeUs !== null && q.OldestInFlightAgeUs >= STALL_WARN_US) {
                log("WARNING: queue " + q.Queue + " has " + q.InFlight + " request(s) in flight, the oldest for " +
                    fmtUs(q.OldestInFlightAgeUs));
            }
        }
        printTargets(a, showAll);
        log("");
        const status = Object.keys(a.Status).map(k => k + "=" + a.Status[k]).join(", ");
        log("SRB status: " + (status || "(none)"));
    }
}

// Errors are reported as one line rather than a script exception.
function run(fn) {
    try {
        fn();
    } catch (e) {
        log("error: " + e.message);
    }
}

// !vioscsi_telemetry [adapter extension address, 0 = all registered] [1 = include idle queues and targets]
function printTelemetry(address, all) {
    run(() => {
        const r = collectTelemetry(address, true);
        printAdapters(r.adapters, all, r.empty);
    });
}

// !vioscsi_telemetry_at <STOR_TELEMETRY address> [1 = include idle queues and targets]
function printTelemetryAt(address, all) {
    run(() => {
        if (address === undefined) {
            throw new Error("usage: !vioscsi_telemetry_at <STOR_TELEMETRY address> [1]");
        }
        printAdapters(vioscsiTelemetryAt(address), all, "");
    });
}

// !vioscsi_telemetry_scan <start> <length> [1 = include idle queues and targets]
function printTelemetryScan(start, length, all) {
    run(() => {
        if (start === undefined || length === undefined) {
            throw new Error("usage: !vioscsi_telemetry_scan <start> <length> [1]");
        }
        printAdapters(vioscsiTelemetryScan(start, length), all,
                      "No STOR_TELEMETRY found in " + hex(start) + " L" + hex(length));
    });
}

// ---- Event ring ----

// The directory, read raw even when symbols are available: only the offsets and adapter
// addresses are needed, and the raw layout is the same either way.
function eventDirectory() {
    try {
        const d = readDirectoryAt(host.getModuleSymbolAddress(MODULE, DIRECTORY_SYMBOL));
        if (d) {
            return d;
        }
    } catch (e) {
        // No symbols: fall back to scanning the image.
    }
    return scanDirectory();
}

// Decodes one VIOSCSI_EVENT from its ULONG64 slots (v[base] .. v[base + EVENT_SLOTS - 1]).
function decodeEvent(v, base) {
    const tail = v[base + 8];
    const lo = low32(tail);
    const hi = high32(tail);
    return {
        Sequence: num(v[base]),
        Time: num(v[base + 1]),
        TablePa: v[base + 2],
        Id: v[base + 3],
        SrbExt: v[base + 4],
        Srb: v[base + 5],
        Value1: v[base + 6],
        Value2: v[base + 7],
        Code: lo & 0xFFFF,
        Queue: lo >>> 16,
        Target: hi & 0xFF,
        Lun: (hi >>> 8) & 0xFF,
        AvailPos: hi >>> 16
    };
}

// True if the event names an avail entry, so its Queue/AvailPos can be compared with QEMU's.
function eventHasPos(e) {
    return e.Queue !== EVENT_NO_QUEUE &&
           (EVENTS_WITH_POS.has(e.Code) || (e.Code === 3 && (high32(e.Value1) & 1) !== 0));
}

// Reads a VIOSCSI_EVENT_RING; events come back oldest first. An entry is kept only if its
// Sequence belongs in its slot: 0 is an unused slot, and a mismatch a slot being rewritten when
// the dump was taken.
function readEventRing(ring) {
    const [magic, version, entrySize, entryCount] = readValues(ring, 4, 4).map(low32);
    if (magic !== VIOSCSI_EVENT_RING_MAGIC) {
        throw new Error("no event ring at " + hex(ring) + " (crash dump instance, or a driver without one)");
    }
    if (entrySize < EVENT_SLOTS * 8 || entrySize % 8 !== 0 || entryCount < 1 ||
        entryCount > EVENT_RING_MAX_ENTRIES || (entryCount & (entryCount - 1)) !== 0) {
        throw new Error("implausible event ring at " + hex(ring) + ": EntrySize " + entrySize +
                        ", EntryCount " + entryCount);
    }
    const next = num(readValues(ring.add(16), 1, 8)[0]);
    const flags = version >= 2 ? low32(readValues(ring.add(24), 1, 4)[0]) : 0;
    const entries = ring.add(version >= 2 ? EVENT_RING_V2_HEADER_SIZE : EVENT_RING_V1_HEADER_SIZE);
    const slots = entrySize / 8;
    const events = [];
    for (let first = 0; first < entryCount; first += EVENT_READ_CHUNK) {
        const count = Math.min(EVENT_READ_CHUNK, entryCount - first);
        const v = readValues(entries.add(first * entrySize), count * slots, 8);
        for (let j = 0; j < count; j++) {
            const e = decodeEvent(v, j * slots);
            if (e.Sequence !== 0 && (e.Sequence - 1) % entryCount === first + j) {
                if (version < 2) {
                    e.AvailPos = 0; // padding before version 2
                }
                events.push(e);
            }
        }
    }
    events.sort((a, b) => a.Sequence - b.Sequence);
    return {
        Address: ring, Version: version, Recorded: next, EntryCount: entryCount, Events: events,
        // No avail positions: a ring from before they were recorded, or packed virtqueues.
        NoAvailPos: version < 2 || (flags & EVENT_RING_PACKED) !== 0, Packed: (flags & EVENT_RING_PACKED) !== 0
    };
}

// Live entries of an adapter's Zombies[]: requests completed early that the device hasn't
// returned yet.
function readZombies(address) {
    const v = readValues(address, VIOSCSI_ZOMBIE_SLOTS * ZOMBIE_SLOTS, 8);
    const zombies = [];
    for (let i = 0; i < VIOSCSI_ZOMBIE_SLOTS; i++) {
        const b = i * ZOMBIE_SLOTS;
        if (isZero(v[b])) {
            continue;
        }
        zombies.push({
            Slot: i, Id: v[b + 1], SrbExt: v[b + 2], Srb: v[b + 3], TablePa: v[b + 4], Time: num(v[b + 5]),
            Reused: low32(v[b + 6]) !== 0, Queue: high32(v[b + 6]), AvailPos: low32(v[b + 7]) & 0xFFFF
        });
    }
    return zombies;
}

function readAdapterEvents(adapter, directory) {
    if (!directory.EventRingOffset) {
        throw new Error("the telemetry directory has no event ring offset (driver predates the event ring)");
    }
    const result = readEventRing(adapter.add(directory.EventRingOffset));
    result.Adapter = adapter;
    result.Zombies = directory.ZombiesOffset ? readZombies(adapter.add(directory.ZombiesOffset)) : [];
    return result;
}

// dx @$vioscsiEvents([adapter extension address])
function vioscsiEvents(address) {
    const directory = eventDirectory();
    const adapters = (address !== undefined && !isZero(address)) ? [toAddress(address)] : directory.Adapters;
    const result = [];
    for (const a of adapters) {
        try {
            result.push(readAdapterEvents(a, directory));
        } catch (e) {
            log("warning: adapter " + hex(a) + ": " + e.message);
        }
    }
    return result;
}

function sameAddress(a, b) {
    return hex(a).toLowerCase() === hex(b).toLowerCase();
}

function hnsToUs(hns) {
    return hns / HNS_PER_US;
}

function describeRequest(v2) {
    return "DataTransferLength " + low32(v2) + ", SRB flags " + hex(high32(v2));
}

// What Value1/Value2 (and Id, for the scatter/gather events) mean for each code, see
// VIOSCSI_EVENT_CODE in vioscsi/vioscsi.h.
function describeEvent(e) {
    const v1 = e.Value1;
    const v2 = e.Value2;
    switch (e.Code) {
        case 1:
            return "out " + (low32(v1) & 0xFFFF) + ", in " + ((low32(v1) >>> 16) & 0xFFFF) + ", " + num(v2) + " bytes";
        case 2:
            return "used length " + low32(v1) + ", response " + (low32(v2) & 0xFF) + ", SCSI status " +
                   hex((low32(v2) >>> 8) & 0xFF);
        case 3: {
            const flags = high32(v1);
            return "used length " + low32(v1) +
                   ((flags & 1) ? ", completed early " + fmtUs(hnsToUs(num(v2))) + " before" :
                                  ", NOT A REQUEST COMPLETED EARLY (unless evicted from a full zombie table)") +
                   ((flags & 2) ? ", RETURNED INTO A REUSED EXTENSION" : "");
        }
        case 4:
            return (num(v1) === 1 ? "by a reset" : num(v1) === 2 ? "by surprise removal" : "reason " + num(v1)) +
                   ", the device had it for " + fmtUs(hnsToUs(num(v2)));
        case 5:
            return "SRB function " + hex(num(v1)) + ", action on reset " + hex(low32(v2));
        case 6:
            return num(v1) + " request(s) completed early";
        case 7:
            return "TMF subtype " + num(v1);
        case 8:
            return "folded into the TMF in flight";
        case 9:
            return "response " + num(v1);
        case 10:
            return "timeout " + num(v1) + "s, " + (EVENT_SITE_NAMES[num(v2)] || "site " + num(v2));
        case 11:
            return EVENT_SITE_NAMES[num(v2)] || "site " + num(v2);
        case 12: {
            // VIOSCSI_REUSE_STILL_MARKED 1, _AGAIN 2, _IN_ZOMBIES 4.
            const flags = num(v2);
            return ((flags & 4) ? "DEVICE STILL HOLDS request " + hex(e.Id) :
                                  "request " + hex(e.Id) + " MAY STILL BE HELD (marked, but no zombie entry: " +
                                  "evicted from a full table, or already returned)") +
                   ((flags & 1) ? ", published " : ", completed early ") + fmtUs(hnsToUs(num(v1))) + " before" +
                   ((flags & 2) ? ", reused before" : "");
        }
        case 13:
            return "REFUSED: element " + high32(v1) + " of " + low32(v1) + " has zero length; SRB function " +
                   hex(num(e.Id)) + ", " + describeRequest(v2);
        case 14:
            return "REFUSED: " + high32(v1) + " elements, limit " + low32(v1) + "; SRB function " + hex(num(e.Id)) +
                   ", " + describeRequest(v2);
        case 15:
            return "elements add up to " + num(v1) + "; SRB function " + hex(num(e.Id)) + ", " + describeRequest(v2);
        case 16:
            return "ZERO-LENGTH DESCRIPTOR " + high32(v1) + " of " + low32(v1) + ", address " + hex(v2);
        default:
            return "Value1 " + hex(v1) + ", Value2 " + hex(v2);
    }
}

// A filter on the requests a QEMU report names: the indirect table address (addr=) and/or the
// virtqueue and avail position (queue=, pos=; QEMU's virtqueue numbering). Any part may be absent.
function chainFilter(tablePa, virtqueue, pos) {
    const f = {};
    if (tablePa !== undefined && !isZero(tablePa)) {
        f.TablePa = tablePa;
    }
    if (virtqueue !== undefined && pos !== undefined && num(virtqueue) >= VIRTIO_SCSI_REQUEST_QUEUE_0) {
        f.Queue = num(virtqueue) - VIRTIO_SCSI_REQUEST_QUEUE_0;
        f.Pos = num(pos) & 0xFFFF;
    }
    return (f.TablePa !== undefined || f.Queue !== undefined) ? f : null;
}

function describeFilter(f) {
    const parts = [];
    if (f.TablePa !== undefined) {
        parts.push("table " + hex(f.TablePa));
    }
    if (f.Queue !== undefined) {
        parts.push("virtqueue " + (f.Queue + VIRTIO_SCSI_REQUEST_QUEUE_0) + " avail pos " + f.Pos);
    }
    return parts.join(" or ");
}

// Matches an event (or zombie, which has the same fields) directly: by table, or by avail entry.
// noPos: the ring records no avail positions, so only the table can match.
function matchesChain(e, f, noPos, isZombie) {
    if (f.TablePa !== undefined && !isZero(e.TablePa) && sameAddress(e.TablePa, f.TablePa)) {
        return true;
    }
    return f.Queue !== undefined && !noPos && (isZombie || eventHasPos(e)) && e.Queue === f.Queue &&
           e.AvailPos === f.Pos;
}

// Events of the request(s) a filter names, plus every event of the same SRB extensions: the table
// lives in the extension, so this also shows what else used that memory (the reuse that matters)
// and events recorded before the table address was known, such as a refused scatter/gather list.
function eventsForChain(events, f, noPos) {
    const exts = new Set();
    for (const e of events) {
        if (matchesChain(e, f, noPos, false) && !isZero(e.SrbExt)) {
            exts.add(hex(e.SrbExt).toLowerCase());
        }
    }
    return events.filter(e => matchesChain(e, f, noPos, false) ||
                              (!isZero(e.SrbExt) && exts.has(hex(e.SrbExt).toLowerCase())));
}

// QEMU's name for an event's avail entry: virtqueue:pos.
function fmtVqPos(e, noPos) {
    if (e.Queue === EVENT_NO_QUEUE) {
        return "-";
    }
    const vq = e.Queue + VIRTIO_SCSI_REQUEST_QUEUE_0;
    return (noPos || !(e.AvailPos !== undefined && (e.IsZombie || eventHasPos(e)))) ? vq + ":-" : vq + ":" + e.AvailPos;
}

const EVENT_COLUMNS = [
    { name: "Seq", value: e => e.Sequence },
    { name: "Age", value: e => e.AgeUs === null ? "-" : fmtUs(e.AgeUs) },
    { name: "Event", value: e => EVENT_NAMES[e.Code] || "code " + e.Code },
    { name: "VQ:Pos", value: e => fmtVqPos(e, e.NoPos) },
    { name: "T:L", value: e => e.Target + ":" + e.Lun },
    { name: "Id", value: e => isZero(e.Id) ? "-" : hex(e.Id) },
    { name: "TablePa", value: e => isZero(e.TablePa) ? "-" : hex(e.TablePa) },
    { name: "SrbExt", value: e => isZero(e.SrbExt) ? "-" : hex(e.SrbExt) },
    { name: "Srb", value: e => isZero(e.Srb) ? "-" : hex(e.Srb) },
    { name: "Detail", value: e => describeEvent(e), left: true }
];

const ZOMBIE_COLUMNS = [
    { name: "Slot", value: z => z.Slot },
    { name: "VQ:Pos", value: z => fmtVqPos(z, z.NoPos) },
    { name: "Id", value: z => hex(z.Id) },
    { name: "TablePa", value: z => hex(z.TablePa) },
    { name: "SrbExt", value: z => hex(z.SrbExt) },
    { name: "Srb", value: z => hex(z.Srb) },
    { name: "CompletedEarly", value: z => z.AgeUs === null ? "-" : fmtAgo(z.AgeUs) },
    { name: "ExtReused", value: z => z.Reused ? "yes" : "no" }
];

// Prints an adapter's ring: the last <count> events, or those a chainFilter selects. Returns the
// number of events shown.
function printEventRing(r, filter, count, quietIfNone) {
    let shown;
    if (filter) {
        shown = eventsForChain(r.Events, filter, r.NoAvailPos);
        if (shown.length === 0 && quietIfNone) {
            return 0;
        }
    } else {
        shown = r.Events.slice(-count);
    }
    // Ages are against the dump/session's interrupt time, or the newest event without one.
    const newest = r.Events.length ? r.Events[r.Events.length - 1].Time : 0;
    const dumpNow = readInterruptTimeHns();
    const now = dumpNow || newest;
    r.Events.forEach(e => {
        e.AgeUs = ageUs(now, e.Time);
        e.NoPos = r.NoAvailPos;
    });
    r.Zombies.forEach(z => {
        z.AgeUs = ageUs(now, z.Time);
        z.NoPos = r.NoAvailPos;
        z.IsZombie = true;
    });
    log("");
    log("== adapter " + hex(r.Adapter) + " event ring " + hex(r.Address) + ": " + r.Recorded +
        " events recorded, the last " + r.Events.length + " kept; ages relative to " +
        (dumpNow ? "the dump/session interrupt time" : "the newest event"));
    if (r.NoAvailPos) {
        log("No avail positions recorded (" + (r.Packed ? "packed virtqueues" : "driver predates them") +
            "): only the table address can be matched.");
    }
    log(filter ? "Events for the request(s) at " + describeFilter(filter) + ", with every other use of their SRB " +
                 "extensions: " + shown.length
               : "Last " + shown.length + " events:");
    if (shown.length) {
        fmtTable(EVENT_COLUMNS, shown);
    }
    let zombies = r.Zombies;
    if (filter) {
        zombies = zombies.filter(z => matchesChain(z, filter, r.NoAvailPos, true));
    }
    log("");
    log("Requests completed early that the device has not returned: " + zombies.length +
        (zombies.length === r.Zombies.length ? "" : " (of " + r.Zombies.length + ")"));
    if (zombies.length) {
        fmtTable(ZOMBIE_COLUMNS, zombies);
    }
    return shown.length;
}

// !vioscsi_events [adapter extension, 0 = all registered] [table PA, 0 = none] [count, 0 = 64]
//                 [virtqueue] [avail pos]
function printEvents(address, tablePa, count, virtqueue, pos) {
    run(() => {
        const n = (count === undefined || isZero(count)) ? EVENTS_DEFAULT_COUNT : num(count);
        const rings = vioscsiEvents(address);
        if (rings.length === 0) {
            log("No vioscsi adapter with an event ring found");
        }
        const filter = chainFilter(tablePa, virtqueue, pos);
        rings.forEach(r => printEventRing(r, filter, n, false));
    });
}

// !vioscsi_chain <table PA> [virtqueue] [avail pos]: the addr=, queue= and pos= of a QEMU
// virtqueue_chain_error line. QEMU's dev= names the adapter by QEMU id, which the guest doesn't
// know, so every adapter is searched and only those with a match are printed.
function printChain(tablePa, virtqueue, pos) {
    run(() => {
        const filter = chainFilter(tablePa, virtqueue, pos);
        if (!filter) {
            throw new Error("usage: !vioscsi_chain <table PA> [<virtqueue> <avail pos>]");
        }
        let matched = 0;
        for (const r of vioscsiEvents(undefined)) {
            matched += printEventRing(r, filter, 0, true) ? 1 : 0;
        }
        if (matched === 0) {
            log("No event in any adapter's ring matches " + describeFilter(filter) +
                ": the request is older than the ring, or the address is not one of this guest's tables.");
        } else if (matched > 1 && filter.TablePa === undefined) {
            log("warning: " + matched + " adapters have an entry at that virtqueue and position; " +
                "add the table address to tell them apart.");
        }
    });
}

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(printTelemetry, "vioscsi_telemetry"),
        new host.functionAlias(printTelemetryAt, "vioscsi_telemetry_at"),
        new host.functionAlias(printTelemetryScan, "vioscsi_telemetry_scan"),
        new host.functionAlias(printEvents, "vioscsi_events"),
        new host.functionAlias(printChain, "vioscsi_chain"),
        new host.functionAlias(vioscsiEvents, "vioscsiEvents"),
        new host.functionAlias(vioscsiTelemetry, "vioscsiTelemetry"),
        new host.functionAlias(vioscsiTelemetryAt, "vioscsiTelemetryAt"),
        new host.functionAlias(vioscsiTelemetryScan, "vioscsiTelemetryScan")
    ];
}
