// WinDbg script: summarize vioscsi STOR_TELEMETRY from a kernel dump or live kernel session.
//
// Usage (vioscsi symbols must be loadable):
//   .scriptload <path>\vioscsi_telemetry.js
//   !vioscsi_telemetry                     summary of every registered vioscsi adapter
//   !vioscsi_telemetry <adapter extension> summary of one adapter, by its miniport device extension
//   !vioscsi_telemetry 0 1                 all adapters, including queues with no completions
//   dx @$vioscsiTelemetry()                the same data as data model objects
//   dx -r3 @$vioscsiTelemetry()[0].Queues  drill into per-queue values and raw histograms
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
const ADAPTER_LIST_SYMBOL = "VioScsiTelemetryAdapters";
const ADAPTER_POINTER_TYPE = "_ADAPTER_EXTENSION *";
const STOR_TELEMETRY_MAGIC = 0x53505331;
const STOR_TELEMETRY_MIN_VERSION = 3;
const MAX_CPU = 256; // length of STOR_TELEMETRY.Queues[]
const STOR_TELEMETRY_HISTOGRAM_BUCKETS = 64; // length of LATENCY_STATS.Buckets[]
const STOR_TELEMETRY_STATUS_SLOTS = 64; // length of QUEUE_TELEMETRY.StatusHistogram[]

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
                        "Completions", "LatencySumUs", "QueueFull"];

function log(s) {
    host.diagnostics.debugLog(s + "\n");
}

// 64-bit fields arrive as host.Int64 objects (smaller ones may arrive as plain numbers).
// Counters are converted to JS numbers for arithmetic and display: exact up to 2^53,
// which no realistic counter (e.g. 8 PiB of I/O) reaches.
function num(v) {
    return (typeof v === "number") ? v : v.convertToNumber();
}

function isZero(v) {
    return (typeof v === "number") ? v === 0 : (v.getLowPart() === 0 && v.getHighPart() === 0);
}

function hex(v) {
    return "0x" + ((typeof v === "number") ? v.toString(16) : v.toString(16).replace(/^0x/, ""));
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

function addLatencyStats(row) {
    row.AvgUs = row.Completions ? Math.round((row.LatencySumUs / row.Completions) * 10) / 10 : null;
    row.P50Us = percentileUs(row.LatencyBuckets, 0.50);
    row.P99Us = percentileUs(row.LatencyBuckets, 0.99);
    return row;
}

function readQueue(q, index, latencyBuckets, statusSlots) {
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
        StatusHistogram: readArray(q.StatusHistogram, statusSlots)
    });
}

function readAdapter(adapterPtr) {
    const adapter = adapterPtr.dereference();
    const t = adapter.Telemetry;
    const source = MODULE + "!_ADAPTER_EXTENSION " + hex(adapterPtr.address);

    if (num(t.Magic) !== STOR_TELEMETRY_MAGIC) {
        throw new Error(source + ": bad telemetry magic " + hex(t.Magic));
    }
    const version = num(t.Version);
    if (version < STOR_TELEMETRY_MIN_VERSION) {
        throw new Error(source + ": telemetry version " + version + " is not supported");
    }

    // Clamp header-reported sizes to the compiled array lengths so a corrupt header
    // can't index past the arrays.
    const latencyBuckets = Math.min(num(t.LatencyBuckets), STOR_TELEMETRY_HISTOGRAM_BUCKETS);
    const statusSlots = Math.min(num(t.StatusSlots), STOR_TELEMETRY_STATUS_SLOTS);
    const queueCount = Math.min(num(t.QueueCount), MAX_CPU);
    const queues = [];
    for (let i = 0; i < queueCount; i++) {
        queues.push(readQueue(t.Queues[i], i, latencyBuckets, statusSlots));
    }

    const total = { Queue: "Total", MinUs: 0, MaxUs: 0, InFlightHwm: 0 };
    COUNTER_FIELDS.forEach(f => total[f] = 0);
    total.LatencyBuckets = new Array(latencyBuckets).fill(0);
    total.StatusHistogram = new Array(statusSlots).fill(0);
    for (const q of queues) {
        COUNTER_FIELDS.forEach(f => total[f] += q[f]);
        if (q.MinUs && (!total.MinUs || q.MinUs < total.MinUs)) {
            total.MinUs = q.MinUs;
        }
        total.MaxUs = Math.max(total.MaxUs, q.MaxUs);
        total.InFlightHwm = Math.max(total.InFlightHwm, q.InFlightHwm);
        q.LatencyBuckets.forEach((v, i) => total.LatencyBuckets[i] += v);
        q.StatusHistogram.forEach((v, i) => total.StatusHistogram[i] += v);
    }
    addLatencyStats(total);

    const status = {};
    total.StatusHistogram.forEach((v, i) => {
        if (v) {
            status[SRB_STATUS_NAMES[i] || "0x" + (i < 16 ? "0" : "") + i.toString(16).toUpperCase()] = v;
        }
    });

    return {
        Source: source,
        Version: version,
        QueueCount: queueCount,
        BusResetCount: num(t.BusResetCount),
        DeviceResetCount: num(t.DeviceResetCount),
        LogicalUnitResetCount: num(t.LogicalUnitResetCount),
        LastResetDurationUs: num(t.LastResetDurationUs),
        MaxResetDurationUs: num(t.MaxResetDurationUs),
        DeviceResetTmfInFlightCount: num(t.DeviceResetTmfInFlightCount),
        Queues: queues,
        Total: total,
        Status: status,
        Telemetry: t
    };
}

function adapterPointers(address) {
    if (address !== undefined && !isZero(address)) {
        return [host.createPointerObject(address, MODULE, ADAPTER_POINTER_TYPE)];
    }
    const out = [];
    for (const p of host.getModuleSymbol(MODULE, ADAPTER_LIST_SYMBOL)) {
        if (!p.isNull) {
            out.push(p);
        }
    }
    return out;
}

// dx @$vioscsiTelemetry([adapter extension address])
function vioscsiTelemetry(address) {
    const result = [];
    for (const p of adapterPointers(address)) {
        try {
            result.push(readAdapter(p));
        } catch (e) {
            log("warning: " + e.message);
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
    const line = vals => vals.map((v, i) => pad(v, widths[i], i === 0)).join("  ");
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

// !vioscsi_telemetry [adapter extension address, 0 = all registered] [1 = include idle queues]
function printTelemetry(address, all) {
    const showAll = all !== undefined && !isZero(all);
    const adapters = vioscsiTelemetry(address);
    if (adapters.length === 0) {
        log("No vioscsi adapters registered in " + MODULE + "!" + ADAPTER_LIST_SYMBOL);
        return;
    }
    for (const a of adapters) {
        log("");
        log("== " + a.Source + "  (telemetry v" + a.Version + ", " + a.QueueCount + " queues)");
        log("Resets: bus " + a.BusResetCount + ", device " + a.DeviceResetCount + ", LUN " +
            a.LogicalUnitResetCount + "; last " + fmtUs(a.LastResetDurationUs) + ", max " +
            fmtUs(a.MaxResetDurationUs) + "; DeviceReset with TMF in flight " + a.DeviceResetTmfInFlightCount);
        log("");
        const rows = a.Queues.filter(q => showAll || q.Completions || q.QueueFull);
        rows.push(a.Total);
        fmtTable(SUMMARY_COLUMNS, rows);
        log("");
        const status = Object.keys(a.Status).map(k => k + "=" + a.Status[k]).join(", ");
        log("SRB status: " + (status || "(none)"));
    }
}

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(printTelemetry, "vioscsi_telemetry"),
        new host.functionAlias(vioscsiTelemetry, "vioscsiTelemetry")
    ];
}
