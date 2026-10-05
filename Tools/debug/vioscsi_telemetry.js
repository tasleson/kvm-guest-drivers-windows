// WinDbg script: summarize vioscsi STOR_TELEMETRY from a kernel dump or live kernel session.
//
// Usage:
//   .scriptload <path>\vioscsi_telemetry.js
//   !vioscsi_telemetry                     summary of every registered vioscsi adapter
//   !vioscsi_telemetry <adapter extension> summary of one adapter, by its miniport device extension
//   !vioscsi_telemetry 0 1                 all adapters, including queues with no completions
//   !vioscsi_telemetry_at <address> [1]    parse a STOR_TELEMETRY at a known address (no symbols needed)
//   !vioscsi_telemetry_scan <start> <len> [1]
//                                          scan a memory range for STOR_TELEMETRY blocks (no symbols needed)
//   dx @$vioscsiTelemetry()                the same data as data model objects
//   dx -r3 @$vioscsiTelemetry()[0].Queues  drill into per-queue values and raw histograms
//
// With matching vioscsi symbols, !vioscsi_telemetry reads vioscsi!VioScsiTelemetryDirectory
// and the typed structures. Without them it finds the vioscsi image in the module list, scans
// its writable sections for the directory's magic, and parses each adapter's STOR_TELEMETRY
// from the raw layout described by the block's own header (see vioscsi/vioscsi.h).
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
const STOR_TELEMETRY_MIN_VERSION = 3;
const MAX_CPU = 256; // length of STOR_TELEMETRY.Queues[]
const STOR_TELEMETRY_HISTOGRAM_BUCKETS = 64; // length of LATENCY_STATS.Buckets[]
const STOR_TELEMETRY_STATUS_SLOTS = 64; // length of QUEUE_TELEMETRY.StatusHistogram[]
const VIOSCSI_TELEMETRY_DIRECTORY_MAGIC = 0x44545356; // 'VSTD'

// Raw (symbol-free) layout, matching Tools/debug/GetVioScsiTelemetry.ps1.
// STOR_TELEMETRY header: Magic, Version, HeaderSize, QueueSize, QueueCount, LatencyBuckets,
// StatusSlots, Reserved (8 ULONGs), then the six adapter-wide ULONG64s.
const HEADER_ULONGS = 8;
const HEADER_V3_SIZE = 80;
const RESET_FIELDS = ["BusResetCount", "DeviceResetCount", "LogicalUnitResetCount", "LastResetDurationUs",
                      "MaxResetDurationUs", "DeviceResetTmfInFlightCount"];
// QUEUE_TELEMETRY, in ULONG64 slots: 7 counters, Buckets[B], Count/SumUs/MinUs/MaxUs,
// StatusHistogram[S], then InFlightHighWaterMark + Reserved (two ULONGs) and QueueFullCount.
const QUEUE_COUNTER_SLOTS = 7;
const QUEUE_LATENCY_SLOTS = 4;
const QUEUE_TRAILER_SLOTS = 2;
// Sanity bounds for header-described sizes in the raw path, so a corrupt header can't make
// the script read megabytes per queue. v3 uses HeaderSize 80 and QueueSize 1128.
const RAW_MAX_ARRAY_SLOTS = 256;
const RAW_MAX_HEADER_SIZE = 4 * 1024;
const RAW_MAX_QUEUE_SIZE = 64 * 1024;
// VIOSCSI_TELEMETRY_DIRECTORY: Magic, Version, PointerSize, MaxAdapters, TelemetryOffset,
// Reserved (6 ULONGs), then Adapters[MaxAdapters] of PointerSize each.
const DIRECTORY_ULONGS = 6;
const DIRECTORY_MAX_ADAPTERS = 64;
const DIRECTORY_MAX_TELEMETRY_OFFSET = 4 * 1024 * 1024;
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
                        "Completions", "LatencySumUs", "QueueFull"];

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

function addLatencyStats(row) {
    row.AvgUs = row.Completions ? Math.round((row.LatencySumUs / row.Completions) * 10) / 10 : null;
    row.P50Us = percentileUs(row.LatencyBuckets, 0.50);
    row.P99Us = percentileUs(row.LatencyBuckets, 0.99);
    return row;
}

// Builds the normalized per-adapter result shared by the typed and raw paths.
// header: { Version, QueueCount, LatencyBuckets, StatusSlots, <RESET_FIELDS> }
function summarize(source, header, queues, typed) {
    const total = { Queue: "Total", MinUs: 0, MaxUs: 0, InFlightHwm: 0 };
    COUNTER_FIELDS.forEach(f => total[f] = 0);
    total.LatencyBuckets = new Array(header.LatencyBuckets).fill(0);
    total.StatusHistogram = new Array(header.StatusSlots).fill(0);
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

    const result = { Source: source, Version: header.Version, QueueCount: queues.length };
    RESET_FIELDS.forEach(f => result[f] = header[f]);
    result.Queues = queues;
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
        StatusHistogram: readArray(q.StatusHistogram, statusSlots)
    });
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
    const queueCount = Math.min(num(t.QueueCount), MAX_CPU);
    const queues = [];
    for (let i = 0; i < queueCount; i++) {
        queues.push(readTypedQueue(t.Queues[i], i, header.LatencyBuckets, header.StatusSlots));
    }
    return summarize(source, header, queues, t);
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
    const [magic, version, headerSize, queueSize, queueCount, latencyBuckets, statusSlots, reserved] = u;
    checkMagicAndVersion(source, magic, version);
    if (strict && reserved !== 0) {
        throw new Error(source + ": telemetry header Reserved is " + hex(reserved));
    }
    const implausible = what => new Error(source + ": implausible telemetry header: " + what);
    if (latencyBuckets < 1 || latencyBuckets > RAW_MAX_ARRAY_SLOTS) {
        throw implausible("LatencyBuckets " + latencyBuckets + " not in 1.." + RAW_MAX_ARRAY_SLOTS);
    }
    if (statusSlots < 1 || statusSlots > RAW_MAX_ARRAY_SLOTS) {
        throw implausible("StatusSlots " + statusSlots + " not in 1.." + RAW_MAX_ARRAY_SLOTS);
    }
    if (headerSize < HEADER_V3_SIZE || headerSize > RAW_MAX_HEADER_SIZE || headerSize % 8 !== 0) {
        throw implausible("HeaderSize " + headerSize + " is not a multiple of 8 in " + HEADER_V3_SIZE + ".." +
                          RAW_MAX_HEADER_SIZE);
    }
    // Only the fields this script knows are read from each queue; QueueSize may be larger.
    const queueSlots = QUEUE_COUNTER_SLOTS + latencyBuckets + QUEUE_LATENCY_SLOTS + statusSlots + QUEUE_TRAILER_SLOTS;
    if (queueSize < queueSlots * 8 || queueSize > RAW_MAX_QUEUE_SIZE || queueSize % 8 !== 0) {
        throw implausible("QueueSize " + queueSize + " is not a multiple of 8 in " + queueSlots * 8 + ".." +
                          RAW_MAX_QUEUE_SIZE);
    }
    if (queueCount > MAX_CPU) {
        throw implausible("QueueCount " + queueCount + " exceeds " + MAX_CPU);
    }
    const header = {
        Version: version, HeaderSize: headerSize, QueueSize: queueSize, QueueCount: queueCount,
        LatencyBuckets: latencyBuckets, StatusSlots: statusSlots, QueueSlots: queueSlots
    };
    const resets = readValues(address.add(HEADER_ULONGS * 4), RESET_FIELDS.length, 8);
    RESET_FIELDS.forEach((f, i) => header[f] = num(resets[i]));
    return header;
}

function readRawQueue(address, index, header) {
    const v = readValues(address, header.QueueSlots, 8);
    const buckets = QUEUE_COUNTER_SLOTS;
    const latency = buckets + header.LatencyBuckets;
    const status = latency + QUEUE_LATENCY_SLOTS;
    const trailer = status + header.StatusSlots;
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
        StatusHistogram: slice(status, header.StatusSlots)
    });
}

function readRawTelemetry(address, source, strict) {
    const header = readRawHeader(address, source, strict);
    const queues = [];
    for (let i = 0; i < header.QueueCount; i++) {
        queues.push(readRawQueue(address.add(header.HeaderSize + i * header.QueueSize), i, header));
    }
    return summarize(source, header, queues, null);
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
        return { Address: address, TelemetryOffset: telemetryOffset, Adapters: adapters };
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

function printAdapters(adapters, all, emptyMessage) {
    const showAll = all !== undefined && !isZero(all);
    if (adapters.length === 0) {
        log(emptyMessage);
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

// Errors are reported as one line rather than a script exception.
function run(fn) {
    try {
        fn();
    } catch (e) {
        log("error: " + e.message);
    }
}

// !vioscsi_telemetry [adapter extension address, 0 = all registered] [1 = include idle queues]
function printTelemetry(address, all) {
    run(() => {
        const r = collectTelemetry(address, true);
        printAdapters(r.adapters, all, r.empty);
    });
}

// !vioscsi_telemetry_at <STOR_TELEMETRY address> [1 = include idle queues]
function printTelemetryAt(address, all) {
    run(() => {
        if (address === undefined) {
            throw new Error("usage: !vioscsi_telemetry_at <STOR_TELEMETRY address> [1]");
        }
        printAdapters(vioscsiTelemetryAt(address), all, "");
    });
}

// !vioscsi_telemetry_scan <start> <length> [1 = include idle queues]
function printTelemetryScan(start, length, all) {
    run(() => {
        if (start === undefined || length === undefined) {
            throw new Error("usage: !vioscsi_telemetry_scan <start> <length> [1]");
        }
        printAdapters(vioscsiTelemetryScan(start, length), all,
                      "No STOR_TELEMETRY found in " + hex(start) + " L" + hex(length));
    });
}

function initializeScript() {
    return [
        new host.apiVersionSupport(1, 7),
        new host.functionAlias(printTelemetry, "vioscsi_telemetry"),
        new host.functionAlias(printTelemetryAt, "vioscsi_telemetry_at"),
        new host.functionAlias(printTelemetryScan, "vioscsi_telemetry_scan"),
        new host.functionAlias(vioscsiTelemetry, "vioscsiTelemetry"),
        new host.functionAlias(vioscsiTelemetryAt, "vioscsiTelemetryAt"),
        new host.functionAlias(vioscsiTelemetryScan, "vioscsiTelemetryScan")
    ];
}
