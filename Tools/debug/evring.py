#!/usr/bin/env python3
# Decode the vioscsi per-adapter event ring and zombie table from a QEMU Windows dump, on the
# host, without WinDbg.
#
# Usage:
#   evring.py events <dump> [--adapter VA] [--count N] [--table PA] [--pos VQ POS]
#                                          last <count> events (default 64) of every adapter, and
#                                          its zombies; or every event of the request(s) whose
#                                          indirect table is at PA or that were published at
#                                          avail position POS of virtqueue VQ (QEMU numbering)
#   evring.py chain <dump> <table PA> [<virtqueue> <avail pos>] [--resets]
#                                          the same for every adapter, taking the addr=, queue=
#                                          and pos= of a QEMU virtqueue_chain_error line
#
# The output follows !vioscsi_events and !vioscsi_chain in vioscsi_telemetry.js; see README.md
# for how to read it. The dump is the one QEMU writes with `dump-guest-memory -w` (a 64-bit
# Windows crash dump, "PAGEDU64"), e.g. the break.dmp of a soak run with x-stop-on-broken.
#
# No symbols are needed. vioscsi lists its started adapters in VioScsiTelemetryDirectory, a
# static in the image's .data that is found by its magic ('VSTD') in physical memory; the
# adapter extensions it points to are read through the guest's own page tables, starting from
# the DirectoryTableBase in the dump header. x64 guests only.
#
# Copyright (c) 2026 Red Hat, Inc. and/or its affiliates. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the names of the copyright holders nor the names of their contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

import argparse
import bisect
import math
import mmap
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

PAGE_SIZE = 0x1000
PFN_MASK = 0x000FFFFFFFFFF000
PTE_PRESENT = 0x1
PTE_LARGE = 0x80

# DUMP_HEADER64: DirectoryTableBase at 0x10, PHYSICAL_MEMORY_DESCRIPTOR at 0x88 (NumberOfRuns,
# padding, NumberOfPages, then Run[] of BasePage/PageCount, room for 43 in the header),
# DumpType at 0xF98. In a full dump (DumpType 1, what QEMU writes) the page data follows the
# 0x2000-byte header in run order; kernel and bitmap dumps are laid out differently.
DUMP_SIGNATURE = b"PAGEDU64"
DUMP_DTB_OFFSET = 0x10
DUMP_RUNS_OFFSET = 0x88
DUMP_PAGES_OFFSET = 0x90
DUMP_RUN_ARRAY_OFFSET = 0x98
DUMP_MAX_RUNS = 43
DUMP_TYPE_OFFSET = 0xF98
DUMP_TYPE_FULL = 1
DUMP_HEADER_SIZE = 0x2000

# Timestamps are interrupt time in 100 ns units; "now" is that clock in KUSER_SHARED_DATA
# (InterruptTime, a KSYSTEM_TIME at offset 8), as in vioscsi_telemetry.js.
HNS_PER_US = 10
KUSER_SHARED_DATA = 0xFFFFF78000000000
KUSER_INTERRUPT_TIME_OFFSET = 8

# VIOSCSI_TELEMETRY_DIRECTORY: Magic, Version, PointerSize, MaxAdapters, TelemetryOffset,
# Reserved (ULONGs), Adapters[MaxAdapters], then from version 2 EventRingOffset and
# ZombiesOffset (ULONGs). Bounds as in the WinDbg script's readDirectoryAt.
DIRECTORY_MAGIC = b"VSTD"
DIRECTORY_HEADER = struct.Struct("<6I")
DIRECTORY_EVENTS_VERSION = 2
DIRECTORY_MAX_ADAPTERS = 64
DIRECTORY_MAX_TELEMETRY_OFFSET = 4 * 1024 * 1024
DIRECTORY_MAX_EXTENSION_OFFSET = 16 * 1024 * 1024
POINTER_SIZE = 8

# VIOSCSI_EVENT_RING: Magic, Version, EntrySize, EntryCount (ULONGs), Next (LONG64), from
# version 2 Flags and Reserved, then Entries[]. VIOSCSI_EVENT: Sequence, Time, TablePa, Id,
# SrbExt, Srb, Value1, Value2 (ULONG64s), Code, Queue (USHORTs), Target, Lun (UCHARs),
# AvailPos (USHORT; padding in version 1).
EVENT_RING_MAGIC = 0x47525645  # 'EVRG'
EVENT_RING_HEADER = struct.Struct("<4Iq")
EVENT_RING_V1_HEADER_SIZE = 24
EVENT_RING_V2_HEADER_SIZE = 32
EVENT_RING_PACKED = 0x1
EVENT_RING_MAX_ENTRIES = 1 << 20
EVENT = struct.Struct("<8Q2H2BH")
EVENT_NO_QUEUE = 0xFFFF
EVENTS_DEFAULT_COUNT = 64
# Events whose AvailPos names a request's avail entry. An OrphanReturn has one only when it
# matched an early-completed request (VIOSCSI_ORPHAN_EARLY_COMPLETED).
EVENTS_WITH_POS = {1, 2, 4, 12, 16}
EVENT_ORPHAN_RETURN = 3
# ResetRequest through Resume: what chain --resets interleaves. The scatter/gather refusals are
# recorded without a queue too, but belong to some other request.
ADAPTER_EVENTS = range(5, 12)

# VIOSCSI_ZOMBIE[VIOSCSI_ZOMBIE_SLOTS]: Key, Id, SrbExt, Srb, TablePa, Time (ULONG64s), Reused,
# Queue (ULONGs), AvailPos (USHORT), padding to 64 bytes.
ZOMBIE_SLOTS = 1024
ZOMBIE = struct.Struct("<6Q2IH6x")

# QEMU numbers virtqueues from the control (0) and event (1) queues, so the driver's request
# queue N is QEMU's virtqueue N + 2.
VIRTIO_SCSI_REQUEST_QUEUE_0 = 2

EVENT_NAMES = {
    1: "Publish", 2: "DeviceComplete", 3: "OrphanReturn", 4: "EarlyComplete", 5: "ResetRequest",
    6: "ResetDone", 7: "TmfSent", 8: "TmfCoalesced", 9: "TmfComplete", 10: "Pause", 11: "Resume",
    12: "ExtReused", 13: "SgZeroLength", 14: "SgTooManyElements", 15: "SgLengthMismatch",
    16: "ZeroLengthDesc",
}
EVENT_SITE_NAMES = {
    1: "CompletePendingRequestsOnReset", 2: "DeviceReset", 3: "ProcessTMFCompletion",
    4: "DeviceReset, TMF not posted",
}


class DumpError(Exception):
    pass


class Dump:
    """Physical and kernel-virtual reads from a 64-bit Windows crash dump."""

    def __init__(self, path):
        try:
            with open(path, "rb") as f:
                self.data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (OSError, ValueError) as e:
            raise DumpError(f"cannot map {path}: {e}") from e
        if len(self.data) < DUMP_HEADER_SIZE or self.data[:8] != DUMP_SIGNATURE:
            raise DumpError(f"{path} is not a 64-bit Windows crash dump (no {DUMP_SIGNATURE.decode()} "
                            "signature); write it with QEMU's dump-guest-memory -w")
        (dump_type,) = struct.unpack_from("<I", self.data, DUMP_TYPE_OFFSET)
        if dump_type != DUMP_TYPE_FULL:
            raise DumpError(f"{path} has DumpType {dump_type}; only full memory dumps (DumpType "
                            f"{DUMP_TYPE_FULL}, as QEMU's dump-guest-memory -w writes) are supported")
        self.dtb = struct.unpack_from("<Q", self.data, DUMP_DTB_OFFSET)[0] & PFN_MASK
        (nruns,) = struct.unpack_from("<I", self.data, DUMP_RUNS_OFFSET)
        (npages,) = struct.unpack_from("<Q", self.data, DUMP_PAGES_OFFSET)
        if not 1 <= nruns <= DUMP_MAX_RUNS:
            raise DumpError(f"{path} has a corrupt header: {nruns} physical memory runs")
        self.runs = []  # (first pfn, page count, file offset), sorted by pfn and by file offset
        offset = DUMP_HEADER_SIZE
        for i in range(nruns):
            base, count = struct.unpack_from("<QQ", self.data, DUMP_RUN_ARRAY_OFFSET + 16 * i)
            if self.runs and base < self.runs[-1][0] + self.runs[-1][1]:
                raise DumpError(f"{path} has a corrupt header: physical memory runs out of order or overlapping")
            self.runs.append((base, count, offset))
            offset += count * PAGE_SIZE
        if sum(r[1] for r in self.runs) != npages:
            raise DumpError(f"{path} has a corrupt header: its runs don't add up to {npages} pages")
        if offset > len(self.data):
            raise DumpError(f"{path} is truncated: its runs need {offset} bytes, the file has {len(self.data)}")
        self._run_pfns = [r[0] for r in self.runs]
        self._run_offsets = [r[2] for r in self.runs]

    def page_offset(self, pfn):
        """File offset of a physical page, or None if the dump doesn't have it."""
        i = bisect.bisect_right(self._run_pfns, pfn) - 1
        if i >= 0:
            base, count, offset = self.runs[i]
            if pfn < base + count:
                return offset + (pfn - base) * PAGE_SIZE
        return None

    def offset_pa(self, offset):
        """Physical address of a file offset in the page data."""
        i = bisect.bisect_right(self._run_offsets, offset) - 1
        base, _, run_offset = self.runs[i]
        return base * PAGE_SIZE + offset - run_offset

    def _table(self, pa):
        """All 512 entries of a page table, or None if the dump doesn't have it."""
        offset = self.page_offset(pa >> 12)
        return None if offset is None else struct.unpack_from("<512Q", self.data, offset)

    def translate(self, va):
        """Physical address of a kernel virtual address, or None if it isn't mapped in the dump."""
        entry = self.dtb
        for shift in (39, 30, 21, 12):
            offset = self.page_offset((entry & PFN_MASK) >> 12)
            if offset is None:
                return None
            (entry,) = struct.unpack_from("<Q", self.data, offset + ((va >> shift) & 0x1FF) * 8)
            if not entry & PTE_PRESENT:
                return None
            if shift in (30, 21) and entry & PTE_LARGE:
                mask = (1 << shift) - 1
                return (entry & PFN_MASK & ~mask) | (va & mask)
        return (entry & PFN_MASK) | (va & 0xFFF)

    def read_va(self, va, length):
        out = bytearray()
        while length:
            pa = self.translate(va)
            offset = None if pa is None else self.page_offset(pa >> 12)
            if offset is None:
                raise DumpError(f"virtual address {va:#x} is not in the dump")
            chunk = min(length, PAGE_SIZE - (va & 0xFFF))
            offset += pa & 0xFFF
            out += self.data[offset:offset + chunk]
            va += chunk
            length -= chunk
        return bytes(out)

    def find(self, needle):
        """Physical addresses of every occurrence of needle in the page data."""
        pos = self.data.find(needle, DUMP_HEADER_SIZE)
        while pos != -1:
            yield self.offset_pa(pos), pos
            pos = self.data.find(needle, pos + 1)

    def kernel_va(self, pa):
        """A kernel virtual address that maps physical address pa, or None. Walks every kernel
        page table, so it is slow; only used when nothing else gives the address."""
        pfn = pa >> 12
        pml4 = self._table(self.dtb)
        for i4 in range(256, 512):
            e4 = pml4[i4] if pml4 else 0
            pdpt = self._table(e4 & PFN_MASK) if e4 & PTE_PRESENT else None
            for i3, e3 in enumerate(pdpt or ()):
                if not e3 & PTE_PRESENT:
                    continue
                va3 = (0xFFFF << 48) | (i4 << 39) | (i3 << 30)
                if e3 & PTE_LARGE:
                    base = (e3 & PFN_MASK & ~0x3FFFFFFF) >> 12
                    if base <= pfn < base + (1 << 18):
                        return va3 | ((pa - (base << 12)) & 0x3FFFFFFF)
                    continue
                for i2, e2 in enumerate(self._table(e3 & PFN_MASK) or ()):
                    if not e2 & PTE_PRESENT:
                        continue
                    va2 = va3 | (i2 << 21)
                    if e2 & PTE_LARGE:
                        base = (e2 & PFN_MASK & ~0x1FFFFF) >> 12
                        if base <= pfn < base + 512:
                            return va2 | ((pa - (base << 12)) & 0x1FFFFF)
                        continue
                    for i1, e1 in enumerate(self._table(e2 & PFN_MASK) or ()):
                        if e1 & PTE_PRESENT and (e1 & PFN_MASK) >> 12 == pfn:
                            return va2 | (i1 << 12) | (pa & 0xFFF)
        return None

    def interrupt_time(self):
        """KUSER_SHARED_DATA.InterruptTime, or 0 if it isn't in the dump or was mid-update."""
        try:
            low, high1, high2 = struct.unpack(
                "<III", self.read_va(KUSER_SHARED_DATA + KUSER_INTERRUPT_TIME_OFFSET, 12))
        except DumpError:
            return 0
        return (high1 << 32) | low if high1 == high2 else 0


@dataclass
class Directory:
    pa: int
    adapters: list
    event_ring_offset: int
    zombies_offset: int


def parse_directory(raw, pa):
    """A Directory from the bytes at a 'VSTD' hit, or None if they aren't a plausible one.
    raw may be cut short; returns the size needed if it is."""
    if len(raw) < DIRECTORY_HEADER.size:
        return DIRECTORY_HEADER.size
    _, version, pointer_size, max_adapters, telemetry_offset, reserved = DIRECTORY_HEADER.unpack_from(raw)
    if (version < 1 or reserved != 0 or pointer_size != POINTER_SIZE or
            not 1 <= max_adapters <= DIRECTORY_MAX_ADAPTERS or telemetry_offset % 8 or
            telemetry_offset >= DIRECTORY_MAX_TELEMETRY_OFFSET):
        return None
    size = DIRECTORY_HEADER.size + max_adapters * POINTER_SIZE + (8 if version >= DIRECTORY_EVENTS_VERSION else 0)
    if len(raw) < size:
        return size
    adapters = [a for a in struct.unpack_from(f"<{max_adapters}Q", raw, DIRECTORY_HEADER.size) if a]
    ring_offset = zombies_offset = 0
    if version >= DIRECTORY_EVENTS_VERSION:
        ring_offset, zombies_offset = struct.unpack_from("<2I", raw, size - 8)
        if (ring_offset % 8 or ring_offset >= DIRECTORY_MAX_EXTENSION_OFFSET or
                zombies_offset % 8 or zombies_offset >= DIRECTORY_MAX_EXTENSION_OFFSET):
            ring_offset = zombies_offset = 0
    return Directory(pa, adapters, ring_offset, zombies_offset)


def find_directories(dump):
    """Telemetry directories with at least one adapter. The image's .data is copied from the
    file, so the file's own copies (in the cache, or the crash dump driver's image) also carry
    the magic, but only the loaded driver's has adapters in it."""
    found = {}
    split = []  # hits whose directory runs onto the next page
    for pa, offset in dump.find(DIRECTORY_MAGIC):
        if pa % POINTER_SIZE:
            continue
        raw = dump.data[offset:offset + PAGE_SIZE - (pa & 0xFFF)]
        d = parse_directory(raw, pa)
        if isinstance(d, int):
            # The rest is on the next virtual page, which needn't be the next physical one. A
            # copy shows no adapters in the part on this page; skip those cheaply.
            visible = 0
            if len(raw) >= DIRECTORY_HEADER.size:
                max_adapters = DIRECTORY_HEADER.unpack_from(raw)[3]
                visible = min((len(raw) - DIRECTORY_HEADER.size) // POINTER_SIZE, max_adapters)
            if not visible or any(struct.unpack_from(f"<{visible}Q", raw, DIRECTORY_HEADER.size)):
                split.append((pa, d))
        elif d and d.adapters:
            found.setdefault(tuple(d.adapters), d)
    if not found and split:
        print("note: the telemetry directory crosses a page boundary; searching the kernel page tables "
              "for its address (this takes a minute or so)", file=sys.stderr)
        for pa, size in split:
            va = dump.kernel_va(pa)
            if va is None:
                continue
            try:
                d = parse_directory(dump.read_va(va, size), pa)
            except DumpError:
                continue
            if isinstance(d, Directory) and d.adapters:
                found.setdefault(tuple(d.adapters), d)
    return list(found.values())


@dataclass
class Event:
    sequence: int
    time: int
    table_pa: int
    id: int
    srb_ext: int
    srb: int
    value1: int
    value2: int
    code: int
    queue: int
    target: int
    lun: int
    avail_pos: int

    def has_pos(self):
        """True if Queue/AvailPos name the avail entry of a request."""
        return self.queue != EVENT_NO_QUEUE and (
            self.code in EVENTS_WITH_POS or (self.code == EVENT_ORPHAN_RETURN and (self.value1 >> 32) & 1))


@dataclass
class Zombie:
    slot: int
    id: int
    srb_ext: int
    srb: int
    table_pa: int
    time: int
    reused: bool
    queue: int
    avail_pos: int

    def has_pos(self):
        return True


@dataclass
class Ring:
    adapter: int
    address: int
    recorded: int
    no_avail_pos: bool
    packed: bool
    events: list
    zombies: list = field(default_factory=list)


def read_ring(dump, adapter, directory):
    address = adapter + directory.event_ring_offset
    magic, version, entry_size, entry_count, recorded = EVENT_RING_HEADER.unpack(
        dump.read_va(address, EVENT_RING_HEADER.size))
    if magic != EVENT_RING_MAGIC:
        raise DumpError(f"no event ring at {address:#x} (a driver without one?)")
    if (entry_size < EVENT.size or entry_size % 8 or not 1 <= entry_count <= EVENT_RING_MAX_ENTRIES or
            entry_count & (entry_count - 1)):
        raise DumpError(f"implausible event ring at {address:#x}: EntrySize {entry_size}, EntryCount {entry_count}")
    flags = 0
    header_size = EVENT_RING_V1_HEADER_SIZE
    if version >= 2:
        flags = struct.unpack("<I", dump.read_va(address + EVENT_RING_HEADER.size, 4))[0]
        header_size = EVENT_RING_V2_HEADER_SIZE
    raw = dump.read_va(address + header_size, entry_size * entry_count)
    events = []
    for slot in range(entry_count):
        e = Event(*EVENT.unpack_from(raw, slot * entry_size))
        # 0 is an unused slot; a sequence that doesn't belong in its slot was being rewritten.
        if e.sequence and (e.sequence - 1) % entry_count == slot:
            if version < 2:
                e.avail_pos = 0
            events.append(e)
    events.sort(key=lambda e: e.sequence)
    ring = Ring(adapter, address, recorded, version < 2 or bool(flags & EVENT_RING_PACKED),
                bool(flags & EVENT_RING_PACKED), events)
    if directory.zombies_offset:
        raw = dump.read_va(adapter + directory.zombies_offset, ZOMBIE_SLOTS * ZOMBIE.size)
        for slot in range(ZOMBIE_SLOTS):
            key, *rest = ZOMBIE.unpack_from(raw, slot * ZOMBIE.size)
            if key:
                zid, srb_ext, srb, table_pa, time, reused, queue, avail_pos = rest
                ring.zombies.append(Zombie(slot, zid, srb_ext, srb, table_pa, time, reused != 0, queue, avail_pos))
    return ring


@dataclass
class ChainFilter:
    """The requests a QEMU report names: indirect table address and/or virtqueue + avail pos."""
    table_pa: Optional[int] = None
    queue: Optional[int] = None  # driver request queue index
    pos: Optional[int] = None

    def describe(self):
        parts = []
        if self.table_pa is not None:
            parts.append(f"table {self.table_pa:#x}")
        if self.queue is not None:
            parts.append(f"virtqueue {self.queue + VIRTIO_SCSI_REQUEST_QUEUE_0} avail pos {self.pos}")
        return " or ".join(parts)

    def matches(self, e, no_pos):
        if self.table_pa is not None and e.table_pa and e.table_pa == self.table_pa:
            return True
        return (self.queue is not None and not no_pos and e.has_pos() and e.queue == self.queue and
                e.avail_pos == self.pos)


def chain_filter(table_pa, virtqueue, pos):
    f = ChainFilter()
    if table_pa:
        f.table_pa = table_pa
    if virtqueue is not None and pos is not None:
        if virtqueue < VIRTIO_SCSI_REQUEST_QUEUE_0:
            raise DumpError(f"virtqueue {virtqueue} is not a request queue (QEMU numbers them from "
                            f"{VIRTIO_SCSI_REQUEST_QUEUE_0})")
        f.queue = virtqueue - VIRTIO_SCSI_REQUEST_QUEUE_0
        f.pos = pos & 0xFFFF
    return f if f.table_pa is not None or f.queue is not None else None


def events_for_chain(ring, f, resets):
    """Events of the request(s) f names plus every event of the same SRB extensions: the table
    lives in the extension, so that shows what else used the memory. With resets, the adapter's
    reset, TMF and pause/resume events from the first of those on are interleaved."""
    exts = {e.srb_ext for e in ring.events if e.srb_ext and f.matches(e, ring.no_avail_pos)}
    shown = [e for e in ring.events if f.matches(e, ring.no_avail_pos) or (e.srb_ext and e.srb_ext in exts)]
    if resets and shown:
        first = shown[0].sequence
        picked = {e.sequence for e in shown}
        shown = [e for e in ring.events
                 if e.sequence in picked or (e.code in ADAPTER_EVENTS and e.sequence >= first)]
    return shown


def round_half_up(x, digits=0):
    """Rounding as the WinDbg script's Math.round and toFixed do it, so both print the same."""
    scale = 10 ** digits
    return math.floor(x * scale + 0.5) / scale


def fmt_us(us):
    if us is None:
        return "-"
    if us >= 1000000:
        return f"{round_half_up(us / 1000000, 1):.1f}s"
    if us >= 1000:
        return f"{round_half_up(us / 1000, 1):.1f}ms"
    return f"{round_half_up(us):.0f}us"


def fmt_ago(us):
    return "-" if us is None else fmt_us(us) + " ago"


def age_us(now, then):
    if not now or not then:
        return None
    return 0 if then >= now else (now - then) // HNS_PER_US


def describe_request(v2):
    return f"DataTransferLength {v2 & 0xFFFFFFFF}, SRB flags {v2 >> 32:#x}"


def describe_event(e):
    """What Value1/Value2 (and Id, for the scatter/gather events) mean, see VIOSCSI_EVENT_CODE."""
    v1, v2 = e.value1, e.value2
    lo1, hi1 = v1 & 0xFFFFFFFF, v1 >> 32
    if e.code == 1:
        return f"out {lo1 & 0xFFFF}, in {(lo1 >> 16) & 0xFFFF}, {v2} bytes"
    if e.code == 2:
        return f"used length {lo1}, response {v2 & 0xFF}, SCSI status {(v2 >> 8) & 0xFF:#x}"
    if e.code == 3:
        return (f"used length {lo1}" +
                (f", completed early {fmt_us(v2 / HNS_PER_US)} before" if hi1 & 1 else
                 ", NOT A REQUEST COMPLETED EARLY (unless evicted from a full zombie table)") +
                (", RETURNED INTO A REUSED EXTENSION" if hi1 & 2 else ""))
    if e.code == 4:
        why = {1: "by a reset", 2: "by surprise removal"}.get(v1, f"reason {v1}")
        return f"{why}, the device had it for {fmt_us(v2 / HNS_PER_US)}"
    if e.code == 5:
        return f"SRB function {v1:#x}, action on reset {v2 & 0xFFFFFFFF:#x}"
    if e.code == 6:
        return f"{v1} request(s) completed early"
    if e.code == 7:
        return f"TMF subtype {v1}"
    if e.code == 8:
        return "folded into the TMF in flight"
    if e.code == 9:
        return f"response {v1}"
    if e.code == 10:
        return f"timeout {v1}s, {EVENT_SITE_NAMES.get(v2, f'site {v2}')}"
    if e.code == 11:
        return EVENT_SITE_NAMES.get(v2, f"site {v2}")
    if e.code == 12:
        # VIOSCSI_REUSE_STILL_MARKED 1, _AGAIN 2, _IN_ZOMBIES 4.
        return ((f"DEVICE STILL HOLDS request {e.id:#x}" if v2 & 4 else
                 f"request {e.id:#x} MAY STILL BE HELD (marked, but no zombie entry: "
                 "evicted from a full table, or already returned)") +
                (", published " if v2 & 1 else ", completed early ") + fmt_us(v1 / HNS_PER_US) + " before" +
                (", reused before" if v2 & 2 else ""))
    if e.code == 13:
        return (f"REFUSED: element {hi1} of {lo1} has zero length; SRB function {e.id:#x}, "
                f"{describe_request(v2)}")
    if e.code == 14:
        return f"REFUSED: {hi1} elements, limit {lo1}; SRB function {e.id:#x}, {describe_request(v2)}"
    if e.code == 15:
        return f"elements add up to {v1}; SRB function {e.id:#x}, {describe_request(v2)}"
    if e.code == 16:
        return f"ZERO-LENGTH DESCRIPTOR {hi1} of {lo1}, address {v2:#x}"
    return f"Value1 {v1:#x}, Value2 {v2:#x}"


def fmt_vq_pos(e, no_pos):
    """QEMU's name for an entry's avail slot: virtqueue:pos."""
    if e.queue == EVENT_NO_QUEUE:
        return "-"
    vq = e.queue + VIRTIO_SCSI_REQUEST_QUEUE_0
    return f"{vq}:-" if no_pos or not e.has_pos() else f"{vq}:{e.avail_pos}"


def hex_or_dash(v):
    return f"{v:#x}" if v else "-"


def print_table(columns, rows):
    cells = [[str(value(r)) for _, value, _ in columns] for r in rows]
    widths = [max([len(name)] + [len(c[i]) for c in cells]) for i, (name, _, _) in enumerate(columns)]

    def line(values):
        # The first column and free text are left-aligned, numbers right-aligned.
        return "  ".join(v.ljust(w) if i == 0 or columns[i][2] else v.rjust(w)
                         for i, (v, w) in enumerate(zip(values, widths))).rstrip()

    print(line([name for name, _, _ in columns]))
    print(line(["-" * w for w in widths]))
    for c in cells:
        print(line(c))


def print_ring(ring, now, f, count, resets, quiet_if_none):
    """Prints a ring's last count events, or those f selects, and its zombies. Returns the number
    of events shown."""
    if f:
        shown = events_for_chain(ring, f, resets)
        if not shown and quiet_if_none:
            return 0
    else:
        shown = ring.events[-count:] if count else []
    # Ages are against the dump's interrupt time, or the newest event without one.
    ref = now or (ring.events[-1].time if ring.events else 0)
    no_pos = ring.no_avail_pos
    print()
    print(f"== adapter {ring.adapter:#x} event ring {ring.address:#x}: {ring.recorded} events recorded, "
          f"the last {len(ring.events)} kept; ages relative to "
          f"{'the dump interrupt time' if now else 'the newest event'}")
    if no_pos:
        print(f"No avail positions recorded ({'packed virtqueues' if ring.packed else 'driver predates them'}): "
              "only the table address can be matched.")
    if f:
        print(f"Events for the request(s) at {f.describe()}, with every other use of their SRB extensions"
              f"{' and the adapter-wide events since the first of them' if resets else ''}: {len(shown)}")
    else:
        print(f"Last {len(shown)} events:")
    if shown:
        print_table([
            ("Seq", lambda e: e.sequence, False),
            ("Age", lambda e: fmt_us(age_us(ref, e.time)), False),
            ("Event", lambda e: EVENT_NAMES.get(e.code, f"code {e.code}"), False),
            ("VQ:Pos", lambda e: fmt_vq_pos(e, no_pos), False),
            ("T:L", lambda e: f"{e.target}:{e.lun}", False),
            ("Id", lambda e: hex_or_dash(e.id), False),
            ("TablePa", lambda e: hex_or_dash(e.table_pa), False),
            ("SrbExt", lambda e: hex_or_dash(e.srb_ext), False),
            ("Srb", lambda e: hex_or_dash(e.srb), False),
            ("Detail", describe_event, True),
        ], shown)
    zombies = [z for z in ring.zombies if f.matches(z, no_pos)] if f else ring.zombies
    print()
    print(f"Requests completed early that the device has not returned: {len(zombies)}"
          f"{'' if len(zombies) == len(ring.zombies) else f' (of {len(ring.zombies)})'}")
    if zombies:
        print_table([
            ("Slot", lambda z: z.slot, False),
            ("VQ:Pos", lambda z: fmt_vq_pos(z, no_pos), False),
            ("Id", lambda z: f"{z.id:#x}", False),
            ("TablePa", lambda z: f"{z.table_pa:#x}", False),
            ("SrbExt", lambda z: f"{z.srb_ext:#x}", False),
            ("Srb", lambda z: f"{z.srb:#x}", False),
            ("CompletedEarly", lambda z: fmt_ago(age_us(ref, z.time)), False),
            ("ExtReused", lambda z: "yes" if z.reused else "no", False),
        ], zombies)
    return len(shown)


def load_rings(dump, adapter):
    directories = find_directories(dump)
    if not directories:
        raise DumpError("no vioscsi telemetry directory with a started adapter in the dump "
                        "(driver without one, or no adapter started)")
    if len(directories) > 1:
        print(f"warning: {len(directories)} telemetry directories with adapters; using all of them", file=sys.stderr)
    rings = []
    for d in directories:
        if not d.event_ring_offset:
            print(f"warning: telemetry directory at PA {d.pa:#x} has no event ring offset "
                  "(driver predates the event ring)", file=sys.stderr)
            continue
        for a in d.adapters:
            if adapter is not None and a != adapter:
                continue
            try:
                rings.append(read_ring(dump, a, d))
            except DumpError as e:
                print(f"warning: adapter {a:#x}: {e}", file=sys.stderr)
    if adapter is not None and not rings:
        raise DumpError(f"adapter {adapter:#x} is not a vioscsi adapter with a readable event ring in this dump")
    return rings


def cmd_events(dump, args):
    f = chain_filter(args.table, *(args.pos or (None, None)))
    rings = load_rings(dump, args.adapter)
    if not rings:
        print("No vioscsi adapter with an event ring found")
    now = dump.interrupt_time()
    for r in rings:
        print_ring(r, now, f, args.count, False, False)


def cmd_chain(dump, args):
    if (args.virtqueue is None) != (args.pos is None):
        raise DumpError("give both the virtqueue and the avail pos, or neither")
    f = chain_filter(args.table, args.virtqueue, args.pos)
    if not f:
        raise DumpError("give a table address, or a virtqueue and avail pos")
    now = dump.interrupt_time()
    matched = sum(1 for r in load_rings(dump, None) if print_ring(r, now, f, 0, args.resets, True))
    if matched == 0:
        print(f"No event in any adapter's ring matches {f.describe()}: the request is older than the ring, "
              "or the address is not one of this guest's tables.")
    elif matched > 1 and f.table_pa is None:
        print(f"warning: {matched} adapters have an entry at that virtqueue and position; "
              "add the table address to tell them apart.")


def number(s):
    """Decimal, or hex with 0x."""
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def event_count(s):
    n = number(s)
    if n < 0:
        raise argparse.ArgumentTypeError(f"{s} is negative")
    return n or EVENTS_DEFAULT_COUNT


def address(s):
    """Addresses are hex with or without 0x, as QEMU and WinDbg print them."""
    a = int(s.replace("`", ""), 16)
    if a < 0:
        raise argparse.ArgumentTypeError(f"{s} is not an address")
    return a


def main():
    parser = argparse.ArgumentParser(description="Decode vioscsi event rings from a QEMU Windows dump.")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("events", help="the last events of every adapter (like !vioscsi_events)")
    p.add_argument("dump", help="64-bit Windows crash dump (QEMU dump-guest-memory -w)")
    p.add_argument("--adapter", type=address, help="only this adapter extension (hex VA)")
    p.add_argument("--count", type=event_count, default=EVENTS_DEFAULT_COUNT,
                   help=f"events per adapter (default and 0: {EVENTS_DEFAULT_COUNT})")
    p.add_argument("--table", type=address, help="only requests with this indirect table (hex PA)")
    p.add_argument("--pos", type=number, nargs=2, metavar=("VQ", "POS"),
                   help="only requests published at this QEMU virtqueue and avail position")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("chain", help="the request(s) a QEMU virtqueue_chain_error names (like !vioscsi_chain)")
    p.add_argument("dump", help="64-bit Windows crash dump (QEMU dump-guest-memory -w)")
    p.add_argument("table", type=address, help="addr= of the chain error (hex PA, 0 for none)")
    p.add_argument("virtqueue", type=number, nargs="?", help="queue= of the chain error")
    p.add_argument("pos", type=number, nargs="?", help="pos= of the chain error")
    p.add_argument("--resets", action="store_true",
                   help="also show the adapter's reset, TMF and pause/resume events from the first shown event on")
    p.set_defaults(func=cmd_chain)

    args = parser.parse_args()
    try:
        args.func(Dump(args.dump), args)
    except DumpError as e:
        sys.exit(f"error: {e}")
    except BrokenPipeError:
        # Point stdout at /dev/null so the flush at exit doesn't fail again.
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(1)


if __name__ == "__main__":
    main()
