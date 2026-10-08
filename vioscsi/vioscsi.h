/*
 * Main include file
 * This file contains various routines and globals
 *
 * Copyright (c) 2012-2017 Red Hat, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met :
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and / or other materials provided with the distribution.
 * 3. Neither the names of the copyright holders nor the names of their contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef ___VIOSCSI_H__
#define ___VIOSCSI_H__

#include <ntddk.h>
#include <storport.h>
#include <ntddscsi.h>
#include "scsiwmi.h"

#include "osdep.h"
#include "virtio_pci.h"
#include "virtio.h"
#include "virtio_ring.h"

typedef struct VirtIOBufferDescriptor VIO_SG, *PVIO_SG;

#define VIRTIO_SCSI_CDB_SIZE   32
#define VIRTIO_SCSI_SENSE_SIZE 96

#ifndef NTDDI_WINTHRESHOLD
#define NTDDI_WINTHRESHOLD 0x0A000000 /* ABRACADABRA_THRESHOLD */
#endif

#define PHYS_SEGMENTS                        32
#define MAX_PHYS_SEGMENTS                    512
#define VIOSCSI_POOL_TAG                     'SoiV'
#define VIRTIO_MAX_SG                        (1 + 1 + MAX_PHYS_SEGMENTS + 1) // cmd + resp + (MAX_PHYS_SEGMENTS + extra_page)

#define SECTOR_SIZE                          512
#define IO_PORT_LENGTH                       0x40
#define MAX_CPU                              256

#define REGISTRY_MAX_PH_BREAKS               "PhysicalBreaks"
#define REGISTRY_ACTION_ON_RESET             "VioscsiActionOnReset"
#define REGISTRY_RESP_TIME_LIMIT             "TraceResponseTime"

/* Feature Bits */
#define VIRTIO_SCSI_F_INOUT                  0
#define VIRTIO_SCSI_F_HOTPLUG                1
#define VIRTIO_SCSI_F_CHANGE                 2

/* Response codes */
#define VIRTIO_SCSI_S_OK                     0
#define VIRTIO_SCSI_S_UNDERRUN               1
#define VIRTIO_SCSI_S_ABORTED                2
#define VIRTIO_SCSI_S_BAD_TARGET             3
#define VIRTIO_SCSI_S_RESET                  4
#define VIRTIO_SCSI_S_BUSY                   5
#define VIRTIO_SCSI_S_TRANSPORT_FAILURE      6
#define VIRTIO_SCSI_S_TARGET_FAILURE         7
#define VIRTIO_SCSI_S_NEXUS_FAILURE          8
#define VIRTIO_SCSI_S_FAILURE                9
#define VIRTIO_SCSI_S_FUNCTION_SUCCEEDED     10
#define VIRTIO_SCSI_S_FUNCTION_REJECTED      11
#define VIRTIO_SCSI_S_INCORRECT_LUN          12

/* Controlq type codes.  */
#define VIRTIO_SCSI_T_TMF                    0
#define VIRTIO_SCSI_T_AN_QUERY               1
#define VIRTIO_SCSI_T_AN_SUBSCRIBE           2

/* Valid TMF subtypes.  */
#define VIRTIO_SCSI_T_TMF_ABORT_TASK         0
#define VIRTIO_SCSI_T_TMF_ABORT_TASK_SET     1
#define VIRTIO_SCSI_T_TMF_CLEAR_ACA          2
#define VIRTIO_SCSI_T_TMF_CLEAR_TASK_SET     3
#define VIRTIO_SCSI_T_TMF_I_T_NEXUS_RESET    4
#define VIRTIO_SCSI_T_TMF_LOGICAL_UNIT_RESET 5
#define VIRTIO_SCSI_T_TMF_QUERY_TASK         6
#define VIRTIO_SCSI_T_TMF_QUERY_TASK_SET     7

/* Events.  */
#define VIRTIO_SCSI_T_EVENTS_MISSED          0x80000000
#define VIRTIO_SCSI_T_NO_EVENT               0
#define VIRTIO_SCSI_T_TRANSPORT_RESET        1
#define VIRTIO_SCSI_T_ASYNC_NOTIFY           2
#define VIRTIO_SCSI_T_PARAM_CHANGE           3

/* Reasons of transport reset event */
#define VIRTIO_SCSI_EVT_RESET_HARD           0
#define VIRTIO_SCSI_EVT_RESET_RESCAN         1
#define VIRTIO_SCSI_EVT_RESET_REMOVED        2

#define VIRTIO_SCSI_S_SIMPLE                 0
#define VIRTIO_SCSI_S_ORDERED                1
#define VIRTIO_SCSI_S_HEAD                   2
#define VIRTIO_SCSI_S_ACA                    3

#define VIRTIO_SCSI_CONTROL_QUEUE            0
#define VIRTIO_SCSI_EVENTS_QUEUE             1
#define VIRTIO_SCSI_REQUEST_QUEUE_0          2
#define VIRTIO_SCSI_QUEUE_LAST               VIRTIO_SCSI_REQUEST_QUEUE_0 + MAX_CPU

/* MSI messages and virtqueue indices are offset by 1, MSI 0 is not used */
#define QUEUE_TO_MESSAGE(QueueId)            ((QueueId) + 1)
#define MESSAGE_TO_QUEUE(MessageId)          ((MessageId)-1)

/* SCSI command request, followed by data-out */
#pragma pack(1)
typedef struct
{
    u8 lun[8];    /* Logical Unit Number */
    u64 tag;      /* Command identifier */
    u8 task_attr; /* Task attribute */
    u8 prio;
    u8 crn;
    u8 cdb[VIRTIO_SCSI_CDB_SIZE];
} VirtIOSCSICmdReq, *PVirtIOSCSICmdReq;
#pragma pack()

/* Response, followed by sense data and data-in */
#pragma pack(1)
typedef struct
{
    u32 sense_len;        /* Sense data length */
    u32 resid;            /* Residual bytes in data buffer */
    u16 status_qualifier; /* Status qualifier */
    u8 status;            /* Command completion status */
    u8 response;          /* Response values */
    u8 sense[VIRTIO_SCSI_SENSE_SIZE];
} VirtIOSCSICmdResp, *PVirtIOSCSICmdResp;
#pragma pack()

/* Task Management Request */
#pragma pack(1)
typedef struct
{
    u32 type;
    u32 subtype;
    u8 lun[8];
    u64 tag;
} VirtIOSCSICtrlTMFReq, *PVirtIOSCSICtrlTMFReq;
#pragma pack()

#pragma pack(1)
typedef struct
{
    u8 response;
} VirtIOSCSICtrlTMFResp, *PVirtIOSCSICtrlTMFResp;
#pragma pack()

/* Asynchronous notification query/subscription */
#pragma pack(1)
typedef struct
{
    u32 type;
    u8 lun[8];
    u32 event_requested;
} VirtIOSCSICtrlANReq, *PVirtIOSCSICtrlANReq;
#pragma pack()

#pragma pack(1)
typedef struct
{
    u32 event_actual;
    u8 response;
} VirtIOSCSICtrlANResp, *PVirtIOSCSICtrlANResp;
#pragma pack()

#pragma pack(1)
typedef struct
{
    u32 event;
    u8 lun[8];
    u32 reason;
} VirtIOSCSIEvent, *PVirtIOSCSIEvent;
#pragma pack()

#pragma pack(1)
typedef struct
{
    u32 num_queues;
    u32 seg_max;
    u32 max_sectors;
    u32 cmd_per_lun;
    u32 event_info_size;
    u32 sense_size;
    u32 cdb_size;
    u16 max_channel;
    u16 max_target;
    u32 max_lun;
} VirtIOSCSIConfig, *PVirtIOSCSIConfig;
#pragma pack()

#pragma pack(1)
typedef struct
{
    PVOID srb;
    PVOID comp;
    union {
        VirtIOSCSICmdReq cmd;
        VirtIOSCSICtrlTMFReq tmf;
        VirtIOSCSICtrlANReq an;
    } req;
    union {
        VirtIOSCSICmdResp cmd;
        VirtIOSCSICtrlTMFResp tmf;
        VirtIOSCSICtrlANResp an;
        VirtIOSCSIEvent event;
    } resp;
} VirtIOSCSICmd, *PVirtIOSCSICmd;
#pragma pack()

#pragma pack(1)
typedef struct
{
    PVOID adapter;
    VirtIOSCSIEvent event;
    VIO_SG sg;
} VirtIOSCSIEventNode, *PVirtIOSCSIEventNode;
#pragma pack()

typedef struct _VRING_DESC_ALIAS
{
    union {
        ULONGLONG data[2];
        UCHAR chars[SIZE_OF_SINGLE_INDIRECT_DESC];
    } u;
} VRING_DESC_ALIAS, *PVRING_DESC_ALIAS;

#pragma pack(1)
typedef struct _SRB_EXTENSION
{
    LIST_ENTRY list_entry;
    PSCSI_REQUEST_BLOCK Srb;
    ULONG out;
    ULONG in;
    ULONG Xfer;
    VirtIOSCSICmd cmd;
    PVIO_SG POINTER_ALIGN psgl;
    PVRING_DESC_ALIAS POINTER_ALIGN pdesc;
    VIO_SG vio_sg[VIRTIO_MAX_SG];
    VRING_DESC_ALIAS desc_alias[VIRTIO_MAX_SG];
    ULONGLONG time;
    ULONG_PTR id;
    ULONG QueueIndex;     // index into ADAPTER_EXTENSION.processing_srbs / Telemetry.Queues, set by SendSRB
    ULONGLONG SubmitTime; // StorPerfInterruptTime() when queued, 0 if never submitted; feeds OldestInFlightTime
    ULONG TargetId;       // SRB_TARGET_ID, set by VioScsiBuildIo; indexes Telemetry.Targets (bounds-checked there)
    ULONG64 TablePa;      // physical address of desc_alias as published by SendSRB, 0 if not sent indirect
    // SendSRB sets OwnedMagic once the request is on a virtqueue and ProcessQueue clears it when the
    // device returns the request, so in a dump an extension still carrying it was handed to the
    // device at OwnedTime (with id, QueueIndex and TablePa) and not given back. Whether the device
    // still references an extension VioScsiBuildIo is about to reuse is decided from
    // ADAPTER_EXTENSION.Zombies instead: BuildIo zeroes these fields with the rest.
    ULONG OwnedMagic;  // VIOSCSI_SRBEXT_OWNED_MAGIC while the device holds this request
    ULONG64 OwnedTime; // StorPerfInterruptTime() when SendSRB published it
} SRB_EXTENSION, *PSRB_EXTENSION;
#pragma pack()

#define VIOSCSI_SRBEXT_OWNED_MAGIC 0x444E574F // 'OWND' in memory byte order

#pragma pack(1)
typedef struct
{
    SCSI_REQUEST_BLOCK Srb;
    PSRB_EXTENSION SrbExtension;
} TMF_COMMAND, *PTMF_COMMAND;
#pragma pack()

typedef struct _REQUEST_LIST
{
    LIST_ENTRY srb_list;
    ULONG srb_cnt;
    ULONG_PTR next_id;
} REQUEST_LIST, *PREQUEST_LIST;

//
// Bugcheck code for the NT_VERIFY corruption guards below. These are deliberately
// fatal rather than recovered from: this driver is currently being run under
// hypervisor-driven error injection to find where it silently corrupts memory
// today, so any such invariant violation should stop the VM immediately and
// visibly rather than being quietly routed around. Distinct from 0xDEADDEAD,
// which is the pre-existing manually-triggered test path (VioscsiResetBugCheck).
//
#define VIOSCSI_BUGCHECK_CORRUPTION_GUARD 0xBAADC0DE

//
// Runtime performance/error telemetry, kept in the (non-paged) adapter
// extension so it is present in a crash dump without any extra plumbing.
//
// The block is self-describing so that a snapshot (IOCTL), an offline tool or
// a debugger script can interpret it without an exact struct-layout match. In
// the adapter extension (what a debugger reads from memory) it is
//
//   [ header + adapter-wide ][ Queues[0..MAX_CPU-1] ][ Targets[0..MAX_TARGETS-1] ]
//   |<----- HeaderSize ----->|<-- QueueSize each -->|<-- TargetSize each ------->|
//
// with only the first QueueCount queues valid and Targets[] indexed by SCSI target ID
// (TargetCount == STOR_TELEMETRY_MAX_TARGETS, each entry's TargetId == its index). The IOCTL
// snapshot is compact instead:
//
//   [ header ][ Queues[0..QueueCount-1] ][ active targets only, in ID order ]
//
// with TargetCount and TargetsOffset in the header rewritten to describe what was sent, and
// TargetId in each entry saying which target it is. A reader therefore never assumes
// "index == target ID": it takes TargetsOffset/TargetSize/TargetCount from the header and the
// ID from the entry. Layout rules:
//   - HeaderSize, QueueSize, QueueCount, TargetSize, TargetCount come first so the first
//     7 * sizeof(ULONG) bytes are enough to size a retry after a truncated IOCTL.
//   - New adapter-wide fields are appended after the last adapter-wide field (growing
//     HeaderSize); new per-queue/per-target fields are appended to QUEUE_TELEMETRY/
//     TARGET_TELEMETRY (growing QueueSize/TargetSize).
//   - Keep every field naturally aligned with explicit padding, so the layout
//     is identical on x86 and x64 and parsers need no ABI knowledge.
//   - Bump STOR_TELEMETRY_VERSION on any change.
//
// Timestamps (OldestInFlightTime, LastCompletionTime, MaxLatencyTime, LastResetTime,
// SnapshotTime, TargetScanTime) are system interrupt time in 100 ns units (KeQueryInterruptTime),
// 0 meaning "never/none". That clock is a single shared counter that a debugger can also read from
// KUSER_SHARED_DATA in a kernel dump, so "how long ago" can be computed after the fact
// (against SnapshotTime for a live IOCTL snapshot, the dump-time interrupt time otherwise).
// The per-request latency counters keep using the Storport performance counter.
//
#define STOR_TELEMETRY_MAGIC              0x53505331 // 'SPS1'
#define STOR_TELEMETRY_VERSION            6
#define STOR_TELEMETRY_HISTOGRAM_BUCKETS  64
#define STOR_TELEMETRY_STATUS_SLOTS       64

// SRB_TARGET_ID is a UCHAR, so 256 entries cover every value an SRB can carry without a range
// check being load-bearing (ConfigInfo->MaximumNumberOfTargets is capped at 255, i.e. IDs 0..254
// are real). Every index is still checked through StorPerfTarget().
#define STOR_TELEMETRY_MAX_TARGETS        256

// Requests slower than these are counted in QUEUE_TELEMETRY/TARGET_TELEMETRY.Slow*Count (each count
// includes the slower ones too: a 40 s request is in all three). A request that never completes
// shows up in OldestInFlightTime instead.
#define STOR_TELEMETRY_SLOW_1S_US         1000000ULL
#define STOR_TELEMETRY_SLOW_5S_US         5000000ULL
#define STOR_TELEMETRY_SLOW_30S_US        30000000ULL

typedef struct _LATENCY_STATS
{
    ULONG64 Buckets[STOR_TELEMETRY_HISTOGRAM_BUCKETS]; // bucket N covers [2^N, 2^(N+1)) microseconds
    ULONG64 Count;
    ULONG64 SumUs;
    ULONG64 MinUs;
    ULONG64 MaxUs;
} LATENCY_STATS, *PLATENCY_STATS;

// Per-queue counters are read without a lock by TelemetryRequest, so the 64-bit tearing noted
// there applies to all of them on x86.
typedef struct _QUEUE_TELEMETRY
{
    ULONG64 ReadCount;
    ULONG64 WriteCount;
    ULONG64 FlushCount;
    ULONG64 UnmapCount;
    ULONG64 OtherCount;
    ULONG64 ReadBytes;
    ULONG64 WriteBytes;
    LATENCY_STATS Latency;
    ULONG64 StatusHistogram[STOR_TELEMETRY_STATUS_SLOTS]; // indexed by SRB_STATUS_* (flag bits masked off)
    ULONG InFlightHighWaterMark;
    ULONG Reserved;         // explicit padding, keeps QueueFullCount 8-byte aligned on x86 too
    ULONG64 QueueFullCount; // virtqueue_add_buf() had no free descriptors

    // OldestInFlightTime comes from SRB_EXTENSION.SubmitTime, which is stamped after the latency
    // clock (SRB_EXTENSION.time), so it can read slightly younger than the latency of a slow request.
    ULONG64 OldestInFlightTime; // SubmitTime of the oldest request still on the virtqueue, 0 if none
    ULONG64 LastCompletionTime; // when the last request completed on this queue
    ULONG64 MaxLatencyTime;     // when Latency.MaxUs was last raised
    ULONG64 Slow1sCount;        // completions slower than STOR_TELEMETRY_SLOW_1S_US
    ULONG64 Slow5sCount;
    ULONG64 Slow30sCount;
    ULONG InFlightCount; // requests on the virtqueue now (InFlightHighWaterMark is the peak)
    ULONG Reserved2;     // explicit padding, keeps sizeof(QUEUE_TELEMETRY) a multiple of 8
} QUEUE_TELEMETRY, *PQUEUE_TELEMETRY;

//
// Per SCSI target (SRB_TARGET_ID), so that on an adapter with several targets a stall or error
// storm can be pinned on one of them. A target's requests are spread over all queues, so these
// are shared counters updated with interlocked operations rather than per-queue state.
//
// Everything is maintained on the I/O path except OldestInFlightTime: a target's oldest
// outstanding request would need a cross-queue minimum that cannot be kept without a shared lock
// (the per-queue request lists are ordered by submission within one queue only). TelemetryRequest
// instead recomputes it for every target in one pass over the request lists, taking each queue's
// lock in turn, and publishes it with TargetScanTime. It is therefore exact at the moment of an
// IOCTL snapshot and, in a crash dump, only as fresh as the last snapshot (0 TargetScanTime means
// never: use InFlightCount together with LastCompletionTime to spot a stalled target instead).
//
// Latency, slow-request and LastCompletionTime state only count requests that were actually
// queued to the device (SRB_EXTENSION.SubmitTime != 0), as for QUEUE_TELEMETRY. The request,
// byte and error counters count every completion, including those made without the device, since
// they record what the initiator was told.
//
typedef struct _TARGET_TELEMETRY
{
    ULONG TargetId;      // SCSI target ID this entry describes
    ULONG InFlightCount; // requests on a virtqueue for this target now, over all queues

    ULONG64 ReadCount;
    ULONG64 WriteCount;
    ULONG64 OtherCount; // everything else: flush, unmap, inquiry, ...
    ULONG64 ReadBytes;
    ULONG64 WriteBytes;

    ULONG64 OldestInFlightTime; // SubmitTime of the oldest outstanding request as of TargetScanTime, 0 if none
    ULONG64 LastCompletionTime; // when the last device completion happened for this target
    ULONG64 LatencyCount;       // device completions measured
    ULONG64 LatencySumUs;
    ULONG64 MaxLatencyUs;
    ULONG64 MaxLatencyTime; // when MaxLatencyUs was last raised
    ULONG64 Slow1sCount;
    ULONG64 Slow5sCount;
    ULONG64 Slow30sCount;

    ULONG64 BusyCount;          // SRB_STATUS_BUSY (device busy or queue full)
    ULONG64 AbortedCount;       // SRB_STATUS_ABORTED / SRB_STATUS_BUS_RESET
    ULONG64 NoDeviceCount;      // SRB_STATUS_NO_DEVICE, including requests refused by VioScsiBuildIo
    ULONG64 ErrorCount;         // SRB_STATUS_ERROR (check condition, transport/target/nexus failure, ...)
    ULONG64 InvalidTargetCount; // SRB_STATUS_INVALID_TARGET_ID, i.e. the device answered BAD_TARGET

    ULONG64 DeviceResetCount; // SRB_FUNCTION_RESET_DEVICE addressed to this target
    ULONG64 LogicalUnitResetCount;
    ULONG64 LastResetTime; // when the last of those two arrived
} TARGET_TELEMETRY, *PTARGET_TELEMETRY;

typedef struct _STOR_TELEMETRY
{
    // Header, see layout rules above.
    ULONG Magic;
    ULONG Version;
    ULONG HeaderSize;     // FIELD_OFFSET(STOR_TELEMETRY, Queues), also the offset of the queue table
    ULONG QueueSize;      // sizeof(QUEUE_TELEMETRY)
    ULONG QueueCount;     // number of valid Queues[] entries, == ADAPTER_EXTENSION.num_queues
    ULONG TargetSize;     // sizeof(TARGET_TELEMETRY)
    ULONG TargetCount;    // entries in the target table: STOR_TELEMETRY_MAX_TARGETS in memory, the active count in a snapshot
    ULONG TargetsOffset;  // byte offset of the target table from the start of the block/snapshot
    ULONG LatencyBuckets; // STOR_TELEMETRY_HISTOGRAM_BUCKETS
    ULONG StatusSlots;    // STOR_TELEMETRY_STATUS_SLOTS
    ULONG Reserved[2];

    // Adapter-wide: resets aren't a per-queue event.
    ULONG64 BusResetCount;
    ULONG64 DeviceResetCount;
    ULONG64 LogicalUnitResetCount;
    ULONG64 LastResetDurationUs;
    ULONG64 MaxResetDurationUs;
    ULONG64 DeviceResetTmfInFlightCount; // DeviceReset() coalesced into a TMF already in flight
    ULONG64 LastResetTime;               // when the last bus/device/LUN reset request arrived
    ULONG64 SnapshotTime;                // when the last IOCTL snapshot was taken, the "now" for live ages
    ULONG64 OutOfRangeTargetCount;       // requests VioScsiBuildIo refused for a target ID the device doesn't have
    ULONG64 TargetScanTime;              // when Targets[].OldestInFlightTime was last computed, 0 never

    // Descriptor ownership (version 6), see VIOSCSI_ZOMBIE. ADAPTER_EXTENSION.EventRing has the
    // individual occurrences behind these counts.
    ULONG64 EarlyCompletedCount;      // requests completed to Storport while the device still held them
    ULONG64 ExtReusedWhileOwnedCount; // VioScsiBuildIo was handed an SRB extension the device still references
    ULONG64 OrphanReturnCount;        // the device returned a request that was on no request list
    ULONG64 OrphanUnexplainedCount;   // ...of those, ones that had not been completed early either
    ULONG64 OrphanIntoReusedExtCount; // ...of those, ones whose extension already served another request
    ULONG64 ZombieEvictedCount;       // early-completed requests forgotten because Zombies[] was full

    // Request validation (version 6). A zero-length descriptor makes QEMU mark the whole device
    // broken, so VioScsiBuildIo refuses requests that would produce one.
    ULONG64 SgZeroLengthCount;      // requests refused for a zero-length scatter/gather element
    ULONG64 SgTooManyElementsCount; // requests refused for more elements than max_physical_breaks + 1
    ULONG64 SgLengthMismatchCount;  // element lengths didn't add up to DataTransferLength (recorded only)
    ULONG64 ZeroLengthDescCount;    // SendSRB found a zero length in the descriptor table it just published

    QUEUE_TELEMETRY Queues[MAX_CPU];
    TARGET_TELEMETRY Targets[STOR_TELEMETRY_MAX_TARGETS]; // must remain the last member
} STOR_TELEMETRY, *PSTOR_TELEMETRY;

C_ASSERT(sizeof(LATENCY_STATS) % sizeof(ULONG64) == 0);
C_ASSERT(sizeof(QUEUE_TELEMETRY) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(QUEUE_TELEMETRY, QueueFullCount) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(QUEUE_TELEMETRY, OldestInFlightTime) ==
         FIELD_OFFSET(QUEUE_TELEMETRY, QueueFullCount) + sizeof(ULONG64));
C_ASSERT(FIELD_OFFSET(QUEUE_TELEMETRY, InFlightCount) == FIELD_OFFSET(QUEUE_TELEMETRY, Slow30sCount) + sizeof(ULONG64));
C_ASSERT(sizeof(TARGET_TELEMETRY) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(TARGET_TELEMETRY, ReadCount) == 2 * sizeof(ULONG));
C_ASSERT(sizeof(TARGET_TELEMETRY) == 184);
C_ASSERT(STOR_TELEMETRY_MAX_TARGETS > MAXUCHAR);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, TargetCount) == 6 * sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, BusResetCount) == 12 * sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, LastResetTime) == 96);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, SnapshotTime) == 104);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, TargetScanTime) == 120);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, EarlyCompletedCount) == 128);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, ZombieEvictedCount) == 168);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, ZeroLengthDescCount) == 200);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, Queues) == 208);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, Queues) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, Targets) == FIELD_OFFSET(STOR_TELEMETRY, Queues) + MAX_CPU * sizeof(QUEUE_TELEMETRY));
C_ASSERT(sizeof(STOR_TELEMETRY) ==
         FIELD_OFFSET(STOR_TELEMETRY, Targets) + STOR_TELEMETRY_MAX_TARGETS * sizeof(TARGET_TELEMETRY));

//
// IOCTL_SCSI_MINIPORT request returning a compact snapshot of STOR_TELEMETRY (header, the
// valid queues, then only the targets that have seen any activity, see the layout above):
// SRB_IO_CONTROL.Signature must be VIOSCSI_IOCTL_SIGNATURE (8 bytes including
// the NUL) and ControlCode VIOSCSI_IOCTL_QUERY_TELEMETRY. The driver copies
// the first min(Length, snapshot size) bytes of the snapshot into the payload and sets
// Length to the number of bytes copied. ReturnCode is VIOSCSI_TELEMETRY_RC_TRUNCATED when that
// is less than the full snapshot; a caller can learn the full size from the header (the first
// 28 bytes hold HeaderSize/QueueSize/QueueCount/TargetSize/TargetCount) and retry with a larger
// buffer. The active target set can change between calls, so a retry may need to grow again.
// Tools/debug/GetVioScsiTelemetry.ps1 mirrors these values.
//
#define VIOSCSI_IOCTL_SIGNATURE        "VIOSCSI"
#define VIOSCSI_IOCTL_QUERY_TELEMETRY  0x56530001 // 'VS' 0001
#define VIOSCSI_TELEMETRY_RC_SUCCESS   0
#define VIOSCSI_TELEMETRY_RC_TRUNCATED 1

C_ASSERT(sizeof(VIOSCSI_IOCTL_SIGNATURE) == RTL_FIELD_SIZE(SRB_IO_CONTROL, Signature));

#define VIOSCSI_MAX_TELEMETRY_ADAPTERS 16

FORCEINLINE ULONG
StorPerfLatencyBucket(IN ULONGLONG ElapsedUs)
{
    ULONG bucket = 0;
    ULONGLONG value = ElapsedUs;
    while (value > 1 && bucket < (STOR_TELEMETRY_HISTOGRAM_BUCKETS - 1))
    {
        value >>= 1;
        bucket++;
    }
    return bucket;
}

FORCEINLINE VOID
StorPerfUpdateMin(IN OUT PULONG64 Target, IN ULONG64 Value)
{
    ULONG64 current = *Target;
    while (current == 0 || Value < current)
    {
        ULONG64 prior = (ULONG64)InterlockedCompareExchange64((PLONG64)Target, (LONG64)Value, (LONG64)current);
        if (prior == current)
        {
            return;
        }
        current = prior;
    }
}

FORCEINLINE BOOLEAN
StorPerfUpdateMax(IN OUT PULONG64 Target, IN ULONG64 Value)
{
    ULONG64 current = *Target;
    while (Value > current)
    {
        ULONG64 prior = (ULONG64)InterlockedCompareExchange64((PLONG64)Target, (LONG64)Value, (LONG64)current);
        if (prior == current)
        {
            return TRUE;
        }
        current = prior;
    }
    return FALSE;
}

// Republishes a queue's in-flight count and oldest submit time from its request list.
// Requests are appended to srb_list in submission order, so the head is the oldest. Call with
// the queue's VioScsiVQLock held after any change to srb_list/srb_cnt.
FORCEINLINE VOID
StorPerfSyncInFlight(IN OUT PQUEUE_TELEMETRY QueueStats, IN PREQUEST_LIST Element)
{
    QueueStats->InFlightCount = Element->srb_cnt;
    if (IsListEmpty(&Element->srb_list))
    {
        QueueStats->OldestInFlightTime = 0;
    }
    else
    {
        PSRB_EXTENSION oldest = CONTAINING_RECORD(Element->srb_list.Flink, SRB_EXTENSION, list_entry);

        QueueStats->OldestInFlightTime = oldest->SubmitTime;
    }
}

// The telemetry entry for a SCSI target ID, or NULL if the ID is outside the table. All
// per-target updates go through this so a bogus ID in an SRB can never index out of bounds.
FORCEINLINE PTARGET_TELEMETRY
StorPerfTarget(IN OUT PSTOR_TELEMETRY Telemetry, IN ULONG TargetId)
{
    return (TargetId < STOR_TELEMETRY_MAX_TARGETS) ? &Telemetry->Targets[TargetId] : NULL;
}

// A request was added to a virtqueue / removed from its request list (completed, aborted by a
// reset or unit removal). Call under the queue's VioScsiVQLock next to the srb_list change, so the
// per-target count always matches the lists the snapshot scan walks.
FORCEINLINE VOID
StorPerfTargetSubmitted(IN OUT PSTOR_TELEMETRY Telemetry, IN PSRB_EXTENSION SrbExt)
{
    PTARGET_TELEMETRY target = StorPerfTarget(Telemetry, SrbExt->TargetId);

    if (target != NULL)
    {
        InterlockedIncrement((PLONG)&target->InFlightCount);
    }
}

FORCEINLINE VOID
StorPerfTargetRemoved(IN OUT PSTOR_TELEMETRY Telemetry, IN PSRB_EXTENSION SrbExt)
{
    PTARGET_TELEMETRY target = StorPerfTarget(Telemetry, SrbExt->TargetId);

    if (target != NULL)
    {
        InterlockedDecrement((PLONG)&target->InFlightCount);
    }
}

// True for a target that has seen anything worth reporting, which is what the IOCTL snapshot
// includes and what the tools show by default.
FORCEINLINE BOOLEAN
StorPerfTargetActive(IN PTARGET_TELEMETRY Target)
{
    return (Target->InFlightCount | Target->ReadCount | Target->WriteCount | Target->OtherCount | Target->NoDeviceCount |
            Target->DeviceResetCount | Target->LogicalUnitResetCount) != 0;
}

//
// Per-adapter event ring: the last VIOSCSI_EVENT_RING_SIZE things that happened to requests and
// resets on this adapter, kept in the adapter extension so a kernel dump taken the moment the
// device breaks shows the sequence that led up to it. Every request is recorded when it is put on
// a virtqueue and when the device returns it, so TablePa (the indirect descriptor table the device
// reads, the "desc addr" QEMU prints for a bad descriptor chain) can be traced back to the request
// that owned it and to what the driver did with that request afterwards.
//
// Recording is lock-free: a writer claims a slot by incrementing Next and writes Sequence last, so
// an entry whose Sequence is 0 or doesn't match its slot was being overwritten when the dump was
// taken. Entries are ordered by Sequence, not by slot. Fields are fixed-width so the layout is the
// same on every architecture; the event codes below say what Id, Value1 and Value2 hold. Not
// recorded in dump mode.
//
#define VIOSCSI_EVENT_RING_MAGIC   0x47525645 // 'EVRG' in memory byte order
#define VIOSCSI_EVENT_RING_VERSION 1
#define VIOSCSI_EVENT_RING_SIZE    8192 // a power of two
#define VIOSCSI_EVENT_NO_QUEUE     0xFFFF

typedef enum _VIOSCSI_EVENT_CODE
{
    // SendSRB put a request on a virtqueue. Value1: out | in << 16, Value2: data bytes.
    VioScsiEventPublish = 1,
    // The device returned a request that was on a request list. Value1: used length, Value2: virtio
    // response | SCSI status << 8.
    VioScsiEventDeviceComplete = 2,
    // The device returned a cookie (Id) that no request list holds. TablePa, SrbExt and Srb are those
    // of the request completed early with that cookie, if any. Value1: used length |
    // VIOSCSI_ORPHAN_* << 32, Value2: 100 ns since that early completion.
    VioScsiEventOrphanReturn = 3,
    // A request was completed to Storport without the device returning it, so the device may still
    // read its descriptors and write its response. Value1: VIOSCSI_EARLY_*, Value2: 100 ns since it
    // was published.
    VioScsiEventEarlyComplete = 4,
    // A reset SRB arrived. Value1: SRB function, Value2: action_on_reset.
    VioScsiEventResetRequest = 5,
    // CompletePendingRequestsOnReset finished. Value1: requests it completed early.
    VioScsiEventResetDone = 6,
    // DeviceReset posted a TMF to Target/Lun. Value1: TMF subtype.
    VioScsiEventTmfSent = 7,
    // DeviceReset folded a reset of Target/Lun into the TMF already in flight.
    VioScsiEventTmfCoalesced = 8,
    // ProcessTMFCompletion reaped the TMF. Value1: virtio response.
    VioScsiEventTmfComplete = 9,
    // StorPortPause. Value1: timeout in seconds, Value2: VIOSCSI_SITE_*.
    VioScsiEventPause = 10,
    // StorPortResume. Value2: VIOSCSI_SITE_*.
    VioScsiEventResume = 11,
    // VioScsiBuildIo was handed an SRB extension that a request completed early still lives in, so
    // the device can still read its old descriptors (which BuildIo is about to zero) and write its
    // old response. Queue, Id and TablePa: that earlier request; Srb, Target and Lun: the new one.
    // Value1: 100 ns since the earlier request was completed early, Value2: VIOSCSI_REUSE_*.
    VioScsiEventExtReused = 12,
    // VioScsiBuildIo refused a request with a zero-length scatter/gather element. Id: SRB function,
    // Value1: element index << 32 | NumberOfElements, Value2: SRB flags << 32 | DataTransferLength.
    VioScsiEventSgZeroLength = 13,
    // VioScsiBuildIo refused a request with more elements than max_physical_breaks + 1. Id: SRB
    // function, Value1: NumberOfElements << 32 | that limit, Value2: as for VioScsiEventSgZeroLength.
    VioScsiEventSgTooManyElements = 14,
    // The element lengths don't add up to DataTransferLength (recorded only, the request proceeds).
    // Id: SRB function, Value1: sum of the element lengths, Value2: as for VioScsiEventSgZeroLength.
    VioScsiEventSgLengthMismatch = 15,
    // SendSRB found a zero length in the indirect table it had just published. Value1: entry index
    // << 32 | out + in, Value2: the entry's address.
    VioScsiEventZeroLengthDesc = 16,
} VIOSCSI_EVENT_CODE;

// VioScsiEventOrphanReturn Value1 bits 32-63.
#define VIOSCSI_ORPHAN_EARLY_COMPLETED      0x1 // the cookie belongs to a request completed early
#define VIOSCSI_ORPHAN_EXT_REUSED           0x2 // ...whose extension already serves another request

// VioScsiEventExtReused Value2.
#define VIOSCSI_REUSE_STILL_MARKED          0x1 // the extension still had OwnedMagic set
#define VIOSCSI_REUSE_AGAIN                 0x2 // already reused once while that request was out

// VioScsiEventEarlyComplete Value1: why the request was completed early.
#define VIOSCSI_EARLY_RESET                 1 // CompletePendingRequestsOnReset
#define VIOSCSI_EARLY_SURPRISE_REMOVAL      2 // ScsiUnitSurpriseRemoval

// VioScsiEventPause/Resume Value2: which code paused or resumed the adapter.
#define VIOSCSI_SITE_COMPLETE_PENDING_RESET 1 // CompletePendingRequestsOnReset
#define VIOSCSI_SITE_DEVICE_RESET           2 // DeviceReset, until the TMF is reaped
#define VIOSCSI_SITE_TMF_COMPLETION         3 // ProcessTMFCompletion
#define VIOSCSI_SITE_TMF_SEND_FAILED        4 // DeviceReset, TMF could not be posted

typedef struct _VIOSCSI_EVENT
{
    ULONG64 Sequence; // 1-based position in this adapter's event stream, written last; 0 = empty
    ULONG64 Time;     // StorPerfInterruptTime() when recorded
    ULONG64 TablePa;  // the request's indirect descriptor table (SRB_EXTENSION.TablePa), 0 if none
    ULONG64 Id;       // virtqueue cookie (SRB_EXTENSION.id), 0 if none
    ULONG64 SrbExt;   // SRB extension address, 0 if none
    ULONG64 Srb;      // SRB address, 0 if none
    ULONG64 Value1;   // see VIOSCSI_EVENT_CODE
    ULONG64 Value2;
    USHORT Code;  // VIOSCSI_EVENT_CODE
    USHORT Queue; // request queue index (processing_srbs/Telemetry.Queues), VIOSCSI_EVENT_NO_QUEUE if none
    UCHAR Target;
    UCHAR Lun;
    USHORT Reserved;
} VIOSCSI_EVENT, *PVIOSCSI_EVENT;

typedef struct _VIOSCSI_EVENT_RING
{
    ULONG Magic;          // VIOSCSI_EVENT_RING_MAGIC once initialized
    ULONG Version;        // VIOSCSI_EVENT_RING_VERSION
    ULONG EntrySize;      // sizeof(VIOSCSI_EVENT)
    ULONG EntryCount;     // VIOSCSI_EVENT_RING_SIZE
    volatile LONG64 Next; // events recorded so far; event N (1-based) is in Entries[(N - 1) % EntryCount]
    VIOSCSI_EVENT Entries[VIOSCSI_EVENT_RING_SIZE];
} VIOSCSI_EVENT_RING, *PVIOSCSI_EVENT_RING;

//
// Requests completed to Storport while the device still held them ("zombies"): reset and unit
// removal hand requests back without waiting for the device, which keeps their descriptors and
// will later read them and write a response into the SRB extension they live in. Each is kept
// here until the device returns its cookie, so that VioScsiBuildIo can tell when Storport hands it
// such an extension for a new request, and ProcessQueue can tell what a returned cookie that no
// request list holds belonged to. SrbExt is only ever compared, never dereferenced: Storport may
// have freed or reused that memory.
//
// Slots are claimed round-robin with interlocked operations; a full table overwrites the oldest
// slot (counted in ZombieEvictedCount). Key is cleared before a slot is refilled and written last,
// so a reader that matched it can claim the slot with a compare-exchange.
//
#define VIOSCSI_ZOMBIE_SLOTS 1024 // a power of two

typedef struct _VIOSCSI_ZOMBIE
{
    volatile LONG64 Key;  // VioScsiZombieKey(Queue, Id), 0 when the slot is free
    ULONG64 Id;           // virtqueue cookie the device will return
    ULONG64 SrbExt;       // extension the request lived in
    ULONG64 Srb;          // the SRB that was completed early
    ULONG64 TablePa;      // its indirect descriptor table
    ULONG64 Time;         // StorPerfInterruptTime() when it was completed early
    volatile LONG Reused; // nonzero once VioScsiBuildIo was handed SrbExt for another request
    ULONG Queue;          // request queue index
} VIOSCSI_ZOMBIE, *PVIOSCSI_ZOMBIE;

C_ASSERT((VIOSCSI_ZOMBIE_SLOTS & (VIOSCSI_ZOMBIE_SLOTS - 1)) == 0);
C_ASSERT(sizeof(VIOSCSI_ZOMBIE) == 56);

C_ASSERT((VIOSCSI_EVENT_RING_SIZE & (VIOSCSI_EVENT_RING_SIZE - 1)) == 0);
C_ASSERT(sizeof(VIOSCSI_EVENT) == 72);
C_ASSERT(FIELD_OFFSET(VIOSCSI_EVENT_RING, Entries) == 24);

typedef struct virtio_bar
{
    PHYSICAL_ADDRESS BasePA;
    ULONG uLength;
    PVOID pBase;
    BOOLEAN bPortSpace;
} VIRTIO_BAR, *PVIRTIO_BAR;

typedef enum ACTION_ON_RESET
{
    VioscsiResetCompleteRequests,
    VioscsiResetDoNothing,
    VioscsiResetBugCheck = 0xDEADDEAD,
} ACTION_ON_RESET;

typedef struct _ADAPTER_EXTENSION
{
    VirtIODevice vdev;

    PVOID pageAllocationVa;
    ULONG pageAllocationSize;
    ULONG pageOffset;

    PVOID poolAllocationVa;
    ULONG poolAllocationSize;
    ULONG poolOffset;

    struct virtqueue *vq[VIRTIO_SCSI_QUEUE_LAST];
    ULONG_PTR device_base;
    VirtIOSCSIConfig scsi_config;
    union {
        PCI_COMMON_HEADER pci_config;
        UCHAR pci_config_buf[sizeof(PCI_COMMON_CONFIG)];
    };
    VIRTIO_BAR pci_bars[PCI_TYPE0_ADDRESSES];
    ULONG system_io_bus_number;
    ULONG slot_number;

    ULONG queue_depth;
    BOOLEAN dump_mode;

    ULONGLONG features;

    ULONG msix_vectors;
    BOOLEAN msix_enabled;
    BOOLEAN msix_one_vector;
    BOOLEAN indirect;

    TMF_COMMAND tmf_cmd;
    // TRUE while tmf_cmd is owned by DeviceReset or the device. Only modify it with
    // Interlocked* operations, see DeviceReset.
    volatile LONG tmf_infly;

    PVirtIOSCSIEventNode events;

    ULONG num_queues;
    REQUEST_LIST processing_srbs[MAX_CPU];
    ULONG perfFlags;
    PGROUP_AFFINITY pmsg_affinity;
    ULONG num_affinity;
    BOOLEAN dpc_ok;
    PSTOR_DPC dpc;
    ULONG max_physical_breaks;
    SCSI_WMILIB_CONTEXT WmiLibContext;
    ULONGLONG hba_id;
    PUCHAR ser_num;
    ULONGLONG wwn;
    ULONGLONG port_wwn;
    ULONG port_idx;
    UCHAR ven_id[8 + 1];
    UCHAR prod_id[16 + 1];
    UCHAR rev_id[4 + 1];
    BOOLEAN reset_in_progress;
    ACTION_ON_RESET action_on_reset;
    ULONGLONG fw_ver;
    ULONG resp_time;
    BOOLEAN bRemoved;
    STOR_TELEMETRY Telemetry;
    VIOSCSI_EVENT_RING EventRing;
    volatile LONG ZombieNext; // slot counter, see VIOSCSI_ZOMBIE
    volatile LONG ZombieLive; // occupied Zombies[] slots
    VIOSCSI_ZOMBIE Zombies[VIOSCSI_ZOMBIE_SLOTS];
} ADAPTER_EXTENSION, *PADAPTER_EXTENSION;

// Current time for telemetry timestamps (see the STOR_TELEMETRY timestamp notes). Returns 0
// in crash dump mode, where the dump environment may not provide kernel time services.
FORCEINLINE ULONGLONG
StorPerfInterruptTime(IN PADAPTER_EXTENSION adaptExt)
{
    return adaptExt->dump_mode ? 0 : KeQueryInterruptTime();
}

//
// Started (non-dump) adapters are listed in the global VioScsiTelemetryDirectory so a
// debugger script (Tools/debug/vioscsi_telemetry.js) can find each one's Telemetry in a
// kernel dump without walking Storport's internal structures. Only the first
// VIOSCSI_MAX_TELEMETRY_ADAPTERS adapters are listed; later ones are left out.
//
// With symbols the script reads the directory by name. Without them it scans the writable
// sections of the vioscsi image for VIOSCSI_TELEMETRY_DIRECTORY_MAGIC and uses PointerSize
// and TelemetryOffset to reach each adapter's STOR_TELEMETRY. The magic is written only by
// the directory's static initializer, never by code, so the directory is the only place it
// appears in the image. Same versioning rules as STOR_TELEMETRY: append fields only, bump
// Version. Version 2 appended EventRingOffset and ZombiesOffset, after Adapters[] so that a
// version 1 reader, which only knows the fields before it, still parses the directory.
//
#define VIOSCSI_TELEMETRY_DIRECTORY_MAGIC   0x44545356 // 'VSTD' in memory byte order
#define VIOSCSI_TELEMETRY_DIRECTORY_VERSION 2

typedef struct _VIOSCSI_TELEMETRY_DIRECTORY
{
    ULONG Magic;
    ULONG Version;
    ULONG PointerSize;     // sizeof(PVOID) of this build: 4 on x86, 8 on x64/arm64
    ULONG MaxAdapters;     // length of Adapters[]
    ULONG TelemetryOffset; // FIELD_OFFSET(ADAPTER_EXTENSION, Telemetry)
    ULONG Reserved;
    PADAPTER_EXTENSION Adapters[VIOSCSI_MAX_TELEMETRY_ADAPTERS];
    ULONG EventRingOffset; // FIELD_OFFSET(ADAPTER_EXTENSION, EventRing) (version 2)
    ULONG ZombiesOffset;   // FIELD_OFFSET(ADAPTER_EXTENSION, Zombies) (version 2)
} VIOSCSI_TELEMETRY_DIRECTORY, *PVIOSCSI_TELEMETRY_DIRECTORY;

C_ASSERT(FIELD_OFFSET(VIOSCSI_TELEMETRY_DIRECTORY, Adapters) == 6 * sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(VIOSCSI_TELEMETRY_DIRECTORY, Adapters) % sizeof(PVOID) == 0);
C_ASSERT(FIELD_OFFSET(ADAPTER_EXTENSION, Telemetry) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(ADAPTER_EXTENSION, EventRing) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(ADAPTER_EXTENSION, Zombies) % sizeof(ULONG64) == 0);

#ifndef PCIX_TABLE_POINTER
typedef struct
{
    union {
        struct
        {
            ULONG BaseIndexRegister : 3;
            ULONG Reserved : 29;
        };
        ULONG TableOffset;
    };
} PCIX_TABLE_POINTER, *PPCIX_TABLE_POINTER;
#endif

#ifndef PCI_MSIX_CAPABILITY
typedef struct
{
    PCI_CAPABILITIES_HEADER Header;
    struct
    {
        USHORT TableSize : 11;
        USHORT Reserved : 3;
        USHORT FunctionMask : 1;
        USHORT MSIXEnable : 1;
    } MessageControl;
    PCIX_TABLE_POINTER MessageTable;
    PCIX_TABLE_POINTER PBATable;
} PCI_MSIX_CAPABILITY, *PPCI_MSIX_CAPABILITY;
#endif

#define SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED        0x0
#define SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED   0x01
#define SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED 0x09

typedef enum VIOSCSI_VPD_CODE_SET
{
    VioscsiVpdCodeSetBinary = 1,
    VioscsiVpdCodeSetAscii = 2,
    VioscsiVpdCodeSetSASBinary = 0x61,
} VIOSCSI_VPD_CODE_SET, *PVIOSCSI_VPD_CODE_SET;

typedef enum VIOSCSI_VPD_IDENTIFIER_TYPE
{
    VioscsiVpdIdentifierTypeVendorSpecific = 0,
    VioscsiVpdIdentifierTypeVendorId = 1,
    VioscsiVpdIdentifierTypeEUI64 = 2,
    VioscsiVpdIdentifierTypeFCPHName = 3,
    VioscsiVpdIdentifierTypeFCTargetPortPHName = 0x93,
    VioscsiVpdIdentifierTypeFCTargetPortRelativeTargetPort = 0x94,
} VIOSCSI_VPD_IDENTIFIER_TYPE, *PVIOSCSI_VPD_IDENTIFIER_TYPE;

#endif ___VIOSCSI__H__
