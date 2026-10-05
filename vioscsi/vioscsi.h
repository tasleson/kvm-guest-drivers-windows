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
    ULONG QueueIndex; // index into ADAPTER_EXTENSION.processing_srbs / Telemetry.Queues, set by SendSRB
} SRB_EXTENSION, *PSRB_EXTENSION;
#pragma pack()

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
// a debugger script can interpret it without an exact struct-layout match:
//
//   [ header + adapter-wide fields ][ Queues[0] ] ... [ Queues[QueueCount-1] ]
//   |<-------- HeaderSize -------->|<- QueueSize ->|
//
// Queues[] is deliberately the last member so that the first
// HeaderSize + QueueCount * QueueSize bytes are a complete compact snapshot.
// Layout rules:
//   - Magic..Reserved never move.
//   - New adapter-wide fields are appended after the last adapter-wide field
//     (growing HeaderSize); new per-queue fields are appended to the end of
//     QUEUE_TELEMETRY (growing QueueSize). Never reorder or remove fields.
//   - Keep every field naturally aligned with explicit padding, so the layout
//     is identical on x86 and x64 and parsers need no ABI knowledge.
//   - Bump STOR_TELEMETRY_VERSION on any change.
//
#define STOR_TELEMETRY_MAGIC              0x53505331 // 'SPS1'
#define STOR_TELEMETRY_VERSION            3
#define STOR_TELEMETRY_HISTOGRAM_BUCKETS  64
#define STOR_TELEMETRY_STATUS_SLOTS       64

typedef struct _LATENCY_STATS
{
    ULONG64 Buckets[STOR_TELEMETRY_HISTOGRAM_BUCKETS]; // bucket N covers [2^N, 2^(N+1)) microseconds
    ULONG64 Count;
    ULONG64 SumUs;
    ULONG64 MinUs;
    ULONG64 MaxUs;
} LATENCY_STATS, *PLATENCY_STATS;

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
} QUEUE_TELEMETRY, *PQUEUE_TELEMETRY;

typedef struct _STOR_TELEMETRY
{
    // Header, see layout rules above.
    ULONG Magic;
    ULONG Version;
    ULONG HeaderSize;     // FIELD_OFFSET(STOR_TELEMETRY, Queues)
    ULONG QueueSize;      // sizeof(QUEUE_TELEMETRY)
    ULONG QueueCount;     // number of valid Queues[] entries, == ADAPTER_EXTENSION.num_queues
    ULONG LatencyBuckets; // STOR_TELEMETRY_HISTOGRAM_BUCKETS
    ULONG StatusSlots;    // STOR_TELEMETRY_STATUS_SLOTS
    ULONG Reserved;

    // Adapter-wide: resets aren't a per-queue event.
    ULONG64 BusResetCount;
    ULONG64 DeviceResetCount;
    ULONG64 LogicalUnitResetCount;
    ULONG64 LastResetDurationUs;
    ULONG64 MaxResetDurationUs;
    ULONG64 DeviceResetTmfInFlightCount; // DeviceReset() entered while a TMF was already in flight

    // Must remain the last member.
    QUEUE_TELEMETRY Queues[MAX_CPU];
} STOR_TELEMETRY, *PSTOR_TELEMETRY;

C_ASSERT(sizeof(LATENCY_STATS) % sizeof(ULONG64) == 0);
C_ASSERT(sizeof(QUEUE_TELEMETRY) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(QUEUE_TELEMETRY, QueueFullCount) % sizeof(ULONG64) == 0);
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, BusResetCount) == 8 * sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(STOR_TELEMETRY, Queues) % sizeof(ULONG64) == 0);
C_ASSERT(sizeof(STOR_TELEMETRY) == FIELD_OFFSET(STOR_TELEMETRY, Queues) + MAX_CPU * sizeof(QUEUE_TELEMETRY));

//
// IOCTL_SCSI_MINIPORT request returning a compact snapshot of STOR_TELEMETRY:
// SRB_IO_CONTROL.Signature must be VIOSCSI_IOCTL_SIGNATURE (8 bytes including
// the NUL) and ControlCode VIOSCSI_IOCTL_QUERY_TELEMETRY. The driver copies
// the first min(Length, HeaderSize + QueueCount * QueueSize) bytes of the live
// block into the payload and sets Length to the number of bytes copied.
// ReturnCode is VIOSCSI_TELEMETRY_RC_TRUNCATED when that is less than the full
// snapshot; a caller can learn the full size from the header (the first 20
// bytes hold HeaderSize/QueueSize/QueueCount) and retry with a larger buffer.
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

FORCEINLINE VOID
StorPerfUpdateMax(IN OUT PULONG64 Target, IN ULONG64 Value)
{
    ULONG64 current = *Target;
    while (Value > current)
    {
        ULONG64 prior = (ULONG64)InterlockedCompareExchange64((PLONG64)Target, (LONG64)Value, (LONG64)current);
        if (prior == current)
        {
            return;
        }
        current = prior;
    }
}

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
    BOOLEAN tmf_infly;

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
} ADAPTER_EXTENSION, *PADAPTER_EXTENSION;

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
// Version.
//
#define VIOSCSI_TELEMETRY_DIRECTORY_MAGIC   0x44545356 // 'VSTD' in memory byte order
#define VIOSCSI_TELEMETRY_DIRECTORY_VERSION 1

typedef struct _VIOSCSI_TELEMETRY_DIRECTORY
{
    ULONG Magic;
    ULONG Version;
    ULONG PointerSize;     // sizeof(PVOID) of this build: 4 on x86, 8 on x64/arm64
    ULONG MaxAdapters;     // length of Adapters[]
    ULONG TelemetryOffset; // FIELD_OFFSET(ADAPTER_EXTENSION, Telemetry)
    ULONG Reserved;
    PADAPTER_EXTENSION Adapters[VIOSCSI_MAX_TELEMETRY_ADAPTERS];
} VIOSCSI_TELEMETRY_DIRECTORY, *PVIOSCSI_TELEMETRY_DIRECTORY;

C_ASSERT(FIELD_OFFSET(VIOSCSI_TELEMETRY_DIRECTORY, Adapters) == 6 * sizeof(ULONG));
C_ASSERT(FIELD_OFFSET(VIOSCSI_TELEMETRY_DIRECTORY, Adapters) % sizeof(PVOID) == 0);
C_ASSERT(FIELD_OFFSET(ADAPTER_EXTENSION, Telemetry) % sizeof(ULONG64) == 0);

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
