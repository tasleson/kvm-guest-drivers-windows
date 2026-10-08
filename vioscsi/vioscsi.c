/*
 * This file contains vioscsi StorPort miniport driver
 *
 * Copyright (c) 2012-2017 Red Hat, Inc.
 *
 * Author(s):
 *  Vadim Rozenfeld <vrozenfe@redhat.com>
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
#include "vioscsi.h"
#include "helper.h"
#include "vioscsidt.h"
#include "trace.h"

#if defined(EVENT_TRACING)
#include "vioscsi.tmh"
#endif

#define MS_SM_HBA_API
#include <hbapiwmi.h>

#include <hbaapi.h>
#include <ntddscsi.h>

#define VioScsiWmi_MofResourceName L"MofResource"

#include "resources.h"
#include "..\build\vendor.ver"

#define VIOSCSI_SETUP_GUID_INDEX             0
#define VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX 1
#define VIOSCSI_MS_PORT_INFORM_GUID_INDEX    2

BOOLEAN IsCrashDumpMode;
// Statically initialized so it sits in the image's .data with the magic already in place.
// clang-format off
VIOSCSI_TELEMETRY_DIRECTORY VioScsiTelemetryDirectory =
{
    VIOSCSI_TELEMETRY_DIRECTORY_MAGIC,          // Magic
    VIOSCSI_TELEMETRY_DIRECTORY_VERSION,        // Version
    sizeof(PVOID),                              // PointerSize
    VIOSCSI_MAX_TELEMETRY_ADAPTERS,             // MaxAdapters
    FIELD_OFFSET(ADAPTER_EXTENSION, Telemetry), // TelemetryOffset
    0,                                          // Reserved
    { NULL },                                   // Adapters
    FIELD_OFFSET(ADAPTER_EXTENSION, EventRing), // EventRingOffset
    FIELD_OFFSET(ADAPTER_EXTENSION, Zombies),   // ZombiesOffset
};
// clang-format on

sp_DRIVER_INITIALIZE DriverEntry;
HW_INITIALIZE VioScsiHwInitialize;
HW_BUILDIO VioScsiBuildIo;
HW_STARTIO VioScsiStartIo;
HW_FIND_ADAPTER VioScsiFindAdapter;
HW_RESET_BUS VioScsiResetBus;
HW_ADAPTER_CONTROL VioScsiAdapterControl;
HW_UNIT_CONTROL VioScsiUnitControl;
HW_INTERRUPT VioScsiInterrupt;
HW_DPC_ROUTINE VioScsiCompleteDpcRoutine;
HW_PASSIVE_INITIALIZE_ROUTINE VioScsiPassiveInitializeRoutine;
HW_MESSAGE_SIGNALED_INTERRUPT_ROUTINE VioScsiMSInterrupt;

#ifdef EVENT_TRACING
PVOID TraceContext = NULL;
VOID WppCleanupRoutine(PVOID arg1)
{
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " WppCleanupRoutine\n");
    WPP_CLEANUP(NULL, TraceContext);
}
#endif

BOOLEAN
VioScsiHwInitialize(IN PVOID DeviceExtension);

BOOLEAN
VioScsiHwReinitialize(IN PVOID DeviceExtension);

BOOLEAN
VioScsiBuildIo(IN PVOID DeviceExtension, IN PSCSI_REQUEST_BLOCK Srb);

BOOLEAN
VioScsiStartIo(IN PVOID DeviceExtension, IN PSCSI_REQUEST_BLOCK Srb);

ULONG
VioScsiFindAdapter(IN PVOID DeviceExtension,
                   IN PVOID HwContext,
                   IN PVOID BusInformation,
                   IN PCHAR ArgumentString,
                   IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
                   IN PBOOLEAN Again);

BOOLEAN
VioScsiResetBus(IN PVOID DeviceExtension, IN ULONG PathId);

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(IN PVOID DeviceExtension, IN SCSI_ADAPTER_CONTROL_TYPE ControlType, IN PVOID Parameters);

SCSI_UNIT_CONTROL_STATUS
VioScsiUnitControl(IN PVOID DeviceExtension, IN SCSI_UNIT_CONTROL_TYPE ControlType, IN PVOID Parameters);

UCHAR
VioScsiProcessPnP(IN PVOID DeviceExtension, IN PSRB_TYPE Srb);

BOOLEAN
FORCEINLINE
PreProcessRequest(IN PVOID DeviceExtension, IN PSRB_TYPE Srb);

VOID FORCEINLINE PostProcessRequest(IN PVOID DeviceExtension, IN PSRB_TYPE Srb);

VOID FORCEINLINE DispatchQueue(IN PVOID DeviceExtension, IN ULONG MessageId);

BOOLEAN
VioScsiInterrupt(IN PVOID DeviceExtension);

VOID TransportReset(IN PVOID DeviceExtension, IN PVirtIOSCSIEvent evt);

VOID ParamChange(IN PVOID DeviceExtension, IN PVirtIOSCSIEvent evt);

BOOLEAN
VioScsiMSInterrupt(IN PVOID DeviceExtension, IN ULONG MessageID);

VOID VioScsiWmiInitialize(IN PVOID DeviceExtension);

VOID VioScsiWmiSrb(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb);

VOID VioScsiIoControl(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb);

BOOLEAN
VioScsiQueryWmiDataBlock(IN PVOID Context,
                         IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
                         IN ULONG GuidIndex,
                         IN ULONG InstanceIndex,
                         IN ULONG InstanceCount,
                         IN OUT PULONG InstanceLengthArray,
                         IN ULONG OutBufferSize,
                         OUT PUCHAR Buffer);

UCHAR
VioScsiExecuteWmiMethod(IN PVOID Context,
                        IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
                        IN ULONG GuidIndex,
                        IN ULONG InstanceIndex,
                        IN ULONG MethodId,
                        IN ULONG InBufferSize,
                        IN ULONG OutBufferSize,
                        IN OUT PUCHAR Buffer);

UCHAR
VioScsiQueryWmiRegInfo(IN PVOID Context, IN PSCSIWMI_REQUEST_CONTEXT RequestContext, OUT PWCHAR *MofResourceName);

VOID VioScsiReadExtendedData(IN PVOID Context, OUT PUCHAR Buffer);

VOID VioScsiSaveInquiryData(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb);

VOID VioScsiPatchInquiryData(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb);

GUID VioScsiWmiExtendedInfoGuid = VioScsiWmi_ExtendedInfo_Guid;
GUID VioScsiWmiAdapterInformationQueryGuid = MS_SM_AdapterInformationQueryGuid;
GUID VioScsiWmiPortInformationMethodsGuid = MS_SM_PortInformationMethodsGuid;

// clang-format off
SCSIWMIGUIDREGINFO VioScsiGuidList[] =
{
   { &VioScsiWmiExtendedInfoGuid,            1, 0 },
   { &VioScsiWmiAdapterInformationQueryGuid, 1, 0 },
   { &VioScsiWmiPortInformationMethodsGuid,  1, 0 },
};
// clang-format on

#define VioScsiGuidCount (sizeof(VioScsiGuidList) / sizeof(SCSIWMIGUIDREGINFO))

void CopyUnicodeString(void *_pDest, const void *_pSrc, size_t _maxlength)
{
    PUSHORT _pDestTemp = _pDest;
    USHORT _length = _maxlength - sizeof(USHORT);
    *_pDestTemp++ = _length;
    _length = (USHORT)min(wcslen(_pSrc) * sizeof(WCHAR), _length);
    memcpy(_pDestTemp, _pSrc, _length);
}

void CopyAnsiToUnicodeString(void *_pDest, const void *_pSrc, size_t _maxlength)
{
    PUSHORT _pDestTemp = _pDest;
    PWCHAR dst;
    PCHAR src = (PCHAR)_pSrc;
    USHORT _length = _maxlength - sizeof(USHORT);
    *_pDestTemp++ = _length;
    dst = (PWCHAR)_pDestTemp;
    _length = (USHORT)min(strlen((const char *)_pSrc) * sizeof(WCHAR), _length);
    _length /= sizeof(WCHAR);
    while (_length)
    {
        *dst++ = *src++;
        --_length;
    };
}

USHORT CopyBufferToAnsiString(void *_pDest, const void *_pSrc, const char delimiter, size_t _maxlength)
{
    PCHAR dst = (PCHAR)_pDest;
    PCHAR src = (PCHAR)_pSrc;
    USHORT _length = _maxlength;

    while (_length && (*src != delimiter))
    {
        *dst++ = *src++;
        --_length;
    };
    *dst = '\0';
    return _length;
}

BOOLEAN VioScsiReadRegistryParameter(IN PVOID DeviceExtension, IN PUCHAR ValueName, IN LONG offset)
{
    BOOLEAN Ret = FALSE;
    ULONG Len = sizeof(ULONG);
    UCHAR *pBuf = NULL;
    PADAPTER_EXTENSION adaptExt;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    pBuf = StorPortAllocateRegistryBuffer(DeviceExtension, &Len);
    if (pBuf == NULL)
    {
        RhelDbgPrint(TRACE_LEVEL_FATAL, "StorPortAllocateRegistryBuffer failed to allocate buffer\n");
        return FALSE;
    }

    memset(pBuf, 0, sizeof(ULONG));

    Ret = StorPortRegistryRead(DeviceExtension, ValueName, 1, MINIPORT_REG_DWORD, pBuf, &Len);

    if ((Ret == FALSE) || (Len == 0))
    {
        RhelDbgPrint(TRACE_LEVEL_FATAL, "StorPortRegistryRead returned 0x%x, Len = %d\n", Ret, Len);
        StorPortFreeRegistryBuffer(DeviceExtension, pBuf);
        return FALSE;
    }

    StorPortCopyMemory((PVOID)((UINT_PTR)adaptExt + offset), (PVOID)pBuf, sizeof(ULONG));

    StorPortFreeRegistryBuffer(DeviceExtension, pBuf);

    return TRUE;
}

ULONG
DriverEntry(IN PVOID DriverObject, IN PVOID RegistryPath)
{

    HW_INITIALIZATION_DATA hwInitData;
    ULONG initResult;

#ifdef EVENT_TRACING
    STORAGE_TRACE_INIT_INFO initInfo;
#endif

    InitializeDebugPrints((PDRIVER_OBJECT)DriverObject, (PUNICODE_STRING)RegistryPath);

    IsCrashDumpMode = FALSE;
    RhelDbgPrint(TRACE_LEVEL_FATAL, " Vioscsi driver started...built on %s %s\n", __DATE__, __TIME__);
    if (RegistryPath == NULL)
    {
        IsCrashDumpMode = TRUE;
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Crash dump mode\n");
    }

    RtlZeroMemory(&hwInitData, sizeof(HW_INITIALIZATION_DATA));

    hwInitData.HwInitializationDataSize = sizeof(HW_INITIALIZATION_DATA);

    hwInitData.HwFindAdapter = VioScsiFindAdapter;
    hwInitData.HwInitialize = VioScsiHwInitialize;
    hwInitData.HwStartIo = VioScsiStartIo;
    hwInitData.HwInterrupt = VioScsiInterrupt;
    hwInitData.HwResetBus = VioScsiResetBus;
    hwInitData.HwAdapterControl = VioScsiAdapterControl;
    hwInitData.HwUnitControl = VioScsiUnitControl;
    hwInitData.HwBuildIo = VioScsiBuildIo;

    hwInitData.NeedPhysicalAddresses = TRUE;
    hwInitData.TaggedQueuing = TRUE;
    hwInitData.AutoRequestSense = TRUE;
    hwInitData.MultipleRequestPerLu = TRUE;

    hwInitData.DeviceExtensionSize = sizeof(ADAPTER_EXTENSION);
    hwInitData.SrbExtensionSize = sizeof(SRB_EXTENSION);

    hwInitData.AdapterInterfaceType = PCIBus;

    /* Virtio doesn't specify the number of BARs used by the device; it may
     * be one, it may be more. PCI_TYPE0_ADDRESSES, the theoretical maximum
     * on PCI, is a safe upper bound.
     */
    hwInitData.NumberOfAccessRanges = PCI_TYPE0_ADDRESSES;
    hwInitData.MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;

    hwInitData.SrbTypeFlags = SRB_TYPE_FLAG_STORAGE_REQUEST_BLOCK;
    hwInitData.AddressTypeFlags = ADDRESS_TYPE_FLAG_BTL8;

    initResult = StorPortInitialize(DriverObject, RegistryPath, &hwInitData, NULL);

#ifdef EVENT_TRACING
    TraceContext = NULL;

    memset(&initInfo, 0, sizeof(STORAGE_TRACE_INIT_INFO));
    initInfo.Size = sizeof(STORAGE_TRACE_INIT_INFO);
    initInfo.DriverObject = DriverObject;
    initInfo.NumErrorLogRecords = 5;
    initInfo.TraceCleanupRoutine = WppCleanupRoutine;
    initInfo.TraceContext = NULL;

    WPP_INIT_TRACING(DriverObject, RegistryPath, &initInfo);

    if (initInfo.TraceContext != NULL)
    {
        TraceContext = initInfo.TraceContext;
    }
#endif

    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Initialize returned 0x%x\n", initResult);

    return initResult;
}

ULONG
VioScsiFindAdapter(IN PVOID DeviceExtension,
                   IN PVOID HwContext,
                   IN PVOID BusInformation,
                   IN PCHAR ArgumentString,
                   IN OUT PPORT_CONFIGURATION_INFORMATION ConfigInfo,
                   IN PBOOLEAN Again)
{
    PADAPTER_EXTENSION adaptExt;
    PVOID uncachedExtensionVa;
    USHORT queueLength = 0;
    ULONG Size;
    ULONG HeapSize;
    ULONG extensionSize;
    ULONG index;
    ULONG num_cpus;
    ULONG max_cpus;
    ULONG max_queues;

    UNREFERENCED_PARAMETER(HwContext);
    UNREFERENCED_PARAMETER(BusInformation);
    UNREFERENCED_PARAMETER(ArgumentString);
    UNREFERENCED_PARAMETER(Again);

    ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    RtlZeroMemory(adaptExt, sizeof(ADAPTER_EXTENSION));

    adaptExt->dump_mode = IsCrashDumpMode;
    adaptExt->hba_id = HBA_ID;
    adaptExt->Telemetry.Magic = STOR_TELEMETRY_MAGIC;
    adaptExt->Telemetry.Version = STOR_TELEMETRY_VERSION;
    adaptExt->Telemetry.HeaderSize = (ULONG)FIELD_OFFSET(STOR_TELEMETRY, Queues);
    adaptExt->Telemetry.QueueSize = (ULONG)sizeof(QUEUE_TELEMETRY);
    adaptExt->Telemetry.TargetSize = (ULONG)sizeof(TARGET_TELEMETRY);
    adaptExt->Telemetry.TargetCount = STOR_TELEMETRY_MAX_TARGETS;
    adaptExt->Telemetry.TargetsOffset = (ULONG)FIELD_OFFSET(STOR_TELEMETRY, Targets);
    adaptExt->Telemetry.LatencyBuckets = STOR_TELEMETRY_HISTOGRAM_BUCKETS;
    adaptExt->Telemetry.StatusSlots = STOR_TELEMETRY_STATUS_SLOTS;
    for (index = 0; index < STOR_TELEMETRY_MAX_TARGETS; ++index)
    {
        adaptExt->Telemetry.Targets[index].TargetId = index;
    }
    VioScsiEventRingInit(adaptExt);
    ConfigInfo->Master = TRUE;
    ConfigInfo->ScatterGather = TRUE;
    ConfigInfo->DmaWidth = Width32Bits;
    ConfigInfo->Dma32BitAddresses = TRUE;
    ConfigInfo->Dma64BitAddresses = SCSI_DMA64_MINIPORT_FULL64BIT_SUPPORTED;
    ConfigInfo->WmiDataProvider = TRUE;
    ConfigInfo->AlignmentMask = 0x3;
    ConfigInfo->MapBuffers = STOR_MAP_NON_READ_WRITE_BUFFERS;
    ConfigInfo->SynchronizationModel = StorSynchronizeFullDuplex;
    ConfigInfo->HwMSInterruptRoutine = VioScsiMSInterrupt;
    ConfigInfo->InterruptSynchronizationMode = InterruptSynchronizePerMessage;

    VioScsiWmiInitialize(DeviceExtension);

    if (!InitHW(DeviceExtension, ConfigInfo))
    {
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot initialize HardWare\n");
        return SP_RETURN_NOT_FOUND;
    }

    /* Initialize the following variables to temporary values to keep
     * Static Driver Verification happy. These values will be immediately
     * reconfigured within GetScsiConfig below, which will retrieve the runtime
     * values advertised by the underlying device.
     */
    adaptExt->scsi_config.num_queues = 1;
    adaptExt->scsi_config.seg_max = SCSI_MINIMUM_PHYSICAL_BREAKS;
    adaptExt->indirect = FALSE;
    adaptExt->max_physical_breaks = SCSI_MINIMUM_PHYSICAL_BREAKS;
    GetScsiConfig(DeviceExtension);
    SetGuestFeatures(DeviceExtension);

    ConfigInfo->NumberOfBuses = 1;
    ConfigInfo->MaximumNumberOfTargets = min((UCHAR)adaptExt->scsi_config.max_target,
                                             255 /*SCSI_MAXIMUM_TARGETS_PER_BUS*/);
    ConfigInfo->MaximumNumberOfLogicalUnits = min((UCHAR)adaptExt->scsi_config.max_lun, SCSI_MAXIMUM_LUNS_PER_TARGET);
    ConfigInfo->MaximumTransferLength = SP_UNINITIALIZED_VALUE;  // Unlimited
    ConfigInfo->NumberOfPhysicalBreaks = SP_UNINITIALIZED_VALUE; // Unlimited

    if (!adaptExt->dump_mode)
    {
        adaptExt->max_physical_breaks = adaptExt->indirect ? MAX_PHYS_SEGMENTS : PHYS_SEGMENTS;

        /* Allow user to override max_physical_breaks via reg key
         * [HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\vioscsi\Parameters\Device]
         * "PhysicalBreaks"={dword value here}
         */
        VioScsiReadRegistryParameter(DeviceExtension,
                                     REGISTRY_MAX_PH_BREAKS,
                                     FIELD_OFFSET(ADAPTER_EXTENSION, max_physical_breaks));
        adaptExt->max_physical_breaks = min(max(SCSI_MINIMUM_PHYSICAL_BREAKS, adaptExt->max_physical_breaks),
                                            MAX_PHYS_SEGMENTS);

        if (adaptExt->scsi_config.max_sectors > 0 && adaptExt->scsi_config.max_sectors != 0xFFFF &&
            adaptExt->max_physical_breaks * PAGE_SIZE > adaptExt->scsi_config.max_sectors * SECTOR_SIZE)
        {
            adaptExt->max_physical_breaks = adaptExt->scsi_config.max_sectors * SECTOR_SIZE / PAGE_SIZE;
        }
    }
    ConfigInfo->NumberOfPhysicalBreaks = adaptExt->max_physical_breaks + 1;
    ConfigInfo->MaximumTransferLength = adaptExt->max_physical_breaks * PAGE_SIZE;

    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " NumberOfPhysicalBreaks %d\n", ConfigInfo->NumberOfPhysicalBreaks);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " MaximumTransferLength %d\n", ConfigInfo->MaximumTransferLength);

    num_cpus = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    max_cpus = KeQueryMaximumProcessorCountEx(ALL_PROCESSOR_GROUPS);
    /* Set num_cpus and max_cpus to some sane values, to keep "Static Driver Verification" happy */
    num_cpus = max(1, num_cpus);
    max_cpus = max(1, max_cpus);

    adaptExt->num_queues = adaptExt->scsi_config.num_queues;
    if (adaptExt->dump_mode || !adaptExt->msix_enabled)
    {
        adaptExt->num_queues = 1;
    }
    else
    {
        adaptExt->num_queues = min(adaptExt->num_queues, (USHORT)num_cpus);
    }

    adaptExt->action_on_reset = VioscsiResetCompleteRequests;
    VioScsiReadRegistryParameter(DeviceExtension,
                                 REGISTRY_ACTION_ON_RESET,
                                 FIELD_OFFSET(ADAPTER_EXTENSION, action_on_reset));

    adaptExt->resp_time = 0;
    VioScsiReadRegistryParameter(DeviceExtension, REGISTRY_RESP_TIME_LIMIT, FIELD_OFFSET(ADAPTER_EXTENSION, resp_time));

    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Queues %d CPUs %d\n", adaptExt->num_queues, num_cpus);

    /* Figure out the maximum number of queues we will ever need to set up. Note that this may
     * be higher than adaptExt->num_queues, because the driver may be reinitialized by calling
     * VioScsiFindAdapter again with more CPUs enabled. Unfortunately StorPortGetUncachedExtension
     * only allocates when called for the first time so we need to always use this upper bound.
     */
    if (adaptExt->dump_mode)
    {
        max_queues = adaptExt->num_queues;
    }
    else
    {
        max_queues = min(max_cpus, adaptExt->scsi_config.num_queues);
        if (adaptExt->num_queues > max_queues)
        {
            RhelDbgPrint(TRACE_LEVEL_WARNING, " Multiqueue can only use at most one queue per cpu.");
            adaptExt->num_queues = max_queues;
        }
    }

    // WHY NT_VERIFY: adaptExt->num_queues is used below (via InitializeVirtualQueues) to
    // write that many virtqueue pointers into the fixed-size adaptExt->vq[] array, and
    // drives indexing into the fixed-size adaptExt->processing_srbs[] array on every I/O -
    // both sized exactly MAX_CPU. adaptExt->scsi_config.num_queues comes from the device
    // config space (host/hypervisor-controlled), and the clamps above only bound it against
    // the host's CPU count, never against MAX_CPU itself. A host reporting more queues than
    // MAX_CPU on a large (>256 logical CPU) VM would overflow both arrays on every
    // subsequent I/O. Must be checked in release builds, not just asserted, since the input
    // is hardware-controlled.
    if (!NT_VERIFY(adaptExt->num_queues <= MAX_CPU))
    {
        RhelDbgPrint(TRACE_LEVEL_WARNING, " Device reported %d queues, clamping to MAX_CPU (%d).", adaptExt->num_queues, MAX_CPU);
        adaptExt->num_queues = MAX_CPU;
    }

    /* This function is our only chance to allocate memory for the driver; allocations are not
     * possible later on. Even worse, the only allocation mechanism guaranteed to work in all
     * cases is StorPortGetUncachedExtension, which gives us one block of physically contiguous
     * pages.
     *
     * Allocations that need to be page-aligned will be satisfied from this one block starting
     * at the first page-aligned offset, up to adaptExt->pageAllocationSize computed below. Other
     * allocations will be cache-line-aligned, of total size adaptExt->poolAllocationSize, also
     * computed below.
     */
    adaptExt->pageAllocationSize = 0;
    adaptExt->poolAllocationSize = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;
    Size = 0;
    for (index = VIRTIO_SCSI_CONTROL_QUEUE; index < max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; ++index)
    {
        virtio_query_queue_allocation(&adaptExt->vdev, index, &queueLength, &Size, &HeapSize);
        if (Size == 0)
        {
            LogError(DeviceExtension, SP_INTERNAL_ADAPTER_ERROR, __LINE__);

            RhelDbgPrint(TRACE_LEVEL_FATAL, " Virtual queue %d config failed.\n", index);
            return SP_RETURN_ERROR;
        }
        adaptExt->pageAllocationSize += ROUND_TO_PAGES(Size);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(HeapSize);
    }
    if (!adaptExt->dump_mode)
    {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(SRB_EXTENSION));
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(VirtIOSCSIEventNode) * 8);
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(sizeof(STOR_DPC) * max_queues);
    }
    if (max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0 > MAX_QUEUES_PER_DEVICE_DEFAULT)
    {
        adaptExt->poolAllocationSize += ROUND_TO_CACHE_LINES(((ULONGLONG)max_queues + VIRTIO_SCSI_REQUEST_QUEUE_0) *
                                                             virtio_get_queue_descriptor_size());
    }

    if (adaptExt->indirect)
    {
        adaptExt->queue_depth = queueLength;
    }
    else
    {
        adaptExt->queue_depth = queueLength / ConfigInfo->NumberOfPhysicalBreaks - 1;
    }
    ConfigInfo->MaxIOsPerLun = adaptExt->queue_depth * adaptExt->num_queues;
    ConfigInfo->InitialLunQueueDepth = ConfigInfo->MaxIOsPerLun;
    ConfigInfo->MaxNumberOfIO = ConfigInfo->MaxIOsPerLun;

    RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                 " breaks_number = %x  queue_depth = %x\n",
                 ConfigInfo->NumberOfPhysicalBreaks,
                 adaptExt->queue_depth);

    extensionSize = PAGE_SIZE + adaptExt->pageAllocationSize + adaptExt->poolAllocationSize;
    uncachedExtensionVa = StorPortGetUncachedExtension(DeviceExtension, ConfigInfo, extensionSize);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                 " StorPortGetUncachedExtension uncachedExtensionVa = %p allocation size = %d\n",
                 uncachedExtensionVa,
                 extensionSize);
    if (!uncachedExtensionVa)
    {
        LogError(DeviceExtension, SP_INTERNAL_ADAPTER_ERROR, __LINE__);

        RhelDbgPrint(TRACE_LEVEL_FATAL, " Can't get uncached extension allocation size = %d\n", extensionSize);
        return SP_RETURN_ERROR;
    }

    /* At this point we have all the memory we're going to need. We lay it out as follows.
     * Note that StorPortGetUncachedExtension tends to return page-aligned memory so the
     * padding1 region will typically be empty and the size of padding2 equal to PAGE_SIZE.
     *
     * uncachedExtensionVa    pageAllocationVa         poolAllocationVa
     * +----------------------+------------------------+--------------------------+----------------------+
     * | \ \ \ \ \ \ \ \ \ \  |<= pageAllocationSize =>|<=  poolAllocationSize  =>| \ \ \ \ \ \ \ \ \ \  |
     * |  \ \  padding1 \ \ \ |                        |                          |  \ \  padding2 \ \ \ |
     * | \ \ \ \ \ \ \ \ \ \  |    page-aligned area   | pool area for cache-line | \ \ \ \ \ \ \ \ \ \  |
     * |  \ \ \ \ \ \ \ \ \ \ |                        | aligned allocations      |  \ \ \ \ \ \ \ \ \ \ |
     * +----------------------+------------------------+--------------------------+----------------------+
     * |<=====================================  extensionSize  =========================================>|
     */
    adaptExt->pageAllocationVa = (PVOID)(((ULONG_PTR)(uncachedExtensionVa) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1));
    if (adaptExt->poolAllocationSize > 0)
    {
        adaptExt->poolAllocationVa = (PVOID)((ULONG_PTR)adaptExt->pageAllocationVa + adaptExt->pageAllocationSize);
    }
    RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                 " Page-aligned area at %p, size = %d\n",
                 adaptExt->pageAllocationVa,
                 adaptExt->pageAllocationSize);
    RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                 " Pool area at %p, size = %d\n",
                 adaptExt->poolAllocationVa,
                 adaptExt->poolAllocationSize);

    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " pmsg_affinity = %p\n", adaptExt->pmsg_affinity);
    if (!adaptExt->dump_mode && (adaptExt->num_queues > 1) && (adaptExt->pmsg_affinity == NULL))
    {
        adaptExt->num_affinity = adaptExt->num_queues + 3;
        ULONG Status = StorPortAllocatePool(DeviceExtension,
                                            sizeof(GROUP_AFFINITY) * (ULONGLONG)adaptExt->num_affinity,
                                            VIOSCSI_POOL_TAG,
                                            (PVOID *)&adaptExt->pmsg_affinity);
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " pmsg_affinity = %p Status = %lu\n", adaptExt->pmsg_affinity, Status);
    }
    adaptExt->fw_ver = '0';

    EXIT_FN();
    return SP_RETURN_FOUND;
}

BOOLEAN
VioScsiPassiveInitializeRoutine(IN PVOID DeviceExtension)
{
    ULONG index;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ENTER_FN();

    for (index = 0; index < adaptExt->num_queues; ++index)
    {
        StorPortInitializeDpc(DeviceExtension, &adaptExt->dpc[index], VioScsiCompleteDpcRoutine);
    }
    adaptExt->dpc_ok = TRUE;
    EXIT_FN();
    return TRUE;
}

static BOOLEAN InitializeVirtualQueues(PADAPTER_EXTENSION adaptExt, ULONG numQueues)
{
    NTSTATUS status;

    status = virtio_find_queues(&adaptExt->vdev, numQueues, adaptExt->vq);
    if (!NT_SUCCESS(status))
    {
        RhelDbgPrint(TRACE_LEVEL_FATAL, " FAILED with status 0x%x\n", status);
        return FALSE;
    }

    return TRUE;
}

PVOID
VioScsiPoolAlloc(IN PVOID DeviceExtension, IN SIZE_T size)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVOID ptr = (PVOID)((ULONG_PTR)adaptExt->poolAllocationVa + adaptExt->poolOffset);

    if ((adaptExt->poolOffset + size) <= adaptExt->poolAllocationSize)
    {
        size = ROUND_TO_CACHE_LINES(size);
        adaptExt->poolOffset += (ULONG)size;
        RtlZeroMemory(ptr, size);
        return ptr;
    }
    RhelDbgPrint(TRACE_LEVEL_FATAL, " Out of memory %Id \n", size);
    return NULL;
}

static VOID TelemetryRegisterAdapter(IN PADAPTER_EXTENSION adaptExt)
{
    ULONG i;

    if (adaptExt->dump_mode)
    {
        return;
    }
    for (i = 0; i < VIOSCSI_MAX_TELEMETRY_ADAPTERS; ++i)
    {
        if (VioScsiTelemetryDirectory.Adapters[i] == adaptExt)
        {
            return;
        }
    }
    for (i = 0; i < VIOSCSI_MAX_TELEMETRY_ADAPTERS; ++i)
    {
        if (InterlockedCompareExchangePointer((PVOID volatile *)&VioScsiTelemetryDirectory.Adapters[i],
                                              adaptExt,
                                              NULL) == NULL)
        {
            return;
        }
    }
    RhelDbgPrint(TRACE_LEVEL_WARNING, " No free telemetry slot for adapter 0x%p\n", adaptExt);
}

static VOID TelemetryDeregisterAdapter(IN PADAPTER_EXTENSION adaptExt)
{
    ULONG i;

    for (i = 0; i < VIOSCSI_MAX_TELEMETRY_ADAPTERS; ++i)
    {
        InterlockedCompareExchangePointer((PVOID volatile *)&VioScsiTelemetryDirectory.Adapters[i], NULL, adaptExt);
    }
}

BOOLEAN
VioScsiHwInitialize(IN PVOID DeviceExtension)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG i;
    ULONG index;

    PERF_CONFIGURATION_DATA perfData = {0};
    ULONG status = STOR_STATUS_SUCCESS;
    MESSAGE_INTERRUPT_INFORMATION msi_info = {0};
    PREQUEST_LIST element;
    ENTER_FN();

    adaptExt->msix_vectors = 0;
    adaptExt->pageOffset = 0;
    adaptExt->poolOffset = 0;

    while (StorPortGetMSIInfo(DeviceExtension, adaptExt->msix_vectors, &msi_info) == STOR_STATUS_SUCCESS)
    {
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " MessageId = %x\n", msi_info.MessageId);
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " MessageData = %x\n", msi_info.MessageData);
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " InterruptVector = %x\n", msi_info.InterruptVector);
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " InterruptLevel = %x\n", msi_info.InterruptLevel);
        RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                     " InterruptMode = %s\n",
                     msi_info.InterruptMode == LevelSensitive ? "LevelSensitive" : "Latched");
        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " MessageAddress = %I64x\n\n", msi_info.MessageAddress.QuadPart);
        ++adaptExt->msix_vectors;
    }

    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Queues %d msix_vectors %d\n", adaptExt->num_queues, adaptExt->msix_vectors);
    if (adaptExt->num_queues > 1 && ((adaptExt->num_queues + 3) > adaptExt->msix_vectors))
    {
        ULONG preMsiNumQueues = adaptExt->num_queues;

        adaptExt->num_queues = (USHORT)adaptExt->msix_vectors;

        // WHY NT_VERIFY + bugcheck: this is meant to shrink num_queues to however many MSI-X
        // vectors were actually granted, but it assigns msix_vectors directly instead of
        // msix_vectors - 3 (control/event/catch-all), so when fewer vectors are granted than
        // requested, num_queues can come out *larger* than it was before (e.g. 8 queues with
        // 10 granted vectors gives 10). VioScsiFindAdapter already sized the page/pool
        // allocation and clamped against MAX_CPU using the smaller, pre-MSI-X-negotiation
        // value, since msix_vectors isn't known until here - growing it now means
        // InitializeVirtualQueues() and the fixed-size arrays get indexed past what was
        // actually allocated/clamped for. Known bug, not yet fixed - this proves when it's
        // actually hit rather than corrupting memory silently.
        if (!NT_VERIFY(adaptExt->num_queues <= preMsiNumQueues))
        {
            KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, adaptExt->num_queues, preMsiNumQueues, adaptExt->msix_vectors);
        }
    }

    if (!adaptExt->dump_mode && adaptExt->msix_vectors > 0)
    {
        if (adaptExt->msix_vectors >= adaptExt->num_queues + 3)
        {
            /* initialize queues with a MSI vector per queue */
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Using a unique MSI vector per queue\n");
            adaptExt->msix_one_vector = FALSE;
        }
        else
        {
            /* if we don't have enough vectors, use one for all queues */
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Using one MSI vector for all queues\n");
            adaptExt->msix_one_vector = TRUE;
        }
        if (!InitializeVirtualQueues(adaptExt, adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0))
        {
            return FALSE;
        }
    }
    else
    {
        /* initialize queues with no MSI interrupts */
        adaptExt->msix_enabled = FALSE;
        if (!InitializeVirtualQueues(adaptExt, adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0))
        {
            return FALSE;
        }
    }

    // num_queues is final here (FindAdapter's value may have been adjusted to the granted MSI-X
    // vectors above), and HwInitialize also runs on restart, so publish it to telemetry now.
    adaptExt->Telemetry.QueueCount = adaptExt->num_queues;

    for (index = 0; index < adaptExt->num_queues; ++index)
    {
        element = &adaptExt->processing_srbs[index];
        InitializeListHead(&element->srb_list);
        element->srb_cnt = 0;
        StorPerfSyncInFlight(&adaptExt->Telemetry.Queues[index], element);
    }
    // The lists were just emptied, so no request is in flight for any target either.
    for (index = 0; index < STOR_TELEMETRY_MAX_TARGETS; ++index)
    {
        adaptExt->Telemetry.Targets[index].InFlightCount = 0;
        adaptExt->Telemetry.Targets[index].OldestInFlightTime = 0;
    }
    // Nor does the device hold any request completed early before it was (re)initialized.
    VioScsiZombieReset(adaptExt);

    if (!adaptExt->dump_mode)
    {
        /* we don't get another chance to call StorPortEnablePassiveInitialization and initialize
         * DPCs if the adapter is being restarted, so leave our datastructures alone on restart
         */
        if (adaptExt->dpc == NULL)
        {
            adaptExt->tmf_cmd.SrbExtension = (PSRB_EXTENSION)VioScsiPoolAlloc(DeviceExtension, sizeof(SRB_EXTENSION));
            adaptExt->events = (PVirtIOSCSIEventNode)VioScsiPoolAlloc(DeviceExtension, sizeof(VirtIOSCSIEventNode) * 8);
            adaptExt->dpc = (PSTOR_DPC)VioScsiPoolAlloc(DeviceExtension, sizeof(STOR_DPC) * adaptExt->num_queues);

            // WHY NT_VERIFY + bugcheck: none of these three allocations are checked for NULL
            // before use - DeviceReset immediately dereferences tmf_cmd.SrbExtension, the
            // hotplug event setup below indexes events[], and PassiveInitialize indexes
            // dpc[index] - any of those would dereference/index through or near a NULL
            // pointer if the allocation failed. Known bug, not yet fixed - this proves when
            // it's actually hit rather than crashing on a NULL deref somewhere downstream
            // with no indication of the real cause.
            if (!NT_VERIFY(adaptExt->tmf_cmd.SrbExtension != NULL) || !NT_VERIFY(adaptExt->events != NULL) ||
                !NT_VERIFY(adaptExt->dpc != NULL))
            {
                KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD,
                            __LINE__,
                            (ULONG_PTR)adaptExt->tmf_cmd.SrbExtension,
                            (ULONG_PTR)adaptExt->events,
                            (ULONG_PTR)adaptExt->dpc);
            }
        }
    }

    if (!adaptExt->dump_mode && CHECKBIT(adaptExt->features, VIRTIO_SCSI_F_HOTPLUG))
    {
        PVirtIOSCSIEventNode events = adaptExt->events;
        for (i = 0; i < 8; i++)
        {
            if (!KickEvent(DeviceExtension, (PVOID)(&events[i])))
            {
                RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot add event %d\n", i);
            }
        }
    }
    if (!adaptExt->dump_mode)
    {
        if ((adaptExt->num_queues > 1) && (adaptExt->perfFlags == 0))
        {
            perfData.Version = STOR_PERF_VERSION;
            perfData.Size = sizeof(PERF_CONFIGURATION_DATA);

            status = StorPortInitializePerfOpts(DeviceExtension, TRUE, &perfData);

            RhelDbgPrint(TRACE_LEVEL_FATAL,
                         " Current PerfOpts Version = 0x%x, Flags = 0x%x, ConcurrentChannels = %d, "
                         "FirstRedirectionMessageNumber = %d,LastRedirectionMessageNumber = %d\n",
                         perfData.Version,
                         perfData.Flags,
                         perfData.ConcurrentChannels,
                         perfData.FirstRedirectionMessageNumber,
                         perfData.LastRedirectionMessageNumber);
            if ((status == STOR_STATUS_SUCCESS) && (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION)))
            {
                adaptExt->perfFlags = STOR_PERF_DPC_REDIRECTION;
                if (CHECKFLAG(perfData.Flags, STOR_PERF_INTERRUPT_MESSAGE_RANGES))
                {
                    adaptExt->perfFlags |= STOR_PERF_INTERRUPT_MESSAGE_RANGES;
                    perfData.FirstRedirectionMessageNumber = 3;
                    perfData.LastRedirectionMessageNumber = perfData.FirstRedirectionMessageNumber +
                                                            adaptExt->num_queues - 1;
                    if ((adaptExt->pmsg_affinity != NULL) && CHECKFLAG(perfData.Flags, STOR_PERF_ADV_CONFIG_LOCALITY))
                    {
                        // WHY NT_VERIFY + bugcheck: LastRedirectionMessageNumber (derived from
                        // num_queues, which the device negotiates) bounds how many GROUP_AFFINITY
                        // entries StorPortInitializePerfOpts() writes into pmsg_affinity below,
                        // which is only sized for num_affinity entries. If the device reports
                        // enough queues to exceed that, Storport would write past the end of
                        // pmsg_affinity and corrupt adjacent non-paged pool. Deliberately fatal
                        // (not a graceful skip) while this driver is under hypervisor error
                        // injection to find silent corruption - a recovered/clamped path here
                        // would hide the violation instead of surfacing it.
                        if (!NT_VERIFY(perfData.LastRedirectionMessageNumber < adaptExt->num_affinity))
                        {
                            KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD,
                                        __LINE__,
                                        perfData.LastRedirectionMessageNumber,
                                        adaptExt->num_affinity,
                                        0);
                        }
                        RtlZeroMemory((PCHAR)adaptExt->pmsg_affinity,
                                      sizeof(GROUP_AFFINITY) * ((ULONGLONG)adaptExt->num_queues + 3));
                        adaptExt->perfFlags |= STOR_PERF_ADV_CONFIG_LOCALITY;
                        perfData.MessageTargets = adaptExt->pmsg_affinity;
                        if (CHECKFLAG(perfData.Flags, STOR_PERF_CONCURRENT_CHANNELS))
                        {
                            adaptExt->perfFlags |= STOR_PERF_CONCURRENT_CHANNELS;
                            perfData.ConcurrentChannels = adaptExt->num_queues;
                        }
                    }
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_DPC_REDIRECTION_CURRENT_CPU))
                {
                    //                    adaptExt->perfFlags |= STOR_PERF_DPC_REDIRECTION_CURRENT_CPU;
                }
                if (CHECKFLAG(perfData.Flags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO))
                {
                    //                    adaptExt->perfFlags |= STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO;
                }
                perfData.Flags = adaptExt->perfFlags;
                RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                             "Applied PerfOpts Version = 0x%x, Flags = 0x%x, ConcurrentChannels = %d, "
                             "FirstRedirectionMessageNumber = %d,LastRedirectionMessageNumber = %d\n",
                             perfData.Version,
                             perfData.Flags,
                             perfData.ConcurrentChannels,
                             perfData.FirstRedirectionMessageNumber,
                             perfData.LastRedirectionMessageNumber);
                status = StorPortInitializePerfOpts(DeviceExtension, FALSE, &perfData);
                if (status != STOR_STATUS_SUCCESS)
                {
                    adaptExt->perfFlags = 0;
                    RhelDbgPrint(TRACE_LEVEL_ERROR,
                                 " StorPortInitializePerfOpts set failed with status = 0x%x\n",
                                 status);
                }
            }
            else
            {
                RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                             " StorPortInitializePerfOpts get failed with status = 0x%x\n",
                             status);
            }
        }
        if (!adaptExt->dpc_ok && !StorPortEnablePassiveInitialization(DeviceExtension, VioScsiPassiveInitializeRoutine))
        {
            RhelDbgPrint(TRACE_LEVEL_FATAL, " StorPortEnablePassiveInitialization FAILED\n");
            return FALSE;
        }
    }

    // Registered here rather than in FindAdapter: HwInitialize runs on both initial start
    // and ScsiRestartAdapter, and only after FindAdapter succeeded, so a failed FindAdapter
    // never leaves a dangling entry. ScsiStopAdapter removes it again.
    TelemetryRegisterAdapter(adaptExt);

    virtio_device_ready(&adaptExt->vdev);
    EXIT_FN();
    return TRUE;
}

BOOLEAN
VioScsiHwReinitialize(IN PVOID DeviceExtension)
{
    /* The adapter is being restarted and we need to bring it back up without
     * running any passive-level code. Note that VioScsiFindAdapter is *not*
     * called on restart.
     */
    if (!InitVirtIODevice(DeviceExtension))
    {
        return FALSE;
    }
    SetGuestFeatures(DeviceExtension);
    return VioScsiHwInitialize(DeviceExtension);
}

BOOLEAN
VioScsiStartIo(IN PVOID DeviceExtension, IN PSCSI_REQUEST_BLOCK Srb)
{
    ENTER_FN_SRB();
    if (PreProcessRequest(DeviceExtension, (PSRB_TYPE)Srb))
    {
        CompleteRequest(DeviceExtension, (PSRB_TYPE)Srb);
    }
    else
    {
        SendSRB(DeviceExtension, (PSRB_TYPE)Srb);
    }
    EXIT_FN_SRB();
    return TRUE;
}

VOID HandleResponse(IN PVOID DeviceExtension, IN PVirtIOSCSICmd cmd)
{
    PSRB_TYPE Srb = (PSRB_TYPE)(cmd->srb);
    PSRB_EXTENSION srbExt = SRB_EXTENSION(Srb);
    VirtIOSCSICmdResp *resp = &cmd->resp.cmd;
    UCHAR senseInfoBufferLength = 0;
    PVOID senseInfoBuffer = NULL;
    UCHAR srbStatus = SRB_STATUS_SUCCESS;
    ULONG srbDataTransferLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    ENTER_FN();

    LOG_SRB_INFO();

    switch (resp->response)
    {
        case VIRTIO_SCSI_S_OK:
            SRB_SET_SCSI_STATUS(Srb, resp->status);
            srbStatus = (resp->status == SCSISTAT_GOOD) ? SRB_STATUS_SUCCESS : SRB_STATUS_ERROR;
            break;
        case VIRTIO_SCSI_S_UNDERRUN:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_UNDERRUN\n");
            srbStatus = SRB_STATUS_DATA_OVERRUN;
            break;
        case VIRTIO_SCSI_S_ABORTED:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_ABORTED\n");
            srbStatus = SRB_STATUS_ABORTED;
            break;
        case VIRTIO_SCSI_S_BAD_TARGET:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_BAD_TARGET\n");
            srbStatus = SRB_STATUS_INVALID_TARGET_ID;
            break;
        case VIRTIO_SCSI_S_RESET:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_RESET\n");
            srbStatus = SRB_STATUS_BUS_RESET;
            break;
        case VIRTIO_SCSI_S_BUSY:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_BUSY\n");
            srbStatus = SRB_STATUS_BUSY;
            break;
        case VIRTIO_SCSI_S_TRANSPORT_FAILURE:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_TRANSPORT_FAILURE\n");
            srbStatus = SRB_STATUS_ERROR;
            break;
        case VIRTIO_SCSI_S_TARGET_FAILURE:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_TARGET_FAILURE\n");
            srbStatus = SRB_STATUS_ERROR;
            break;
        case VIRTIO_SCSI_S_NEXUS_FAILURE:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_NEXUS_FAILURE\n");
            srbStatus = SRB_STATUS_ERROR;
            break;
        case VIRTIO_SCSI_S_FAILURE:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " VIRTIO_SCSI_S_FAILURE\n");
            srbStatus = SRB_STATUS_ERROR;
            break;
        default:
            srbStatus = SRB_STATUS_ERROR;
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Unknown response %d\n", resp->response);
            break;
    }
    if (srbStatus == SRB_STATUS_SUCCESS && resp->resid && srbDataTransferLen > resp->resid)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbDataTransferLen - resp->resid);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    else if (srbStatus != SRB_STATUS_SUCCESS)
    {
        SRB_GET_SENSE_INFO(Srb, senseInfoBuffer, senseInfoBufferLength);
        if (senseInfoBufferLength >= FIELD_OFFSET(SENSE_DATA, CommandSpecificInformation))
        {
            // WHY NT_VERIFY + bugcheck: min(resp->sense_len, senseInfoBufferLength) only
            // clamps against the destination (caller's sense buffer) size - it does not clamp
            // against resp->sense's actual size, VIRTIO_SCSI_SENSE_SIZE (96 bytes).
            // resp->sense_len is device-reported and can exceed 96; if the destination sense
            // buffer is also larger than 96 (common - SPC sense buffers are often 252 bytes),
            // this reads past the end of resp->sense into adjacent SRB_EXTENSION memory
            // (pointers, physical addresses) and copies it into the caller's sense buffer - an
            // out-of-bounds read and info leak. Known bug, not yet fixed - this proves when
            // it's actually hit rather than leaking memory silently.
            if (!NT_VERIFY(resp->sense_len <= VIRTIO_SCSI_SENSE_SIZE))
            {
                KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, resp->sense_len, VIRTIO_SCSI_SENSE_SIZE, (ULONG_PTR)Srb);
            }
            RtlCopyMemory(senseInfoBuffer, resp->sense, min(resp->sense_len, senseInfoBufferLength));
            if (srbStatus == SRB_STATUS_ERROR)
            {
                srbStatus |= SRB_STATUS_AUTOSENSE_VALID;
            }
        }
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
    }
    else if (srbExt && srbExt->Xfer && srbDataTransferLen > srbExt->Xfer)
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbExt->Xfer);
        srbStatus = SRB_STATUS_DATA_OVERRUN;
    }
    SRB_SET_SRB_STATUS(Srb, srbStatus);
    CompleteRequest(DeviceExtension, Srb);

    EXIT_FN();
}

static VOID ProcessTMFCompletion(IN PVOID DeviceExtension)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PVirtIOSCSICmd cmd;
    PSRB_TYPE Srb;
    unsigned int len;
    BOOLEAN reaped = FALSE;

    if (!adaptExt->tmf_infly)
    {
        return;
    }

    while ((cmd = (PVirtIOSCSICmd)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_CONTROL_QUEUE], &len)) != NULL)
    {
        VirtIOSCSICtrlTMFResp *resp;
        Srb = (PSRB_TYPE)cmd->srb;
        NT_ASSERT(Srb == (PSRB_TYPE)&adaptExt->tmf_cmd.Srb);
        resp = &cmd->resp.tmf;
        switch (resp->response)
        {
            case VIRTIO_SCSI_S_OK:
            case VIRTIO_SCSI_S_FUNCTION_SUCCEEDED:
                break;
            default:
                RhelDbgPrint(TRACE_LEVEL_ERROR, " Unknown response %d\n", resp->response);
                NT_ASSERT(0);
                break;
        }
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventTmfComplete,
                           VIOSCSI_EVENT_NO_QUEUE,
                           cmd->req.tmf.lun[1],
                           cmd->req.tmf.lun[3],
                           0,
                           NULL,
                           Srb,
                           0,
                           resp->response,
                           0);
        reaped = TRUE;
    }

    // Only hand tmf_cmd back to DeviceReset once the device has actually returned it. The
    // legacy ISR gets here for every interrupt, most of them request queue completions, so
    // clearing the flag unconditionally let the next reset rebuild tmf_cmd while the TMF
    // was still outstanding on the control queue. Resume before releasing it: StorPortPause
    // and StorPortResume act on the whole adapter, so if the flag went first, a reset on
    // another CPU could claim it and pause, and this resume would then undo that pause
    // while the new TMF is outstanding.
    if (reaped)
    {
        StorPortResume(DeviceExtension);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventResume,
                           VIOSCSI_EVENT_NO_QUEUE,
                           0,
                           0,
                           0,
                           NULL,
                           NULL,
                           0,
                           0,
                           VIOSCSI_SITE_TMF_COMPLETION);
        InterlockedExchange(&adaptExt->tmf_infly, FALSE);
    }
}

BOOLEAN
VioScsiInterrupt(IN PVOID DeviceExtension)
{
    PVirtIOSCSIEventNode evtNode = NULL;
    unsigned int len = 0;
    PADAPTER_EXTENSION adaptExt = NULL;
    BOOLEAN isInterruptServiced = FALSE;
    ULONG intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (adaptExt->bRemoved)
    {
        return FALSE;
    }

    // NOTE : SDV banned function
    // RhelDbgPrint(TRACE_LEVEL_VERBOSE, " IRQL (%d)\n", KeGetCurrentIrql());

    intReason = virtio_read_isr_status(&adaptExt->vdev);

    if (intReason == 1 || adaptExt->dump_mode)
    {
        isInterruptServiced = TRUE;

        ProcessTMFCompletion(DeviceExtension);
        while ((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) !=
               NULL)
        {
            PVirtIOSCSIEvent evt = &evtNode->event;
            switch (evt->event)
            {
                case VIRTIO_SCSI_T_NO_EVENT:
                    break;
                case VIRTIO_SCSI_T_TRANSPORT_RESET:
                    TransportReset(DeviceExtension, evt);
                    break;
                case VIRTIO_SCSI_T_PARAM_CHANGE:
                    ParamChange(DeviceExtension, evt);
                    break;
                default:
                    RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupport virtio scsi event %x\n", evt->event);
                    break;
            }
            SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }

        if (!adaptExt->dump_mode && adaptExt->dpc_ok)
        {
            StorPortIssueDpc(DeviceExtension,
                             &adaptExt->dpc[0],
                             ULongToPtr(QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)),
                             ULongToPtr(QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)));
        }
        else
        {
            ProcessQueue(DeviceExtension, QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0), TRUE);
        }
    }

    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " isInterruptServiced = %d\n", isInterruptServiced);
    return isInterruptServiced;
}

static BOOLEAN VioScsiMSInterruptWorker(IN PVOID DeviceExtension, IN ULONG MessageID)
{
    PVirtIOSCSIEventNode evtNode;
    unsigned int len;
    PADAPTER_EXTENSION adaptExt;
    ULONG intReason = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " MessageID 0x%x\n", MessageID);

    if (MessageID >= QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0))
    {
        DispatchQueue(DeviceExtension, MessageID);
        return TRUE;
    }
    if (MessageID == 0)
    {
        return TRUE;
    }
    if (MessageID == QUEUE_TO_MESSAGE(VIRTIO_SCSI_CONTROL_QUEUE))
    {
        ProcessTMFCompletion(DeviceExtension);
        return TRUE;
    }
    if (MessageID == QUEUE_TO_MESSAGE(VIRTIO_SCSI_EVENTS_QUEUE))
    {
        while ((evtNode = (PVirtIOSCSIEventNode)virtqueue_get_buf(adaptExt->vq[VIRTIO_SCSI_EVENTS_QUEUE], &len)) !=
               NULL)
        {
            PVirtIOSCSIEvent evt = &evtNode->event;
            switch (evt->event)
            {
                case VIRTIO_SCSI_T_NO_EVENT:
                    break;
                case VIRTIO_SCSI_T_TRANSPORT_RESET:
                    TransportReset(DeviceExtension, evt);
                    break;
                case VIRTIO_SCSI_T_PARAM_CHANGE:
                    ParamChange(DeviceExtension, evt);
                    break;
                default:
                    RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupport virtio scsi event %x\n", evt->event);
                    break;
            }
            SynchronizedKickEventRoutine(DeviceExtension, evtNode);
        }
        return TRUE;
    }
    return FALSE;
}

BOOLEAN
VioScsiMSInterrupt(IN PVOID DeviceExtension, IN ULONG MessageID)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    BOOLEAN isInterruptServiced = FALSE;
    ULONG i;

    if (adaptExt->bRemoved)
    {
        return FALSE;
    }

    if (!adaptExt->msix_one_vector)
    {
        /* Each queue has its own vector, this is the fast and common case */
        return VioScsiMSInterruptWorker(DeviceExtension, MessageID);
    }

    /* Fall back to checking all queues */
    for (i = 0; i < adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0; i++)
    {
        if (virtqueue_has_buf(adaptExt->vq[i]))
        {
            isInterruptServiced |= VioScsiMSInterruptWorker(DeviceExtension, i + 1);
        }
    }
    return isInterruptServiced;
}

BOOLEAN
VioScsiResetBus(IN PVOID DeviceExtension, IN ULONG PathId)
{
    UNREFERENCED_PARAMETER(PathId);

    // Storport hands HwResetBus a path, not a target, and tmf_cmd carries one TMF at a
    // time, so there is no single target to address here. Keep sending target 0, which is
    // what every reset did before target and LUN resets took theirs from the SRB.
    return DeviceReset(DeviceExtension, 0, 0);
}

SCSI_ADAPTER_CONTROL_STATUS
VioScsiAdapterControl(IN PVOID DeviceExtension, IN SCSI_ADAPTER_CONTROL_TYPE ControlType, IN PVOID Parameters)
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG AdjustedMaxControlType;
    ULONG Index;
    PADAPTER_EXTENSION adaptExt;
    SCSI_ADAPTER_CONTROL_STATUS status = ScsiAdapterControlUnsuccessful;
    BOOLEAN SupportedControlTypes[ScsiAdapterControlMax] = {FALSE};

    ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    SupportedControlTypes[ScsiQuerySupportedControlTypes] = TRUE;
    SupportedControlTypes[ScsiStopAdapter] = TRUE;
    SupportedControlTypes[ScsiRestartAdapter] = TRUE;
    SupportedControlTypes[ScsiAdapterSurpriseRemoval] = TRUE;

    switch (ControlType)
    {

        case ScsiQuerySupportedControlTypes:
            {
                RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ScsiQuerySupportedControlTypes\n");
                ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
                AdjustedMaxControlType = (ControlTypeList->MaxControlType < ScsiAdapterControlMax) ? ControlTypeList->MaxControlType
                                                                                                   : ScsiAdapterControlMax;
                for (Index = 0; Index < AdjustedMaxControlType; Index++)
                {
                    ControlTypeList->SupportedTypeList[Index] = SupportedControlTypes[Index];
                }
                status = ScsiAdapterControlSuccess;
                break;
            }
        case ScsiStopAdapter:
            {
                RhelDbgPrint(TRACE_LEVEL_VERBOSE, " ScsiStopAdapter\n");
                TelemetryDeregisterAdapter(adaptExt);
                ShutDown(DeviceExtension);
                if (adaptExt->pmsg_affinity != NULL)
                {
                    StorPortFreePool(DeviceExtension, (PVOID)adaptExt->pmsg_affinity);
                    adaptExt->pmsg_affinity = NULL;
                }
                adaptExt->perfFlags = 0;
                status = ScsiAdapterControlSuccess;
                break;
            }
        case ScsiRestartAdapter:
            {
                RhelDbgPrint(TRACE_LEVEL_FATAL, " ScsiRestartAdapter\n");
                ShutDown(DeviceExtension);
                if (!VioScsiHwReinitialize(DeviceExtension))
                {
                    RhelDbgPrint(TRACE_LEVEL_FATAL, " Cannot reinitialize HW\n");
                    break;
                }
                status = ScsiAdapterControlSuccess;
                break;
            }
        case ScsiAdapterSurpriseRemoval:
            {
                RhelDbgPrint(TRACE_LEVEL_FATAL, " ScsiAdapterSurpriseRemoval\n");
                adaptExt->bRemoved = TRUE;
                status = ScsiAdapterControlSuccess;
                break;
            }
        default:
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported ControlType %d\n", ControlType);
            break;
    }

    EXIT_FN();
    return status;
}

SCSI_UNIT_CONTROL_STATUS
VioScsiUnitControl(IN PVOID DeviceExtension, IN SCSI_UNIT_CONTROL_TYPE ControlType, IN PVOID Parameters)
{
    PSCSI_SUPPORTED_CONTROL_TYPE_LIST ControlTypeList;
    ULONG AdjustedMaxControlType;
    ULONG index;
    PADAPTER_EXTENSION adaptExt;
    SCSI_UNIT_CONTROL_STATUS Status = ScsiUnitControlUnsuccessful;
    BOOLEAN SupportedControlTypes[ScsiUnitControlMax] = {FALSE};

    ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    SupportedControlTypes[ScsiQuerySupportedControlTypes] = TRUE;
    SupportedControlTypes[ScsiUnitStart] = TRUE;
    SupportedControlTypes[ScsiUnitRemove] = TRUE;
    SupportedControlTypes[ScsiUnitSurpriseRemoval] = TRUE;

    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Unit Control Type %d\n", ControlType);
    switch (ControlType)
    {
        case ScsiQuerySupportedUnitControlTypes:
            ControlTypeList = (PSCSI_SUPPORTED_CONTROL_TYPE_LIST)Parameters;
            AdjustedMaxControlType = (ControlTypeList->MaxControlType < ScsiUnitControlMax) ? ControlTypeList->MaxControlType
                                                                                            : ScsiUnitControlMax;
            for (index = 0; index < AdjustedMaxControlType; index++)
            {
                ControlTypeList->SupportedTypeList[index] = SupportedControlTypes[index];
            }
            Status = ScsiUnitControlSuccess;
            break;
        case ScsiUnitStart:
            Status = ScsiUnitControlSuccess;
            break;
        case ScsiUnitRemove:
        case ScsiUnitSurpriseRemoval:
            ULONG QueuNum;
            ULONG MsgId;
            STOR_LOCK_HANDLE LockHandle = {0};
            PSTOR_ADDR_BTL8 stor_addr = (PSTOR_ADDR_BTL8)Parameters;

            for (index = 0; index < adaptExt->num_queues; index++)
            {
                PREQUEST_LIST element = &adaptExt->processing_srbs[index];
                QueuNum = index + VIRTIO_SCSI_REQUEST_QUEUE_0;
                MsgId = QUEUE_TO_MESSAGE(QueuNum);
                VioScsiVQLock(DeviceExtension, MsgId, &LockHandle, FALSE);
                if (!IsListEmpty(&element->srb_list))
                {
                    PLIST_ENTRY entry = element->srb_list.Flink;
                    while (entry != &element->srb_list)
                    {
                        PSRB_EXTENSION currSrbExt = CONTAINING_RECORD(entry, SRB_EXTENSION, list_entry);
                        PSCSI_REQUEST_BLOCK currSrb = currSrbExt->Srb;
                        PLIST_ENTRY next = entry->Flink;
                        if (SRB_PATH_ID(currSrb) == stor_addr->Path && SRB_TARGET_ID(currSrb) == stor_addr->Target &&
                            SRB_LUN(currSrb) == stor_addr->Lun)
                        {
                            VioScsiRecordSrbEvent(adaptExt,
                                                  VioScsiEventEarlyComplete,
                                                  currSrbExt,
                                                  VIOSCSI_EARLY_SURPRISE_REMOVAL,
                                                  currSrbExt->SubmitTime ? StorPerfInterruptTime(adaptExt) - currSrbExt->SubmitTime
                                                                         : 0);
                            VioScsiZombieAdd(adaptExt, currSrbExt);
                            InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.EarlyCompletedCount);
                            SRB_SET_SRB_STATUS(currSrb, SRB_STATUS_NO_DEVICE);
                            SRB_SET_DATA_TRANSFER_LENGTH(currSrb, 0);
                            currSrbExt->SubmitTime = 0; // not a device completion, keep it out of latency stats
                            StorPerfTargetRemoved(&adaptExt->Telemetry, currSrbExt); // before the SRB is handed back
                            CompleteRequest(DeviceExtension, (PSRB_TYPE)currSrb);
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                                         " Complete pending I/Os on Path %d Target %d Lun %d \n",
                                         SRB_PATH_ID(currSrb),
                                         SRB_TARGET_ID(currSrb),
                                         SRB_LUN(currSrb));
                            RemoveEntryList(entry);
                            element->srb_cnt--;
                            StorPerfSyncInFlight(&adaptExt->Telemetry.Queues[index], element);
                        }
                        entry = next;
                    }
                }
                VioScsiVQUnlock(DeviceExtension, MsgId, &LockHandle, FALSE);
            }
            Status = ScsiUnitControlSuccess;
            break;
        default:
            RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported Unit ControlType %d\n", ControlType);
            break;
    }

    EXIT_FN();
    return Status;
}

// Storport handed VioScsiBuildIo an SRB extension for a new request. If a request completed early
// (reset, unit removal) lived in it and the device hasn't returned that request, the device still
// references this memory: zeroing it for the new request also zeroes the descriptor table the
// device may yet read, and the device may yet write the old response over the new request.
static VOID CheckExtensionStillReferenced(IN PADAPTER_EXTENSION adaptExt,
                                          IN PSRB_EXTENSION srbExt,
                                          IN PSCSI_REQUEST_BLOCK Srb,
                                          IN UCHAR TargetId,
                                          IN UCHAR Lun)
{
    PVIOSCSI_ZOMBIE zombie = VioScsiZombieFindExt(adaptExt, srbExt);
    ULONG64 flags = 0;

    if (zombie == NULL)
    {
        return;
    }
    if (srbExt->OwnedMagic == VIOSCSI_SRBEXT_OWNED_MAGIC)
    {
        flags |= VIOSCSI_REUSE_STILL_MARKED;
    }
    if (InterlockedExchange(&zombie->Reused, TRUE) != 0)
    {
        flags |= VIOSCSI_REUSE_AGAIN;
    }
    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.ExtReusedWhileOwnedCount);
    VioScsiRecordEvent(adaptExt,
                       VioScsiEventExtReused,
                       zombie->Queue,
                       TargetId,
                       Lun,
                       (ULONG_PTR)zombie->Id,
                       srbExt,
                       Srb,
                       zombie->TablePa,
                       StorPerfInterruptTime(adaptExt) - zombie->Time,
                       flags);
    RhelDbgPrint(TRACE_LEVEL_ERROR,
                 " SRB 0x%p reuses extension 0x%p while the device still holds request id 0x%p, table 0x%I64x\n",
                 Srb,
                 srbExt,
                 (void *)(ULONG_PTR)zombie->Id,
                 zombie->TablePa);
}

// FALSE for the SRB functions PreProcessRequest completes itself: their data buffers (WMI and
// IOCTL payloads such as the telemetry snapshot) never become descriptors, so their
// scatter/gather lists are not checked. Keep in step with PreProcessRequest.
static BOOLEAN SrbGoesToDevice(IN PSCSI_REQUEST_BLOCK Srb)
{
    switch (SRB_FUNCTION(Srb))
    {
        case SRB_FUNCTION_PNP:
        case SRB_FUNCTION_POWER:
        case SRB_FUNCTION_RESET_BUS:
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
        case SRB_FUNCTION_WMI:
        case SRB_FUNCTION_IO_CONTROL:
            return FALSE;
        default:
            return TRUE;
    }
}

// Checks a request's scatter/gather list before VioScsiBuildIo turns it into descriptors. QEMU
// treats a zero-length descriptor as a device error and stops servicing every queue of the
// adapter, so one bad element would take down every LUN behind it: refuse the request instead.
// More elements than max_physical_breaks + 1 used to be cut off silently (sgMaxElements), sending
// the device a shorter buffer than the command describes, so refuse that too. A length total that
// doesn't match DataTransferLength is only recorded. Returns FALSE to refuse the request.
static BOOLEAN ValidateScatterGatherList(IN PADAPTER_EXTENSION adaptExt,
                                         IN PSRB_EXTENSION srbExt,
                                         IN PSCSI_REQUEST_BLOCK Srb,
                                         IN PSTOR_SCATTER_GATHER_LIST sgList,
                                         IN UCHAR TargetId,
                                         IN UCHAR Lun)
{
    ULONG count = sgList->NumberOfElements;
    ULONG limit = adaptExt->max_physical_breaks + 1;
    ULONG transferLength = SRB_DATA_TRANSFER_LENGTH(Srb);
    ULONG64 request = ((ULONG64)SRB_FLAGS(Srb) << 32) | transferLength;
    ULONG64 sum = 0;
    ULONG i;

    if (count > limit)
    {
        InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.SgTooManyElementsCount);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventSgTooManyElements,
                           VIOSCSI_EVENT_NO_QUEUE,
                           TargetId,
                           Lun,
                           SRB_FUNCTION(Srb),
                           srbExt,
                           Srb,
                           0,
                           ((ULONG64)count << 32) | limit,
                           request);
        RhelDbgPrint(TRACE_LEVEL_ERROR,
                     " SRB 0x%p has %lu scatter/gather elements, more than %lu, refusing it\n",
                     Srb,
                     count,
                     limit);
        return FALSE;
    }
    for (i = 0; i < count; i++)
    {
        if (sgList->List[i].Length == 0)
        {
            InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.SgZeroLengthCount);
            VioScsiRecordEvent(adaptExt,
                               VioScsiEventSgZeroLength,
                               VIOSCSI_EVENT_NO_QUEUE,
                               TargetId,
                               Lun,
                               SRB_FUNCTION(Srb),
                               srbExt,
                               Srb,
                               0,
                               ((ULONG64)i << 32) | count,
                               request);
            RhelDbgPrint(TRACE_LEVEL_ERROR,
                         " SRB 0x%p scatter/gather element %lu of %lu has zero length, refusing it\n",
                         Srb,
                         i,
                         count);
            return FALSE;
        }
        sum += sgList->List[i].Length;
    }
    if (sum != transferLength)
    {
        InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.SgLengthMismatchCount);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventSgLengthMismatch,
                           VIOSCSI_EVENT_NO_QUEUE,
                           TargetId,
                           Lun,
                           SRB_FUNCTION(Srb),
                           srbExt,
                           Srb,
                           0,
                           sum,
                           request);
        RhelDbgPrint(TRACE_LEVEL_WARNING,
                     " SRB 0x%p scatter/gather lengths add up to %I64u, DataTransferLength is %lu\n",
                     Srb,
                     sum,
                     transferLength);
    }
    return TRUE;
}

BOOLEAN
VioScsiBuildIo(IN PVOID DeviceExtension, IN PSCSI_REQUEST_BLOCK Srb)
{
    PCDB cdb;
    ULONG i;
    ULONG fragLen;
    ULONG sgElement;
    ULONG sgMaxElements;
    PADAPTER_EXTENSION adaptExt;
    PSRB_EXTENSION srbExt;
    PSTOR_SCATTER_GATHER_LIST sgList;
    VirtIOSCSICmd *cmd;
    UCHAR TargetId;
    UCHAR Lun;

    ENTER_FN_SRB();
    cdb = SRB_CDB(Srb);
    srbExt = SRB_EXTENSION(Srb);
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    TargetId = SRB_TARGET_ID(Srb);
    Lun = SRB_LUN(Srb);

    if ((SRB_PATH_ID(Srb) > (UCHAR)adaptExt->num_queues) || (TargetId >= adaptExt->scsi_config.max_target) ||
        (Lun >= adaptExt->scsi_config.max_lun) || adaptExt->bRemoved)
    {
        // These never reach the SRB extension or CompleteRequest, so count them here (only I/O:
        // other SRB functions don't address a target). A target ID the device doesn't have goes in
        // an adapter-wide counter since it isn't a real target; anything else is a refusal for a
        // target that exists.
        if (SRB_FUNCTION(Srb) == SRB_FUNCTION_EXECUTE_SCSI)
        {
            if (TargetId >= adaptExt->scsi_config.max_target)
            {
                InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.OutOfRangeTargetCount);
            }
            else
            {
                PTARGET_TELEMETRY target = StorPerfTarget(&adaptExt->Telemetry, TargetId);

                if (target != NULL)
                {
                    InterlockedIncrement64((PLONG64)&target->NoDeviceCount);
                }
            }
        }
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_NO_DEVICE);
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        StorPortNotification(RequestComplete, DeviceExtension, Srb);
        return FALSE;
    }

    LOG_SRB_INFO();

    CheckExtensionStillReferenced(adaptExt, srbExt, Srb, TargetId, Lun);
    RtlZeroMemory(srbExt, sizeof(*srbExt));
    srbExt->Srb = Srb;
    srbExt->TargetId = TargetId;
    srbExt->psgl = srbExt->vio_sg;
    srbExt->pdesc = srbExt->desc_alias;

    cmd = &srbExt->cmd;
    cmd->srb = (PVOID)Srb;
    cmd->req.cmd.lun[0] = 1;
    cmd->req.cmd.lun[1] = TargetId;
    cmd->req.cmd.lun[2] = 0;
    cmd->req.cmd.lun[3] = Lun;
    cmd->req.cmd.tag = (ULONG_PTR)(Srb);
    cmd->req.cmd.task_attr = VIRTIO_SCSI_S_SIMPLE;
    cmd->req.cmd.prio = 0;
    cmd->req.cmd.crn = 0;
    if (cdb != NULL)
    {
        RtlCopyMemory(cmd->req.cmd.cdb, cdb, min(VIRTIO_SCSI_CDB_SIZE, SRB_CDB_LENGTH(Srb)));
    }

    sgElement = 0;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->req.cmd, &fragLen);
    srbExt->psgl[sgElement].length = sizeof(cmd->req.cmd);
    sgElement++;

    sgList = StorPortGetScatterGatherList(DeviceExtension, Srb);
    if (sgList && SrbGoesToDevice(Srb) && !ValidateScatterGatherList(adaptExt, srbExt, Srb, sgList, TargetId, Lun))
    {
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        StorPortNotification(RequestComplete, DeviceExtension, Srb);
        return FALSE;
    }
    if (sgList)
    {
        sgMaxElements = min((adaptExt->max_physical_breaks + 1), sgList->NumberOfElements);

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) == SRB_FLAGS_DATA_OUT)
        {
            for (i = 0; i < sgMaxElements; i++, sgElement++)
            {
                srbExt->psgl[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->psgl[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }

    srbExt->out = sgElement;
    srbExt->psgl[sgElement].physAddr = StorPortGetPhysicalAddress(DeviceExtension, NULL, &cmd->resp.cmd, &fragLen);
    srbExt->psgl[sgElement].length = sizeof(cmd->resp.cmd);
    sgElement++;
    if (sgList)
    {
        sgMaxElements = min((adaptExt->max_physical_breaks + 1), sgList->NumberOfElements);

        if ((SRB_FLAGS(Srb) & SRB_FLAGS_DATA_OUT) != SRB_FLAGS_DATA_OUT)
        {
            for (i = 0; i < sgMaxElements; i++, sgElement++)
            {
                srbExt->psgl[sgElement].physAddr = sgList->List[i].PhysicalAddress;
                srbExt->psgl[sgElement].length = sgList->List[i].Length;
                srbExt->Xfer += sgList->List[i].Length;
            }
        }
    }
    srbExt->in = sgElement - srbExt->out;

    // The SRB extension is reused: clear what a previous request left so a request that never
    // reaches the virtqueue isn't treated as submitted (see RecordIoCompletionStats).
    srbExt->time = 0;
    srbExt->SubmitTime = 0;
    {
        LARGE_INTEGER counter = {0};
        ULONG status = STOR_STATUS_SUCCESS;
        status = StorPortQueryPerformanceCounter(DeviceExtension, NULL, &counter);
        if (status == STOR_STATUS_SUCCESS)
        {
            srbExt->time = counter.QuadPart;
        }
        else
        {
            RhelDbgPrint(TRACE_LEVEL_ERROR,
                         "SRB 0x%p StorPortQueryPerformanceCounter failed with status  0x%lx\n",
                         Srb,
                         status);
        }
    }

    EXIT_FN_SRB();
    return TRUE;
}

VOID FORCEINLINE DispatchQueue(IN PVOID DeviceExtension, IN ULONG MessageId)
{
    PADAPTER_EXTENSION adaptExt;
    ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (!adaptExt->dump_mode && adaptExt->dpc_ok)
    {
        // WHY NT_VERIFY + bugcheck: MessageId - QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)
        // indexes adaptExt->dpc[] below. If MessageId were smaller than the subtrahend, the
        // unsigned subtraction underflows into a huge index, handing StorPortIssueDpc a wild
        // pointer into adjacent pool memory instead of a real PSTOR_DPC. This should be
        // unreachable under correct operation (Storport only hands back MessageIds this driver
        // itself registered), so a violation means something is already broken - deliberately
        // fatal rather than silently falling back, while this driver is under hypervisor error
        // injection to find where it corrupts memory today.
        if (!NT_VERIFY(MessageId >= QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)))
        {
            KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD,
                        __LINE__,
                        MessageId,
                        QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0),
                        0);
        }
        StorPortIssueDpc(DeviceExtension,
                         &adaptExt->dpc[MessageId - QUEUE_TO_MESSAGE(VIRTIO_SCSI_REQUEST_QUEUE_0)],
                         ULongToPtr(MessageId),
                         ULongToPtr(MessageId));
        EXIT_FN();
        return;
    }
    ProcessQueue(DeviceExtension, MessageId, TRUE);
    EXIT_FN();
}

// The device returned a cookie that no request list holds. Expected only for requests completed
// early (reset, unit removal), whose entries in Zombies[] say what they were; anything else means
// the request lists and the virtqueue disagree. Called under the queue's VioScsiVQLock.
static VOID RecordOrphanReturn(IN PADAPTER_EXTENSION adaptExt, IN ULONG Queue, IN ULONG_PTR Id, IN ULONG Len)
{
    VIOSCSI_ZOMBIE zombie = {0};
    ULONG64 flags = 0;
    ULONG64 age = 0;

    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.OrphanReturnCount);
    if (VioScsiZombieTake(adaptExt, Queue, Id, &zombie))
    {
        flags |= VIOSCSI_ORPHAN_EARLY_COMPLETED;
        age = StorPerfInterruptTime(adaptExt) - zombie.Time;
        if (zombie.Reused)
        {
            // The device has just written this request's response into an extension that belongs
            // to another request by now.
            flags |= VIOSCSI_ORPHAN_EXT_REUSED;
            InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.OrphanIntoReusedExtCount);
            RhelDbgPrint(TRACE_LEVEL_ERROR,
                         " Request id 0x%p returned into extension 0x%p, already reused by another request\n",
                         (void *)Id,
                         (void *)(ULONG_PTR)zombie.SrbExt);
        }
    }
    else
    {
        InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.OrphanUnexplainedCount);
        RhelDbgPrint(TRACE_LEVEL_ERROR,
                     " Request id 0x%p returned on queue %lu was never completed early\n",
                     (void *)Id,
                     Queue);
    }
    VioScsiRecordEvent(adaptExt,
                       VioScsiEventOrphanReturn,
                       Queue,
                       0,
                       0,
                       Id,
                       (PVOID)(ULONG_PTR)zombie.SrbExt,
                       (PVOID)(ULONG_PTR)zombie.Srb,
                       zombie.TablePa,
                       Len | (flags << 32),
                       age);
}

VOID ProcessQueue(IN PVOID DeviceExtension, IN ULONG MessageID, IN BOOLEAN isr)
{
    ULONG_PTR srbId;
    unsigned int len;
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ULONG index = MESSAGE_TO_QUEUE(MessageID);
    STOR_LOCK_HANDLE queueLock = {0};
    struct virtqueue *vq;
    PSRB_EXTENSION srbExt = NULL;

    ENTER_FN();

    if (index >= (adaptExt->num_queues + VIRTIO_SCSI_REQUEST_QUEUE_0))
    {
        index %= adaptExt->num_queues;
    }

    // WHY NT_VERIFY + bugcheck: the %= above drops the VIRTIO_SCSI_REQUEST_QUEUE_0 offset
    // instead of preserving it, so whenever the wrap branch is taken, index lands below
    // VIRTIO_SCSI_REQUEST_QUEUE_0. That underflows the processing_srbs[] index below into a
    // huge value, and adaptExt->vq[index] can resolve to the control queue's virtqueue -
    // this is the hottest of the three wraparound sites since ProcessQueue runs on every
    // completion interrupt/DPC. Known bug, not yet fixed - this proves when it's actually
    // hit rather than corrupting memory silently.
    if (!NT_VERIFY(index >= VIRTIO_SCSI_REQUEST_QUEUE_0))
    {
        KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, index, adaptExt->num_queues, 0);
    }

    PREQUEST_LIST element = &adaptExt->processing_srbs[index - VIRTIO_SCSI_REQUEST_QUEUE_0];
    vq = adaptExt->vq[index];

    VioScsiVQLock(DeviceExtension, MessageID, &queueLock, isr);

    do
    {
        virtqueue_disable_cb(vq);
        while ((srbId = (ULONG_PTR)virtqueue_get_buf(vq, &len)) != 0)
        {
            PLIST_ENTRY le = NULL;
            BOOLEAN bFound = FALSE;

            for (le = element->srb_list.Flink; le != &element->srb_list && !bFound; le = le->Flink)
            {
                srbExt = CONTAINING_RECORD(le, SRB_EXTENSION, list_entry);
                if (srbExt->id == srbId)
                {
                    RemoveEntryList(le);
                    bFound = TRUE;
                    element->srb_cnt--;
                    StorPerfSyncInFlight(&adaptExt->Telemetry.Queues[index - VIRTIO_SCSI_REQUEST_QUEUE_0], element);
                    StorPerfTargetRemoved(&adaptExt->Telemetry, srbExt);
                    break;
                }
            }

            if (!bFound)
            {
                RhelDbgPrint(TRACE_LEVEL_WARNING, " No SRB found for ID 0x%p\n", (void *)srbId);
                RecordOrphanReturn(adaptExt, index - VIRTIO_SCSI_REQUEST_QUEUE_0, srbId, len);
            }

            if (bFound)
            {
                srbExt->OwnedMagic = 0;
                VioScsiRecordSrbEvent(adaptExt,
                                      VioScsiEventDeviceComplete,
                                      srbExt,
                                      len,
                                      srbExt->cmd.resp.cmd.response | ((ULONG64)srbExt->cmd.resp.cmd.status << 8));
                HandleResponse(DeviceExtension, &srbExt->cmd);
            }
        }
    } while (!virtqueue_enable_cb(vq));

    VioScsiVQUnlock(DeviceExtension, MessageID, &queueLock, isr);

    EXIT_FN();
}

VOID VioScsiCompleteDpcRoutine(IN PSTOR_DPC Dpc, IN PVOID Context, IN PVOID SystemArgument1, IN PVOID SystemArgument2)
{
    ULONG MessageId;

    ENTER_FN();
    MessageId = PtrToUlong(SystemArgument1);
    ProcessQueue(Context, MessageId, FALSE);
    EXIT_FN();
}

VOID CompletePendingRequestsOnReset(IN PVOID DeviceExtension, IN UCHAR TargetId, IN UCHAR Lun)
{
    PADAPTER_EXTENSION adaptExt;
    ULONG QueueNum;
    ULONG MsgId;
    ULONG64 earlyCount = 0;

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    if (!adaptExt->reset_in_progress)
    {
        adaptExt->reset_in_progress = TRUE;
        StorPortPause(DeviceExtension, 10);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventPause,
                           VIOSCSI_EVENT_NO_QUEUE,
                           TargetId,
                           Lun,
                           0,
                           NULL,
                           NULL,
                           0,
                           10,
                           VIOSCSI_SITE_COMPLETE_PENDING_RESET);
        DeviceReset(DeviceExtension, TargetId, Lun);

        for (ULONG index = 0; index < adaptExt->num_queues; index++)
        {
            PREQUEST_LIST element = &adaptExt->processing_srbs[index];
            STOR_LOCK_HANDLE LockHandle = {0};
            RhelDbgPrint(TRACE_LEVEL_FATAL, " queue %d cnt %d\n", index, element->srb_cnt);
            QueueNum = index + VIRTIO_SCSI_REQUEST_QUEUE_0;
            MsgId = QUEUE_TO_MESSAGE(QueueNum);
            VioScsiVQLock(DeviceExtension, MsgId, &LockHandle, FALSE);
            while (!IsListEmpty(&element->srb_list))
            {
                PLIST_ENTRY entry = RemoveHeadList(&element->srb_list);
                if (entry)
                {
                    PSRB_EXTENSION currSrbExt = CONTAINING_RECORD(entry, SRB_EXTENSION, list_entry);
                    PSCSI_REQUEST_BLOCK currSrb = currSrbExt->Srb;
                    StorPerfTargetRemoved(&adaptExt->Telemetry, currSrbExt);
                    // Still on a request list, so the device hasn't returned it: it may yet read the
                    // descriptors and write the response of a request Storport now considers done.
                    VioScsiRecordSrbEvent(adaptExt,
                                          VioScsiEventEarlyComplete,
                                          currSrbExt,
                                          VIOSCSI_EARLY_RESET,
                                          currSrbExt->SubmitTime ? StorPerfInterruptTime(adaptExt) - currSrbExt->SubmitTime
                                                                 : 0);
                    VioScsiZombieAdd(adaptExt, currSrbExt);
                    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.EarlyCompletedCount);
                    earlyCount++;
                    if (currSrb)
                    {
                        SRB_SET_SRB_STATUS(currSrb, SRB_STATUS_BUS_RESET);
                        SRB_SET_DATA_TRANSFER_LENGTH(currSrb, 0);
                        currSrbExt->SubmitTime = 0; // not a device completion, keep it out of latency stats
                        CompleteRequest(DeviceExtension, (PSRB_TYPE)currSrb);
                        element->srb_cnt--;
                    }
                }
            }
            if (element->srb_cnt)
            {
                element->srb_cnt = 0;
            }
            StorPerfSyncInFlight(&adaptExt->Telemetry.Queues[index], element);
            VioScsiVQUnlock(DeviceExtension, MsgId, &LockHandle, FALSE);
        }
        StorPortResume(DeviceExtension);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventResume,
                           VIOSCSI_EVENT_NO_QUEUE,
                           TargetId,
                           Lun,
                           0,
                           NULL,
                           NULL,
                           0,
                           0,
                           VIOSCSI_SITE_COMPLETE_PENDING_RESET);
        VioScsiRecordEvent(adaptExt,
                           VioScsiEventResetDone,
                           VIOSCSI_EVENT_NO_QUEUE,
                           TargetId,
                           Lun,
                           0,
                           NULL,
                           NULL,
                           0,
                           earlyCount,
                           0);
    }
    else
    {
        RhelDbgPrint(TRACE_LEVEL_FATAL, " Reset is already in progress, doing nothing.\n");
    }
    adaptExt->reset_in_progress = FALSE;
}

UCHAR
VioScsiProcessPnP(IN PVOID DeviceExtension, IN PSRB_TYPE Srb)
{
    PADAPTER_EXTENSION adaptExt;
    PSCSI_PNP_REQUEST_BLOCK pnpBlock;
    ULONG SrbPnPFlags;
    ULONG PnPAction;
    UCHAR SrbStatus;

    ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    pnpBlock = (PSCSI_PNP_REQUEST_BLOCK)Srb;
    SrbStatus = SRB_STATUS_SUCCESS;
    SRB_GET_PNP_INFO(Srb, SrbPnPFlags, PnPAction);
    switch (PnPAction)
    {
        case StorQueryCapabilities:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                         " StorQueryCapabilities on %d::%d::%d\n",
                         SRB_PATH_ID(Srb),
                         SRB_TARGET_ID(Srb),
                         SRB_LUN(Srb));
            if (((SrbPnPFlags & SRB_PNP_FLAGS_ADAPTER_REQUEST) == 0) ||
                (SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(STOR_DEVICE_CAPABILITIES)))
            {
                PSTOR_DEVICE_CAPABILITIES devCap = (PSTOR_DEVICE_CAPABILITIES)SRB_DATA_BUFFER(Srb);
                RtlZeroMemory(devCap, sizeof(*devCap));
                devCap->Removable = 1;
                devCap->SurpriseRemovalOK = 1;
            }
            break;
        case StorRemoveDevice:
        case StorSurpriseRemoval:
            RhelDbgPrint(TRACE_LEVEL_FATAL,
                         " Adapter Removal happens on %d::%d::%d\n",
                         SRB_PATH_ID(Srb),
                         SRB_TARGET_ID(Srb),
                         SRB_LUN(Srb));
            adaptExt->bRemoved = TRUE;
            break;
        default:
            RhelDbgPrint(TRACE_LEVEL_FATAL,
                         " Unsupported PnPAction SrbPnPFlags = %d, PnPAction = %d\n",
                         SrbPnPFlags,
                         PnPAction);
            SrbStatus = SRB_STATUS_INVALID_REQUEST;
            break;
    }
    EXIT_FN();
    return SrbStatus;
}

// Attributes a device/LUN reset to the target it was addressed to. Bus resets have no target.
static VOID RecordTargetReset(IN PADAPTER_EXTENSION adaptExt, IN PSRB_TYPE Srb, IN BOOLEAN LogicalUnit)
{
    PTARGET_TELEMETRY target = StorPerfTarget(&adaptExt->Telemetry, SRB_TARGET_ID(Srb));

    if (target == NULL)
    {
        return;
    }
    InterlockedIncrement64((PLONG64)(LogicalUnit ? &target->LogicalUnitResetCount : &target->DeviceResetCount));
    InterlockedExchange64((PLONG64)&target->LastResetTime, (LONG64)StorPerfInterruptTime(adaptExt));
}

BOOLEAN
FORCEINLINE
PreProcessRequest(IN PVOID DeviceExtension, IN PSRB_TYPE Srb)
{
    PADAPTER_EXTENSION adaptExt;

    ENTER_FN_SRB();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (SRB_FUNCTION(Srb))
    {
        case SRB_FUNCTION_PNP:
            SRB_SET_SRB_STATUS(Srb, VioScsiProcessPnP(DeviceExtension, Srb));
            return TRUE;

        case SRB_FUNCTION_POWER:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
            return TRUE;

        case SRB_FUNCTION_RESET_BUS:
        case SRB_FUNCTION_RESET_DEVICE:
        case SRB_FUNCTION_RESET_LOGICAL_UNIT:
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                         " <--> SRB_FUNCTION_RESET_LOGICAL_UNIT Target (%d::%d::%d), SRB 0x%p\n",
                         SRB_PATH_ID(Srb),
                         SRB_TARGET_ID(Srb),
                         SRB_LUN(Srb),
                         Srb);

            switch (SRB_FUNCTION(Srb))
            {
                case SRB_FUNCTION_RESET_BUS:
                    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.BusResetCount);
                    break;
                case SRB_FUNCTION_RESET_DEVICE:
                    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.DeviceResetCount);
                    RecordTargetReset(adaptExt, Srb, FALSE);
                    break;
                case SRB_FUNCTION_RESET_LOGICAL_UNIT:
                    InterlockedIncrement64((PLONG64)&adaptExt->Telemetry.LogicalUnitResetCount);
                    RecordTargetReset(adaptExt, Srb, TRUE);
                    break;
            }
            InterlockedExchange64((PLONG64)&adaptExt->Telemetry.LastResetTime,
                                  (LONG64)StorPerfInterruptTime(adaptExt));
            VioScsiRecordEvent(adaptExt,
                               VioScsiEventResetRequest,
                               VIOSCSI_EVENT_NO_QUEUE,
                               SRB_TARGET_ID(Srb),
                               SRB_LUN(Srb),
                               0,
                               NULL,
                               Srb,
                               0,
                               SRB_FUNCTION(Srb),
                               (ULONG64)(ULONG)adaptExt->action_on_reset);

            switch (adaptExt->action_on_reset)
            {
                case VioscsiResetCompleteRequests:
                {
                    LARGE_INTEGER resetStart = {0};
                    LARGE_INTEGER resetEnd = {0};
                    LARGE_INTEGER freq = {0};
                    ULONG qpcStatus;
                    ULONG qpcEndStatus;
                    UCHAR resetTarget = 0;
                    UCHAR resetLun = 0;

                    // A bus reset names no target. Target and LUN resets name the one that
                    // stopped responding, and that is where the TMF has to go.
                    if (SRB_FUNCTION(Srb) != SRB_FUNCTION_RESET_BUS)
                    {
                        resetTarget = SRB_TARGET_ID(Srb);
                        resetLun = SRB_LUN(Srb);
                    }

                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Completing all pending SRBs\n");
                    qpcStatus = StorPortQueryPerformanceCounter(DeviceExtension, &freq, &resetStart);
                    if (qpcStatus != STOR_STATUS_SUCCESS)
                    {
                        RhelDbgPrint(TRACE_LEVEL_ERROR,
                                     "StorPortQueryPerformanceCounter failed with status 0x%lx, reset duration will not be recorded\n",
                                     qpcStatus);
                    }
                    CompletePendingRequestsOnReset(DeviceExtension, resetTarget, resetLun);
                    if (qpcStatus == STOR_STATUS_SUCCESS && freq.QuadPart != 0)
                    {
                        qpcEndStatus = StorPortQueryPerformanceCounter(DeviceExtension, NULL, &resetEnd);
                        if (qpcEndStatus == STOR_STATUS_SUCCESS)
                        {
                            ULONG64 durationUs =
                                (ULONG64)(((resetEnd.QuadPart - resetStart.QuadPart) * 1000000) / freq.QuadPart);
                            adaptExt->Telemetry.LastResetDurationUs = durationUs;
                            StorPerfUpdateMax(&adaptExt->Telemetry.MaxResetDurationUs, durationUs);
                        }
                        else
                        {
                            RhelDbgPrint(TRACE_LEVEL_ERROR,
                                         "StorPortQueryPerformanceCounter failed with status 0x%lx, reset duration will not "
                                         "be recorded\n",
                                         qpcEndStatus);
                        }
                    }
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
                    return TRUE;
                }
                case VioscsiResetDoNothing:
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Doing nothing with all pending SRBs\n");
                    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
                    return TRUE;
                case VioscsiResetBugCheck:
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION, " Let's bugcheck due to this reset event\n");
                    KeBugCheckEx(0xDEADDEAD, (ULONG_PTR)Srb, SRB_PATH_ID(Srb), SRB_TARGET_ID(Srb), SRB_LUN(Srb));
                    return TRUE;
            }
        case SRB_FUNCTION_WMI:
            VioScsiWmiSrb(DeviceExtension, Srb);
            return TRUE;
        case SRB_FUNCTION_IO_CONTROL:
            VioScsiIoControl(DeviceExtension, Srb);
            return TRUE;
    }
    EXIT_FN_SRB();
    return FALSE;
}

VOID PostProcessRequest(IN PVOID DeviceExtension, IN PSRB_TYPE Srb)
{
    PCDB cdb = NULL;
    PADAPTER_EXTENSION adaptExt = NULL;
    PSRB_EXTENSION srbExt = NULL;
    ENTER_FN_SRB();
    if (SRB_FUNCTION(Srb) != SRB_FUNCTION_EXECUTE_SCSI)
    {
        return;
    }
    cdb = SRB_CDB(Srb);
    if (!cdb)
    {
        return;
    }

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ_CAPACITY:
        case SCSIOP_READ_CAPACITY16:
            break;
        case SCSIOP_INQUIRY:
            VioScsiSaveInquiryData(DeviceExtension, Srb);
            VioScsiPatchInquiryData(DeviceExtension, Srb);
            if (!StorPortSetDeviceQueueDepth(DeviceExtension,
                                             SRB_PATH_ID(Srb),
                                             SRB_TARGET_ID(Srb),
                                             SRB_LUN(Srb),
                                             adaptExt->queue_depth))
            {
                RhelDbgPrint(TRACE_LEVEL_ERROR,
                             " StorPortSetDeviceQueueDepth(%p, %x) failed.\n",
                             DeviceExtension,
                             adaptExt->queue_depth);
            }
            break;
        default:
            break;
    }
    EXIT_FN_SRB();
}

// Per-target counterpart of the queue accounting in RecordIoCompletionStats, which calls it once
// the SRB is known to be an I/O request. The same SubmitTime rule applies: only requests that
// were actually queued to the device feed latency, slow-request and last-completion state.
static VOID RecordTargetCompletionStats(IN PADAPTER_EXTENSION adaptExt,
                                        IN PSRB_TYPE Srb,
                                        IN PSRB_EXTENSION srbExt,
                                        IN UCHAR SrbStatus,
                                        IN ULONGLONG ElapsedUs)
{
    PTARGET_TELEMETRY target = StorPerfTarget(&adaptExt->Telemetry, srbExt->TargetId);
    PCDB cdb;
    ULONG dataLen;

    if (target == NULL)
    {
        return;
    }

    if (srbExt->SubmitTime != 0)
    {
        ULONGLONG now = StorPerfInterruptTime(adaptExt);

        InterlockedIncrement64((PLONG64)&target->LatencyCount);
        InterlockedExchangeAdd64((PLONG64)&target->LatencySumUs, (LONG64)ElapsedUs);
        if (StorPerfUpdateMax(&target->MaxLatencyUs, ElapsedUs))
        {
            InterlockedExchange64((PLONG64)&target->MaxLatencyTime, (LONG64)now);
        }
        InterlockedExchange64((PLONG64)&target->LastCompletionTime, (LONG64)now);
        if (ElapsedUs > STOR_TELEMETRY_SLOW_1S_US)
        {
            InterlockedIncrement64((PLONG64)&target->Slow1sCount);
            if (ElapsedUs > STOR_TELEMETRY_SLOW_5S_US)
            {
                InterlockedIncrement64((PLONG64)&target->Slow5sCount);
                if (ElapsedUs > STOR_TELEMETRY_SLOW_30S_US)
                {
                    InterlockedIncrement64((PLONG64)&target->Slow30sCount);
                }
            }
        }
    }

    switch (SrbStatus)
    {
        case SRB_STATUS_BUSY:
            InterlockedIncrement64((PLONG64)&target->BusyCount);
            break;
        case SRB_STATUS_ABORTED:
        case SRB_STATUS_BUS_RESET:
            InterlockedIncrement64((PLONG64)&target->AbortedCount);
            break;
        case SRB_STATUS_NO_DEVICE:
            InterlockedIncrement64((PLONG64)&target->NoDeviceCount);
            break;
        case SRB_STATUS_INVALID_TARGET_ID:
            InterlockedIncrement64((PLONG64)&target->InvalidTargetCount);
            break;
        case SRB_STATUS_ERROR:
            InterlockedIncrement64((PLONG64)&target->ErrorCount);
            break;
        default:
            break;
    }

    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);
    cdb = SRB_CDB(Srb);
    if (!cdb)
    {
        InterlockedIncrement64((PLONG64)&target->OtherCount);
        return;
    }

    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ6:
        case SCSIOP_READ:
        case SCSIOP_READ12:
        case SCSIOP_READ16:
            InterlockedIncrement64((PLONG64)&target->ReadCount);
            InterlockedExchangeAdd64((PLONG64)&target->ReadBytes, dataLen);
            break;
        case SCSIOP_WRITE6:
        case SCSIOP_WRITE:
        case SCSIOP_WRITE12:
        case SCSIOP_WRITE16:
        case SCSIOP_WRITE_VERIFY:
        case SCSIOP_WRITE_VERIFY12:
        case SCSIOP_WRITE_VERIFY16:
            InterlockedIncrement64((PLONG64)&target->WriteCount);
            InterlockedExchangeAdd64((PLONG64)&target->WriteBytes, dataLen);
            break;
        default:
            InterlockedIncrement64((PLONG64)&target->OtherCount);
            break;
    }
}

VOID
FORCEINLINE
RecordIoCompletionStats(IN PADAPTER_EXTENSION adaptExt, IN PSRB_TYPE Srb, IN PSRB_EXTENSION srbExt, IN ULONGLONG ElapsedUs)
{
    PQUEUE_TELEMETRY queueStats;
    PCDB cdb;
    ULONG dataLen;
    UCHAR srbStatus;
    UCHAR statusIndex;
    ULONG bucket;
    ULONGLONG now;

    if (SRB_FUNCTION(Srb) != SRB_FUNCTION_EXECUTE_SCSI || srbExt->QueueIndex >= adaptExt->num_queues)
    {
        return;
    }

    queueStats = &adaptExt->Telemetry.Queues[srbExt->QueueIndex];
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    // Latency, slow-request and last-completion state describe the device, so only requests that
    // were actually queued to the virtqueue (SubmitTime set by SendSRB) feed them. Completions
    // made without the device (queue full -> BUSY, bRemoved, reset, surprise removal) would
    // otherwise refresh LastCompletionTime and hide a real stall. The read/write counters and
    // status histogram below still count every completion: they record what the initiator was
    // told, and the BUSY/BUS_RESET/NO_DEVICE slots are useful there.
    // The latency clock (srbExt->time, stamped in BuildIo) starts earlier than SubmitTime
    // (stamped after virtqueue_add_buf), so an oldest-in-flight age can be slightly smaller
    // than the latency of a slow request.
    if (srbExt->SubmitTime != 0)
    {
        bucket = StorPerfLatencyBucket(ElapsedUs);
        InterlockedIncrement64((PLONG64)&queueStats->Latency.Buckets[bucket]);
        InterlockedIncrement64((PLONG64)&queueStats->Latency.Count);
        InterlockedExchangeAdd64((PLONG64)&queueStats->Latency.SumUs, (LONG64)ElapsedUs);
        StorPerfUpdateMin(&queueStats->Latency.MinUs, ElapsedUs);
        now = StorPerfInterruptTime(adaptExt);
        if (StorPerfUpdateMax(&queueStats->Latency.MaxUs, ElapsedUs))
        {
            InterlockedExchange64((PLONG64)&queueStats->MaxLatencyTime, (LONG64)now);
        }
        InterlockedExchange64((PLONG64)&queueStats->LastCompletionTime, (LONG64)now);
        if (ElapsedUs > STOR_TELEMETRY_SLOW_1S_US)
        {
            InterlockedIncrement64((PLONG64)&queueStats->Slow1sCount);
            if (ElapsedUs > STOR_TELEMETRY_SLOW_5S_US)
            {
                InterlockedIncrement64((PLONG64)&queueStats->Slow5sCount);
                if (ElapsedUs > STOR_TELEMETRY_SLOW_30S_US)
                {
                    InterlockedIncrement64((PLONG64)&queueStats->Slow30sCount);
                }
            }
        }
    }

    srbStatus = SrbGetSrbStatus(Srb);
    statusIndex = srbStatus & ~(SRB_STATUS_QUEUE_FROZEN | SRB_STATUS_AUTOSENSE_VALID);
    if (statusIndex >= STOR_TELEMETRY_STATUS_SLOTS)
    {
        statusIndex = STOR_TELEMETRY_STATUS_SLOTS - 1;
    }
    InterlockedIncrement64((PLONG64)&queueStats->StatusHistogram[statusIndex]);
    RecordTargetCompletionStats(adaptExt, Srb, srbExt, statusIndex, ElapsedUs);

    cdb = SRB_CDB(Srb);
    if (!cdb)
    {
        InterlockedIncrement64((PLONG64)&queueStats->OtherCount);
        return;
    }

    switch (cdb->CDB6GENERIC.OperationCode)
    {
        case SCSIOP_READ6:
        case SCSIOP_READ:
        case SCSIOP_READ12:
        case SCSIOP_READ16:
            InterlockedIncrement64((PLONG64)&queueStats->ReadCount);
            InterlockedExchangeAdd64((PLONG64)&queueStats->ReadBytes, dataLen);
            break;
        case SCSIOP_WRITE6:
        case SCSIOP_WRITE:
        case SCSIOP_WRITE12:
        case SCSIOP_WRITE16:
        case SCSIOP_WRITE_VERIFY:
        case SCSIOP_WRITE_VERIFY12:
        case SCSIOP_WRITE_VERIFY16:
            InterlockedIncrement64((PLONG64)&queueStats->WriteCount);
            InterlockedExchangeAdd64((PLONG64)&queueStats->WriteBytes, dataLen);
            break;
        case SCSIOP_SYNCHRONIZE_CACHE:
        case SCSIOP_SYNCHRONIZE_CACHE16:
            InterlockedIncrement64((PLONG64)&queueStats->FlushCount);
            break;
        case SCSIOP_UNMAP:
            InterlockedIncrement64((PLONG64)&queueStats->UnmapCount);
            break;
        default:
            InterlockedIncrement64((PLONG64)&queueStats->OtherCount);
            break;
    }
}

VOID CompleteRequest(IN PVOID DeviceExtension, IN PSRB_TYPE Srb)
{
    PADAPTER_EXTENSION adaptExt = NULL;
    PSRB_EXTENSION srbExt = NULL;

    ENTER_FN_SRB();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PostProcessRequest(DeviceExtension, Srb);

    srbExt = SRB_EXTENSION(Srb);
    if (srbExt->time != 0)
    {
        LARGE_INTEGER counter = {0};
        LARGE_INTEGER freq = {0};
        ULONG status = StorPortQueryPerformanceCounter(DeviceExtension, &freq, &counter);

        if (status == STOR_STATUS_SUCCESS)
        {
            ULONGLONG elapsed_us = ((counter.QuadPart - srbExt->time) * 1000000) / freq.QuadPart;
            ULONGLONG time_msec = elapsed_us / 1000;

            RecordIoCompletionStats(adaptExt, Srb, srbExt, elapsed_us);

            if (adaptExt->resp_time)
            {
                RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                             "time_msec %I64d Start %llu End %llu Freq %llu\n",
                             time_msec,
                             srbExt->time,
                             counter.QuadPart,
                             freq.QuadPart);
                if (time_msec >= adaptExt->resp_time)
                {
                    PCDB cdb = SRB_CDB(Srb);
                    if (cdb)
                    { // Check for SDV compliance
                        UCHAR OpCode = cdb->CDB6GENERIC.OperationCode;
                        RhelDbgPrint(TRACE_LEVEL_WARNING,
                                     "Response Time SRB 0x%p : time %I64d (%lu) : length %d : OpCode 0x%x (%s)\n",
                                     Srb,
                                     time_msec,
                                     SRB_GET_TIMEOUTVALUE(Srb) * 1000,
                                     SRB_DATA_TRANSFER_LENGTH(Srb),
                                     OpCode,
                                     DbgGetScsiOpStr(OpCode));
                        DbgPrint("Response Time SRB 0x%p : time %I64d (%lu) : length %d : OpCode 0x%x (%s)\n",
                                 Srb,
                                 time_msec,
                                 SRB_GET_TIMEOUTVALUE(Srb) * 1000,
                                 SRB_DATA_TRANSFER_LENGTH(Srb),
                                 OpCode,
                                 DbgGetScsiOpStr(OpCode));
                    }
                }
            }
        }
        else
        {
            RhelDbgPrint(TRACE_LEVEL_ERROR,
                         "SRB 0x%p StorPortQueryPerformanceCounter failed with status  0x%lx\n",
                         Srb,
                         status);
        }
    }
    StorPortNotification(RequestComplete, DeviceExtension, Srb);
    EXIT_FN_SRB();
}

VOID LogError(IN PVOID DeviceExtension, IN ULONG ErrorCode, IN ULONG UniqueId)
{
    STOR_LOG_EVENT_DETAILS logEvent;
    ULONG sz = 0;
    RtlZeroMemory(&logEvent, sizeof(logEvent));
    logEvent.InterfaceRevision = STOR_CURRENT_LOG_INTERFACE_REVISION;
    logEvent.Size = sizeof(logEvent);
    logEvent.EventAssociation = StorEventAdapterAssociation;
    logEvent.StorportSpecificErrorCode = TRUE;
    logEvent.ErrorCode = ErrorCode;
    logEvent.DumpDataSize = sizeof(UniqueId);
    logEvent.DumpData = &UniqueId;
    StorPortLogSystemEvent(DeviceExtension, &logEvent, &sz);
}

VOID TransportReset(IN PVOID DeviceExtension, IN PVirtIOSCSIEvent evt)
{
    UCHAR TargetId = evt->lun[1];
    UCHAR Lun = (evt->lun[2] << 8) | evt->lun[3];
    ENTER_FN();

    switch (evt->reason)
    {
        case VIRTIO_SCSI_EVT_RESET_RESCAN:
            StorPortNotification(BusChangeDetected, DeviceExtension, 0);
            break;
        case VIRTIO_SCSI_EVT_RESET_REMOVED:
            StorPortNotification(BusChangeDetected, DeviceExtension, 0);
            break;
        default:
            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " <--> Unsupport virtio scsi event reason 0x%x\n", evt->reason);
    }
    EXIT_FN();
}

VOID ParamChange(IN PVOID DeviceExtension, IN PVirtIOSCSIEvent evt)
{
    UCHAR TargetId = evt->lun[1];
    UCHAR Lun = (evt->lun[2] << 8) | evt->lun[3];
    UCHAR AdditionalSenseCode = (UCHAR)(evt->reason & 255);
    UCHAR AdditionalSenseCodeQualifier = (UCHAR)(evt->reason >> 8);
    ENTER_FN();

    if (AdditionalSenseCode == SCSI_ADSENSE_PARAMETERS_CHANGED &&
        (AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_PARAMETERS_CHANGED ||
         AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_MODE_PARAMETERS_CHANGED ||
         AdditionalSenseCodeQualifier == SPC3_SCSI_SENSEQ_CAPACITY_DATA_HAS_CHANGED))
    {
        StorPortNotification(BusChangeDetected, DeviceExtension, 0);
    }
    EXIT_FN();
}

VOID VioScsiWmiInitialize(IN PVOID DeviceExtension)
{
    PADAPTER_EXTENSION adaptExt;
    PSCSI_WMILIB_CONTEXT WmiLibContext;
    ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    WmiLibContext = (PSCSI_WMILIB_CONTEXT)(&(adaptExt->WmiLibContext));

    WmiLibContext->GuidList = VioScsiGuidList;
    WmiLibContext->GuidCount = VioScsiGuidCount;
    WmiLibContext->QueryWmiRegInfo = VioScsiQueryWmiRegInfo;
    WmiLibContext->QueryWmiDataBlock = VioScsiQueryWmiDataBlock;
    WmiLibContext->SetWmiDataItem = NULL;
    WmiLibContext->SetWmiDataBlock = NULL;
    WmiLibContext->ExecuteWmiMethod = VioScsiExecuteWmiMethod;
    WmiLibContext->WmiFunctionControl = NULL;
    EXIT_FN();
}

VOID VioScsiWmiSrb(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb)
{
    UCHAR status;
    SCSIWMI_REQUEST_CONTEXT requestContext = {0};
    ULONG retSize;
    PADAPTER_EXTENSION adaptExt;
    PSRB_WMI_DATA pSrbWmi = SRB_WMI_DATA(Srb);

    ENTER_FN_SRB();
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;

    // WHY NT_VERIFY + bugcheck (all three below): SRB_DATA_TRANSFER_LENGTH(Srb)/
    // SRB_DATA_BUFFER(Srb) get passed straight into ScsiPortWmiDispatchFunction() below with
    // no further size check. If the SRB doesn't actually match these shape/size assumptions,
    // that dispatch call reads/writes a buffer that's smaller than it expects - a buffer
    // over-read/over-write. Checked individually (not combined) so a crash dump's bugcheck
    // parameters identify exactly which assumption failed. Deliberately fatal rather than
    // rejecting the SRB, while this driver is under hypervisor error injection to find where
    // it corrupts memory today.
    //
    // NOTE: a fourth check used to live here, SRB_LENGTH(Srb) == sizeof(SCSI_WMI_REQUEST_BLOCK).
    // It fired on every boot (confirmed via hypervisor-driven testing) because it encoded a
    // legacy, fixed-layout SRB assumption that doesn't hold for the extended STORAGE_REQUEST_BLOCK
    // model this driver (and Windows 11) actually uses for WMI - SRB_LENGTH legitimately differs
    // from sizeof(SCSI_WMI_REQUEST_BLOCK) under that model. Removed as a false positive, not a
    // real corruption risk: nothing downstream relies on that equality.
    if (!NT_VERIFY(SRB_FUNCTION(Srb) == SRB_FUNCTION_WMI))
    {
        KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, (ULONG_PTR)Srb, SRB_FUNCTION(Srb), 0);
    }
    if (!NT_VERIFY(SRB_DATA_TRANSFER_LENGTH(Srb) >= sizeof(ULONG)))
    {
        KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, (ULONG_PTR)Srb, SRB_DATA_TRANSFER_LENGTH(Srb), 0);
    }
    if (!NT_VERIFY(SRB_DATA_BUFFER(Srb)))
    {
        KeBugCheckEx(VIOSCSI_BUGCHECK_CORRUPTION_GUARD, __LINE__, (ULONG_PTR)Srb, 0, 0);
    }

    if (!pSrbWmi)
    {
        return;
    }
    if (!(pSrbWmi->WMIFlags & SRB_WMI_FLAGS_ADAPTER_REQUEST))
    {
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
    }
    else
    {
        requestContext.UserContext = Srb;
        (VOID) ScsiPortWmiDispatchFunction(&adaptExt->WmiLibContext,
                                           pSrbWmi->WMISubFunction,
                                           DeviceExtension,
                                           &requestContext,
                                           pSrbWmi->DataPath,
                                           SRB_DATA_TRANSFER_LENGTH(Srb),
                                           SRB_DATA_BUFFER(Srb));

        retSize = ScsiPortWmiGetReturnSize(&requestContext);
        status = ScsiPortWmiGetReturnStatus(&requestContext);

        SRB_SET_DATA_TRANSFER_LENGTH(Srb, retSize);
        SRB_SET_SRB_STATUS(Srb, status);
    }

    EXIT_FN_SRB();
}

// Recomputes every target's OldestInFlightTime from the request lists. A target's requests are
// spread over all queues and each list is ordered by submission only within its own queue, so the
// minimum can't be kept up to date on the I/O path without a lock shared by all queues. Instead
// walk the lists here, one queue at a time under that queue's lock (the same lock the I/O path
// holds while changing the list, so entries and SubmitTime are stable), and publish the result.
// The cost is proportional to the number of requests in flight and is only paid per IOCTL.
//
// The minimums are gathered in a local table (2 KB, which is fine for a kernel stack) and only
// published at the end, rather than being accumulated in the telemetry table: that would need a
// reset first, and a reader (or a snapshot copy) in between would see 0 ("nothing in flight")
// for a target that has requests. If two IOCTLs run at once each publishes a complete, valid
// result, so the later one simply wins; TargetScanTime is written last and each value is only
// ever the age of a real request, so the worst case is a slightly older scan time than the data.
static VOID TelemetryScanTargets(IN PADAPTER_EXTENSION adaptExt)
{
    ULONGLONG oldest[STOR_TELEMETRY_MAX_TARGETS] = {0};
    ULONG queueCount = min(adaptExt->num_queues, MAX_CPU);
    ULONG index;

    for (index = 0; index < queueCount; index++)
    {
        PREQUEST_LIST element = &adaptExt->processing_srbs[index];
        STOR_LOCK_HANDLE lockHandle = {0};
        ULONG msgId = QUEUE_TO_MESSAGE(index + VIRTIO_SCSI_REQUEST_QUEUE_0);
        PLIST_ENTRY entry;

        VioScsiVQLock(adaptExt, msgId, &lockHandle, FALSE);
        for (entry = element->srb_list.Flink; entry != &element->srb_list; entry = entry->Flink)
        {
            PSRB_EXTENSION srbExt = CONTAINING_RECORD(entry, SRB_EXTENSION, list_entry);

            if (srbExt->TargetId < STOR_TELEMETRY_MAX_TARGETS && srbExt->SubmitTime != 0 &&
                (oldest[srbExt->TargetId] == 0 || srbExt->SubmitTime < oldest[srbExt->TargetId]))
            {
                oldest[srbExt->TargetId] = srbExt->SubmitTime;
            }
        }
        VioScsiVQUnlock(adaptExt, msgId, &lockHandle, FALSE);
    }

    for (index = 0; index < STOR_TELEMETRY_MAX_TARGETS; index++)
    {
        InterlockedExchange64((PLONG64)&adaptExt->Telemetry.Targets[index].OldestInFlightTime, (LONG64)oldest[index]);
    }
    InterlockedExchange64((PLONG64)&adaptExt->Telemetry.TargetScanTime, (LONG64)StorPerfInterruptTime(adaptExt));
}

// Appends Length bytes of Source at Used in a Capacity-byte buffer, dropping whatever doesn't
// fit. Returns the new Used. Lets the snapshot be assembled in pieces and truncated anywhere.
static ULONG TelemetryAppend(IN PUCHAR Dest, IN ULONG Capacity, IN ULONG Used, IN const VOID *Source, IN ULONG Length)
{
    ULONG count = min(Length, Capacity - Used);

    if (count != 0)
    {
        RtlCopyMemory(Dest + Used, Source, count);
    }
    return Used + count;
}

static VOID TelemetryRequest(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    PSRB_IO_CONTROL srbControl = (PSRB_IO_CONTROL)SRB_DATA_BUFFER(Srb);
    ULONG dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);
    // The header is copied out and patched (TargetCount/TargetsOffset describe the compact
    // snapshot, not the in-memory table), so keep it 8-byte aligned like the real thing.
    ULONG64 headerCopy[FIELD_OFFSET(STOR_TELEMETRY, Queues) / sizeof(ULONG64)];
    PSTOR_TELEMETRY header = (PSTOR_TELEMETRY)headerCopy;
    UCHAR activeTargets[STOR_TELEMETRY_MAX_TARGETS];
    PUCHAR payload;
    ULONG queueCount;
    ULONG targetCount = 0;
    ULONG index;
    ULONG snapshotLen;
    ULONG used;

    // HeaderLength and Length are caller-supplied: never let them address past the SRB buffer.
    if (dataLen < sizeof(SRB_IO_CONTROL) || srbControl->HeaderLength < sizeof(SRB_IO_CONTROL) ||
        srbControl->HeaderLength > dataLen || srbControl->Length > dataLen - srbControl->HeaderLength)
    {
        RhelDbgPrint(TRACE_LEVEL_ERROR, " TelemetryRequest bad length %lu\n", dataLen);
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_BAD_SRB_BLOCK_LENGTH);
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        return;
    }

    if (RtlCompareMemory(srbControl->Signature, VIOSCSI_IOCTL_SIGNATURE, sizeof(srbControl->Signature)) !=
        sizeof(srbControl->Signature))
    {
        SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
        SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
        return;
    }

    // Sized from the compile-time layout rather than the stored sizes, so a corrupted header
    // can't widen the copy beyond the STOR_TELEMETRY object.
    queueCount = min(adaptExt->Telemetry.QueueCount, MAX_CPU);

    // OldestInFlightTime needs a pass over the request lists under their locks, see above.
    TelemetryScanTargets(adaptExt);
    InterlockedExchange64((PLONG64)&adaptExt->Telemetry.SnapshotTime, (LONG64)StorPerfInterruptTime(adaptExt));

    // No lock for the counters: they are updated with interlocked operations, so the snapshot is
    // not a consistent point-in-time view across fields (and on 32-bit builds an individual
    // 64-bit counter can tear), which is fine for statistics. Only targets that have seen
    // activity are sent, so a mostly idle 256-entry table doesn't cost 47 KB per query.
    for (index = 0; index < STOR_TELEMETRY_MAX_TARGETS; index++)
    {
        if (StorPerfTargetActive(&adaptExt->Telemetry.Targets[index]))
        {
            activeTargets[targetCount++] = (UCHAR)index;
        }
    }

    RtlCopyMemory(headerCopy, &adaptExt->Telemetry, sizeof(headerCopy));
    header->QueueCount = queueCount;
    header->TargetCount = targetCount;
    header->TargetsOffset = (ULONG)FIELD_OFFSET(STOR_TELEMETRY, Queues) + queueCount * (ULONG)sizeof(QUEUE_TELEMETRY);
    snapshotLen = header->TargetsOffset + targetCount * (ULONG)sizeof(TARGET_TELEMETRY);

    payload = (PUCHAR)srbControl + srbControl->HeaderLength;
    used = TelemetryAppend(payload, srbControl->Length, 0, headerCopy, sizeof(headerCopy));
    used = TelemetryAppend(payload,
                           srbControl->Length,
                           used,
                           adaptExt->Telemetry.Queues,
                           queueCount * (ULONG)sizeof(QUEUE_TELEMETRY));
    for (index = 0; index < targetCount; index++)
    {
        used = TelemetryAppend(payload,
                               srbControl->Length,
                               used,
                               &adaptExt->Telemetry.Targets[activeTargets[index]],
                               (ULONG)sizeof(TARGET_TELEMETRY));
    }

    srbControl->Length = used;
    srbControl->ReturnCode = (used < snapshotLen) ? VIOSCSI_TELEMETRY_RC_TRUNCATED : VIOSCSI_TELEMETRY_RC_SUCCESS;
    SRB_SET_DATA_TRANSFER_LENGTH(Srb, srbControl->HeaderLength + used);
    SRB_SET_SRB_STATUS(Srb, SRB_STATUS_SUCCESS);
}

VOID VioScsiIoControl(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb)
{
    PSRB_IO_CONTROL srbControl;
    PVOID srbDataBuffer = SRB_DATA_BUFFER(Srb);
    PADAPTER_EXTENSION adaptExt;

    ENTER_FN_SRB();

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    srbControl = (PSRB_IO_CONTROL)srbDataBuffer;

    switch (srbControl->ControlCode)
    {
        case IOCTL_SCSI_MINIPORT_NOT_QUORUM_CAPABLE:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_ERROR);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                         " <--> Signature = %02x %02x %02x %02x %02x %02x %02x %02x\n",
                         srbControl->Signature[0],
                         srbControl->Signature[1],
                         srbControl->Signature[2],
                         srbControl->Signature[3],
                         srbControl->Signature[4],
                         srbControl->Signature[5],
                         srbControl->Signature[6],
                         srbControl->Signature[7]);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> IOCTL_SCSI_MINIPORT_NOT_QUORUM_CAPABLE\n");
            break;
        case IOCTL_SCSI_MINIPORT_FIRMWARE:
            FirmwareRequest(DeviceExtension, Srb);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> IOCTL_SCSI_MINIPORT_FIRMWARE\n");
            break;
        case VIOSCSI_IOCTL_QUERY_TELEMETRY:
            TelemetryRequest(DeviceExtension, Srb);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> VIOSCSI_IOCTL_QUERY_TELEMETRY\n");
            break;
        default:
            SRB_SET_SRB_STATUS(Srb, SRB_STATUS_INVALID_REQUEST);
            SRB_SET_DATA_TRANSFER_LENGTH(Srb, 0);
            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " <--> Unsupport control code 0x%x\n", srbControl->ControlCode);
            break;
    }
    EXIT_FN_SRB();
}

UCHAR
ParseIdentificationDescr(IN PVOID DeviceExtension,
                         IN PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr,
                         IN UCHAR PageLength)
{
    PADAPTER_EXTENSION adaptExt;
    UCHAR CodeSet = 0;
    UCHAR IdentifierType = 0;
    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    ENTER_FN();
    if (IdentificationDescr)
    {
        CodeSet = IdentificationDescr->CodeSet;               //(UCHAR)(((PCHAR)IdentificationDescr)[0]);
        IdentifierType = IdentificationDescr->IdentifierType; //(UCHAR)(((PCHAR)IdentificationDescr)[1]);
        if (PageLength < IdentificationDescr->IdentifierLength)
        {
            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                         " Skipping VPD identifier's descriptor as its length"
                         "(0x%02x) is bigger than the remaining data buffer length (0x%02x), therefore"
                         "the descriptor is unreliable.\n",
                         IdentificationDescr->IdentifierLength,
                         PageLength);
            return PageLength;
        }
        switch (IdentifierType)
        {
            case VioscsiVpdIdentifierTypeVendorSpecific:
                {
                    if (CodeSet == VioscsiVpdCodeSetAscii)
                    {
                        if (IdentificationDescr->IdentifierLength > 0 && adaptExt->ser_num == NULL)
                        {
                            int ln = min(64, IdentificationDescr->IdentifierLength);
                            ULONG Status = StorPortAllocatePool(DeviceExtension,
                                                                ln + 1,
                                                                VIOSCSI_POOL_TAG,
                                                                (PVOID *)&adaptExt->ser_num);
                            if (NT_SUCCESS(Status))
                            {
                                StorPortMoveMemory(adaptExt->ser_num, IdentificationDescr->Identifier, ln);
                                adaptExt->ser_num[ln] = '\0';
                                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " serial number %s\n", adaptExt->ser_num);
                            }
                        }
                    }
                }
                break;
            case VioscsiVpdIdentifierTypeFCPHName:
                {
                    if ((CodeSet == VioscsiVpdCodeSetBinary) &&
                        (IdentificationDescr->IdentifierLength == sizeof(ULONGLONG)))
                    {
                        REVERSE_BYTES_QUAD(&adaptExt->wwn, IdentificationDescr->Identifier);
                        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " wwn %llu\n", (ULONGLONG)adaptExt->wwn);
                    }
                }
                break;
            case VioscsiVpdIdentifierTypeFCTargetPortPHName:
                {
                    if ((CodeSet == VioscsiVpdCodeSetSASBinary) &&
                        (IdentificationDescr->IdentifierLength == sizeof(ULONGLONG)))
                    {
                        REVERSE_BYTES_QUAD(&adaptExt->port_wwn, IdentificationDescr->Identifier);
                        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " port wwn %llu\n", (ULONGLONG)adaptExt->port_wwn);
                    }
                }
                break;
            case VioscsiVpdIdentifierTypeFCTargetPortRelativeTargetPort:
                {
                    if ((CodeSet == VioscsiVpdCodeSetSASBinary) &&
                        (IdentificationDescr->IdentifierLength == sizeof(ULONG)))
                    {
                        REVERSE_BYTES(&adaptExt->port_idx, IdentificationDescr->Identifier);
                        RhelDbgPrint(TRACE_LEVEL_INFORMATION, " port index %lu\n", (ULONG)adaptExt->port_idx);
                    }
                }
                break;
            default:
                RhelDbgPrint(TRACE_LEVEL_ERROR, " Unsupported IdentifierType = %x!\n", IdentifierType);
                break;
        }
        return IdentificationDescr->IdentifierLength;
    }
    EXIT_FN();
    return 0;
}

VOID VioScsiSaveInquiryData(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb)
{
    PVOID dataBuffer;
    PADAPTER_EXTENSION adaptExt;
    PCDB cdb;
    ULONG dataLen;
    UCHAR SrbStatus = SRB_STATUS_SUCCESS;
    ENTER_FN_SRB();

    if (!Srb)
    {
        return;
    }

    cdb = SRB_CDB(Srb);

    if (!cdb)
    {
        return;
    }

    SRB_GET_SCSI_STATUS(Srb, SrbStatus);
    if (SrbStatus == SRB_STATUS_ERROR)
    {
        return;
    }

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    dataBuffer = SRB_DATA_BUFFER(Srb);
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    if (cdb->CDB6INQUIRY3.EnableVitalProductData == 1)
    {
        switch (cdb->CDB6INQUIRY3.PageCode)
        {
            case VPD_SERIAL_NUMBER:
                {
                    PVPD_SERIAL_NUMBER_PAGE SerialPage;
                    SerialPage = (PVPD_SERIAL_NUMBER_PAGE)dataBuffer;
                    RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                                 " VPD_SERIAL_NUMBER PageLength = %d\n",
                                 SerialPage->PageLength);
                    if (SerialPage->PageLength > 0 && adaptExt->ser_num == NULL)
                    {
                        int ln = min(64, SerialPage->PageLength);
                        ULONG Status = StorPortAllocatePool(DeviceExtension,
                                                            ln + 1,
                                                            VIOSCSI_POOL_TAG,
                                                            (PVOID *)&adaptExt->ser_num);
                        if (NT_SUCCESS(Status))
                        {
                            StorPortMoveMemory(adaptExt->ser_num, SerialPage->SerialNumber, ln);
                            adaptExt->ser_num[ln] = '\0';
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " serial number %s\n", adaptExt->ser_num);
                        }
                    }
                }
                break;
            case VPD_DEVICE_IDENTIFIERS:
                {
                    PVPD_IDENTIFICATION_PAGE IdentificationPage;
                    PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr;
                    UCHAR PageLength = 0;
                    IdentificationPage = (PVPD_IDENTIFICATION_PAGE)dataBuffer;
                    PageLength = min((UCHAR)(dataLen & 0xFF) - sizeof(VPD_IDENTIFICATION_PAGE),
                                     IdentificationPage->PageLength);
                    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " SRB's DataTransferLength: 0x%x\n", dataLen);
                    RhelDbgPrint(TRACE_LEVEL_VERBOSE,
                                 " Identification page's length: 0x%x\n",
                                 IdentificationPage->PageLength);
                    RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Total PageLength: 0x%x\n", PageLength);
                    if (PageLength >= sizeof(VPD_IDENTIFICATION_DESCRIPTOR))
                    {
                        UCHAR IdentifierLength = 0;
                        IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)IdentificationPage->Descriptors;
                        do
                        {
                            UCHAR offset = 0;
                            IdentifierLength = ParseIdentificationDescr(DeviceExtension,
                                                                        IdentificationDescr,
                                                                        PageLength);
                            offset = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + IdentifierLength;
                            PageLength -= min(PageLength, offset);
                            IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)((ULONG_PTR)IdentificationDescr +
                                                                                   offset);
                            RhelDbgPrint(TRACE_LEVEL_VERBOSE, " Remaining PageLength: 0x%x\n", PageLength);
                        } while (PageLength >= sizeof(VPD_IDENTIFICATION_DESCRIPTOR));
                    }
                }
                break;
        }
    }
    else if (cdb->CDB6INQUIRY3.PageCode == VPD_SUPPORTED_PAGES)
    {
        PINQUIRYDATA InquiryData = (PINQUIRYDATA)dataBuffer;
        if (InquiryData && dataLen)
        {
            CopyBufferToAnsiString(adaptExt->ven_id, InquiryData->VendorId, ' ', sizeof(InquiryData->VendorId));
            CopyBufferToAnsiString(adaptExt->prod_id, InquiryData->ProductId, ' ', sizeof(InquiryData->ProductId));
            CopyBufferToAnsiString(adaptExt->rev_id,
                                   InquiryData->ProductRevisionLevel,
                                   ' ',
                                   sizeof(InquiryData->ProductRevisionLevel));
        }
    }
    EXIT_FN_SRB();
}

VOID VioScsiPatchInquiryData(IN PVOID DeviceExtension, IN OUT PSRB_TYPE Srb)
{
    PVOID dataBuffer;
    PADAPTER_EXTENSION adaptExt;
    PCDB cdb;
    ULONG dataLen;
    UCHAR SrbStatus = SRB_STATUS_SUCCESS;
    ENTER_FN_SRB();

    if (!Srb)
    {
        return;
    }

    cdb = SRB_CDB(Srb);

    if (!cdb)
    {
        return;
    }

    SRB_GET_SCSI_STATUS(Srb, SrbStatus);
    if (SrbStatus == SRB_STATUS_ERROR)
    {
        return;
    }

    adaptExt = (PADAPTER_EXTENSION)DeviceExtension;
    dataBuffer = SRB_DATA_BUFFER(Srb);
    dataLen = SRB_DATA_TRANSFER_LENGTH(Srb);

    if (cdb->CDB6INQUIRY3.EnableVitalProductData == 1)
    {
        switch (cdb->CDB6INQUIRY3.PageCode)
        {
            case VPD_DEVICE_IDENTIFIERS:
                {
                    PVPD_IDENTIFICATION_PAGE IdentificationPage;
                    PVPD_IDENTIFICATION_DESCRIPTOR IdentificationDescr;
                    UCHAR PageLength = 0;
                    IdentificationPage = (PVPD_IDENTIFICATION_PAGE)dataBuffer;
                    PageLength = IdentificationPage->PageLength;
                    if (dataLen >= (sizeof(VPD_IDENTIFICATION_DESCRIPTOR) + sizeof(VPD_IDENTIFICATION_PAGE) + 8) &&
                        PageLength <= sizeof(VPD_IDENTIFICATION_PAGE))
                    {
                        UCHAR IdentifierLength = 0;
                        IdentificationDescr = (PVPD_IDENTIFICATION_DESCRIPTOR)IdentificationPage->Descriptors;
                        if (IdentificationDescr->IdentifierLength == 0)
                        {
                            IdentificationDescr->CodeSet = VpdCodeSetBinary;
                            IdentificationDescr->IdentifierType = VpdIdentifierTypeEUI64;
                            IdentificationDescr->IdentifierLength = 8;
                            IdentificationDescr->Identifier[0] = (adaptExt->system_io_bus_number >> 12) & 0xF;
                            IdentificationDescr->Identifier[1] = (adaptExt->system_io_bus_number >> 8) & 0xF;
                            IdentificationDescr->Identifier[2] = (adaptExt->system_io_bus_number >> 4) & 0xF;
                            IdentificationDescr->Identifier[3] = adaptExt->system_io_bus_number & 0xF;
                            IdentificationDescr->Identifier[4] = (adaptExt->slot_number >> 12) & 0xF;
                            IdentificationDescr->Identifier[5] = (adaptExt->slot_number >> 8) & 0xF;
                            IdentificationDescr->Identifier[6] = (adaptExt->slot_number >> 4) & 0xF;
                            IdentificationDescr->Identifier[7] = adaptExt->slot_number & 0xF;
                            IdentificationPage->PageLength = sizeof(VPD_IDENTIFICATION_DESCRIPTOR) +
                                                             IdentificationDescr->IdentifierLength;
                            SRB_SET_DATA_TRANSFER_LENGTH(Srb,
                                                         (sizeof(VPD_IDENTIFICATION_PAGE) +
                                                          IdentificationPage->PageLength));
                        }
                    }
                }
                break;
        }
    }
    EXIT_FN_SRB();
}

BOOLEAN
VioScsiQueryWmiDataBlock(IN PVOID Context,
                         IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
                         IN ULONG GuidIndex,
                         IN ULONG InstanceIndex,
                         IN ULONG InstanceCount,
                         IN OUT PULONG InstanceLengthArray,
                         IN ULONG OutBufferSize,
                         OUT PUCHAR Buffer)
{
    ULONG size = 0;
    UCHAR status = SRB_STATUS_SUCCESS;
    PADAPTER_EXTENSION adaptExt;

    ENTER_FN();
    adaptExt = (PADAPTER_EXTENSION)Context;

    UNREFERENCED_PARAMETER(InstanceIndex);

    switch (GuidIndex)
    {
        case VIOSCSI_SETUP_GUID_INDEX:
            {
                size = VioScsiExtendedInfo_SIZE;
                if (OutBufferSize < size)
                {
                    status = SRB_STATUS_DATA_OVERRUN;
                    break;
                }

                VioScsiReadExtendedData(Context, Buffer);
                *InstanceLengthArray = size;
                status = SRB_STATUS_SUCCESS;
            }
            break;
        case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX:
            {
                PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
                RhelDbgPrint(TRACE_LEVEL_FATAL, " --> VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX\n");
                size = sizeof(MS_SM_AdapterInformationQuery);
                if (OutBufferSize < size)
                {
                    status = SRB_STATUS_DATA_OVERRUN;
                    break;
                }

                RtlZeroMemory(pOutBfr, size);
                pOutBfr->UniqueAdapterId = adaptExt->hba_id;
                pOutBfr->HBAStatus = HBA_STATUS_OK;
                pOutBfr->NumberOfPorts = 1;
                pOutBfr->VendorSpecificID = VENDORID | (PRODUCTID << 16);
                CopyUnicodeString(pOutBfr->Manufacturer, MANUFACTURER, sizeof(pOutBfr->Manufacturer));
                if (adaptExt->ser_num)
                {
                    CopyAnsiToUnicodeString(pOutBfr->SerialNumber, adaptExt->ser_num, sizeof(pOutBfr->SerialNumber));
                }
                else
                {
                    CopyUnicodeString(pOutBfr->SerialNumber, SERIALNUMBER, sizeof(pOutBfr->SerialNumber));
                }
                CopyUnicodeString(pOutBfr->Model, MODEL, sizeof(pOutBfr->Model));
                CopyUnicodeString(pOutBfr->ModelDescription, MODELDESCRIPTION, sizeof(pOutBfr->ModelDescription));
                CopyUnicodeString(pOutBfr->HardwareVersion, HARDWAREVERSION, sizeof(pOutBfr->ModelDescription));
                CopyUnicodeString(pOutBfr->DriverVersion, DRIVERVERSION, sizeof(pOutBfr->DriverVersion));
                CopyUnicodeString(pOutBfr->OptionROMVersion, OPTIONROMVERSION, sizeof(pOutBfr->OptionROMVersion));
                CopyAnsiToUnicodeString(pOutBfr->FirmwareVersion, adaptExt->rev_id, sizeof(pOutBfr->FirmwareVersion));
                CopyUnicodeString(pOutBfr->DriverName, DRIVERNAME, sizeof(pOutBfr->DriverName));
                CopyUnicodeString(pOutBfr->HBASymbolicName, HBASYMBOLICNAME, sizeof(pOutBfr->HBASymbolicName));
                CopyUnicodeString(pOutBfr->RedundantFirmwareVersion,
                                  REDUNDANTFIRMWAREVERSION,
                                  sizeof(pOutBfr->RedundantFirmwareVersion));
                CopyUnicodeString(pOutBfr->RedundantOptionROMVersion,
                                  REDUNDANTOPTIONROMVERSION,
                                  sizeof(pOutBfr->RedundantOptionROMVersion));
                CopyUnicodeString(pOutBfr->MfgDomain, MFRDOMAIN, sizeof(pOutBfr->MfgDomain));

                *InstanceLengthArray = size;
                status = SRB_STATUS_SUCCESS;
            }
            break;
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
            {
                size = sizeof(ULONG);
                if (OutBufferSize < size)
                {
                    status = SRB_STATUS_DATA_OVERRUN;
                    RhelDbgPrint(TRACE_LEVEL_WARNING,
                                 " --> VIOSCSI_MS_PORT_INFORM_GUID_INDEX out buffer too small %d %d\n",
                                 OutBufferSize,
                                 size);
                    break;
                }
                *InstanceLengthArray = size;
                status = SRB_STATUS_SUCCESS;
            }
            break;
        default:
            {
                status = SRB_STATUS_ERROR;
            }
    }

    ScsiPortWmiPostProcess(RequestContext, status, size);

    EXIT_FN();
    return TRUE;
}

UCHAR
VioScsiExecuteWmiMethod(IN PVOID Context,
                        IN PSCSIWMI_REQUEST_CONTEXT RequestContext,
                        IN ULONG GuidIndex,
                        IN ULONG InstanceIndex,
                        IN ULONG MethodId,
                        IN ULONG InBufferSize,
                        IN ULONG OutBufferSize,
                        IN OUT PUCHAR Buffer)
{
    PADAPTER_EXTENSION adaptExt = (PADAPTER_EXTENSION)Context;
    ULONG size = 0;
    UCHAR status = SRB_STATUS_SUCCESS;
    UNREFERENCED_PARAMETER(InstanceIndex);

    ENTER_FN();
    switch (GuidIndex)
    {
        case VIOSCSI_SETUP_GUID_INDEX:
            {
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> VIOSCSI_SETUP_GUID_INDEX ERROR\n");
            }
            break;
        case VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX:
            {
                PMS_SM_AdapterInformationQuery pOutBfr = (PMS_SM_AdapterInformationQuery)Buffer;
                pOutBfr;
                RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> VIOSCSI_MS_ADAPTER_INFORM_GUID_INDEX ERROR\n");
            }
            break;
        case VIOSCSI_MS_PORT_INFORM_GUID_INDEX:
            {
                switch (MethodId)
                {
                    case SM_GetPortType:
                        {
                            PSM_GetPortType_IN pInBfr = (PSM_GetPortType_IN)Buffer;
                            PSM_GetPortType_OUT pOutBfr = (PSM_GetPortType_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPortType\n");
                            size = SM_GetPortType_OUT_SIZE;
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetPortType_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                            pOutBfr->HBAStatus = HBA_STATUS_OK;
                            pOutBfr->PortType = HBA_PORTTYPE_SASDEVICE;
                        }
                        break;
                    case SM_GetAdapterPortAttributes:
                        {
                            PSM_GetAdapterPortAttributes_IN pInBfr = (PSM_GetAdapterPortAttributes_IN)Buffer;
                            PSM_GetAdapterPortAttributes_OUT pOutBfr = (PSM_GetAdapterPortAttributes_OUT)Buffer;
                            PMS_SMHBA_FC_Port pPortSpecificAttributes = NULL;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetAdapterPortAttributes\n");
                            size = FIELD_OFFSET(SM_GetAdapterPortAttributes_OUT, PortAttributes) +
                                   FIELD_OFFSET(MS_SMHBA_PORTATTRIBUTES, PortSpecificAttributes) +
                                   sizeof(MS_SMHBA_FC_Port);
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetAdapterPortAttributes_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                            pOutBfr->HBAStatus = HBA_STATUS_OK;
                            CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName,
                                              MODEL,
                                              sizeof(pOutBfr->PortAttributes.OSDeviceName));
                            pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                            pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                            pOutBfr->PortAttributes.PortSpecificAttributesSize = sizeof(MS_SMHBA_FC_Port);
                            pPortSpecificAttributes = (PMS_SMHBA_FC_Port)pOutBfr->PortAttributes.PortSpecificAttributes;
                            RtlZeroMemory(pPortSpecificAttributes, sizeof(MS_SMHBA_FC_Port));
                            RtlMoveMemory(pPortSpecificAttributes->NodeWWN,
                                          &adaptExt->wwn,
                                          sizeof(pPortSpecificAttributes->NodeWWN));
                            RtlMoveMemory(pPortSpecificAttributes->PortWWN,
                                          &adaptExt->port_wwn,
                                          sizeof(pPortSpecificAttributes->PortWWN));
                            pPortSpecificAttributes->FcId = 0;
                            pPortSpecificAttributes->PortSupportedClassofService = 0;
                            // FIXME report PortSupportedFc4Types PortActiveFc4Types FabricName;
                            pPortSpecificAttributes->NumberofDiscoveredPorts = 1;
                            pPortSpecificAttributes->NumberofPhys = 1;
                            CopyUnicodeString(pPortSpecificAttributes->PortSymbolicName,
                                              PORTSYMBOLICNAME,
                                              sizeof(pPortSpecificAttributes->PortSymbolicName));
                        }
                        break;
                    case SM_GetDiscoveredPortAttributes:
                        {
                            PSM_GetDiscoveredPortAttributes_IN pInBfr = (PSM_GetDiscoveredPortAttributes_IN)Buffer;
                            PSM_GetDiscoveredPortAttributes_OUT pOutBfr = (PSM_GetDiscoveredPortAttributes_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetDiscoveredPortAttributes\n");
                            size = SM_GetDiscoveredPortAttributes_OUT_SIZE;
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetDiscoveredPortAttributes_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                            pOutBfr->HBAStatus = HBA_STATUS_OK;
                            CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName,
                                              MODEL,
                                              sizeof(pOutBfr->PortAttributes.OSDeviceName));
                            pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                            pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                        }
                        break;
                    case SM_GetPortAttributesByWWN:
                        {
                            PSM_GetPortAttributesByWWN_IN pInBfr = (PSM_GetPortAttributesByWWN_IN)Buffer;
                            PSM_GetPortAttributesByWWN_OUT pOutBfr = (PSM_GetPortAttributesByWWN_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPortAttributesByWWN\n");
                            size = SM_GetPortAttributesByWWN_OUT_SIZE;
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetPortAttributesByWWN_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                            pOutBfr->HBAStatus = HBA_STATUS_OK;
                            CopyUnicodeString(pOutBfr->PortAttributes.OSDeviceName,
                                              MODEL,
                                              sizeof(pOutBfr->PortAttributes.OSDeviceName));
                            pOutBfr->PortAttributes.PortState = HBA_PORTSTATE_ONLINE;
                            pOutBfr->PortAttributes.PortType = HBA_PORTTYPE_SASDEVICE;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION,
                                         " --> SM_GetPortAttributesByWWN Not Implemented Yet\n");
                        }
                        break;
                    case SM_GetProtocolStatistics:
                        {
                            PSM_GetProtocolStatistics_IN pInBfr = (PSM_GetProtocolStatistics_IN)Buffer;
                            PSM_GetProtocolStatistics_OUT pOutBfr = (PSM_GetProtocolStatistics_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetProtocolStatistics\n");
                            size = SM_GetProtocolStatistics_OUT_SIZE;
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetProtocolStatistics_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                        }
                        break;
                    case SM_GetPhyStatistics:
                        {
                            PSM_GetPhyStatistics_IN pInBfr = (PSM_GetPhyStatistics_IN)Buffer;
                            PSM_GetPhyStatistics_OUT pOutBfr = (PSM_GetPhyStatistics_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetPhyStatistics\n");
                            size = FIELD_OFFSET(SM_GetPhyStatistics_OUT, PhyCounter) + sizeof(LONGLONG);
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetPhyStatistics_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                        }
                        break;
                    case SM_GetFCPhyAttributes:
                        {
                            PSM_GetFCPhyAttributes_IN pInBfr = (PSM_GetFCPhyAttributes_IN)Buffer;
                            PSM_GetFCPhyAttributes_OUT pOutBfr = (PSM_GetFCPhyAttributes_OUT)Buffer;

                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetFCPhyAttributes\n");
                            size = SM_GetFCPhyAttributes_OUT_SIZE;

                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }

                            if (InBufferSize < SM_GetFCPhyAttributes_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                        }
                        break;
                    case SM_GetSASPhyAttributes:
                        {
                            PSM_GetSASPhyAttributes_IN pInBfr = (PSM_GetSASPhyAttributes_IN)Buffer;
                            PSM_GetSASPhyAttributes_OUT pOutBfr = (PSM_GetSASPhyAttributes_OUT)Buffer;
                            RhelDbgPrint(TRACE_LEVEL_INFORMATION, " --> SM_GetSASPhyAttributes\n");
                            size = SM_GetSASPhyAttributes_OUT_SIZE;
                            if (OutBufferSize < size)
                            {
                                status = SRB_STATUS_DATA_OVERRUN;
                                break;
                            }
                            if (InBufferSize < SM_GetSASPhyAttributes_IN_SIZE)
                            {
                                status = SRB_STATUS_ERROR;
                                break;
                            }
                        }
                        break;
                    case SM_RefreshInformation:
                        {
                        }
                        break;
                    default:
                        status = SRB_STATUS_INVALID_REQUEST;
                        RhelDbgPrint(TRACE_LEVEL_ERROR, " --> ERROR Unknown MethodId = %lu\n", MethodId);
                        break;
                }
            }
            break;
        default:
            status = SRB_STATUS_INVALID_REQUEST;
            RhelDbgPrint(TRACE_LEVEL_ERROR, " --> VioScsiExecuteWmiMethod Unsupported GuidIndex = %lu\n", GuidIndex);
            break;
    }
    ScsiPortWmiPostProcess(RequestContext, status, size);

    EXIT_FN();
    return SRB_STATUS_SUCCESS;
}

UCHAR
VioScsiQueryWmiRegInfo(IN PVOID Context, IN PSCSIWMI_REQUEST_CONTEXT RequestContext, OUT PWCHAR *MofResourceName)
{
    ENTER_FN();
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(RequestContext);

    *MofResourceName = VioScsiWmi_MofResourceName;
    return SRB_STATUS_SUCCESS;
}

VOID VioScsiReadExtendedData(IN PVOID Context, OUT PUCHAR Buffer)
{
    UCHAR numberOfBytes = sizeof(VioScsiExtendedInfo) - 1;
    PADAPTER_EXTENSION adaptExt;
    PVioScsiExtendedInfo extInfo;

    ENTER_FN();

    adaptExt = (PADAPTER_EXTENSION)Context;
    extInfo = (PVioScsiExtendedInfo)Buffer;

    RtlZeroMemory(Buffer, numberOfBytes);

    extInfo->QueueDepth = (ULONG)adaptExt->queue_depth;
    extInfo->QueuesCount = (UCHAR)adaptExt->num_queues;
    extInfo->Indirect = CHECKBIT(adaptExt->features, VIRTIO_RING_F_INDIRECT_DESC);
    extInfo->EventIndex = CHECKBIT(adaptExt->features, VIRTIO_RING_F_EVENT_IDX);
    extInfo->RingPacked = CHECKBIT(adaptExt->features, VIRTIO_F_RING_PACKED);
    extInfo->DpcRedirection = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_DPC_REDIRECTION);
    extInfo->ConcurrentChannels = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_CONCURRENT_CHANNELS);
    extInfo->InterruptMsgRanges = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_INTERRUPT_MESSAGE_RANGES);
    extInfo->CompletionDuringStartIo = CHECKFLAG(adaptExt->perfFlags, STOR_PERF_OPTIMIZE_FOR_COMPLETION_DURING_STARTIO);
    extInfo->PhysicalBreaks = adaptExt->max_physical_breaks;
    extInfo->ResponseTime = adaptExt->resp_time;
    EXIT_FN();
}
