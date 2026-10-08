# Debug Tools

This directory contains diagnostic tools for Windows guest systems running virtio-win drivers.

## Tool Selection Guide

- **CollectSystemInfo.ps1** - Comprehensive diagnostics bundle (1-5 minutes)
- **GetVirtioWinInfo.ps1** - Quick version check and reboot status (~5 seconds)
- **CollectSystemInfo-WinPE.ps1** - Offline diagnostics from WinPE/WinRE
- **GetVioScsiTelemetry.ps1** - vioscsi per-queue and per-target I/O, latency and error counters from a running system
- **vioscsi_telemetry.js** - WinDbg script showing the same vioscsi counters from a kernel crash dump, plus the per-adapter event ring
- **GetVioScsiDriverInfo.ps1** - Which vioscsi driver is installed and loaded (file hash, version, driver store, boot time), to confirm a new build is the one running

---

# CollectSystemInfo

## Overview

This PowerShell script is designed for comprehensive system diagnostics. It gathers a wide range of information, including system configuration, event logs, driver lists, SetupAPI logs, registry settings, update logs, services, uptime, processes, installed applications, installed KBs (knowledge base articles), network configuration, and optionally, memory dumps.

The collected data is organized into two subfolders within the time-stamped summary folder, one for log and the other for dump. and then compressed into two ZIP archives correspondingly for easy sharing and analysis.

## Usage

1. **Prerequisites:**
   - PowerShell (Windows 10/Windows Server 2016 or later)
   - Administrative privileges (for collecting event logs)
   - Ensure the script runs with an unrestricted execution policy (for Windows 10 and Windows Server 2016): 
     ```powershell   
     Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope Process -Force
     ```

2. **Running the Script:**
   - Open PowerShell as an administrator.
   - Navigate to the script's directory.
   - Execute the script:
      ```powershell
      .\CollectSystemInfo.ps1 -IncludeSensitiveData
      ```
      - `-IncludeSensitiveData`: Optional switch to include memory dumps in the collection (use with caution).
      - `-Help`: Provide basic usage of the script.

3. **Output:**
   - A folder named `SystemInfo_YYYY-MM-DD_HH-MM-SS` will be created in the script's directory.
   - This folder contains the collected data folders:
      - A foler named `Log_folder_YYYY-MM-DD_HH-MM-SS` will be created for log data.
      - A ZIP archive named `Log_folder_YYYY-MM-DD_HH-MM-SS.zip` will also be created correspondingly.
      - A foler named `Dump_folder_YYYY-MM-DD_HH-MM-SS` will be created for dump files if add param `-IncludeSensitiveData`.
      - A ZIP archive named `Dump_folder_YYYY-MM-DD_HH-MM-SS.zip` will also be created correspondingly.

## Data Collected

- `msinfo32.txt`: Detailed hardware and software configuration report.
- `system.evtx`, `security.evtx`, `application.evtx`: System, Security, and Application event logs.
- `drv_list.csv`: List of all installed drivers.
- `virtio_disk.txt`: Specific configuration details for Virtio-Win storage drivers.
- `WindowsUpdate.log`: Detailed logs of Windows Update activity.
- `Services.csv`: List of services and their status.
- `WindowsUptime.txt`: Duration since the last system boot.
- `RunningProcesses.csv`: Snapshot of active processes.
- `InstalledApplications.csv`: List of installed applications.
- `InstalledKBs.csv`: List of installed Windows updates.
- `NetworkInterfaces.txt` and `IPConfiguration.txt`: Network configuration details.
- `setupapi*.log`: Logs related to device and driver installations.
- `MEMORY.DMP` and `Minidump` folder: Full or mini memory dumps (if `-IncludeSensitiveData` is used).
- `Collecting_Status.txt`: Generated during data collection and deleted after completion. If the script is interrupted, this file indicates incomplete data collection.

---

# GetVirtioWinInfo

## Overview

A fast, lightweight diagnostic tool designed to quickly identify version inconsistencies in virtio-win installations. This tool was created specifically to help customers troubleshoot driver version mismatches and installation issues without the overhead of full system diagnostics.

## Information Gathered

### VirtIO-Win MSI Package
- MSI/installer version
- Product name
- Installation date

### QEMU Guest Agent
- Version number
- Service status (Running/Stopped)
- Installation path

### VirtIO Drivers (All Types)
- **NetKVM** - Network adapter driver
- **viostor** - SCSI storage controller driver
- **vioscsi** - SCSI storage driver  
- **viorng** - Random Number Generator driver
- **Balloon** - Memory balloon driver
- **vioserial** - Serial port driver
- **viofs** - Shared filesystem (virtiofs) driver
- **viosock** - Socket communication driver
- **fwcfg** - Firmware configuration device driver
- **pvpanic** - Panic notification device driver
- **viomem** - Memory balloon device driver
- **vioinput** - Input device driver (keyboard/mouse/tablet)
- **viogpu** - GPU/Display adapter driver

### System Reboot Status
Detects pending reboots from multiple sources:
- Component Based Servicing (CBS)
- Windows Update
- Pending File Rename Operations
- Computer Rename pending
- SCCM/ConfigMgr (if installed)

## Usage

### Basic Usage
```powershell
.\GetVirtioWinInfo.ps1
```
Displays all component versions and system status to console.

### Check Version Mismatches
```powershell
.\GetVirtioWinInfo.ps1 -CheckMismatches
```
Analyzes drivers against the MSI package version and highlights inconsistencies with `[MISMATCH]` markers. Particularly useful for:
- Partial driver updates
- Mixed installation sources (MSI vs manual installation)
- Troubleshooting "driver not working" issues

### Export Results
```powershell
.\GetVirtioWinInfo.ps1 -Export
```
Saves output to timestamped file: `VirtioWinInfo_YYYY-MM-DD_HH-MM-SS.txt`

### Custom Output File
```powershell
.\GetVirtioWinInfo.ps1 -OutputFile "C:\diagnostics\virtio-check.txt"
```

### Combined Usage
```powershell
.\GetVirtioWinInfo.ps1 -CheckMismatches -Export
```
Performs mismatch analysis and exports results to file.

### Help
```powershell
.\GetVirtioWinInfo.ps1 -Help
```

## Example Output

### Without Mismatch Detection
```
======================================================================
VirtIO-Win Component Information
Generated: 2026-07-16 14:41:33
======================================================================

VirtIO-Win MSI Package:
----------------------------------------------------------------------
  Version:      1.9.58
  Product:      Virtio-win-driver-installer
  Install Date: 20260716

QEMU Guest Agent:
----------------------------------------------------------------------
  Version: 110.2.2
  Status:  Running
  Path:    C:\Program Files\Qemu-ga\qemu-ga.exe

VirtIO Drivers:
----------------------------------------------------------------------
  Balloon (Memory)               1.9.58.0
  NetKVM (Network)               1.9.58.0
  viofs (Shared Filesystem)      1.9.58.0
  viorng (RNG)                   1.9.58.0
  vioscsi (Storage SCSI)         1.9.58.0
  vioserial (Serial)             1.9.58.0
  viosock (Socket)               Not Installed
  viostor (Storage SCSI)         1.9.58.0

System Reboot Status:
----------------------------------------------------------------------
  Status: No reboot required

======================================================================
```

### With Mismatch Detection (`-CheckMismatches`)
```
VirtIO Drivers:
----------------------------------------------------------------------
  Balloon (Memory)               10.0.17763.1007 [MISMATCH]
  NetKVM (Network)               10.0.17763.1 [MISMATCH]
  viofs (Shared Filesystem)      10.0.17763.1007 [MISMATCH]
  viorng (RNG)                   10.0.17763.1007 [MISMATCH]
  vioscsi (Storage SCSI)         10.0.17763.1192 [MISMATCH]
  vioserial (Serial)             10.0.17763.1007 [MISMATCH]
  viosock (Socket)               10.0.17763.1007 [MISMATCH]
  viostor (Storage SCSI)         10.0.17763.1192 [MISMATCH]

Version Mismatch Analysis:
----------------------------------------------------------------------
  WARNING: 8 driver(s) do not match MSI package version

  - Balloon (Memory) : Expected 1.9.58, Found 10.0.17763.1007
  - NetKVM (Network) : Expected 1.9.58, Found 10.0.17763.1
  - vioscsi (Storage SCSI) : Expected 1.9.58, Found 10.0.17763.1192
  ...

  Recommendation: Reinstall virtio-win MSI package or update drivers
```

## Troubleshooting Common Issues

### No MSI Detected
If the MSI shows "Not Installed", drivers were likely installed manually via Device Manager or Windows Update rather than the virtio-win MSI package. The `-CheckMismatches` feature will indicate this scenario.

### Service Exists - Driver/Executable Missing  
Indicates corrupted installation where registry entries exist but files are missing. Reinstall virtio-win package to resolve.

### Version Mismatches
Common causes:
- Partial MSI upgrade (some drivers updated, others weren't)
- Manual driver updates via Device Manager
- Windows Update overriding MSI-installed drivers
- Mixed installation from multiple virtio-win versions

**Solution:** Reinstall the complete virtio-win MSI package to ensure consistency.

## Prerequisites

- Windows 10 / Windows Server 2016 or later
- PowerShell 5.1 or later
- May require Administrator privileges for complete information

## Related Tools

- **CollectSystemInfo.ps1** - Full system diagnostics including virtio-win information plus comprehensive system data
- **CollectSystemInfo-WinPE.ps1** - Offline diagnostics when Windows won't boot

---

# GetVioScsiTelemetry

## Overview

The vioscsi driver keeps cumulative per-queue telemetry: read/write/flush/unmap counts
and bytes, a log2 latency histogram with min/max/average, a histogram of SRB completion
statuses, the in-flight high-water mark, the number of times a virtqueue was full, and
adapter-wide reset counts and durations. This script reads it from every vioscsi adapter
with an `IOCTL_SCSI_MINIPORT` request and prints a summary. It needs a vioscsi driver
with telemetry version 5 or later, and must be run as Administrator.

For chasing storage timeouts there are per-queue stall indicators: the number of
requests in flight now, the age of the oldest one, the time since the last completion, the
time the maximum latency was seen, and counts of requests slower than 1s, 5s and 30s, plus
the time since the last reset. The latency figures only cover requests that completed, so a
request that never returns shows up only as a large oldest-in-flight age (the script prints
a warning for 5s or more). Ages are relative to the moment the driver took the snapshot.

A target's requests are spread over all queues, so with several targets on one adapter the
queue tables cannot say which disk has the problem. A per-target section lists each active
SCSI target (one that has seen any I/O, refusal or reset; `-All` also lists entries without
activity) with the same stall indicators and latency figures, plus counts of completions
that ended BUSY, ABORTED/BUS_RESET, NO_DEVICE, other errors or INVALID_TARGET_ID, and
device and LUN resets addressed to that target. A target with requests in flight whose
oldest request has been outstanding for 5 seconds or more is marked `STALLED`. Requests
the driver refuses for a target ID the device doesn't have cannot be attributed to a
target and are reported once per adapter. The oldest in-flight request per target is
computed by the driver when it answers this query (it would need a lock shared by all
queues to keep it up to date on the I/O path), so it is exact in this live view.

Counters accumulate from when the adapter was started and cannot be cleared, so compare
two snapshots to see what changed over an interval. Latency percentiles are upper bounds of
the histogram bucket they fall in (buckets double in width).

From telemetry version 6 the summary also has descriptor ownership counters. A reset (and a
unit's surprise removal) completes the requests still on the virtqueue back to Storport
without waiting for the device, which keeps their descriptors and later writes their
responses. The driver counts those early completions, the times `VioScsiBuildIo` was handed
an SRB extension for a new request while the device still referenced it (it zeroes the
extension, including the indirect descriptor table inside it), and the requests the device
returned that were on no request list: early-completed ones, ones returned into an extension
already serving another request, and unexplained ones. It also counts requests it refused
because their scatter/gather list had a zero-length element or more elements than the
adapter allows, which would have made the device stop servicing the adapter. The individual
occurrences are only in a dump; see [the event ring](#event-ring).

## Usage

```powershell
.\GetVioScsiTelemetry.ps1                  # summary of every vioscsi adapter
.\GetVioScsiTelemetry.ps1 -All             # include queues with no completed requests and idle targets
.\GetVioScsiTelemetry.ps1 -Port 2          # only \\.\Scsi2:
.\GetVioScsiTelemetry.ps1 -PassThru        # objects (Queues, Targets, raw histograms) for further processing
.\GetVioScsiTelemetry.ps1 -SaveRaw C:\temp # also save each raw snapshot as a .bin file
.\GetVioScsiTelemetry.ps1 -InputFile C:\temp\vioscsi-telemetry-scsi2-20261005-101500.bin
```

Stalled targets can also be picked out of the objects:
`(.\GetVioScsiTelemetry.ps1 -PassThru)[0].Targets | Where-Object Stalled`.

`-InputFile` parses a saved snapshot without talking to the driver, so a `.bin`
collected from a guest can be examined elsewhere (Windows PowerShell 5.1 or PowerShell 7).

---

# vioscsi_telemetry.js

## Overview

WinDbg JavaScript extension that prints the vioscsi telemetry described under
[GetVioScsiTelemetry](#getvioscsitelemetry) from a crash dump or a live kernel debugging
session, in the same format as the PowerShell script. vioscsi lists its started adapters
(up to 16) in the global `vioscsi!VioScsiTelemetryDirectory`.

The telemetry lives in the adapter's device extension in nonpaged pool, so it is only
present in **kernel, automatic or complete memory dumps**. Small memory dumps (minidumps)
don't contain it.

The stall indicators are included. Their ages are measured against the interrupt
time at the moment of the dump (read from `KUSER_SHARED_DATA`), so "oldest in flight 60s"
means a request had been outstanding that long when the system crashed. If that page isn't in
the dump, the script falls back to the time of the driver's last IOCTL snapshot and says that
the ages may be understated.

The per-target table is read from the adapter's full 256-entry table; only active targets are
shown unless the second argument is 1. One difference from the live script: the driver works
out each target's oldest in-flight request when it answers an IOCTL snapshot, so in a dump that
value is shown as `OldestAtScan`, the request's age at the last scan (`never scanned` if no
snapshot was ever taken), not against the dump time. A target is flagged `STALLED` when it has requests in flight and its oldest request was already
5 seconds old at the last scan. Without scan data for it (never scanned, or its request arrived
after the scan) the script can only go by completions, so a target in flight that has not
completed anything for 5 seconds or more, or ever, is reported as a `possible stall` and the
warning says which evidence was used. A long-idle target whose oldest request was young at the
scan is not flagged, as that request may simply be new.

Symbols are optional:

- **With matching vioscsi symbols** (a private PDB from the same build as the `vioscsi.sys` in
  the dump), the script reads the directory by name and each adapter's `Telemetry` through the
  PDB types, and `dx` results include the typed `Telemetry` object for drill-down.
- **Without symbols**, it finds `vioscsi.sys` in the loaded module list (always present in a
  kernel dump), scans the image's writable sections for the directory's magic (`VSTD`), and
  parses each `STOR_TELEMETRY` from the raw layout its own header describes. The summary is the
  same; only the typed `Telemetry` object is missing. This needs a driver build that has the
  directory.
- `!vioscsi_telemetry_at` and `!vioscsi_telemetry_scan` never use symbols or the directory, so
  they also work on a STOR_TELEMETRY found some other way, e.g. with `s -d <range> 53505331`.

## Usage

```
.scriptload C:\path\to\vioscsi_telemetry.js
!vioscsi_telemetry                       # every registered vioscsi adapter
!vioscsi_telemetry <adapter extension>   # one adapter, by its miniport device extension address
!vioscsi_telemetry 0 1                   # all adapters, including idle queues and targets
!vioscsi_telemetry_at <address> [1]      # parse the STOR_TELEMETRY at a known address
!vioscsi_telemetry_scan <start> <len> [1]  # scan a range for STOR_TELEMETRY blocks
dx @$vioscsiTelemetry()                  # the same data as debugger data model objects
dx -r3 @$vioscsiTelemetry()[0].Queues    # per-queue values including raw histograms
dx @$vioscsiTelemetry()[0].Targets       # per-target values (active targets)
```

`dx @$vioscsiTelemetryAt(<address>)` and `dx @$vioscsiTelemetryScan(<start>, <len>)` return
the corresponding objects. A scan uses the debugger's native `s -d` search and falls back to
reading the range page by page (skipping pages missing from the dump) if that isn't available.
Either way it is slow over very large ranges, so keep it to a region you have reason to suspect.

With symbols, the raw structure is also available directly, e.g.
`dx -r2 ((vioscsi!_ADAPTER_EXTENSION *)<address>)->Telemetry`.

## Event ring

Each adapter also keeps its last 8192 events in `EventRing` in the adapter extension
(`VIOSCSI_EVENT_RING` in `vioscsi/vioscsi.h`, which documents every event code): each
request as it goes onto a virtqueue (`Publish`) and as the device returns it
(`DeviceComplete`), requests completed without the device (`EarlyComplete`), cookies the
device returned that no request list held (`OrphanReturn`), SRB extensions reused while the
device still referenced them (`ExtReused`), reset SRBs, TMFs sent, coalesced and reaped,
`StorPortPause`/`Resume`, and refused scatter/gather lists. Every request event carries the
physical address of the request's indirect descriptor table (`TablePa`): the address QEMU
reports for the head descriptor of a chain it rejects, e.g. for "virtio: zero sized buffers
are not allowed". Requests completed early that the device hasn't returned yet are listed
in `Zombies` until it does. Neither is recorded by the crash dump instance of the driver.

```
!vioscsi_events                          # last 64 events of every adapter, and its zombies
!vioscsi_events 0 0 1000                 # last 1000
!vioscsi_events 0 <table PA>             # every event of the request(s) that owned that table
!vioscsi_events <adapter extension>      # one adapter
dx @$vioscsiEvents()                     # decoded events and zombies as objects
```

Ages are measured against the dump's interrupt time. To find out what happened to the
request QEMU choked on, take the table address from QEMU's report and run
`!vioscsi_events 0 <table PA>`. The events are matched by `TablePa` and by SRB extension,
since the table lives in the extension. Read the result like this:

- `ExtReused` for that table before the break: the device still referenced the extension
  when `VioScsiBuildIo` zeroed it for another request. The `Publish`, `EarlyComplete` and
  `ExtReused` sequence shows the request being handed back early and its memory reused.
- A `Publish` and nothing after it, with no zero length found by `ZeroLengthDesc`: the
  driver published a valid table and did not touch it again, so the zero came from
  elsewhere.
- `ZeroLengthDesc`: the zero was in the table as the driver built it.
- `SgZeroLength`/`SgTooManyElements`: Storport handed the driver a list that would have
  broken the virtqueue; the request was refused instead.
- `OrphanReturn` flagged `NOT A REQUEST COMPLETED EARLY`: the device returned a cookie the
  driver never handed back early, so the request lists and the virtqueue disagree.

The script finds the ring through the telemetry directory (version 2 adds the ring and
zombie table offsets), with or without symbols. With symbols the structures can also be
read directly:

```
dx vioscsi!VioScsiTelemetryDirectory.Adapters
dx -g ((vioscsi!_ADAPTER_EXTENSION *)<adapter>)->EventRing.Entries.Where(e => e.TablePa == <table PA>)
dx -g ((vioscsi!_ADAPTER_EXTENSION *)<adapter>)->Zombies.Where(z => z.Key != 0)
dt vioscsi!_SRB_EXTENSION <SrbExt> OwnedMagic OwnedTime TablePa id QueueIndex
```

Entries are in slot order there; `Sequence` gives the order (slot `(Sequence - 1) % 8192`).
An extension whose `OwnedMagic` is `0x444E574F` was put on a virtqueue at `OwnedTime` and the
device had not returned it.

---

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.
