// SPDX-License-Identifier: MIT

#include "apic.h"
#include "cpu.h"
#include "event.h"
#include "kalloc.h"
#include "lock.h"
#include "x86.h"
#include <acpi.h>

#define UNIMPLEMENTED PANIC("Function %s is not implemented", __FUNCTION__);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

ACPI_PHYSICAL_ADDRESS AcpiOsGetRootPointer(void) {
    ACPI_PHYSICAL_ADDRESS addr;
    if (AcpiFindRootPointer(&addr) == AE_OK)
        return addr;
    return (ACPI_PHYSICAL_ADDRESS)NULL;
}

ACPI_STATUS AcpiOsPredefinedOverride(const ACPI_PREDEFINED_NAMES *PredefinedObject, ACPI_STRING *NewValue) {
    *NewValue = NULL;
    return AE_OK;
}

ACPI_STATUS AcpiOsTableOverride(ACPI_TABLE_HEADER *ExistingTable, ACPI_TABLE_HEADER **NewTable) {
    *NewTable = NULL;
    return AE_OK;
}

ACPI_STATUS AcpiOsPhysicalTableOverride(ACPI_TABLE_HEADER *ExistingTable, ACPI_PHYSICAL_ADDRESS *NewAddress, UINT32 *NewTableLength) {
    *NewAddress = (ACPI_PHYSICAL_ADDRESS)NULL;
    return AE_OK;
}

void *AcpiOsMapMemory(ACPI_PHYSICAL_ADDRESS Where, ACPI_SIZE Length) { return (void *)Where; }

void AcpiOsUnmapMemory(void *LogicalAddress, ACPI_SIZE Length) {}

void AcpiOsPrintf(const char *fmt, ...) {
    va_list Args;

    va_start(Args, fmt);
    vprintf(fmt, Args);
    va_end(Args);
}

void AcpiOsVprintf(const char *Format, va_list Args) { (void)vprintf(Format, Args); }

ACPI_STATUS AcpiOsInitialize(void) { return AE_OK; }

ACPI_STATUS AcpiOsTerminate(void) { return AE_OK; }

ACPI_THREAD_ID AcpiOsGetThreadId(void) { return current_cpu_id; }

void *AcpiOsAllocate(ACPI_SIZE Size) { return kalloc_size(Size); }

ACPI_STATUS AcpiOsWriteMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 Value, UINT32 Width) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsReadMemory(ACPI_PHYSICAL_ADDRESS Address, UINT64 *Value, UINT32 Width) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsExecute(ACPI_EXECUTE_TYPE Type, ACPI_OSD_EXEC_CALLBACK Function, void *Context) {
    if (!Function) {
        return AE_BAD_PARAMETER;
    }

    switch (Type) {
    case OSL_GLOBAL_LOCK_HANDLER:
    case OSL_NOTIFY_HANDLER:
    case OSL_GPE_HANDLER:
    case OSL_DEBUGGER_MAIN_THREAD:
    case OSL_DEBUGGER_EXEC_THREAD:
    case OSL_EC_POLL_HANDLER:
    case OSL_EC_BURST_HANDLER:
        break;
    default:
        return AE_BAD_PARAMETER;
    }

    struct event e = {.handler = Function, .data = Context};
    deferredevent_queue(e);

    return AE_OK;
}

ACPI_STATUS AcpiOsCreateMutex(ACPI_MUTEX *OutHandle) {
#if IS_ENABLED(CONFIG_SMP)
    *OutHandle = kalloc(lock_t);
#else
    *OutHandle = NULL;
#endif
    return AE_OK;
}

ACPI_STATUS AcpiOsAcquireMutex(ACPI_MUTEX Handle, UINT16 Timeout) {
    lock(Handle);
    return AE_OK;
}

void AcpiOsReleaseMutex(ACPI_MUTEX Handle) { unlock(Handle); }

void AcpiOsDeleteMutex(ACPI_MUTEX Handle) { kfree(Handle); }

ACPI_STATUS AcpiOsCreateLock(ACPI_SPINLOCK *OutHandle) {
#if IS_ENABLED(CONFIG_SMP)
    *OutHandle = kalloc(lock_t);
#else
    *OutHandle = NULL;
#endif

    return AE_OK;
}

void AcpiOsDeleteLock(ACPI_SPINLOCK Handle) { kfree(Handle); }

ACPI_CPU_FLAGS AcpiOsAcquireLock(ACPI_SPINLOCK Handle) {
    lock(Handle);
    return 0;
}

void AcpiOsReleaseLock(ACPI_SPINLOCK Handle, ACPI_CPU_FLAGS Flags) { unlock(Handle); }

ACPI_STATUS AcpiOsReadPort(ACPI_IO_ADDRESS Address, UINT32 *Value, UINT32 Width) {
    if (Address > 0xffff) {
        return AE_BAD_PARAMETER;
    }

    switch (Width) {
    case 8:
        *Value = inb((uint16_t)Address);
        break;
    case 16:
        *Value = inw((uint16_t)Address);
        break;
    case 32:
        *Value = ind((uint16_t)Address);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

ACPI_STATUS AcpiOsWritePort(ACPI_IO_ADDRESS Address, UINT32 Value, UINT32 Width) {
    if (Address > 0xffff) {
        return AE_BAD_PARAMETER;
    }

    switch (Width) {
    case 8:
        outb((uint16_t)Address, (uint8_t)Value);
        break;
    case 16:
        outw((uint16_t)Address, (uint16_t)Value);
        break;
    case 32:
        outd((uint16_t)Address, (uint32_t)Value);
        break;
    default:
        return AE_BAD_PARAMETER;
    }
    return AE_OK;
}

void *AcpiOsAcquireObject(ACPI_CACHE_T *Cache) {
    size_t size = *Cache;
    void *ptr = kalloc_size(size);
    memset(ptr, 0, size);
    return ptr;
}

ACPI_STATUS AcpiOsCreateCache(char *CacheName, UINT16 ObjectSize, UINT16 MaxDepth, ACPI_CACHE_T **ReturnCache) {
    *ReturnCache = kalloc(size_t);
    **ReturnCache = ObjectSize;
    return AE_OK;
}

ACPI_STATUS AcpiOsReleaseObject(ACPI_CACHE_T *Cache, void *Object) {
    kfree_size(Object, *Cache);
    return AE_OK;
}

ACPI_STATUS AcpiOsPurgeCache(ACPI_CACHE_T *Cache) { return AE_OK; }

ACPI_STATUS AcpiOsDeleteCache(ACPI_CACHE_T *Cache) {
    kfree(Cache);
    return AE_OK;
}

ACPI_STATUS AcpiOsCreateSemaphore(UINT32 MaxUnits, UINT32 InitialUnits, ACPI_HANDLE *OutHandle) { return AE_OK; }

ACPI_STATUS AcpiOsDeleteSemaphore(ACPI_HANDLE Handle) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsSignalSemaphore(ACPI_HANDLE Handle, UINT32 Units) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsWaitSemaphore(ACPI_HANDLE Handle, UINT32 Units, UINT16 Timeout) { UNIMPLEMENTED; }

void AcpiOsSleep(UINT64 milliseconds) { UNIMPLEMENTED; }

void AcpiOsStall(UINT32 microseconds) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsSignal(UINT32 Function, void *Info) { UNIMPLEMENTED; }

UINT64 AcpiOsGetTimer(void) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsWritePciConfiguration(ACPI_PCI_ID *PciId, UINT32 PciRegister, UINT64 Value64, UINT32 Width) { UNIMPLEMENTED; }

ACPI_STATUS AcpiOsReadPciConfiguration(ACPI_PCI_ID *PciId, UINT32 PciRegister, UINT64 *Value64, UINT32 Width) { UNIMPLEMENTED; }

UINT32 AcpiOsInstallInterruptHandler(UINT32 InterruptNumber, ACPI_OSD_HANDLER ServiceRoutine, void *Context) {
    printf("Please implement me! AcpiOsInstallInterruptHandler Num %d Routine %p Context %p\n", InterruptNumber, ServiceRoutine, Context);
    return AE_OK;
}

ACPI_STATUS AcpiOsRemoveInterruptHandler(UINT32 InterruptNumber, ACPI_OSD_HANDLER ServiceRoutine) { UNIMPLEMENTED; }

#pragma GCC diagnostic pop
