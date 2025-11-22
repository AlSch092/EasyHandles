/*++

Module Name:

	driver.c

Abstract:

	This file contains the driver entry points and callbacks.

Environment:

	Kernel-mode Driver Framework

Author:

	AlSch092 @ Github

Usage:

  Pentesting, red-teaming, AV/AC bypassing, reversing windows system processes

--*/
#include <ntifs.h>
#include <ntddk.h>


PDRIVER_OBJECT g_DriverObject = NULL;

#define IOCTL_OPEN_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLOSE_HANDLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OPEN_PROC_REQUEST {
	ULONG Pid;
	ACCESS_MASK Access;
} OPEN_PROC_REQUEST, * POPEN_PROC_REQUEST;

typedef struct _OPEN_PROC_RESPONSE {
	HANDLE HandleValue;     // returned handle
} OPEN_PROC_RESPONSE, * POPEN_PROC_RESPONSE;

typedef struct _CLOSE_HANDLE_REQUEST {
	ULONG Pid;
	HANDLE HandleValue;
} CLOSE_HANDLE_REQUEST, * PCLOSE_HANDLE_REQUEST;

NTSTATUS DeviceControl(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inLen = stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (code)
	{
	case IOCTL_OPEN_PROCESS:
	{
		if (inLen < sizeof(OPEN_PROC_REQUEST) || outLen < sizeof(OPEN_PROC_RESPONSE))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		POPEN_PROC_REQUEST req = (POPEN_PROC_REQUEST)buffer;
		POPEN_PROC_RESPONSE resp = (POPEN_PROC_RESPONSE)buffer;

		PEPROCESS targetProc = NULL;
		status = PsLookupProcessByProcessId((HANDLE)req->Pid, &targetProc); 		//Look up the target process object
		if (!NT_SUCCESS(status))
			break;

		PEPROCESS caller = IoGetRequestorProcess(Irp);		//Attach to the caller process
		KAPC_STATE apc;
		KeStackAttachProcess(caller, &apc);

		HANDLE hUser = NULL;
		status = ObOpenObjectByPointer(  		//open the handle using kernel privileges
			targetProc,
			0,
			NULL,
			req->Access,
			*PsProcessType,
			KernelMode,
			&hUser
		);

		KeUnstackDetachProcess(&apc);
		ObDereferenceObject(targetProc);

		DbgPrint("ObOpenObjectByPointer returned: %d, handle: %llx\n", status, (UINT64)hUser);

		if (!NT_SUCCESS(status))
			break;
    
		resp->HandleValue = hUser; 		//return handle directly to usermode
		Irp->IoStatus.Information = sizeof(OPEN_PROC_RESPONSE);

		break;
	}

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS CreateCloseRequest(PDEVICE_OBJECT DeviceObj, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObj);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}


VOID UnloadDriver(IN PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	DbgPrint("Unloading driver...\n");

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\HandleDrv");
	if (NT_SUCCESS(IoDeleteSymbolicLink(&symLink)))
	{
		DbgPrint("Symbolic link deleted.\n");
	}
	else
	{
		DbgPrint("Symbolic link was not created, no deletion needed.\n");
	}

	PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
	IoDeleteDevice(deviceObject);

	DbgPrint("Driver unloaded successfully.\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	g_DriverObject = DriverObject;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseRequest;
	DriverObject->DriverUnload = UnloadDriver;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\HandleDrv");
	UNICODE_STRING symName = RTL_CONSTANT_STRING(L"\\DosDevices\\HandleDrv");

	PDEVICE_OBJECT devObj = NULL;
	NTSTATUS status = IoCreateDevice(
		DriverObject,
		0,
		&devName,
		FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN,
		FALSE,
		&devObj
	);
	if (!NT_SUCCESS(status))
		return status;

	devObj->Flags |= DO_BUFFERED_IO;
	devObj->Flags &= ~DO_DEVICE_INITIALIZING;

	IoCreateSymbolicLink(&symName, &devName);

	return STATUS_SUCCESS;
}
