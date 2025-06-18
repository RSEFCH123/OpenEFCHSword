#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
#include <wchar.h>
#include <ntimage.h>
#include <minwindef.h>
#include "h/IrpFile.h"
//#include "h\Func_def.h"
//#include "h\NTKD2.h"
// "abc/DriverFileManager.h"

PDRIVER_OBJECT driver;
#define IOCTL_KILLPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwTerminateProcess
#define IOCTL_SUSPENDPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS) //PsSuspendProcess
#define IOCTL_RESUMEPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS) //PsResumeProcess
#define IOCTL_HIDEPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS) //RemoveEntryList
#define IOCTL_UNHIDEPROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS) //InsertHeadList
#define IOCTL_ZWDELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwDeleteFile
#define IOCTL_OCCUPYFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwCreateFileռ���ļ�
#define IOCTL_WRITEDISK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_BUFFERED, FILE_ANY_ACCESS) //ZwWriteFile
#define IOCTL_FORCEDELETEFILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_BUFFERED, FILE_ANY_ACCESS) //IrpDeleteFile

#define DEVICE_NAME     L"\\Device\\OpenEFCHKernelDriver"   
#define DOS_DEVICE_NAME L"\\DosDevices\\OpenEFCHKernelDriver" 

VOID DriverUnload(PDRIVER_OBJECT driver) {
    // DriverUnload
    DbgPrint("Driver Unloading\n");
	UNICODE_STRING symLinkName;
	RtlInitUnicodeString(&symLinkName, DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	IoDeleteDevice(driver->DeviceObject);
	DbgPrint("Driver Unload\n");
}
ULONG g_ImageNameOffset = 0x450;
#if (NTDDI_VERSION >= NTDDI_WIN10_RS1)
#define PSGETNEXTPROCESS(proc) PsGetNextProcess(proc)
#else
#define PSGETNEXTPROCESS(proc) PsGetNextProcess(proc, 0)
#endif
#define THREAD_QUERY_INFORMATION				(0x0040)  
EXTERN_C_START
NTSTATUS ZwAdjustPrivilegesToken(IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength);
NTSTATUS
ZwSetInformationProcess(
	IN HANDLE                    ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID                     ProcessInformation,
	IN ULONG                     ProcessInformationLength);
NTSTATUS NTAPI ZwQuerySystemInformation(
	DWORD32 systemInformationClass,
	PVOID systemInformation,
	ULONG systemInformationLength,
	PULONG returnLength);
NTSTATUS ZwOpenThread(
	_Out_  PHANDLE ThreadHandle,
	_In_   ACCESS_MASK DesiredAccess,
	_In_   POBJECT_ATTRIBUTES ObjectAttributes,
	_In_   PCLIENT_ID ClientId
);
NTKERNELAPI PVOID NTAPI ObGetObjectType(IN PVOID pObject);
NTSTATUS NTAPI ObReferenceObjectByName(IN PUNICODE_STRING ObjectName, IN ULONG64 Attributes, IN PACCESS_STATE PassedAccessState OPTIONAL, IN ACCESS_MASK DesiredAccess OPTIONAL, IN POBJECT_TYPE ObjectType, IN KPROCESSOR_MODE AccessMode, IN OUT PVOID ParseContext OPTIONAL, OUT PVOID* Object);
NTSTATUS PsSuspendProcess(PEPROCESS Process);
NTSTATUS PsResumeProcess(PEPROCESS Process);

/*/NTSTATUS SeCreateAccessState(
	PACCESS_STATE AccessState,
	PVOID AuxData,
	ACCESS_MASK DesiredAccess,
	PGENERIC_MAPPING GenericMapping
);
NTSTATUS ObCreateObject(
	__in KPROCESSOR_MODE ProbeMode,
	__in POBJECT_TYPE ObjectType,
	__in POBJECT_ATTRIBUTES ObjectAttributes,
	__in KPROCESSOR_MODE OwnershipMode,
	__inout_opt PVOID ParseContext,
	__in ULONG ObjectBodySize,
	__in ULONG PagedPoolCharge,
	__in ULONG NonPagedPoolCharge,
	__out PVOID* Object
);
*/
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(
	IN PVOID                ModuleAddress);
VOID IoUnregisterPriorityCallback(_In_ PDRIVER_OBJECT DriverObject);
VOID PoUnregisterCoalescingCallback(
	_In_  PVOID Handle);
NTSTATUS PsSetCreateProcessNotifyRoutineEx2(
	PSCREATEPROCESSNOTIFYTYPE NotifyType,
	PVOID                     NotifyInformation,
	BOOLEAN                   Remove
);
PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
NTKERNELAPI VOID NTAPI HalReturnToFirmware(
	LONG lReturnType
);

VOID
_sgdt(
	_Out_ PVOID Descriptor
);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTKERNELAPI PVOID NTAPI PsGetThreadTeb(PETHREAD pEthread);
NTKERNELAPI NTSTATUS
PsReferenceProcessFilePointer(
	IN PEPROCESS Process,
	OUT PVOID* pFilePointer
);
NTSYSAPI
UCHAR*
PsGetProcessImageFileName(
	PEPROCESS Process
);
EXTERN_C_END

typedef unsigned long ULONG;
typedef unsigned short wchar_t;
typedef unsigned long DWORD;
typedef int                 BOOL;
#define RANDOM_SEED_INIT 0x3AF84E05
static ULONG RandomSeed = RANDOM_SEED_INIT;

BOOLEAN ZwKillProcess_Handle(HANDLE ProcHandle)
{
	NTSTATUS kpstatus = ZwTerminateProcess(ProcHandle, 0);
	if (NT_SUCCESS(kpstatus))
	{
		return TRUE;
	}
	return FALSE;
}
HANDLE ZwGetProcessHandlePAA(ULONG PID)
{
	OBJECT_ATTRIBUTES obj = { 0 };
	InitializeObjectAttributes(&obj, NULL, 0, NULL, NULL);
	CLIENT_ID clentid = { 0 };
	clentid.UniqueProcess = (HANDLE)PID;
	HANDLE ProcHandle;
	NTSTATUS zopstatus = ZwOpenProcess(&ProcHandle, PROCESS_ALL_ACCESS, &obj, &clentid);
	if (NT_SUCCESS(zopstatus))
	{
		return ProcHandle;
	}
	return 0;
}
BOOLEAN ZwKillProcess(ULONG PID)
{
	HANDLE hProcess = ZwGetProcessHandlePAA(PID);
	if (hProcess == 0)
	{
		return FALSE;
	}
	BOOLEAN kpstatus = ZwKillProcess_Handle(hProcess);
	if (kpstatus)
	{
		ZwClose(hProcess);
		return TRUE;
	}
	ZwClose(hProcess);
	return FALSE;
}
NTSTATUS GetPEPROCESS(
	_In_ HANDLE PID,
	_Out_ PEPROCESS* Process
) {
	NTSTATUS status = PsLookupProcessByProcessId(PID, Process);
	return status;
}

NTSTATUS SuspendProcess(ULONG PID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS PEProc = NULL;
	status = GetPEPROCESS((HANDLE)PID, &PEProc);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = PsSuspendProcess(PEProc);
	return status;
}

NTSTATUS ResumeProcess(ULONG PID)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PEPROCESS PEProc = NULL;
	status = GetPEPROCESS((HANDLE)PID, &PEProc);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	status = PsResumeProcess(PEProc);
	return status;
}

BOOLEAN HideProcesss(ULONG PID)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &process);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	LIST_ENTRY* entry = (LIST_ENTRY*)((LONG_PTR)process + 0x448);
	BOOLEAN statusbool = RemoveEntryList(entry);
	ObfDereferenceObject(process);
	return statusbool;
}

BOOLEAN UnHideProcess(ULONG PID)
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &process);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	// ��ȡ���̵�ActiveProcessLinks��ַ
	LIST_ENTRY* targetEntry = (LIST_ENTRY*)((ULONG_PTR)process + 0x448);

	// ��ȡϵͳ���̵�����ͷ
	PEPROCESS systemProcess;
	status = PsLookupProcessByProcessId((HANDLE)4, &systemProcess);
	if (!NT_SUCCESS(status)) {
		ObfDereferenceObject(process);
		return FALSE;
	}
	LIST_ENTRY* listHead = (LIST_ENTRY*)((ULONG_PTR)systemProcess + 0x448);

	// ���ڵ����²�������ͷ��
	InsertHeadList(listHead, targetEntry);

	ObfDereferenceObject(systemProcess);
	ObfDereferenceObject(process);
	return TRUE;
}

LIST_ENTRY* GetHead()
{
	PEPROCESS process;
	NTSTATUS status = PsLookupProcessByProcessId((HANDLE)4, &process);
	if (!NT_SUCCESS(status))
	{
		return nullptr;
	}
	LIST_ENTRY* entry = (LIST_ENTRY*)((LONG_PTR)process + 0x448);
	ObfDereferenceObject(process);
	return entry->Blink;
}
//Thread




//File



BOOLEAN ZwForceDeleteFile(UNICODE_STRING pwzFileName)
{
	PEPROCESS pCurEprocess = NULL;
	KAPC_STATE kapc = { 0 };
	OBJECT_ATTRIBUTES fileOb;
	HANDLE hFile = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK iosta;
	PDEVICE_OBJECT DeviceObject = NULL;
	PVOID pHandleFileObject = NULL;


	// �ж��жϵȼ�������0
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return FALSE;
	}
	if (pwzFileName.Buffer == NULL || pwzFileName.Length <= 0)
	{
		return FALSE;
	}

	__try
	{
		// ��ȡ��ǰ���̵�EProcess
		pCurEprocess = IoGetCurrentProcess();

		// ���ӽ���
		KeStackAttachProcess(pCurEprocess, &kapc);

		// ��ʼ���ṹ
		InitializeObjectAttributes(&fileOb, &pwzFileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		// �ļ�ϵͳɸѡ���������� ����ָ���豸���������ɸѡ�����ļ�ϵͳ���ʹ�������
		status = IoCreateFileSpecifyDeviceObjectHint(&hFile,
			SYNCHRONIZE | FILE_WRITE_ATTRIBUTES | FILE_READ_ATTRIBUTES | FILE_READ_DATA,
			&fileOb,
			&iosta,
			NULL,
			0,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
			0,
			0,
			CreateFileTypeNone,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK,
			DeviceObject);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		// �ڶ��������ṩ������֤����������������Ȩ�ޣ��򷵻�ָ���������ĵ���Ӧָ�롣
		status = ObReferenceObjectByHandle(hFile, 0, 0, 0, &pHandleFileObject, 0);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}

		// ����ڶ�������Ϊ0
		((PFILE_OBJECT)(pHandleFileObject))->SectionObjectPointer->ImageSectionObject = 0;

		// ɾ��Ȩ�޴�
		((PFILE_OBJECT)(pHandleFileObject))->DeleteAccess = 1;

		// ����ɾ���ļ�API
		status = ZwDeleteFile(&fileOb);
		if (!NT_SUCCESS(status))
		{
			return FALSE;
		}
	}

	_finally
	{
		if (pHandleFileObject != NULL)
		{
			ObDereferenceObject(pHandleFileObject);
			pHandleFileObject = NULL;
		}
		KeUnstackDetachProcess(&kapc);

		if (hFile != NULL || hFile != (PVOID)-1)
		{
			ZwClose(hFile);
			hFile = (PVOID)-1;
		}
	}
	return TRUE;
}

NTSTATUS WriteToDisk(ULONG StartSector,ULONG SectorCount,PVOID DataBuffer) {
	UNICODE_STRING diskPath;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	HANDLE hDisk = NULL;
	LARGE_INTEGER offset;
	NTSTATUS status;

	// ��������̣�ʾ��ʹ�õ�һ��������̣�
	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");
	InitializeObjectAttributes(&objAttr, &diskPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	status = ZwCreateFile(
		&hDisk,
		GENERIC_WRITE | SYNCHRONIZE,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("�򿪴���ʧ��: 0x%X\n", status);
		return status;
	}

	// �����ֽ�ƫ���� (������ * 512)
	offset.QuadPart = (LONGLONG)StartSector * 512;

	// д������
	status = ZwWriteFile(
		hDisk,
		NULL, NULL, NULL,
		&ioStatus,
		DataBuffer,
		SectorCount * 512,
		&offset,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("WriteFile Fail: 0x%X\n", status);
	}

	ZwClose(hDisk);
	return status;
}
NTSTATUS WriteToDiskEx(LARGE_INTEGER StartSector, ULONG SectorCount, PVOID DataBuffer)
{
	UNICODE_STRING diskPath;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	HANDLE hDisk = NULL;
	NTSTATUS status;

	// �޸�2��ʹ�ö�̬����·����ʾ����
	RtlInitUnicodeString(&diskPath, L"\\Device\\Harddisk0\\DR0");

	InitializeObjectAttributes(&objAttr, &diskPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	// �޸�3�����д��Ȩ��
	status = ZwCreateFile(
		&hDisk,
		GENERIC_WRITE | SYNCHRONIZE | FILE_WRITE_DATA,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_WRITE | FILE_SHARE_READ,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Open Disk Failed: 0x%X\n", status);
		return status;
	}

	// �޸�4��ֱ��ʹ��64λƫ����
	LARGE_INTEGER offset;
	offset.QuadPart = StartSector.QuadPart * 512;

	status = ZwWriteFile(
		hDisk,
		NULL, NULL, NULL,
		&ioStatus,
		DataBuffer,
		SectorCount * 512,
		&offset,
		NULL
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("WriteFile Failed: 0x%X\n", status);
	}

	if (hDisk) ZwClose(hDisk);
	return status;
}

NTSTATUS ForceDeleteFile(UNICODE_STRING ustrFileName)
{
	NTSTATUS status = STATUS_SUCCESS;
	PFILE_OBJECT pFileObject = NULL;
	IO_STATUS_BLOCK iosb = { 0 };
	FILE_BASIC_INFORMATION fileBaseInfo = { 0 };
	FILE_DISPOSITION_INFORMATION fileDispositionInfo = { 0 };
	PVOID pImageSectionObject = NULL;
	PVOID pDataSectionObject = NULL;
	PVOID pSharedCacheMap = NULL;

	// ����IRP���ļ�
	status = IrpCreateFile(&pFileObject, GENERIC_READ | GENERIC_WRITE, &ustrFileName,
		&iosb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpCreateFile Error[0x%X]\n", status);
		return FALSE;
	}
	// ����IRP�����ļ�����, ȥ��ֻ������, �޸�Ϊ FILE_ATTRIBUTE_NORMAL
	RtlZeroMemory(&fileBaseInfo, sizeof(fileBaseInfo));
	fileBaseInfo.FileAttributes = FILE_ATTRIBUTE_NORMAL;
	status = _IrpSetInformationFile(pFileObject, &iosb, &fileBaseInfo, sizeof(fileBaseInfo), FileBasicInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpSetInformationFile[SetInformation] Error[0x%X]\n", status);
		return status;
	}
	// ���PSECTION_OBJECT_POINTERS�ṹ
	if (pFileObject->SectionObjectPointer)
	{
		// �����ֵ
		pImageSectionObject = pFileObject->SectionObjectPointer->ImageSectionObject;
		pDataSectionObject = pFileObject->SectionObjectPointer->DataSectionObject;
		pSharedCacheMap = pFileObject->SectionObjectPointer->SharedCacheMap;
		// ��Ϊ��
		pFileObject->SectionObjectPointer->ImageSectionObject = NULL;
		pFileObject->SectionObjectPointer->DataSectionObject = NULL;
		pFileObject->SectionObjectPointer->SharedCacheMap = NULL;
	}
	// ����IRP�����ļ�����, ����ɾ���ļ�����
	RtlZeroMemory(&fileDispositionInfo, sizeof(fileDispositionInfo));
	fileDispositionInfo.DeleteFile = TRUE;
	status = _IrpSetInformationFile(pFileObject, &iosb, &fileDispositionInfo, sizeof(fileDispositionInfo), FileDispositionInformation);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("IrpSetInformationFile[DeleteFile] Error[0x%X]\n", status);
		return status;
	}
	//��ԭ��ֵ  
	if (pFileObject->SectionObjectPointer)
	{
		pFileObject->SectionObjectPointer->ImageSectionObject = pImageSectionObject;
		pFileObject->SectionObjectPointer->DataSectionObject = pDataSectionObject;
		pFileObject->SectionObjectPointer->SharedCacheMap = pSharedCacheMap;
	}
	// �ر��ļ�����
	ObDereferenceObject(pFileObject);
	return status;
}
BOOLEAN OccupyFile(UNICODE_STRING pwzFileName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatus;
	if (KeGetCurrentIrql() > PASSIVE_LEVEL)
	{
		return FALSE;
	}
	if (pwzFileName.Buffer == NULL || pwzFileName.Length <= 0)
	{
		return FALSE;
	}
	InitializeObjectAttributes(
		&objAttr,
		&pwzFileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL
	);
	status = ZwCreateFile(
		&hFile,
		FILE_READ_DATA,
		&objAttr,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ,
		FILE_OPEN,
		FILE_NON_DIRECTORY_FILE,
		NULL,
		0
	);
	return NT_SUCCESS(status);
}

//SYSTEM

//other

NTSTATUS DeviceIoctl(PDEVICE_OBJECT Device, PIRP pIrp)
{
	NTSTATUS status;
	// ��ȡIRP��Ϣ������
	PIO_STACK_LOCATION irps = IoGetCurrentIrpStackLocation(pIrp);
	// ��ȡ�������Ŀ�����
	ULONG CODE = irps->Parameters.DeviceIoControl.IoControlCode;
	ULONG info = 0;
	DbgPrint("IoControlCode:%d",CODE);
	switch (CODE)
	{
	case IOCTL_KILLPROCESS:
	{
		DbgPrint("Enter the IO KP \n");
		// ��ȡҪɱ���Ľ��̵�PID
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (ZwKillProcess(pid))
		{
			DbgPrint("Kill Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Kill Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_SUSPENDPROCESS:
	{
		DbgPrint("Enter the IO SuspendProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (NT_SUCCESS(SuspendProcess(pid)))
		{
			DbgPrint("Suspend Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Suspend Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_RESUMEPROCESS:
	{
		DbgPrint("Enter the IO ResumeProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (NT_SUCCESS(ResumeProcess(pid)))
		{
			DbgPrint("Resume Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Resume Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_HIDEPROCESS:
	{
		DbgPrint("Enter the IO HideProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (HideProcesss(pid))
		{
			DbgPrint("Hide Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("Hide Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_UNHIDEPROCESS:
	{
		DbgPrint("Enter the IO UnHideProcess \n");
		ULONG pid = *(PLONG)(pIrp->AssociatedIrp.SystemBuffer);
		DbgPrint("Get PID : %d\n", pid);
		if (UnHideProcess(pid))
		{
			DbgPrint("UnHide Process Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("UnHide Process Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_ZWDELETEFILE:
	{
		DbgPrint("Enter the IO ZwDeleteFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		DbgPrint("FILE : %S\n", filePatch);
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath,filePatch);
		if (ZwForceDeleteFile(uniPath)) //�������������
		{
			DbgPrint("DeleteFile(Zw) Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("DeleteFile(Zw) Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_OCCUPYFILE:
	{
		DbgPrint("Enter the IO OccupyFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		if (OccupyFile(uniPath))
		{
			DbgPrint("OccupyFile Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("OccupyFile Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	case IOCTL_FORCEDELETEFILE:
	{
		DbgPrint("Enter the IO ForceDeleteFile\n");
		WCHAR* filePatch = (WCHAR*)pIrp->AssociatedIrp.SystemBuffer;
		UNICODE_STRING uniPath;
		RtlInitUnicodeString(&uniPath, filePatch);
		if (ForceDeleteFile(uniPath))
		{
			DbgPrint("ForceDeleteFile Successful\n");
			status = STATUS_SUCCESS;
		}
		else
		{
			DbgPrint("ForceDeleteFile Failed\n");
			status = STATUS_UNSUCCESSFUL;
		}
		break;
	}
	default:
		DbgPrint("Unknown CODE!\n");
		status = STATUS_UNSUCCESSFUL;
		break;
	}

	// I/O���������
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = info;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
// DriverEntry ���������

EXTERN_C NTSTATUS DriverEntry(PDRIVER_OBJECT driver, PUNICODE_STRING reg_path) {
    // �ں�ģ���������ڣ�����д����Ҫ��
	DbgPrint("Open EFCH Kernel Driver\n");
	DbgPrint("[OpenEFCHKMD] By RanShaoEFCH(Github:RSEFCH123)\n");
	DbgPrint("[OpenEFCHKMD] Build 1\n");
    DbgPrint("[OpenEFCHKMD] Driver Entry\n");
	NTSTATUS status;
	PDEVICE_OBJECT deviceObject = NULL;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	// ע������ж�غ���

	driver->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	driver->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	driver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoctl;
	driver->DriverUnload = DriverUnload;
	// ͨ��ѭ�����豸��������д���رյȺ�������Ϊͨ�õ�DeviceApi


	// ���豸��ת��ΪUnicode�ַ���
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	// �����豸����
	status = IoCreateDevice(driver, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create Device Faild!\n");
		return STATUS_UNSUCCESSFUL;
	}

	// ��������ת��ΪUnicode�ַ���
	RtlInitUnicodeString(&ustrLinkName, DOS_DEVICE_NAME);
	// ���������豸����
	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("Create SymLink Faild!\n");
		IoDeleteDevice(deviceObject);
		return STATUS_UNSUCCESSFUL;
	}

    
	DbgPrintEx(0, 0, "[OpenEFCHKMD] INIT:Done!\n");
	//ForceDeleteFile(L"\\??\\C:\\1.exe");
    return STATUS_SUCCESS;
}
