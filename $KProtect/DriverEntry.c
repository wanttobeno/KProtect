/*
	$KProtect

	某总：这是我们公司级别的产品，谁能成功调试下断的，奖励1w元
	A few days later......
	某总：那怎么可能兑现呢，扯几把蛋呢
*/

#include <ntifs.h>
#include <ntddk.h>
#include "Helper.h"
#include "NtDefine.h"
#include "NtStruct.h"
#include "NtFunction.h"

typedef struct _GLOBAL
{
	struct {
		ULONG		UniqueProcessId;
		ULONG		InheritedFromUniqueProcessId;
		ULONG		DebugPort;
		ULONGLONG	ValidAccessMask;
	} Offsets;
	ULONGLONG	ProtectPid;
	PVOID		hObReg;
	HANDLE		hThread;
	PVOID		ThreadObj;
	BOOLEAN		Unload;
} GLOBAL;

GLOBAL g = { 0 };

#if DBG
#define DO_SOMETHING()	{	DbgPrint("$KProtect: GG Boom!\n");	}
#else
#define DO_SOMETHING()	{	KeBugCheck(0x233);	}
#endif

void LoopThread(PVOID StartContext)
{
	PEPROCESS ProtectPEProcess = NULL;

	while (!g.Unload) {
		KeSleep(5000);

		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)g.ProtectPid, &ProtectPEProcess))) {
			continue;
		}

		if (*(PVOID*)((PUCHAR)ProtectPEProcess + g.Offsets.DebugPort) != NULL) {
			DO_SOMETHING();
		}
		ObDereferenceObject(ProtectPEProcess);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}

OB_PREOP_CALLBACK_STATUS ProcessCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PACCESS_MASK pOriginalDesiredAccess = NULL;
	PACCESS_MASK pDesiredAccess = NULL;

	if ((ULONGLONG)PsGetProcessId((PEPROCESS)OperationInformation->Object) != g.ProtectPid)
		return OB_PREOP_SUCCESS;

	pOriginalDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

	*pDesiredAccess = 0;
	return OB_PREOP_SUCCESS;
}

OB_PREOP_CALLBACK_STATUS ThreadCallBack(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION OperationInformation)
{
	PACCESS_MASK pOriginalDesiredAccess = NULL;
	PACCESS_MASK pDesiredAccess = NULL;

	if ((ULONGLONG)PsGetProcessId((PEPROCESS)OperationInformation->Object) != g.ProtectPid)
		return OB_PREOP_SUCCESS;

	pOriginalDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
	pDesiredAccess = &OperationInformation->Parameters->CreateHandleInformation.DesiredAccess;

	*pDesiredAccess = 0;

	return OB_PREOP_SUCCESS;
}

NTSTATUS InstallProtectCallBack()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	OB_CALLBACK_REGISTRATION obRegP, obRegT = { 0 };
	OB_OPERATION_REGISTRATION opReg[2] = { 0 };


	RtlInitUnicodeString(&obRegP.Altitude, L"320264");
	obRegP.Version = OB_FLT_REGISTRATION_VERSION;
	obRegP.OperationRegistrationCount = 2;
	obRegP.RegistrationContext = NULL;
	obRegP.OperationRegistration = opReg;

	opReg[0].ObjectType = PsProcessType;
	opReg[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg[0].PreOperation = ProcessCallBack;

	opReg[1].ObjectType = PsThreadType;
	opReg[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg[1].PreOperation = ThreadCallBack;

	status = ObRegisterCallbacks(&obRegP, &g.hObReg);
	if (!NT_SUCCESS(status)) {
		KdPrint(("$KProtect: ObRegisterCallbacks Falied.\n"));
		return status;
	}

	return status;
}

NTSTATUS HideProcess()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONGLONG winlogonPid = 0;
	PEPROCESS ProtectPEProcess = NULL;

	status = GetProcessIdByName("winlogon.exe", &winlogonPid);
	if (!NT_SUCCESS(status) || !winlogonPid) {
		KdPrint(("$KProtect: winlogon.exe Pid Get Failed.\n"));
		return status;
	}

	KdPrint(("$KProtect: ProtectPid: %d\n", g.ProtectPid));
	KdPrint(("$KProtect: winlogonPid: %d\n", winlogonPid));

	status = PsLookupProcessByProcessId((HANDLE)g.ProtectPid, &ProtectPEProcess);
	if (!NT_SUCCESS(status) || !MmIsAddressValid(ProtectPEProcess)) {
		KdPrint(("$KProtect: PsLookupProcessByProcessId Failed.\n"));
		return status;
	}

	*(ULONGLONG*)((PUCHAR)ProtectPEProcess + g.Offsets.InheritedFromUniqueProcessId) = 4;
	*(ULONGLONG*)((PUCHAR)ProtectPEProcess + g.Offsets.UniqueProcessId) = winlogonPid;

	ObDereferenceObject(ProtectPEProcess);

	KdPrint(("$KProtect: Hide Process Success.\n"));
	return status;
}

NTSTATUS InitProtectProcess()
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	// 这里偷懒了 懒得创建设备
	status = GetProcessIdByName("$KDemo.exe", &g.ProtectPid);
	if (!NT_SUCCESS(status) || !g.ProtectPid) {
		KdPrint(("$KProtect: Process Not Be Open.\n"));
		return status;
	}

	status = HideProcess();
	if (!NT_SUCCESS(status)) {
		KdPrint(("$KProtect: HideProcess falied\n"));
		return status;
	}

	return status;
}

NTSTATUS ValidAccessMaskZeroSet()
{
	PVOID NtCreateDebugObject = (PVOID)GetDbgkDebugObjectTypeAddr(); //GetKernelAddress("NtCreateDebugObject");
	if (!MmIsAddressValid(NtCreateDebugObject)) {
		KdPrint(("$KProtect: Get NtCreateDebugObject failed!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	/*
		fffff800`042775fc	48 8b 15 cd 0a de ff	mov		rdx,qword ptr [nt!DbgkDebugObjectType (fffff800`040580d0)]
		fffff800`04277603	41 8a ca				mov		cl,r10b
	*/
	PVOID Code = (PVOID)((PUCHAR)FindPattern(NtCreateDebugObject, 0x1000, "\x48\x8b\x15\x00\x00\x00\x00", "xxx????"));
	if (!MmIsAddressValid(Code)) {
		KdPrint(("$KProtect: Get DbgkDebugObjectType failed!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	ULONG Offset = *(ULONG*)((PUCHAR)Code + 3);
	PVOID Next = (PVOID)((PUCHAR)Code + 7);
	POBJECT_TYPE pDbgkDebugObjectType = *(POBJECT_TYPE*)((PUCHAR)Next + (Offset | 0xFFFFFFFF00000000));
	pDbgkDebugObjectType->TypeInfo.ValidAccessMask = 0;
	return STATUS_SUCCESS;
}

NTSTATUS GetOffsets()
{
	UNICODE_STRING usApiName = { 0 };
	PVOID fnPsGetProcessInheritedFromUniqueProcessId = NULL;
	PVOID fnPsGetProcessDebugPort = NULL;

	RtlInitUnicodeString(&usApiName, L"PsGetProcessInheritedFromUniqueProcessId");
	fnPsGetProcessInheritedFromUniqueProcessId = MmGetSystemRoutineAddress(&usApiName);
	RtlInitUnicodeString(&usApiName, L"PsGetProcessDebugPort");
	fnPsGetProcessDebugPort = MmGetSystemRoutineAddress(&usApiName);
	if (!MmIsAddressValid(fnPsGetProcessInheritedFromUniqueProcessId) || !MmIsAddressValid(fnPsGetProcessDebugPort)) {
		KdPrint(("$KProtect: Get Api failed!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	g.Offsets.UniqueProcessId = *(ULONG*)((PUCHAR)PsGetProcessId + 3);
	g.Offsets.InheritedFromUniqueProcessId = *(ULONG*)((PUCHAR)fnPsGetProcessInheritedFromUniqueProcessId + 3);
	g.Offsets.DebugPort = *(ULONG*)((PUCHAR)fnPsGetProcessDebugPort + 3);
	if (!g.Offsets.UniqueProcessId || !g.Offsets.InheritedFromUniqueProcessId || !g.Offsets.DebugPort) {
		KdPrint(("$KProtect: Get Offsets failed!\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrint(("$KProtect: UniqueProcessId: 0x%x\n", g.Offsets.UniqueProcessId));
	KdPrint(("$KProtect: InheritedFromUniqueProcessId: 0x%x\n", g.Offsets.InheritedFromUniqueProcessId));
	KdPrint(("$KProtect: DebugPort: 0x%x\n", g.Offsets.DebugPort));
	return STATUS_SUCCESS;
}

void MyDriverUnload(PDRIVER_OBJECT pDrvObj)
{
	g.Unload = TRUE;
	KeWaitForSingleObject(g.ThreadObj, Executive, KernelMode, FALSE, NULL);
	ObDereferenceObject(g.ThreadObj);

	if (g.hObReg) {
		ObUnRegisterCallbacks(g.hObReg);
	}

	KdPrint(("$KProtect: DriverUnload\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pReg)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	KdPrint(("$KProtect: DriverEntry\n"));

	pDrvObj->DriverUnload = MyDriverUnload;

	((PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection)->Flags |= 0x20;

	status = GetOffsets();
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = ValidAccessMaskZeroSet();
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = InitProtectProcess();
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = InstallProtectCallBack();
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = PsCreateSystemThread(&g.hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, LoopThread, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	status = ObReferenceObjectByHandle(g.hThread, THREAD_ALL_ACCESS, NULL, KernelMode, &g.ThreadObj, NULL);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	return STATUS_SUCCESS;
}