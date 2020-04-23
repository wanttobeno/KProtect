


VOID TimerRoutine2(
	_In_      struct _KDPC *Dpc,
	_In_opt_  PVOID DeferredContext,
	_In_opt_  PVOID SystemArgument1,
	_In_opt_  PVOID SystemArgument2
)
{
	DbgPrint("TimeOut\n");
}

KDPC myDpc2 = { 0 };
NTSTATUS KeSleep(ULONG timelong)
{
	BOOLEAN bTimerStart = FALSE;
	KTIMER kTimer;
	LARGE_INTEGER timeout;
	timeout.QuadPart = timelong;
	KeInitializeTimer(&kTimer);

	KeInitializeDpc(&myDpc2, TimerRoutine2, NULL);

	timeout = RtlConvertLongToLargeInteger(-10 * timelong);
	bTimerStart = KeSetTimer(&kTimer, timeout, &myDpc2);
	if (bTimerStart)
	{
		DbgPrint("Timer turned on successfully\n");
		return STATUS_SUCCESS;
	}
	DbgPrint("Timer turned on failed\n");
	return STATUS_UNSUCCESSFUL;
}

// https://gist.github.com/geemion/b61aa49e1b19dc8421b953ec3939fa4f

ULONGLONG GetKeServiceDescriptorTable64()
{
	PUCHAR      pStartSearchAddress = (PUCHAR)__readmsr(0xC0000082);
	PUCHAR      pEndSearchAddress = (PUCHAR)(((ULONG_PTR)pStartSearchAddress + PAGE_SIZE) & (~0x0FFF));
	PULONG      pFindCodeAddress = NULL;

	while (++pStartSearchAddress < pEndSearchAddress)
	{
		if ((*(PULONG)pStartSearchAddress & 0xFFFFFF00) == 0x83f70000)
		{
			pFindCodeAddress = (PULONG)(pStartSearchAddress - 12);
			return (ULONG_PTR)pFindCodeAddress + (((*(PULONG)pFindCodeAddress) >> 24) + 7) + (ULONG_PTR)(((*(PULONG)(pFindCodeAddress + 1)) & 0x0FFFF) << 8);
		}
	}
	return 0;
}


typedef struct _KSERVICE_TABLE_DESCRIPTOR {
	unsigned long *ServiceTableBase;
	unsigned long *ServiceCounterTableBase;
	unsigned long NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry, *pServiceDescriptorTableEntry;


const ULONG kNtCreateDebugObjectIndex = 0x90;
const LONG  kDbgkDebugObjectOffsetW7 = 0x7c;
const LONG  kInstructLen = 0x7;

ULONGLONG GetNTAddressFromSSDT(PULONG KiServiceTable, ULONG ServiceId)
{
	return (LONGLONG)(KiServiceTable[ServiceId] >> 4)
		+ (ULONGLONG)KiServiceTable;
}

ULONGLONG GetDbgkDebugObjectTypeAddr()
{
	LONGLONG Result = 0;

	pServiceDescriptorTableEntry KeSericeDescriptorTable = (pServiceDescriptorTableEntry)GetKeServiceDescriptorTable64();
	ULONGLONG NtCreateDebugObject = GetNTAddressFromSSDT(KeSericeDescriptorTable->ServiceTableBase, kNtCreateDebugObjectIndex);
	LONG DbgkDebugObjectTypeOffset = *(LONG*)(NtCreateDebugObject + kDbgkDebugObjectOffsetW7 + 0x3);

	Result = DbgkDebugObjectTypeOffset + (LONGLONG)NtCreateDebugObject + kDbgkDebugObjectOffsetW7 + kInstructLen;

	KdPrint(("NtCreateDebugObject:%p:%p:%x\n", NtCreateDebugObject, Result, DbgkDebugObjectTypeOffset));

	return Result;
}



ULONG GetKernelAddress(char* pChar)
{
	return 0;
}


CHAR*  PsGetProcessImageFileName(PEPROCESS Process);



void EumProcessByQueyInformation()
{
	NTSTATUS status;
	ULONG Retlength;
	PVOID Buffer = NULL;
	PSYSTEM_PROCESS_INFORMATION SystemProcess = NULL;
	status = ZwQuerySystemInformation(5, NULL, 0, &Retlength);
	if (status == STATUS_INFO_LENGTH_MISMATCH)
	{
		KdPrint(("开始运行！\n"));
		Buffer = ExAllocatePool(PagedPool, Retlength);
		if (Buffer)
		{
			RtlZeroMemory(Buffer, Retlength);
			status = ZwQuerySystemInformation(5, Buffer, Retlength, &Retlength);
			if (NT_SUCCESS(status))
			{
				SystemProcess = Buffer;
				do {
					KdPrint(("%wZ\n", SystemProcess->ImageName));
					SystemProcess = ((ULONG64)SystemProcess) + SystemProcess->NextEntryOffset;
				} while (SystemProcess->NextEntryOffset);


			}
			ExFreePool(Buffer);
		}
	}
}

// 打印所有进程名
void EumProcessByLookUpProcessId()
{
	ULONG Pid;
	NTSTATUS status;
	PEPROCESS Process;
	for (Pid = 0; Pid <= 240000; Pid += 4)
	{
		status = PsLookupProcessByProcessId(Pid, &Process);
		if (NT_SUCCESS(status))
		{
			KdPrint(("%s\n", PsGetProcessImageFileName(Process)));
			ObDereferenceObject(Process);
		}
	}
}

NTSTATUS GetProcessIdByName(char* process, ULONG* winlogonPid)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	ULONG Pid;
	PEPROCESS Process;
	for (Pid = 0; Pid <= 240000; Pid += 4)
	{
		status = PsLookupProcessByProcessId(Pid, &Process);
		if (NT_SUCCESS(status))
		{
			KdPrint(("%s\n", PsGetProcessImageFileName(Process)));
			if (strstr(PsGetProcessImageFileName(Process), process))
			{
				winlogonPid = Pid;
				status = STATUS_SUCCESS;
				ObDereferenceObject(Process);
				break;
			}
			ObDereferenceObject(Process);
		}
	}
	return status;
}