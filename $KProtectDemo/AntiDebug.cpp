#include "stdafx.h"
#include <Windows.h>
#include "AntiDebug.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,
	SystemProcessorInformation,
	SystemPerformanceInformation,
	SystemTimeOfDayInformation,
	SystemPathInformation,
	SystemProcessInformation,
	SystemCallCountInformation,
	SystemDeviceInformation,
	SystemProcessorPerformanceInformation,
	SystemFlagsInformation,
	SystemCallTimeInformation,
	SystemModuleInformation,
	SystemLocksInformation,
	SystemStackTraceInformation,
	SystemPagedPoolInformation,
	SystemNonPagedPoolInformation,
	SystemHandleInformation,
	SystemObjectInformation,
	SystemPageFileInformation,
	SystemVdmInstemulInformation,
	SystemVdmBopInformation,
	SystemFileCacheInformation,
	SystemPoolTagInformation,
	SystemInterruptInformation,
	SystemDpcBehaviorInformation,
	SystemFullMemoryInformation,
	SystemLoadGdiDriverInformation,
	SystemUnloadGdiDriverInformation,
	SystemTimeAdjustmentInformation,
	SystemSummaryMemoryInformation,
	SystemMirrorMemoryInformation,
	SystemPerformanceTraceInformation,
	SystemObsolete0,
	SystemExceptionInformation,
	SystemCrashDumpStateInformation,
	SystemKernelDebuggerInformation,
	SystemContextSwitchInformation,
	SystemRegistryQuotaInformation,
	SystemExtendServiceTableInformation,
	SystemPrioritySeperation,
	SystemVerifierAddDriverInformation,
	SystemVerifierRemoveDriverInformation,
	SystemProcessorIdleInformation,
	SystemLegacyDriverInformation,
	SystemCurrentTimeZoneInformation,
	SystemLookasideInformation,
	SystemTimeSlipNotification,
	SystemSessionCreate,
	SystemSessionDetach,
	SystemSessionInformation,
	SystemRangeStartInformation,
	SystemVerifierInformation,
	SystemVerifierThunkExtend,
	SystemSessionProcessInformation,
	SystemLoadGdiDriverInSystemSpace,
	SystemNumaProcessorMap,
	SystemPrefetcherInformation,
	SystemExtendedProcessInformation,
	SystemRecommendedSharedDataAlignment,
	SystemComPlusPackage,
	SystemNumaAvailableMemory,
	SystemProcessorPowerInformation,
	SystemEmulationBasicInformation,
	SystemEmulationProcessorInformation,
	SystemExtendedHandleInformation,
	SystemLostDelayedWriteInformation,
	SystemBigPoolInformation,
	SystemSessionPoolTagInformation,
	SystemSessionMappedViewInformation,
	SystemHotpatchInformation,
	SystemObjectSecurityMode,
	SystemWatchdogTimerHandler,
	SystemWatchdogTimerInformation,
	SystemLogicalProcessorInformation,
	SystemWow64SharedInformation,
	SystemRegisterFirmwareTableInformationHandler,
	SystemFirmwareTableInformation,
	SystemModuleInformationEx,
	SystemVerifierTriageInformation,
	SystemSuperfetchInformation,
	SystemMemoryListInformation,
	SystemFileCacheInformationEx,
	MaxSystemInfoClass  // MaxSystemInfoClass should always be the last enum
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters, // q: IO_COUNTERS
	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
	ProcessTimes, // q: KERNEL_USER_TIMES
	ProcessBasePriority, // s: KPRIORITY
	ProcessRaisePriority, // s: ULONG
	ProcessDebugPort, // q: HANDLE
	ProcessExceptionPort, // s: HANDLE
	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation, // 10
	ProcessLdtSize,
	ProcessDefaultHardErrorMode, // qs: ULONG
	ProcessIoPortHandlers, // (kernel-mode only)
	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,
	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,
	ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
	ProcessAffinityMask, // s: KAFFINITY
	ProcessPriorityBoost, // qs: ULONG
	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information, // q: ULONG_PTR
	ProcessImageFileName, // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled, // q: ULONG
	ProcessBreakOnTermination, // qs: ULONG
	ProcessDebugObjectHandle, // 30, q: HANDLE
	ProcessDebugFlags, // qs: ULONG
	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority, // qs: ULONG
	ProcessExecuteFlags, // qs: ULONG
	ProcessResourceManagement,
	ProcessCookie, // q: ULONG
	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
	ProcessPagePriority, // q: ULONG
	ProcessInstrumentationCallback, // 40
	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32, // q: UNICODE_STRING
	ProcessImageFileMapping, // q: HANDLE (input)
	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation, // q: USHORT[]
	ProcessTokenVirtualizationEnabled, // s: ULONG
	ProcessConsoleHostProcess, // q: ULONG_PTR
	ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,
	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	MaxProcessInfoClass
}PROCESSINFOCLASS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,   // Obsolete
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	ThreadSwitchLegacyState,
	ThreadIsTerminated,
	ThreadLastSystemCall,
	ThreadIoPriority,
	ThreadCycleTime,
	ThreadPagePriority,
	ThreadActualBasePriority,
	ThreadTebInformation,
	ThreadCSwitchMon,          // Obsolete
	ThreadCSwitchPmu,
	ThreadWow64Context,
	ThreadGroupInformation,
	ThreadUmsInformation,      // UMS
	ThreadCounterProfiling,
	ThreadIdealProcessorEx,
	MaxThreadInfoClass
} THREADINFOCLASS;
#pragma pack(1)
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
}SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
#pragma pack()

#ifdef _WIN32
#pragma pack(4)

typedef struct _STRING32 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONG  Buffer;
} STRING32;
typedef STRING32 *PSTRING32;

typedef struct _PEB {                                    // 91 elements, 0x248 bytes (sizeof)
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union {                                                // 2 elements, 0x1 bytes (sizeof)
		/*0x003*/         UINT8        BitField;
		struct {                                           // 6 elements, 0x1 bytes (sizeof)
			/*0x003*/             UINT8        ImageUsesLargePages : 1;          // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;           // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;              // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;  // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1; // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                    // 5 BitPosition
		};
	};
	/*0x004*/     ULONG32      Mutant;
	/*0x008*/     ULONG32      ImageBaseAddress;
	/*0x00C*/     ULONG32      Ldr;
	/*0x010*/     ULONG32      ProcessParameters;
	/*0x014*/     ULONG32      SubSystemData;
	/*0x018*/     ULONG32      ProcessHeap;
	/*0x01C*/     ULONG32      FastPebLock;
	/*0x020*/     ULONG32      AtlThunkSListPtr;
	/*0x024*/     ULONG32      IFEOKey;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x028*/         ULONG32      CrossProcessFlags;
		struct {                                           // 6 elements, 0x4 bytes (sizeof)
			/*0x028*/             ULONG32      ProcessInJob : 1;                 // 0 BitPosition
			/*0x028*/             ULONG32      ProcessInitializing : 1;          // 1 BitPosition
			/*0x028*/             ULONG32      ProcessUsingVEH : 1;              // 2 BitPosition
			/*0x028*/             ULONG32      ProcessUsingVCH : 1;              // 3 BitPosition
			/*0x028*/             ULONG32      ProcessUsingFTH : 1;              // 4 BitPosition
			/*0x028*/             ULONG32      ReservedBits0 : 27;               // 5 BitPosition
		};
	};
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x02C*/         ULONG32      KernelCallbackTable;
		/*0x02C*/         ULONG32      UserSharedInfoPtr;
	};
	/*0x030*/     ULONG32      SystemReserved[1];
	/*0x034*/     ULONG32      AtlThunkSListPtr32;
	/*0x038*/     ULONG32      ApiSetMap;
	/*0x03C*/     ULONG32      TlsExpansionCounter;
	/*0x040*/     ULONG32      TlsBitmap;
	/*0x044*/     ULONG32      TlsBitmapBits[2];
	/*0x04C*/     ULONG32      ReadOnlySharedMemoryBase;
	/*0x050*/     ULONG32      HotpatchInformation;
	/*0x054*/     ULONG32      ReadOnlyStaticServerData;
	/*0x058*/     ULONG32      AnsiCodePageData;
	/*0x05C*/     ULONG32      OemCodePageData;
	/*0x060*/     ULONG32      UnicodeCaseTableData;
	/*0x064*/     ULONG32      NumberOfProcessors;
	/*0x068*/     ULONG32      NtGlobalFlag;
	/*0x06C*/     UINT8        _PADDING0_[0x4];
	/*0x070*/     union _LARGE_INTEGER CriticalSectionTimeout;           // 4 elements, 0x8 bytes (sizeof)
	/*0x078*/     ULONG32      HeapSegmentReserve;
	/*0x07C*/     ULONG32      HeapSegmentCommit;
	/*0x080*/     ULONG32      HeapDeCommitTotalFreeThreshold;
	/*0x084*/     ULONG32      HeapDeCommitFreeBlockThreshold;
	/*0x088*/     ULONG32      NumberOfHeaps;
	/*0x08C*/     ULONG32      MaximumNumberOfHeaps;
	/*0x090*/     ULONG32      ProcessHeaps;
	/*0x094*/     ULONG32      GdiSharedHandleTable;
	/*0x098*/     ULONG32      ProcessStarterHelper;
	/*0x09C*/     ULONG32      GdiDCAttributeList;
	/*0x0A0*/     ULONG32      LoaderLock;
	/*0x0A4*/     ULONG32      OSMajorVersion;
	/*0x0A8*/     ULONG32      OSMinorVersion;
	/*0x0AC*/     UINT16       OSBuildNumber;
	/*0x0AE*/     UINT16       OSCSDVersion;
	/*0x0B0*/     ULONG32      OSPlatformId;
	/*0x0B4*/     ULONG32      ImageSubsystem;
	/*0x0B8*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x0BC*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x0C0*/     ULONG32      ActiveProcessAffinityMask;
	/*0x0C4*/     ULONG32      GdiHandleBuffer[34];
	/*0x14C*/     ULONG32      PostProcessInitRoutine;
	/*0x150*/     ULONG32      TlsExpansionBitmap;
	/*0x154*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x1D4*/     ULONG32      SessionId;
	/*0x1D8*/     union _ULARGE_INTEGER AppCompatFlags;                  // 4 elements, 0x8 bytes (sizeof)
	/*0x1E0*/     union _ULARGE_INTEGER AppCompatFlagsUser;              // 4 elements, 0x8 bytes (sizeof)
	/*0x1E8*/     ULONG32      pShimData;
	/*0x1EC*/     ULONG32      AppCompatInfo;
	/*0x1F0*/     struct _STRING32 CSDVersion;                           // 3 elements, 0x8 bytes (sizeof)
	/*0x1F8*/     ULONG32      ActivationContextData;
	/*0x1FC*/     ULONG32      ProcessAssemblyStorageMap;
	/*0x200*/     ULONG32      SystemDefaultActivationContextData;
	/*0x204*/     ULONG32      SystemAssemblyStorageMap;
	/*0x208*/     ULONG32      MinimumStackCommit;
	/*0x20C*/     ULONG32      FlsCallback;
	/*0x210*/     struct LIST_ENTRY32 FlsListHead;                      // 2 elements, 0x8 bytes (sizeof)
	/*0x218*/     ULONG32      FlsBitmap;
	/*0x21C*/     ULONG32      FlsBitmapBits[4];
	/*0x22C*/     ULONG32      FlsHighIndex;
	/*0x230*/     ULONG32      WerRegistrationData;
	/*0x234*/     ULONG32      WerShipAssertPtr;
	/*0x238*/     ULONG32      pContextData;
	/*0x23C*/     ULONG32      pImageHeaderHash;
	union {                                                // 2 elements, 0x4 bytes (sizeof)
		/*0x240*/         ULONG32      TracingFlags;
		struct {                                           // 3 elements, 0x4 bytes (sizeof)
			/*0x240*/             ULONG32      HeapTracingEnabled : 1;           // 0 BitPosition
			/*0x240*/             ULONG32      CritSecTracingEnabled : 1;        // 1 BitPosition
			/*0x240*/             ULONG32      SpareTracingBits : 30;            // 2 BitPosition
		};
	};
#ifdef _WIN10_
	/*0x248*/	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	/*0x250*/	ULONG32 TppWorkerpListLock;
	/*0x254*/	LIST_ENTRY32 TppWorkerpList;
	/*0x25C*/	ULONG32 WaitOnAddressHashTable[128];
#endif
} PEB, *PPEB;
#pragma pack()
#else
#pragma pack(8)

typedef struct _STRING64 {
	USHORT   Length;
	USHORT   MaximumLength;
	ULONGLONG  Buffer;
} STRING64;
typedef STRING64 *PSTRING64;

typedef struct _PEB {                                                                             // 91 elements, 0x380 bytes (sizeof)
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union {                                                                                       // 2 elements, 0x1 bytes (sizeof)
		/*0x003*/         UINT8        BitField;
		struct {                                                                                  // 6 elements, 0x1 bytes (sizeof)
			/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                 // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;                                                  // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;                                                     // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                         // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                        // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                                                           // 5 BitPosition
		};
	};
	/*0x008*/     VOID*        Mutant;
	/*0x010*/     VOID*        ImageBaseAddress;
	/*0x018*/     struct _PEB_LDR_DATA* Ldr;
	/*0x020*/     struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	/*0x028*/     VOID*        SubSystemData;
	/*0x030*/     VOID*        ProcessHeap;
	/*0x038*/     struct _RTL_CRITICAL_SECTION* FastPebLock;
	/*0x040*/     VOID*        AtlThunkSListPtr;
	/*0x048*/     VOID*        IFEOKey;
	union {                                                                                       // 2 elements, 0x4 bytes (sizeof)
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct {                                                                                  // 6 elements, 0x4 bytes (sizeof)
			/*0x050*/             ULONG32      ProcessInJob : 1;                                                        // 0 BitPosition
			/*0x050*/             ULONG32      ProcessInitializing : 1;                                                 // 1 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;                                                     // 2 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;                                                     // 3 BitPosition
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;                                                     // 4 BitPosition
			/*0x050*/             ULONG32      ReservedBits0 : 27;                                                      // 5 BitPosition
		};
	};
	union {                                                                                       // 2 elements, 0x8 bytes (sizeof)
		/*0x058*/         VOID*        KernelCallbackTable;
		/*0x058*/         VOID*        UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved[1];
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     VOID*        ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        _PADDING0_[0x4];
	/*0x078*/     VOID*        TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     VOID*        ReadOnlySharedMemoryBase;
	/*0x090*/     VOID*        HotpatchInformation;
	/*0x098*/     VOID**       ReadOnlyStaticServerData;
	/*0x0A0*/     VOID*        AnsiCodePageData;
	/*0x0A8*/     VOID*        OemCodePageData;
	/*0x0B0*/     VOID*        UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;                                                  // 4 elements, 0x8 bytes (sizeof)
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     VOID**       ProcessHeaps;
	/*0x0F8*/     VOID*        GdiSharedHandleTable;
	/*0x100*/     VOID*        ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        _PADDING1_[0x4];
	/*0x110*/     struct _RTL_CRITICAL_SECTION* LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        _PADDING2_[0x4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     PVOID PostProcessInitRoutine;
	/*0x238*/     VOID*        TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        _PADDING3_[0x4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                                                         // 4 elements, 0x8 bytes (sizeof)
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;                                                     // 4 elements, 0x8 bytes (sizeof)
	/*0x2D8*/     VOID*        pShimData;
	/*0x2E0*/     VOID*        AppCompatInfo;
	/*0x2E8*/     struct _UNICODE_STRING CSDVersion;                                                            // 3 elements, 0x10 bytes (sizeof)
	/*0x2F8*/     VOID*		   ActivationContextData;//struct _ACTIVATION_CONTEXT_DATA*
	/*0x300*/     VOID*		   ProcessAssemblyStorageMap;//struct _ASSEMBLY_STORAGE_MAP*
	/*0x308*/     VOID*        SystemDefaultActivationContextData;//struct _ACTIVATION_CONTEXT_DATA*
	/*0x310*/     VOID*		   SystemAssemblyStorageMap;//struct _ASSEMBLY_STORAGE_MAP*
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     VOID*        FlsCallback;//struct _FLS_CALLBACK_INFO*
	/*0x328*/     struct _LIST_ENTRY FlsListHead;                                                               // 2 elements, 0x10 bytes (sizeof)
	/*0x338*/     VOID*        FlsBitmap;
	/*0x340*/     ULONG32      FlsBitmapBits[4];
	/*0x350*/     ULONG32      FlsHighIndex;
	/*0x354*/     UINT8        _PADDING4_[0x4];
	/*0x358*/     VOID*        WerRegistrationData;
	/*0x360*/     VOID*        WerShipAssertPtr;
	/*0x368*/     VOID*        pContextData;
	/*0x370*/     VOID*        pImageHeaderHash;
	union {                                                                                       // 2 elements, 0x4 bytes (sizeof)
		/*0x378*/         ULONG32      TracingFlags;
		struct {                                                                                  // 3 elements, 0x4 bytes (sizeof)
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;                                                  // 0 BitPosition
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;                                               // 1 BitPosition
			/*0x378*/             ULONG32      SpareTracingBits : 30;                                                   // 2 BitPosition
		};
	};
#ifdef _WIN10_
	/*0x380*/	ULONGLONG CsrServerReadOnlySharedMemoryBase;
	/*0x388*/	PVOID TppWorkerpListLock;
	/*0x390*/	LIST_ENTRY TppWorkerpList;
	/*0x3A0*/	PVOID WaitOnAddressHashTable[128];
#endif
} PEB, *PPEB;
#pragma pack()
#endif

typedef LONG NTSTATUS;

typedef HRESULT(WINAPI *p_ZwQuerySystemInformation)(
	_In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_   PVOID                    SystemInformation,
	_In_      ULONG                    SystemInformationLength,
	_Out_opt_ PULONG                   ReturnLength
	);
typedef NTSTATUS(WINAPI *p_ZwQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);
typedef NTSYSAPI NTSTATUS(*p_ZwSetInformationThread)(
	HANDLE          ThreadHandle,
	THREADINFOCLASS ThreadInformationClass,
	PVOID           ThreadInformation,
	ULONG           ThreadInformationLength
	);

p_ZwQuerySystemInformation ZwQuerySystemInformation;
p_ZwQueryInformationProcess ZwQueryInformationProcess;
p_ZwSetInformationThread ZwSetInformationThread;



#if _DEBUG
#define DO_SOMETHING()	{	MessageBox(NULL, L"GG Boom!", L"某总：", MB_OK);	}
#else
#define DO_SOMETHING()	{	exit(0);	}
#endif

void HookJmp(PVOID target, PVOID local)
{
	BYTE Jmp[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
	*(ULONG*)(Jmp + 1) = (ULONG)((PUCHAR)local - (PUCHAR)target - 5);

	SIZE_T size = 0;
	DWORD OldProtect = 0;
	VirtualProtectEx((HANDLE)-1, (PVOID)target, sizeof(Jmp), PAGE_EXECUTE_READWRITE, &OldProtect);
	WriteProcessMemory((HANDLE)-1, (PVOID)target, Jmp, sizeof(Jmp), &size);
	VirtualProtectEx((HANDLE)-1, (PVOID)target, sizeof(Jmp), OldProtect, &OldProtect);
}
void HookApi()
{
	DWORD Old;
	PVOID fnDbgUiRemoteBreakin = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgUiRemoteBreakin");
	PVOID fnDbgBreakPoint = GetProcAddress(GetModuleHandleA("ntdll.dll"), "DbgBreakPoint");

	HookJmp(fnDbgUiRemoteBreakin, GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrShutdownProcess"));
	
	VirtualProtect(fnDbgBreakPoint, 1, PAGE_EXECUTE_READWRITE, &Old);
	*(BYTE*)fnDbgBreakPoint = 0xC3;
	VirtualProtect(fnDbgBreakPoint, 1, Old, &Old);
}
void GetKernelDebugger(HANDLE hMainThread)
{
	DWORD RetLength;

	SYSTEM_KERNEL_DEBUGGER_INFORMATION Info;
	ZwQuerySystemInformation = (p_ZwQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQuerySystemInformation");
	ZwQuerySystemInformation(SystemKernelDebuggerInformation, &Info, sizeof(Info), &RetLength);
	if (Info.KernelDebuggerEnabled || !Info.KernelDebuggerNotPresent) {
		// 虚拟机会影响这俩标志位
		// DO_SOMETHING();
	}

	HANDLE DebugPort;
	HANDLE DebugObjectHandle;
	ULONG DebugFlags;
	ZwQueryInformationProcess = (p_ZwQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwQueryInformationProcess");
	ZwQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &DebugPort, sizeof(DebugPort), &RetLength);
	if (DebugPort) {
		DO_SOMETHING();
	}
	ZwQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &DebugObjectHandle, sizeof(DebugObjectHandle), &RetLength);
	if (DebugObjectHandle) {
		DO_SOMETHING();
	}
	ZwQueryInformationProcess(GetCurrentProcess(), ProcessDebugFlags, &DebugFlags, sizeof(DebugFlags), &RetLength);
	if (!DebugFlags) {
		DO_SOMETHING();
	}

	HookApi();
	// PPEB PPeb = (PPEB)__readfsdword(0x30);
	// printf("PPeb->BeingDebugged:%X\nPPeb->Ldr:%X\nPPeb->ProcessHeap:%X\nPPeb->NtGlobalFlag:%X\n", PPeb->BeingDebugged, PPeb->Ldr, PPeb->ProcessHeap, PPeb->NtGlobalFlag);

	ZwSetInformationThread = (p_ZwSetInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetInformationThread");
	ZwSetInformationThread(hMainThread, ThreadHideFromDebugger, NULL, 0);
	ZwSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, NULL, 0);
	__try {
		printf("%d\n", *(DWORD*)0);
	}
	__except (1) {
		printf("Error\n");
	}
}