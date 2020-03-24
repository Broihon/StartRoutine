#pragma once

#include "Windows.h"

#ifndef NT_FAIL
	#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
	#define NT_SUCCESS(status) (status >= 0)
#endif

#define THREAD_CREATE_FLAGS_CREATE_SUSPENDED	0x00000001
#define THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH  0x00000002
#define THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER	0x00000004

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

struct UNICODE_STRING
{
	WORD		Length;
	WORD		MaxLength;
	wchar_t *	szBuffer;
};

typedef struct _RTL_BALANCED_NODE
{
	union
	{
		struct _RTL_BALANCED_NODE * Children[2];
		struct
		{
			struct _RTL_BALANCED_NODE * Left;
			struct _RTL_BALANCED_NODE * Right;
		};
	};
	
	union
	{
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	};
} RTL_BALANCED_NODE, *PRTL_BALANCED_NODE;

struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY		InLoadOrderLinks;
	LIST_ENTRY		InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};

	PVOID			DllBase;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;

	UNICODE_STRING	FullDllName;
	UNICODE_STRING	BaseDllName;

	ULONG			Flags;
	WORD			LoadCount;
	WORD			TlsIndex;

	LIST_ENTRY		HashLinks;
};

struct PEB_LDR_DATA
{
	ULONG		Length;
	BYTE		Initialized;
	HANDLE		SsHandle;
	LIST_ENTRY	InLoadOrderModuleListHead;
	LIST_ENTRY	InMemoryOrderModuleListHead;
	LIST_ENTRY	InInitializationOrderModuleListHead;
	void *		EntryInProgress;
	BYTE		ShutdownInProgress;
	HANDLE		ShutdownThreadId;
};

struct PEB
{
	void * Reserved[3];
	PEB_LDR_DATA * Ldr;
};

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef LONG KPRIORITY;

struct PROCESS_BASIC_INFORMATION
{
	NTSTATUS	ExitStatus;
	PEB *		pPEB;
	ULONG_PTR	AffinityMask;
	LONG		BasePriority;
	HANDLE		UniqueProcessId;
	HANDLE		InheritedFromUniqueProcessId;
};

struct PROCESS_SESSION_INFORMATION
{
	ULONG SessionId;
};

struct THREAD_BASIC_INFORMATION
{
	NTSTATUS                ExitStatus;
	PVOID                   TebBaseAddress;
	CLIENT_ID               ClientId;
	KAFFINITY               AffinityMask;
	KPRIORITY               Priority;
	KPRIORITY               BasePriority;
};

enum _PROCESSINFOCLASS
{
	ProcessBasicInformation		= 0,
	ProcessSessionInformation	= 24,
	ProcessWow64Information		= 26
};
typedef _PROCESSINFOCLASS PROCESSINFOCLASS;

enum _SYSTEM_INFORMATION_CLASS
{
	SystemProcessInformation	= 5,
	SystemHandleInformation		= 16
};
typedef _SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS;

enum _THREADINFOCLASS
{
	ThreadBasicInformation			= 0,
	ThreadQuerySetWin32StartAddress = 9
};
typedef _THREADINFOCLASS THREADINFOCLASS;

struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	WORD UniqueProcessId;
	WORD CreateBackTraceIndex;
	BYTE ObjectTypeIndex;
	BYTE HandleAttributes;
	WORD HandleValue;
	void * Object;
	ULONG GrantedAccess;
};
typedef SYSTEM_HANDLE_TABLE_ENTRY_INFO SYSTEM_HANDLE_TABLE_ENTRY_INFO;

struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
};
typedef _SYSTEM_HANDLE_INFORMATION SYSTEM_HANDLE_INFORMATION;

enum _OBEJECT_TYPE_INDEX : BYTE
{
	OTI_Unknown00				= 0x00,
	OTI_Unknown01				= 0x01,
	OTI_Unknown02				= 0x00,
	OTI_Directory				= 0x03,
	OTI_Unknown04				= 0x04,
	OTI_Token					= 0x05,
	OTI_Job						= 0x06,
	OTI_Process					= 0x07,
	OTI_Thread					= 0x08,
	OTI_Unknown09				= 0x09,
	OTI_IoCompletionReserve		= 0x0A,
	OTI_Unknown0B				= 0x0B,
	OTI_Unknown0C				= 0x0C,
	OTI_Unknown0D				= 0x0D,
	OTI_DebugObject				= 0x0E,
	OTI_Event					= 0x0F,
	OTI_Mutant					= 0x10,
	OTI_Unknown11				= 0x11,
	OTI_Semaphore				= 0x12,
	OTI_Timer					= 0x13,
	OTI_IRTimer					= 0x14,
	OTI_Unknown15				= 0x15,
	OTI_Unknown16				= 0x16,
	OTI_WindowStation			= 0x17,
	OTI_Desktop					= 0x18,
	OTI_Composition				= 0x19,
	OTI_RawInputManager			= 0x1A,
	OTI_Unknown1B				= 0x1B,
	OTI_TpWorkerFactory			= 0x1C,
	OTI_Unknown1D				= 0x1D,
	OTI_Unknown1E				= 0x1E,
	OTI_Unknown1F				= 0x1F,
	OTI_Unknown20				= 0x20,
	OTI_IoCompletion			= 0x21,
	OTI_WaitCompletionPacket	= 0x22,
	OTI_File					= 0x23,
	OTI_Unknown24				= 0x24,
	OTI_Unknown25				= 0x25,
	OTI_Unknown26				= 0x26,
	OTI_Unknown27				= 0x27,
	OTI_Section					= 0x28,
	OTI_Session					= 0x29,
	OTI_Partition				= 0x2A,
	OTI_Key						= 0x2B,
	OTI_Unknown2C				= 0x2C,
	OTI_ALPC_Port				= 0x2D,
	OTI_Unknown2E				= 0x2E,
	OTI_WmiGuid					= 0x2F,
	OTI_Unknown30				= 0x30,
	OTI_Unknown31				= 0x31,
	OTI_Unknown32				= 0x32,
	OTI_Unknown33				= 0x33,
	OTI_Unknown34				= 0x34,
	OTI_Unknown35				= 0x35,
};
typedef _OBEJECT_TYPE_INDEX OBJECT_TYPE_INDEX;

enum class THREAD_STATE
{
    Running = 0x02,
    Waiting = 0x05
};

typedef enum class _KWAIT_REASON
{
	Executive			= 0x00,
	FreePage			= 0x01,
	PageIn				= 0x02,
	PoolAllocation		= 0x03,
	DelayExecution		= 0x04,
	Suspended			= 0x05,
	UserRequest			= 0x06,
	WrExecutive			= 0x07,
	WrFreePage			= 0x08,
	WrPageIn			= 0x09,
	WrPoolAllocation	= 0x0A,
	WrDelayExecution	= 0x0B,
	WrSuspended			= 0x0C,
	WrUserRequest		= 0x0D,
	WrEventPair			= 0x0E,
	WrQueue				= 0x0F,
	WrLpcReceive		= 0x10,
	WrLpcReply			= 0x11,
	WrVirtualMemory		= 0x12,
	WrPageOut			= 0x13,
	WrRendezvous		= 0x14,
	WrCalloutStack		= 0x19,
	WrKernel			= 0x1A,
	WrResource			= 0x1B,
	WrPushLock			= 0x1C,
	WrMutex				= 0x1D,
	WrQuantumEnd		= 0x1E,
	WrDispatchInt		= 0x1F,
	WrPreempted			= 0x20,
	WrYieldExecution	= 0x21,
	WrFastMutex			= 0x22,
	WrGuardedMutex		= 0x23,
	WrRundown			= 0x24,
	MaximumWaitReason	= 0x25
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER	KernelTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	CreateTime;
	ULONG			WaitTime;
	PVOID			StartAddress;
	CLIENT_ID		ClientId;
	KPRIORITY		Priority;
	LONG			BasePriority;
	ULONG			ContextSwitches;
	THREAD_STATE	ThreadState;
	KWAIT_REASON	WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG			NextEntryOffset;
	ULONG			NumberOfThreads;
	LARGE_INTEGER	WorkingSetPrivateSize;
	ULONG			HardFaultCount;
	ULONG			NumberOfThreadsHighWatermark;
	ULONGLONG		CycleTime;
	LARGE_INTEGER	CreateTime;
	LARGE_INTEGER	UserTime;
	LARGE_INTEGER	KernelTime;
	UNICODE_STRING	ImageName;
	KPRIORITY		BasePriority;
	HANDLE			UniqueProcessId;
	HANDLE			InheritedFromUniqueProcessId;
	ULONG			HandleCount;
	ULONG			SessionId;
	ULONG_PTR		UniqueProcessKey;
	SIZE_T			PeakVirtualSize;
	SIZE_T			VirtualSize;
	ULONG			PageFaultCount;
	SIZE_T 			PeakWorkingSetSize;
	SIZE_T			WorkingSetSize;
	SIZE_T			QuotaPeakPagedPoolUsage;
	SIZE_T 			QuotaPagedPoolUsage;
	SIZE_T 			QuotaPeakNonPagedPoolUsage;
	SIZE_T 			QuotaNonPagedPoolUsage;
	SIZE_T 			PagefileUsage;
	SIZE_T 			PeakPagefileUsage;
	SIZE_T 			PrivatePageCount;
	LARGE_INTEGER	ReadOperationCount;
	LARGE_INTEGER	WriteOperationCount;
	LARGE_INTEGER	OtherOperationCount;
	LARGE_INTEGER 	ReadTransferCount;
	LARGE_INTEGER	WriteTransferCount;
	LARGE_INTEGER	OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef union _LDRP_PATH_SEARCH_OPTIONS
{
	ULONG32 Flags;

	struct
	{
		ULONG32 Unknown;
	};
} LDRP_PATH_SEARCH_OPTIONS, * PLDRP_PATH_SEARCH_OPTIONS;

typedef struct _LDRP_PATH_SEARCH_CONTEXT
{
	UNICODE_STRING				DllSearchPath;
	BOOLEAN						AllocatedOnLdrpHeap;
	LDRP_PATH_SEARCH_OPTIONS	SearchOptions;
	UNICODE_STRING				OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT, * PLDRP_PATH_SEARCH_CONTEXT;

#ifdef _WIN64

struct UNICODE_STRING32
{
	WORD	Length;
	WORD	MaxLength;
	DWORD	szBuffer;
};

typedef struct _LDRP_PATH_SEARCH_CONTEXT32
{
	UNICODE_STRING32			DllSearchPath;
	BOOLEAN						AllocatedOnLdrpHeap;
	LDRP_PATH_SEARCH_OPTIONS	SearchOptions;
	UNICODE_STRING32			OriginalFullDllName;
} LDRP_PATH_SEARCH_CONTEXT32, * PLDRP_PATH_SEARCH_CONTEXT32;

struct LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32		InLoadOrderLinks;
	LIST_ENTRY32		InMemoryOrderLinks;
	LIST_ENTRY32		InInitializationOrderLinks;
	DWORD				DllBase;
	DWORD				EntryPoint;
	ULONG				SizeOfImage;
	UNICODE_STRING32	FullDllName;
	UNICODE_STRING32	BaseDllName;
	ULONG				Flags;
	WORD				LoadCount;
	WORD				TlsIndex;
	union
	{
		LIST_ENTRY32 HashLinks;
		struct
		{
			ULONG SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		ULONG LoadedImports;
	};
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
};

struct PEB_LDR_DATA32
{
	ULONG			Length;
	BYTE			Initialized;
	DWORD			SsHandle;
	LIST_ENTRY32	InLoadOrderModuleListHead;
	LIST_ENTRY32	InMemoryOrderModuleListHead;
	LIST_ENTRY32	InInitializationOrderModuleListHead;
	DWORD			EntryInProgress;
	BYTE			ShutdownInProgress;
	DWORD			ShutdownThreadId;
};

struct PEB32
{
	DWORD Reserved[3];
	DWORD Ldr;
};

#endif

using f_NtCreateThreadEx = NTSTATUS (__stdcall*)	
(
	HANDLE		*	pHandle, 
	ACCESS_MASK		DesiredAccess, 
	void		*	pAttr, 
	HANDLE			hTargetProc, 
	void		*	pFunc, 
	void		*	pArg,
	ULONG			Flags, 
	SIZE_T			ZeroBits, 
	SIZE_T			StackSize, 
	SIZE_T			MaxStackSize, 
	void		*	pAttrListOut
);

using f_LdrLoadDll = NTSTATUS (__stdcall*)	
(
	wchar_t			*	szOptPath, 
	ULONG				ulFlags, 
	UNICODE_STRING	*	pModuleFileName, 
	HANDLE			*	pOut
);

using f_LdrpLoadDll = NTSTATUS (__fastcall*)
(
	UNICODE_STRING				*	dll_path, 
	LDRP_PATH_SEARCH_CONTEXT	*	search_path,
	ULONG32							Flags,
	LDR_DATA_TABLE_ENTRY		**	ldr_out
);

using f_LdrpPreprocessDllName = NTSTATUS (__fastcall*)
(
	UNICODE_STRING	*	dll_path_in, 
	UNICODE_STRING	*	dll_path_out, 
	uintptr_t		*	unknown_out_1, 
	uintptr_t		*	unknown_out_2
);

using f_RtlInsertInvertedFunctionTable = BOOL (__fastcall*)
(
	void	*	hDll,
	DWORD		SizeOfImage
);

using f_NtQueryInformationProcess = NTSTATUS (__stdcall*)
(
	HANDLE					hTargetProc, 
	PROCESSINFOCLASS		PIC, 
	void				*	pBuffer, 
	ULONG					BufferSize, 
	ULONG				*	SizeOut
);

using f_NtQuerySystemInformation = NTSTATUS	(__stdcall*)
(
	SYSTEM_INFORMATION_CLASS		SIC, 
	void						*	pBuffer, 
	ULONG							BufferSize, 
	ULONG						*	SizeOut
);

using f_NtQueryInformationThread = NTSTATUS (__stdcall*)
(
	HANDLE				hThread, 
	THREADINFOCLASS		TIC, 
	void			*	pBuffer, 
	ULONG				BufferSize, 
	ULONG			*	SizeOut
);

using f_RtlQueueApcWow64Thread = NTSTATUS (__stdcall*)
(
	HANDLE		hThread, 
	void	*	pRoutine, 
	void	*	pArg1, 
	void	*	pArg2, 
	void	*	pArg3
);