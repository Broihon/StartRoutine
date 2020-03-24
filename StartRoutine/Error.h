#pragma once

//Start Routine errors:
#define SR_ERR_SUCCESS					0x00000000
													
													//Source					:	error description

#define SR_ERR_CANT_QUERY_SESSION_ID	0x00000001	//NtQueryInformationProcess	:	NTSTATUS
#define SR_ERR_INVALID_LAUNCH_METHOD	0x10000002	//bruh moment				:	bruh moment
#define SR_ERR_NOT_LOCAL_SYSTEM			0x10000003	//internal error			:	SetWindowsHookEx with handle hijacking only works within the same session or from session 0 (LocalSystem account) because of the WtsAPIs


///////////////////
///NtCreateThreadEx
														//Source					:	error description

#define SR_NTCTE_ERR_NTCTE_MISSING			0x10100001	//GetProcAddress			:	win32 error
#define SR_NTCTE_ERR_CANT_ALLOC_MEM			0x10100002	//VirtualAllocEx			:	win32 error
#define SR_NTCTE_ERR_WPM_FAIL				0x10100003	//WriteProcessMemory		:	win32 error
#define SR_NTCTE_ERR_NTCTE_FAIL				0x10100004	//NtCreateThreadEx			:	NTSTATUS
#define SR_NTCTE_ERR_GET_CONTEXT_FAIL		0x10100005	//(Wow64)GetThreadContext	:	win32 error
#define SR_NTCTE_ERR_SET_CONTEXT_FAIL		0x10100006	//(Wow64)SetThreadContext	:	win32 error
#define SR_NTCTE_ERR_RESUME_FAIL			0x10100007	//ResumeThread				:	win32 error
#define SR_NTCTE_ERR_RPM_FAIL				0x10100008	//ReadProcessMemory			:	win32 error
#define SR_NTCTE_ERR_REMOTE_TIMEOUT			0x10100009	//WaitForSingleObject		:	win32 error
#define SR_NTCTE_ERR_GECT_FAIL				0x1010000A	//GetExitCodeThread			:	win32 error
#define SR_NTCTE_ERR_GET_MODULE_HANDLE_FAIL	0x1010000B	//GetModuleHandle			:	win32 error
#define SR_NTCTE_ERR_SHELLCODE_SETUP_FAIL	0x1010000C	//shellcode argument is 0	:	

///////////////
///HijackThread
														//Source					:	error description

#define SR_HT_ERR_PROC_INFO_FAIL			0x10200001	//internal error			:	can't grab process information
#define SR_HT_ERR_NO_THREADS				0x10200002	//internal error			:	no thread to hijack
#define SR_HT_ERR_OPEN_THREAD_FAIL			0x10200003	//OpenThread				:	win32 error
#define SR_HT_ERR_CANT_ALLOC_MEM			0x10200004	//VirtualAllocEx			:	win32 error
#define SR_HT_ERR_SUSPEND_FAIL				0x10200005	//SuspendThread				:	win32 error
#define SR_HT_ERR_GET_CONTEXT_FAIL			0x10200006	//(Wow64)GetThreadContext	:	win32 error
#define SR_HT_ERR_WPM_FAIL					0x10200007	//WriteProcessMemory		:	win32 error
#define SR_HT_ERR_MAMBDA_IS_NOOB			0x10200008	//NtStupidNoobFunction		:	NTSTATUS
#define SR_HT_ERR_SET_CONTEXT_FAIL			0x10200009	//(Wow64)SetThreadContext	:	win32 error
#define SR_HT_ERR_RESUME_FAIL				0x1020000A	//ResumeThread				:	win32 error
#define SR_HT_ERR_REMOTE_TIMEOUT			0x1020000B	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT (can't be deallocated safely)
#define SR_HT_ERR_REMOTE_PENDING_TIMEOUT	0x1020000C	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT while pending (can be deallocated safely)

////////////////////
///SetWindowsHookEx
														//Source				:	error description

#define SR_SWHEX_ERR_CANT_QUERY_INFO_PATH	0x10300001	//internal error		:	can't resolve own module filepath
#define SR_SWHEX_ERR_CANT_OPEN_INFO_TXT		0x10300002	//internal error		:	can't open swhex info file
#define SR_SWHEX_ERR_VAE_FAIL				0x10300003	//VirtualAllocEx		:	win32 error
#define SR_SWHEX_ERR_CNHEX_MISSING			0x10300004	//GetProcAddressEx		:	can't find pointer to CallNextHookEx
#define SR_SWHEX_ERR_WPM_FAIL				0x10300005	//WriteProcessMemory	:	win32 error
#define SR_SWHEX_ERR_ENUM_WINDOWS_FAIL		0x10300006	//EnumWindows			:	win32 error
#define SR_SWHEX_ERR_NO_WINDOWS				0x10300007	//internal error		:	no windows
#define SR_SWHEX_ERR_REMOTE_TIMEOUT			0x1030000C	//internal error		:	execution time exceeded SR_REMOTE_TIMEOUT

///////////////
///QueueUserAPC
														//Source					:	error description

#define SR_QUAPC_ERR_RTLQAW64_MISSING		0x10400001	//GetProcAddress			:	win32 error
#define SR_QUAPC_ERR_CANT_ALLOC_MEM			0x10400001	//VirtualAllocEx			:	win32 error
#define SR_QUAPC_ERR_WPM_FAIL				0x10400002	//WriteProcessMemory		:	win32 error
#define SR_QUAPC_ERR_TH32_FAIL				0x10400003	//CreateToolhelp32Snapshot	:	win32 error
#define SR_QUAPC_ERR_T32FIRST_FAIL			0x10400004	//Thread32First				:	win32 error
#define SR_QUAPC_ERR_NO_APC_THREAD			0x10400005	//QueueUserAPC				:	no alertable (non worker) thread available
#define SR_QUAPC_ERR_REMOTE_TIMEOUT			0x10400006	//internal error			:	execution time exceeded SR_REMOTE_TIMEOUT
#define SR_QUAPC_ERR_RPM_TIMEOUT_FAIL		0x10400007	//ReadProcessMemory			:	win32 error
#define SR_QUAPC_ERR_GET_MODULE_HANDLE_FAIL	0x10100008	//GetModuleHandle			:	win32 error