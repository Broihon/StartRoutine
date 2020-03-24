#ifdef _WIN64

#include "QueueUserAPC.h"

DWORD SR_QueueUserAPC_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error, DWORD & Out)
{
	HINSTANCE h_nt_dll = GetModuleHandleA("ntdll.dll");
	if (!h_nt_dll)
	{
		LastWin32Error = GetLastError();

		return SR_QUAPC_ERR_GET_MODULE_HANDLE_FAIL;
	}

	auto p_RtlQueueApcWow64Thread = reinterpret_cast<f_RtlQueueApcWow64Thread>(GetProcAddress(h_nt_dll, "RtlQueueApcWow64Thread"));
	if (!p_RtlQueueApcWow64Thread)
	{
		LastWin32Error = GetLastError();

		return SR_QUAPC_ERR_RTLQAW64_MISSING;
	}

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x55,								// + 0x00	-> push	ebp						; x86 stack frame creation
		0x89, 0xE5,							// + 0x01	-> mov	ebp, esp

		0x53,								// + 0x03	-> push	ebx						; push ebx on stack (non volatile)
		0x8B, 0x5D, 0x08,					// + 0x04	-> mov	ebx, [ebp + 0x08]		; store pData in ebx
		0x85, 0xDB,							// + 0x07	-> test	ebx, ebx				; check if pData is valid
		0x74, 0x24,							// + 0x09	-> je	0x2F					; jmp to ret if not

		0x83, 0x3B, 0x00,					// + 0x0B	-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA_WOW64::State is equal to (DWORD)SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x0E	-> jne	0x2F					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x10	-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x13	-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x16	-> call	[ebx + 0x10]			; call pRoutine
		0x89, 0x43, 0x04,					// + 0x19	-> mov	[ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x1C	-> test	eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x1E	-> je	0x2C					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x20	-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x26	-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x29	-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA_WOW64::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x2C	-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to (DWORD)SR_RS_ExecutionFinished

		0x5B,								// + 0x2F	-> pop	ebx						; restore ebx
		0x5D,								// + 0x30	-> pop	ebp						; restore ebp
		0xC2, 0x04, 0x00					// + 0x31	-> ret	0x04					; return
	}; // SIZE = 0x34 (+ sizeof(SR_REMOTE_DATA_WOW64))

	void * pMem = VirtualAllocEx(hTargetProc, nullptr, sizeof(Shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		LastWin32Error = GetLastError();

		return SR_QUAPC_ERR_CANT_ALLOC_MEM;
	}

	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg	  = pArg;
	sr_data->pRoutine = pRoutine;

	BOOL bRet = WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr);
	if (!bRet)
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_WPM_FAIL;
	}

	ProcessInfo PI;
	if (!PI.SetProcess(hTargetProc))
	{
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_HT_ERR_PROC_INFO_FAIL;
	}

	bool APC_Queued = false;

	do
	{
		KWAIT_REASON reason;
		THREAD_STATE state;
		if (!PI.GetThreadState(state, reason) || reason == KWAIT_REASON::WrQueue)
		{
			continue;
		}

		if (!PI.IsThreadWorkerThread() || state == THREAD_STATE::Running)
		{
			DWORD ThreadID = PI.GetThreadId();
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, ThreadID);
			if (!hThread)
			{
				continue;
			}

			if (NT_SUCCESS(p_RtlQueueApcWow64Thread(hThread, pRemoteFunc, pMem, nullptr, nullptr)))
			{
				PostThreadMessageW(ThreadID, WM_NULL, 0, 0);
				APC_Queued = true;
			}

			CloseHandle(hThread);
		}
	} while (PI.NextThread());

	if (!APC_Queued)
	{
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_QUAPC_ERR_NO_APC_THREAD;
	}

	SR_REMOTE_DATA_WOW64 data;
	data.State			= (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < SR_REMOTE_TIMEOUT)
	{
		if (ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr))
		{
			if (data.State == (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				break;
			}
		}

		Sleep(10);
	}

	if (data.State != (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		return SR_QUAPC_ERR_REMOTE_TIMEOUT;
	}

	Out				= (DWORD)data.Ret;
	LastWin32Error	= data.LastWin32Error;

	return SR_ERR_SUCCESS;
}

#endif