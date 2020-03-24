#ifdef _WIN64

#include "SetWindowsHookEx.h"

DWORD SR_SetWindowsHookEx_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error, DWORD & Out)
{
	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		LastWin32Error = GetLastError();

		return SR_SWHEX_ERR_VAE_FAIL;
	}
	
	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x53,								// + 0x00			-> push	ebx						; push ebx on stack (non volatile)
		0xBB, 0x00, 0x00, 0x00, 0x00,		// + 0x01 (+ 0x02)	-> mov	ebx, 0x00000000			; move pData into ebx (update address manually on runtime)
		0x83, 0x3B, 0x00,					// + 0x06			-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA_WOW64::State is equal to (DWORD)SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x09			-> jne	0x2A					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x0B			-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA_WOW64::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x0E			-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x11			-> call dword ptr [ebx + 0x10]	; call pRoutine
		0x89, 0x43, 0x04,					// + 0x14			-> mov	[ebx + 0x04], eax		; store returned value

		0x85, 0xC0,							// + 0x17			-> test eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x19			-> je	0x27					; jmp if equal/zero

		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1B			-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x21			-> mov	eax, [eax + 0x34]		;
		0x89, 0x43, 0x08,					// + 0x24			-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA_WOW64::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x27			-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA_WOW64::State to (DWORD)SR_RS_ExecutionFinished

		0x5B,								// + 0x2A			-> pop	ebx						; restore ebx
		0x31, 0xC0,							// + 0x2B			-> xor	eax, eax				; set eax to 0 to prevent further handling of the message
		0xC2, 0x04, 0x00					// + 0x2D			-> ret	0x04					; return
	}; // SIZE = 0x30 (+ sizeof(SR_REMOTE_DATA_WOW64))

	*ReCa<DWORD*>(Shellcode + 0x02 + sizeof(SR_REMOTE_DATA_WOW64)) = (DWORD)(UINT_PTR)(pMem);

	void * pRemoteFunc = ReCa<BYTE *>(pMem) + sizeof(SR_REMOTE_DATA_WOW64);

	auto * sr_data = ReCa<SR_REMOTE_DATA_WOW64*>(Shellcode);
	sr_data->pArg		= pArg;
	sr_data->pRoutine	= pRoutine;

	if (!WriteProcessMemory(hTargetProc, pMem, Shellcode, sizeof(Shellcode), nullptr))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_SWHEX_ERR_WPM_FAIL;
	}

	EnumWindowsCallback_Data window_data;
	window_data.m_PID		= GetProcessId(hTargetProc);
	window_data.m_pHook		= reinterpret_cast<HOOKPROC>(pRemoteFunc);
	window_data.m_hModule	= GetModuleHandleW(L"kernel32.dll");

	if (!EnumWindows(EnumWindowsCallback, reinterpret_cast<LPARAM>(&window_data)))
	{
		LastWin32Error = GetLastError();

		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_SWHEX_ERR_ENUM_WINDOWS_FAIL;
	}

	if (window_data.m_HookData.empty())
	{
		VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

		return SR_SWHEX_ERR_NO_WINDOWS;
	}

	for (auto i : window_data.m_HookData)
	{
		SetForegroundWindow(i.m_hWnd);
		SendMessageW(i.m_hWnd, WM_KEYDOWN, VK_SPACE, 0);
		Sleep(10);
		SendMessageW(i.m_hWnd, WM_KEYUP, VK_SPACE, 0);
		UnhookWindowsHookEx(i.m_hHook);
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

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	if (data.State != (DWORD)SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		return SR_SWHEX_ERR_REMOTE_TIMEOUT;
	}

	Out				= data.Ret;
	LastWin32Error	= data.LastWin32Error;

	return SR_ERR_SUCCESS;
}

#endif