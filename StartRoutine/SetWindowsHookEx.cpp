#include "SetWindowsHookEx.h"

DWORD SR_SetWindowsHookEx(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error, DWORD & Out)
{
	void * pMem = VirtualAllocEx(hTargetProc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pMem)
	{
		LastWin32Error = GetLastError();

		return SR_SWHEX_ERR_VAE_FAIL;
	}
	
#ifdef _WIN64

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_64

		0x53,													// + 0x00	-> push rbx						; push rbx on stack (non volatile)
		0x48, 0x8D, 0x1D, 0xC8, 0xFF, 0xFF, 0xFF,				// + 0x01	-> lea rbx, [-0x30]				; load pData into rbx

		0x83, 0x3B, 0x00,										// + 0x08	-> cmp	dword ptr [rbx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x33,												// + 0x0B	-> jne	0x41					; jump if not equal

		0xC7, 0x03, 0x01, 0x00, 0x00, 0x00,						// + 0x0D	-> mov	[rbx], 1				; set SR_REMOTE_DATA::State to SR_RS_Executing

		0x48, 0x8B, 0x4B, 0x18,									// + 0x13	-> mov  rcx, [rbx + 0x18]		; move pArg into rcx
		0x48, 0x83, 0xEC, 0x20,									// + 0x17	-> sub	rsp, 0x20				; reserve stack
		0xFF, 0x53, 0x20,										// + 0x1B	-> call qword ptr [rbx + 0x20]	; call pRoutine
		0x48, 0x83, 0xC4, 0x20,									// + 0x1E	-> add	rsp, 0x20				; update stack
		0x48, 0x89, 0x43, 0x08,									// + 0x22	-> mov	[rbx + 0x08], rax		; store returned value

		0x48, 0x85, 0xC0,										// + 0x26	-> test rax, rax				; check if rax is 0 (SUCCESS)
		0x74, 0x0F,												// + 0x29	-> je	0x3B					; jmp if equal/zero

		0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,	// + 0x2B	-> mov	rax, gs:[0x30]			; GetLastError
		0x8B, 0x40, 0x68,										// + 0x34	-> mov	eax, [rax + 0x68]
		0x89, 0x43, 0x10,										// + 0x37	-> mov	[rbx + 0x10], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC7, 0x03, 0x02, 0x00, 0x00, 0x00,						// + 0x3A	-> mov	[rbx], 2				; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,													// + 0x40	-> pop	rbx						; restore rbx

		0x48, 0x31, 0xC0,										// + 0x41	-> xor	rax, rax				; set rax to 0 to prevent further handling of the message

		0xC3													// + 0x44	-> ret							; return
	}; // SIZE = 0x45 (+ sizeof(SR_REMOTE_DATA))
	
#else

	BYTE Shellcode[] =
	{
		SR_REMOTE_DATA_BUFFER_86

		0x53,								// + 0x00			-> push	ebx						; push ebx on stack (non volatile)
		0xBB, 0x00, 0x00, 0x00, 0x00,		// + 0x01 (+ 0x02)	-> mov	ebx, 0x00000000			; move pData into ebx (update address manually on runtime)
		0x83, 0x3B, 0x00,					// + 0x06			-> cmp	dword ptr [ebx], 0x00	; test if SR_REMOTE_DATA::State is equal to SR_RS_ExecutionPending
		0x75, 0x1F,							// + 0x09			-> jne	0x2A					; jump if not equal

		0xC6, 0x03, 0x01,					// + 0x0B			-> mov	byte ptr [ebx], 1		; set SR_REMOTE_DATA::State to SR_RS_Executing

		0xFF, 0x73, 0x0C,					// + 0x0E			-> push	[ebx + 0x0C]			; push pArg
		0xFF, 0x53, 0x10,					// + 0x11			-> call dword ptr [ebx + 0x10]	; call pRoutine
		0x89, 0x43, 0x04,					// + 0x14			-> mov	[ebx + 0x04], eax		; store returned value
		
		0x85, 0xC0,							// + 0x17			-> test eax, eax				; check if eax is 0 (SUCCESS)
		0x74, 0x0C,							// + 0x19			-> je	0x27					; jmp if equal/zero
		
		0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,	// + 0x1B			-> mov	eax, fs:[0x18]			; GetLastError
		0x8B, 0x40, 0x34,					// + 0x21			-> mov	eax, [eax + 0x34]
		0x89, 0x43, 0x08,					// + 0x24			-> mov	[ebx + 0x08], eax		; store in SR_REMOTE_DATA::LastWin32Error

		0xC6, 0x03, 0x02,					// + 0x27			-> mov	byte ptr [ebx], 2		; set SR_REMOTE_DATA::State to SR_RS_ExecutionFinished

		0x5B,								// + 0x2A			-> pop	ebx						; restore ebx
		0x31, 0xC0,							// + 0x2B			-> xor	eax, eax				; set eax to 0 to prevent further handling of the message
		0xC2, 0x04, 0x00					// + 0x2D			-> ret	0x04					; return
	}; // SIZE = 0x30 (+ sizeof(SR_REMOTE_DATA))

	*ReCa<void**>(Shellcode + 0x02 + sizeof(SR_REMOTE_DATA)) = pMem;

#endif
	
	void * pRemoteFunc = ReCa<BYTE*>(pMem) + sizeof(SR_REMOTE_DATA);

	auto * sr_data = ReCa<SR_REMOTE_DATA*>(Shellcode);
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
	
	SR_REMOTE_DATA data;
	data.State			= SR_REMOTE_STATE::SR_RS_ExecutionPending;
	data.Ret			= ERROR_SUCCESS;
	data.LastWin32Error = ERROR_SUCCESS;

	auto Timer = GetTickCount64();
	while (GetTickCount64() - Timer < SR_REMOTE_TIMEOUT)
	{
		if (ReadProcessMemory(hTargetProc, pMem, &data, sizeof(data), nullptr))
		{
			if (data.State == SR_REMOTE_STATE::SR_RS_ExecutionFinished)
			{
				break;
			}
		}

		Sleep(10);
	}

	VirtualFreeEx(hTargetProc, pMem, 0, MEM_RELEASE);

	if (data.State != SR_REMOTE_STATE::SR_RS_ExecutionFinished)
	{
		return SR_SWHEX_ERR_REMOTE_TIMEOUT;
	}

	Out				= (DWORD)data.Ret;
	LastWin32Error	= data.LastWin32Error;

	return SR_ERR_SUCCESS;
}

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam)
{
	auto * data = reinterpret_cast<EnumWindowsCallback_Data *>(lParam);

	DWORD winPID = 0;
	DWORD winTID = GetWindowThreadProcessId(hWnd, &winPID);

	if (winPID == data->m_PID)
	{
		wchar_t szWindow[MAX_PATH]{ 0 };
		if (IsWindowVisible(hWnd) && GetWindowTextW(hWnd, szWindow, MAX_PATH))
		{
			if (GetClassNameW(hWnd, szWindow, MAX_PATH) && wcscmp(szWindow, L"ConsoleWindowClass"))
			{
				HHOOK hHook = SetWindowsHookEx(WH_CALLWNDPROC, data->m_pHook, data->m_hModule, winTID);
				if (hHook)
				{
					data->m_HookData.push_back({ hHook, hWnd });
				}
			}
		}
	}

	return TRUE;
}