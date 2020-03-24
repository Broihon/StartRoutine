#include "Process Info.h"

#define NEXT_SYSTEM_PROCESS_ENTRY(pCurrent) reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<BYTE*>(pCurrent) + pCurrent->NextEntryOffset)

PEB * ProcessInfo::GetPEB_Native()
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PROCESS_BASIC_INFORMATION PBI{ 0 };
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &size_out);

	if (NT_FAIL(ntRet))
	{
		return nullptr;
	}

	return PBI.pPEB;
}

LDR_DATA_TABLE_ENTRY * ProcessInfo::GetLdrEntry_Native(HINSTANCE hMod)
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PEB * ppeb = GetPEB();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB	peb{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(PEB), nullptr))
	{
		return nullptr;
	}

	PEB_LDR_DATA ldrdata{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA), nullptr))
	{
		return nullptr;
	}

	LIST_ENTRY * pCurrentEntry	= ldrdata.InLoadOrderModuleListHead.Flink;
	LIST_ENTRY * pLastEntry		= ldrdata.InLoadOrderModuleListHead.Blink;

	while (true)
	{
		LDR_DATA_TABLE_ENTRY CurrentEntry{ 0 };
		ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr);

		if (CurrentEntry.DllBase == hMod)
		{
			return reinterpret_cast<LDR_DATA_TABLE_ENTRY *>(pCurrentEntry);
		}
		else if (pCurrentEntry == pLastEntry)
		{
			break;
		}

		pCurrentEntry = CurrentEntry.InLoadOrderLinks.Flink;
	}

	return nullptr;
}

ProcessInfo::ProcessInfo()
{
	HINSTANCE hNTDLL = GetModuleHandle(TEXT("ntdll.dll"));
	if (!hNTDLL)
	{
		return;
	}

	m_pNtQueryInformationProcess	= reinterpret_cast<f_NtQueryInformationProcess>	(GetProcAddress(hNTDLL, "NtQueryInformationProcess"));
	m_pNtQuerySystemInformation		= reinterpret_cast<f_NtQuerySystemInformation>	(GetProcAddress(hNTDLL, "NtQuerySystemInformation"));
	m_pNtQueryInformationThread		= reinterpret_cast<f_NtQueryInformationThread>	(GetProcAddress(hNTDLL, "NtQueryInformationThread"));

	if (!m_pNtQueryInformationProcess || !m_pNtQuerySystemInformation || !m_pNtQueryInformationThread)
	{
		return;
	}

	m_BufferSize	= 0x10000;
	m_pFirstProcess = nullptr;

	m_WaitFunctionReturnAddress[0] = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL, "NtDelayExecution"				)) + NT_RET_OFFSET;
	m_WaitFunctionReturnAddress[1] = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL, "NtWaitForSingleObject"			)) + NT_RET_OFFSET;
	m_WaitFunctionReturnAddress[2] = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL, "NtWaitForMultipleObjects"		)) + NT_RET_OFFSET;
	m_WaitFunctionReturnAddress[3] = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL, "NtSignalAndWaitForSingleObject"	)) + NT_RET_OFFSET;
	m_WaitFunctionReturnAddress[4] = reinterpret_cast<UINT_PTR>(GetProcAddress(hNTDLL, "NtRemoveIoCompletionEx"			)) + NT_RET_OFFSET;

	HINSTANCE hWIN32U = LoadLibrary(TEXT("win32u.dll"));
	if (hWIN32U)
	{
		m_WaitFunctionReturnAddress[5] = reinterpret_cast<UINT_PTR>(GetProcAddress(hWIN32U, "NtUserMsgWaitForMultipleObjectsEx")) + NT_RET_OFFSET;
	}
}

ProcessInfo::~ProcessInfo()
{
	if (m_pFirstProcess)
	{
		delete[] m_pFirstProcess;
	}
}

bool ProcessInfo::SetProcess(HANDLE hTargetProc)
{
	DWORD dwHandleInfo = 0;
	if (!hTargetProc || hTargetProc == INVALID_HANDLE_VALUE || !GetHandleInformation(hTargetProc, &dwHandleInfo))
	{
		return false;
	}

	if (!m_pFirstProcess)
	{
		if (!RefreshInformation())
		{
			return false;
		}
	}

	m_hCurrentProcess = hTargetProc;

	ULONG_PTR PID = GetProcessId(m_hCurrentProcess);

	while (NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess) != m_pCurrentProcess)
	{
		if (m_pCurrentProcess->UniqueProcessId == reinterpret_cast<void*>(PID))
		{
			break;
		}

		m_pCurrentProcess = NEXT_SYSTEM_PROCESS_ENTRY(m_pCurrentProcess);
	}

	if (m_pCurrentProcess->UniqueProcessId != reinterpret_cast<void*>(PID))
	{
		m_pCurrentProcess = m_pFirstProcess;
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInfo::SetThread(DWORD TID)
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	m_pCurrentThread = nullptr;

	for (UINT i = 0; i != m_pCurrentProcess->NumberOfThreads; ++i)
	{
		if (m_pCurrentProcess->Threads[i].ClientId.UniqueThread == reinterpret_cast<void*>(ULONG_PTR(TID)))
		{
			m_CurrentThreadIndex = i;
			m_pCurrentThread = &m_pCurrentProcess->Threads[i];
			break;
		}
	}
	
	if (m_pCurrentThread == nullptr)
	{
		m_CurrentThreadIndex = 0;
		m_pCurrentThread = &m_pCurrentProcess->Threads[0];
		return false;
	}

	return true;
}

bool ProcessInfo::FirstThread()
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	m_CurrentThreadIndex = 0;
	m_pCurrentThread = &m_pCurrentProcess->Threads[0];

	return true;
}

bool ProcessInfo::NextThread()
{
	if (!m_pFirstProcess)
	{
		return false;
	}

	if (m_CurrentThreadIndex == m_pCurrentProcess->NumberOfThreads - 1)
	{
		return false;
	}

	m_pCurrentThread = &m_pCurrentProcess->Threads[++m_CurrentThreadIndex];

	return true;
}

bool ProcessInfo::RefreshInformation()
{
	if (!m_pFirstProcess)
	{
		m_pFirstProcess = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(new BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
		{
			return false;
		}
	}
	else
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return RefreshInformation();
	}

	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQuerySystemInformation(SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);

	while (ntRet == STATUS_INFO_LENGTH_MISMATCH)
	{
		delete[] m_pFirstProcess;

		m_BufferSize	= size_out + 0x1000;
		m_pFirstProcess = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(new BYTE[m_BufferSize]);
		if (!m_pFirstProcess)
		{
			return false;
		}

		ntRet = m_pNtQuerySystemInformation(SystemProcessInformation, m_pFirstProcess, m_BufferSize, &size_out);
	}

	if (NT_FAIL(ntRet))
	{
		delete[] m_pFirstProcess;
		m_pFirstProcess = nullptr;

		return false;
	}

	m_pCurrentProcess	= m_pFirstProcess;
	m_pCurrentThread	= &m_pCurrentProcess->Threads[0];

	return true;
}

PEB * ProcessInfo::GetPEB()
{
	return GetPEB_Native();
}

LDR_DATA_TABLE_ENTRY * ProcessInfo::GetLdrEntry(HINSTANCE hMod)
{
	return GetLdrEntry_Native(hMod);
}

DWORD ProcessInfo::GetPID()
{
	return GetProcessId(m_hCurrentProcess);
}

bool ProcessInfo::IsNative()
{
	BOOL bOut = FALSE;
	IsWow64Process(m_hCurrentProcess, &bOut);
	return (bOut == FALSE);
}

void * ProcessInfo::GetEntrypoint()
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}

	PEB * ppeb = GetPEB();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB	peb;
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(PEB), nullptr))
	{
		return nullptr;
	}

	PEB_LDR_DATA ldrdata;
	if (!ReadProcessMemory(m_hCurrentProcess, peb.Ldr, &ldrdata, sizeof(PEB_LDR_DATA), nullptr))
	{
		return nullptr;
	}

	LIST_ENTRY * pCurrentEntry	= ldrdata.InLoadOrderModuleListHead.Flink;
	LIST_ENTRY * pLastEntry		= ldrdata.InLoadOrderModuleListHead.Blink;
	
	wchar_t NameBuffer[MAX_PATH]{ 0 };
	while (true)
	{
		LDR_DATA_TABLE_ENTRY CurrentEntry;
		if (ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))
		{
			if (ReadProcessMemory(m_hCurrentProcess, CurrentEntry.BaseDllName.szBuffer, NameBuffer, CurrentEntry.BaseDllName.Length, nullptr))
			{
				if (NameBuffer[CurrentEntry.BaseDllName.Length / 2 - 1] == 'e')
				{
					return CurrentEntry.EntryPoint;
				}
			}
		}

		if (pCurrentEntry == pLastEntry)
		{
			break;
		}

		pCurrentEntry = CurrentEntry.InLoadOrderLinks.Flink;
	}

	return nullptr;
}

DWORD ProcessInfo::GetTID()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(reinterpret_cast<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

DWORD ProcessInfo::GetThreadId()
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	return DWORD(reinterpret_cast<ULONG_PTR>(m_pCurrentThread->ClientId.UniqueThread) & 0xFFFFFFFF);
}

bool ProcessInfo::GetThreadState(THREAD_STATE & state, KWAIT_REASON & reason)
{
	if (!m_pCurrentThread)
	{
		return 0;
	}

	state	= m_pCurrentThread->ThreadState;
	reason	= m_pCurrentThread->WaitReason;

	return true;
}

bool ProcessInfo::GetThreadStartAddress(void *& start_address)
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	if (!IsNative())
	{
		return GetThreadStartAddress_WOW64(start_address);
	}

	start_address = m_pCurrentThread->StartAddress;

	return true;
}

bool ProcessInfo::GetThreadStartAddress_WOW64(void *& start_address)
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)(UINT_PTR)(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	if (NT_SUCCESS(m_pNtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &start_address, sizeof(start_address), nullptr)))
	{
		CloseHandle(hThread);

		return true;
	}

	CloseHandle(hThread);

	return false;
}

bool ProcessInfo::IsThreadInAlertableState()
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, (DWORD)(UINT_PTR)(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	CONTEXT ctx{ 0 };
	ctx.ContextFlags = CONTEXT_ALL;

	if (!GetThreadContext(hThread, &ctx))
	{
		CloseHandle(hThread);

		return false;
	}

	CloseHandle(hThread);

#ifdef _WIN64

	if (ctx.Rip == m_WaitFunctionReturnAddress[0])
	{
		return (ctx.Rcx == TRUE);
	} 
	else if (ctx.Rip == m_WaitFunctionReturnAddress[1])
	{
		return (ctx.Rdx == TRUE);
	} 
	else if (ctx.Rip == m_WaitFunctionReturnAddress[2])
	{
		return (ctx.Rsi == TRUE);
	} 
	else if (ctx.Rip == m_WaitFunctionReturnAddress[3])
	{
		return (ctx.Rsi == TRUE);
	} 
	else if (ctx.Rip == m_WaitFunctionReturnAddress[4] && ctx.Rsp)
	{
		UINT_PTR buffer = 0;
		if (ReadProcessMemory(m_hCurrentProcess, reinterpret_cast<void*>(ctx.Rsp + 0x30), &buffer, sizeof(buffer), nullptr))
		{
			return (buffer == TRUE);
		}
	}
	else if (ctx.Rip == m_WaitFunctionReturnAddress[5] && ctx.Rsp)
	{
		UINT_PTR buffer = 0;
		if (ReadProcessMemory(m_hCurrentProcess, reinterpret_cast<void*>(ctx.Rsp + 0x28), &buffer, sizeof(buffer), nullptr))
		{
			return ((buffer & MWMO_ALERTABLE) != 0);
		}
	} 

#else

	if (!ctx.Esp)
	{
		return false;
	}

	DWORD stack_buffer[6] = { 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, reinterpret_cast<void*>(ctx.Esp), stack_buffer, sizeof(stack_buffer), nullptr))
	{
		return false;
	}

	if (ctx.Eip == m_WaitFunctionReturnAddress[0])
	{
		return (stack_buffer[1] == TRUE);
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[1])
	{
		return (stack_buffer[2] == TRUE);
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[2])
	{
		return (stack_buffer[4] == TRUE);
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[3])
	{
		return (stack_buffer[3] == TRUE);
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[4])
	{
		return (stack_buffer[4] == TRUE);
	}
	else if (ctx.Eip == m_WaitFunctionReturnAddress[5])
	{
		return ((stack_buffer[5] & MWMO_ALERTABLE) != 0);
	}

#endif

	return false;
}

bool ProcessInfo::IsThreadWorkerThread()
{
	if (!m_pCurrentThread)
	{
		return false;
	}

	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)(UINT_PTR)(m_pCurrentThread->ClientId.UniqueThread));
	if (!hThread)
	{
		return false;
	}

	THREAD_BASIC_INFORMATION tbi{ 0 };
	if (FAILED(m_pNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr)) || !tbi.TebBaseAddress)
	{
		return false;
	}

	CloseHandle(hThread);

	USHORT TebInfo = NULL;
	if (ReadProcessMemory(m_hCurrentProcess, reinterpret_cast<BYTE *>(tbi.TebBaseAddress) + TEB_SAMETEBFLAGS, &TebInfo, sizeof(TebInfo), nullptr))
	{
		return ((TebInfo & 0x2000) != 0);
	}

	return false;
}

const SYSTEM_PROCESS_INFORMATION * ProcessInfo::GetProcessInfo()
{
	return m_pFirstProcess ? m_pCurrentProcess : nullptr;
}

const SYSTEM_THREAD_INFORMATION * ProcessInfo::GetThreadInfo()
{
	return m_pFirstProcess ? m_pCurrentThread : nullptr;
}

#ifdef _WIN64

PEB32 * ProcessInfo::GetPEB_WOW64()
{
	if (!m_pFirstProcess)
	{
		return 0;
	}

	ULONG_PTR pPEB;
	ULONG size_out = 0;
	NTSTATUS ntRet = m_pNtQueryInformationProcess(m_hCurrentProcess, ProcessWow64Information, &pPEB, sizeof(pPEB), &size_out);

	if (NT_FAIL(ntRet))
	{ 
		return nullptr;
	}

	return reinterpret_cast<PEB32 *>(pPEB);
}

LDR_DATA_TABLE_ENTRY32 * ProcessInfo::GetLdrEntry_WOW64(HINSTANCE hMod)
{
	if (!m_pFirstProcess)
	{
		return nullptr;
	}
	
	PEB32 * ppeb = GetPEB_WOW64();
	if (!ppeb)
	{
		return nullptr;
	}

	PEB32 peb{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, ppeb, &peb, sizeof(PEB32), nullptr))
	{
		return nullptr;
	}
	
	PEB_LDR_DATA32 ldrdata{ 0 };
	if (!ReadProcessMemory(m_hCurrentProcess, (void*)(UINT_PTR)(peb.Ldr), &ldrdata, sizeof(PEB_LDR_DATA32), nullptr))
	{
		return nullptr;
	}
		
	LIST_ENTRY32 * pCurrentEntry	= reinterpret_cast<LIST_ENTRY32*>((ULONG_PTR)ldrdata.InLoadOrderModuleListHead.Flink);
	LIST_ENTRY32 * pLastEntry		= reinterpret_cast<LIST_ENTRY32*>((ULONG_PTR)ldrdata.InLoadOrderModuleListHead.Blink);

	while (true)
	{
		LDR_DATA_TABLE_ENTRY32 CurrentEntry{ 0 };
		ReadProcessMemory(m_hCurrentProcess, pCurrentEntry, &CurrentEntry, sizeof(LDR_DATA_TABLE_ENTRY32), nullptr);

		if (CurrentEntry.DllBase == (DWORD)(UINT_PTR)(hMod))
		{
			return reinterpret_cast<LDR_DATA_TABLE_ENTRY32*>(pCurrentEntry);
		}
		else if (pCurrentEntry == pLastEntry)			
		{
			break;
		}

		pCurrentEntry = reinterpret_cast<LIST_ENTRY32*>((ULONG_PTR)CurrentEntry.InLoadOrderLinks.Flink);
	}

	return nullptr;
}

#endif