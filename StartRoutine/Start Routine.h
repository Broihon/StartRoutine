#pragma once

#include <Windows.h>
#include <vector>

#include "Error.h"

enum class LAUNCH_METHOD
{
	LM_NtCreateThreadEx,
	LM_HijackThread,
	LM_SetWindowsHookEx,
	LM_QueueUserAPC
};
//enum which is used to select the method to execute the shellcode

#ifdef _WIN64
using f_Routine			= DWORD(__fastcall*)(void * pArg);
using f_Routine_WOW64	= DWORD; //DWORD(__stdcall*)(void * pArg);
#else
using f_Routine = DWORD(__stdcall*)(void * pArg);
#endif

#define SR_REMOTE_TIMEOUT 2000

DWORD StartRoutine(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, LAUNCH_METHOD Method, bool CloakThread, DWORD & LastWin32Error, DWORD & Out);
//Executes shellcode in the target process.
//
//Arguments:
//		hTargetProc (HANDLE):
///			A handle to the target process. Access rights depend on the launch method. PROCESS_ALL_ACCESS is the best option here.
//		pRoutine (f_Routine):
///			A pointer to the shellcode in the virtual memory of the target process.
//		pArg (void*):
///			A pointer to the argument which gets passed to the shellcode.
//		Method (LAUNCH_METHOD):
///			A LAUNCH_METHOD enum which defines the method to be used when executing the shellcode.
//		CloakThread (bool):
///			A boolean which is only used when the Method parameter is LM_NtCreateThreadEx. Then a few cloaking related flags get passed to NtCreateThreadEx.
//		LastWin32Error (DWORD&):
///			A reference to a DWORD which can be used to store an errorcode if something goes wrong. Otherwise it's INJ_ERROR_SUCCESS (0).
//		hOut (ULONG_PTR&):
///			A reference to a ULONG_PTR which is used to store the returned value of the shellcode. This can be changed into any datatype (a 32 bit type on x86 and a 64 bit type on x64).
//
//Returnvalue (DWORD):
///		On success: 0 (SR_ERROR_SUCCESS).
///		On failure:	An errorcode from Error.h (start routine section).


#ifdef _WIN64
DWORD StartRoutine_WOW64(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, LAUNCH_METHOD Method, bool CloakThread, DWORD & LastWin32Error, DWORD & Out);
//Equivalent of StartRoutine when injecting from x64 into a WOW64 process. For documentation check the comments on StartRoutine.
#endif