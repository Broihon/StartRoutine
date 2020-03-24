#pragma once

#include "Start Routine.h"
#include "Process Info.h"

#define ReCa reinterpret_cast

#define PTR_64_ARR 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
#define PTR_86_ARR 0x00, 0x00, 0x00, 0x00,

#define SR_REMOTE_DATA_BUFFER_64 PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR PTR_64_ARR
#define SR_REMOTE_DATA_BUFFER_86 PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR PTR_86_ARR

#ifndef NT_FAIL
#define NT_FAIL(status) (status < 0)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(status) (status >= 0)
#endif

enum class SR_REMOTE_STATE : ULONG_PTR
{
	SR_RS_ExecutionPending	= 0,
	SR_RS_Executing			= 1,
	SR_RS_ExecutionFinished = 2
};

struct SR_REMOTE_DATA
{
	SR_REMOTE_STATE		State;
	ULONG_PTR			Ret;
	DWORD				LastWin32Error;
	void			*	pArg;
	void			*	pRoutine;
	UINT_PTR			Buffer;
};

DWORD SR_NtCreateThreadEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error, bool CloakThread,			DWORD & Out);
DWORD SR_HijackThread		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_SetWindowsHookEx	(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_QueueUserAPC		(HANDLE hTargetProc, f_Routine pRoutine, void * pArg, DWORD & LastWin32Error,							DWORD & Out);

#ifdef _WIN64

struct SR_REMOTE_DATA_WOW64
{
	DWORD State;
	DWORD Ret;
	DWORD LastWin32Error;
	DWORD pArg;
	DWORD pRoutine;
	DWORD Buffer;
};

#define SR_REMOTE_DATA_BUFFER_WOW64 SR_REMOTE_DATA_BUFFER_86

DWORD SR_NtCreateThreadEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error, bool CloakThread,		DWORD & Out);
DWORD SR_HijackThread_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_SetWindowsHookEx_WOW64	(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error,							DWORD & Out);
DWORD SR_QueueUserAPC_WOW64		(HANDLE hTargetProc, f_Routine_WOW64 pRoutine, DWORD pArg, DWORD & LastWin32Error,							DWORD & Out);

#endif