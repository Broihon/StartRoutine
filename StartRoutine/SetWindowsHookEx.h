#pragma once

#include "StartRoutine_internal.h"

struct HookData
{
	HHOOK	m_hHook;
	HWND	m_hWnd;
};

struct EnumWindowsCallback_Data
{
	std::vector<HookData>	m_HookData;
	DWORD					m_PID		= 0;
	HOOKPROC				m_pHook		= nullptr;
	HINSTANCE				m_hModule	= NULL;
};

BOOL CALLBACK EnumWindowsCallback(HWND hWnd, LPARAM lParam);