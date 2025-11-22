// dllmain.cpp : Defines the entry point for the DLL application.
// Author : AlSch092 @ Github
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <stdio.h>
#include <atomic>
#include "disasm-lib/mhook.h"

#define DRIVER_NAME L"\\\\.\\HandleDrv"

#define FILE_DEVICE_UNKNOWN   0x00000022
#define METHOD_BUFFERED 0
#define FILE_ANY_ACCESS 0

#define CTL_CODE( DeviceType, Function, Method, Access ) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )

#define IOCTL_OPEN_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_CLOSE_HANDLE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OPEN_PROC_REQUEST {
	ULONG Pid;
	ACCESS_MASK Access;
} OPEN_PROC_REQUEST, * POPEN_PROC_REQUEST;

typedef struct _OPEN_PROC_RESPONSE {
	HANDLE HandleValue;     // returned handle
} OPEN_PROC_RESPONSE, * POPEN_PROC_RESPONSE;

typedef struct _CLOSE_HANDLE_REQUEST {
	ULONG Pid;
	HANDLE HandleValue;
} CLOSE_HANDLE_REQUEST, * PCLOSE_HANDLE_REQUEST;

std::atomic<bool> g_bHooked = false;
std::atomic<uintptr_t> g_OpenProcessAddr = 0;

HANDLE FetchPseudohandle(__in const DWORD pid, __in const ACCESS_MASK access)
{
	HANDLE h = CreateFileW(DRIVER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

	if (h == NULL || h == INVALID_HANDLE_VALUE)
	{
		printf("[ERROR] OpenProcessHook: CreateFileW failed\n");
		return NULL;
	}

	OPEN_PROC_REQUEST req = { pid, access };
	OPEN_PROC_RESPONSE resp;

	DWORD bytesReturned = 0;

	if (DeviceIoControl(h, IOCTL_OPEN_PROCESS, &req, sizeof(req), &resp, sizeof(resp), &bytesReturned, NULL))
	{
		printf("Kernel gave us handle: %p\n", resp.HandleValue);
		CloseHandle(h);
		return resp.HandleValue;
	}
	else
	{
		printf("[ERROR] DeviceIoControl: failed with %d, %p\n", GetLastError(), resp.HandleValue);
		return NULL;
	}
}

HANDLE OpenProcessHook(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	return FetchPseudohandle(dwProcessId, dwDesiredAccess);
}

bool InitEasyHandlesAgent()
{
	HMODULE hModule = GetModuleHandleA("kernel32.dll");

	if (!hModule)
	{
		printf("[ERROR] Failed to hook OpenProcess: GetModuleHandleA failed with: %d\n ", GetLastError());
		return false;
	}

	g_OpenProcessAddr.store((uintptr_t)GetProcAddress(hModule, "OpenProcess"), std::memory_order_relaxed);

	if (!g_OpenProcessAddr)
	{
		printf("[ERROR] Failed to hook OpenProcess: GetProcAddress failed with: %d\n", GetLastError());
		return false;
	}

	uintptr_t HookFunc = (uintptr_t)&OpenProcessHook;
	uintptr_t HookedFunc = (uintptr_t)g_OpenProcessAddr.load(std::memory_order_relaxed);

	//set hook
	if (Mhook_SetHook((PVOID*)&HookedFunc, (PVOID)HookFunc))
	{
		printf("Successfully hooked OpenProcess!\n");
		g_bHooked = true;
	}
	else
	{
		printf("[ERROR] Failed to hook OpenProcess!\n");
		return false;
	}

	return true;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		freopen("CONIN$", "r", stdin);

		InitEasyHandlesAgent();

		//{
		//    HANDLE t = FetchPseudohandle(16320, PROCESS_ALL_ACCESS); //...or if you want to test on an individual PID without hooking `OpenProcess`

		//    if (t != INVALID_HANDLE_VALUE)
		//    {
		//        CloseHandle(t);
		//    }
		//}

	} break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		if (g_bHooked)
		{
			Mhook_Unhook((PVOID*)&OpenProcess);
		}
		break;
	}
	return TRUE;
}

