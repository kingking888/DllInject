#include "DllInject.h"

#define DEBUG 1

BOOL CDllInject::CreateRemoteThreadInject(DWORD dwPid,const char* pszFilePath)
{
	HANDLE hProcess = NULL;
	HANDLE hRemoteThread = NULL;
	PVOID pRemoteBuffer = NULL;
	PROC pLoadLibarayAddress = NULL;
	SIZE_T dwPathSize = strlen(pszFilePath) + 1;
	BOOL bFlag = FALSE;

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)	//�˴�����INVALID_HANDLE_VALUE�����Ǹ���ʷ�����Ĵ�ӣ���ʱ�����жϾ����Ҫ����Ӧ�����ķ���ֵ
	{
		if (DEBUG)
		{
			printf("OpenProcess Fail:%x\n", GetLastError());
		}
		return FALSE;
	}

	pRemoteBuffer = VirtualAllocEx(hProcess, NULL, dwPathSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pRemoteBuffer)
	{
		if (DEBUG)
		{
			printf("VirtualAllocEx Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	bFlag = WriteProcessMemory(hProcess, pRemoteBuffer, pszFilePath, dwPathSize, NULL);
	if (!bFlag)
	{
		if (DEBUG)
		{
			printf("WriteProcessMemory Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hKernel32 = NULL;
	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
	{
		if (DEBUG)
		{
			printf("WriteProcessMemory Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}
	pLoadLibarayAddress = GetProcAddress(hKernel32, "LoadLibraryA");
	if (!pLoadLibarayAddress)
	{
		if (DEBUG)
		{
			printf("GetProcAddress Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibarayAddress, pRemoteBuffer, 0, NULL);
	if (!hRemoteThread)
	{
		if (DEBUG)
		{
			printf("CreateRemoteThread Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);

	return TRUE;
}

BOOL EnableDebugPriv(LPCWSTR name)
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tp;
	// �򿪽�������
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		printf("[!]Get Process Token Error!\n");
		return false;
	}
	// ��ȡȨ��Luid
	if (!LookupPrivilegeValue(NULL, name, &luid))
	{
		printf("[!]Get Privilege Error!\n");
		return false;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	// �޸Ľ���Ȩ��
	if (!AdjustTokenPrivileges(hToken, false, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]Adjust Privilege Error!\n");
		return false;
	}
	return true;
}

BOOL CDllInject::ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath)
{
	HANDLE hProcess = NULL;
	HANDLE hRemoteThread = NULL;
	PVOID pRemoteBuffer = NULL;
	PROC pLoadLibarayAddress = NULL;
	SIZE_T dwPathSize = strlen(pszFilePath) + 1;
	BOOL bFlag = FALSE;

	//EnableDebugPriv(SE_DEBUG_NAME);

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProcess == NULL)	//�˴�����INVALID_HANDLE_VALUE�����Ǹ���ʷ�����Ĵ�ӣ���ʱ�����жϾ����Ҫ����Ӧ�����ķ���ֵ
	{
		if (DEBUG)
		{
			printf("OpenProcess Fail:%x\n", GetLastError());
		}
		return FALSE;
	}

	pRemoteBuffer = VirtualAllocEx(hProcess, NULL, dwPathSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pRemoteBuffer)
	{
		if (DEBUG)
		{
			printf("VirtualAllocEx Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	bFlag = WriteProcessMemory(hProcess, pRemoteBuffer, pszFilePath, dwPathSize, NULL);
	if (!bFlag)
	{
		if (DEBUG)
		{
			printf("WriteProcessMemory Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hKernel32 = NULL;
	hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
	{
		if (DEBUG)
		{
			printf("GetKernel32ModuleHandleA Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}
	pLoadLibarayAddress = GetProcAddress(hKernel32, "LoadLibraryA");
	if (!pLoadLibarayAddress)
	{
		if (DEBUG)
		{
			printf("GetProcAddress Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

	HMODULE hNtdll = NULL;
	hNtdll = GetModuleHandleA("ntdll.dll");
	//hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll)
	{
		if (DEBUG)
		{
			printf("GetNtdllModuleHandleA Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}

#ifdef _WIN64
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		ULONG CreateThreadFlags,
		SIZE_T ZeroBits,
		SIZE_T StackSize,
		SIZE_T MaximumStackSize,
		LPVOID pUnkown);
#else
	typedef DWORD(WINAPI* typedef_ZwCreateThreadEx)(
		PHANDLE ThreadHandle,   //�߳̾��
		ACCESS_MASK DesiredAccess,
		LPVOID ObjectAttributes,
		HANDLE ProcessHandle,	//���̾��
		LPTHREAD_START_ROUTINE lpStartAddress,
		LPVOID lpParameter,
		BOOL CreateSuspended,
		DWORD dwStackSize,
		DWORD dw1,
		DWORD dw2,
		LPVOID pUnkown);
#endif

	typedef_ZwCreateThreadEx ZwCreateThreadEx = NULL;
	ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
	if (ZwCreateThreadEx == NULL)
	{
		if (DEBUG)
		{
			printf("GetZwCreateThreadExProcAddress Fail:%x\n", GetLastError());
		}
		CloseHandle(hProcess);
		return FALSE;
	}


	NTSTATUS ntStatus = ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoadLibarayAddress, pRemoteBuffer, FALSE, 0, 0, 0, NULL);
	if (ntStatus < 0)
	{
		if (DEBUG)
		{
			printf("ZwCreateThreadEx Fail:%x\n", ntStatus);
		}
		CloseHandle(hProcess);
		return FALSE;
	}


	CloseHandle(hProcess);
	CloseHandle(hRemoteThread);

	return TRUE;

	return 0;
}

BOOL CDllInject::QueueUserAPCInject(DWORD CurrentWindowThreadId, const char* pszFilePath)
{

	return 0;
}



HHOOK g_hHook = NULL;

LRESULT HookCallbackProc(int code, WPARAM wParam, LPARAM lParam)
{
	return CallNextHookEx(g_hHook, code, wParam, lParam);
}

BOOL CDllInject::SetWindowsHookExInject(DWORD CurrentWindowThreadId, const char* pszFilePath)
{
	HMODULE hMod = NULL;
	hMod = LoadLibraryA(pszFilePath);
	if (hMod == NULL)
	{
		if (DEBUG)
		{
			printf("LoadLibrary Fail:%x\n", GetLastError());
			system("pause");
		}
		return false;
	}

	//g_hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)HookCallbackProc, hMod, CurrentWindowThreadId);
	g_hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)HookCallbackProc, hMod, CurrentWindowThreadId);
	if (g_hHook == NULL)
	{
		if (DEBUG)
		{
			printf("Hook Fail:%x\n", GetLastError());
			system("pause");
		}
		return false;
	}
	else
	{
		printf("Hook Success\n");
		system("pause");
	}

	if (!UnhookWindowsHookEx(g_hHook))
	{
		if (DEBUG)
{
			printf("UnHook Fail:%x\n", GetLastError());
			system("pause");
		}
		return false;
	}
	printf("UnHook Success\n");
	system("pause");

	return TRUE;
}
