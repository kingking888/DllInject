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
	WaitForSingleObject(hRemoteThread, 1000);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

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

	WaitForSingleObject(hRemoteThread, 1000);

	CloseHandle(hRemoteThread);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL GetAllThreadIdByProcessId(DWORD dwProcessId, DWORD** ppThreadId, DWORD* pdwThreadIdLength)
{
	DWORD* pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	DWORD dwBufferLength = 1000;
	THREADENTRY32 te32 = { 0 };
	HANDLE hSnapshot = NULL;
	BOOL bRet = TRUE;

	do
	{
		// �����ڴ�
		pThreadId = new DWORD[dwBufferLength];
		if (NULL == pThreadId)
		{
			printf("new");
			bRet = FALSE;
			break;
		}
		::RtlZeroMemory(pThreadId, (dwBufferLength * sizeof(DWORD)));

		// ��ȡ�߳̿���
		::RtlZeroMemory(&te32, sizeof(te32));
		te32.dwSize = sizeof(te32);
		hSnapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (NULL == hSnapshot)
		{
			printf("CreateToolhelp32Snapshot");
			bRet = FALSE;
			break;
		}

		// ��ȡ��һ���߳̿�����Ϣ
		bRet = ::Thread32First(hSnapshot, &te32);
		while (bRet)
		{
			// ��ȡ���̶�Ӧ���߳�ID
			if (te32.th32OwnerProcessID == dwProcessId)
			{
				pThreadId[dwThreadIdLength] = te32.th32ThreadID;
				dwThreadIdLength++;
			}

			// ������һ���߳̿�����Ϣ
			bRet = ::Thread32Next(hSnapshot, &te32);
		}

		// ����
		*ppThreadId = pThreadId;
		*pdwThreadIdLength = dwThreadIdLength;
		bRet = TRUE;

	} while (FALSE);

	if (FALSE == bRet)
	{
		if (pThreadId)
		{
			delete[]pThreadId;
			pThreadId = NULL;
		}
	}
	return bRet;
}

BOOL CDllInject::QueueUserAPCInject(DWORD dwPid, const char* pszFilePath)
{
	BOOL bRet = FALSE;
	DWORD* pThreadId = NULL;
	DWORD dwThreadIdLength = 0;
	HANDLE hProcess = NULL, hThread = NULL;
	PVOID pBaseAddress = NULL;
	PVOID pLoadLibraryAFunc = NULL;
	SIZE_T dwRet = 0, dwDllPathLen = 1 + ::strlen(pszFilePath);
	DWORD i = 0;

	bRet = GetAllThreadIdByProcessId(dwPid, &pThreadId, &dwThreadIdLength);
	if (FALSE == bRet)
	{
		return FALSE;
	}
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		printf("OpenProcess");
		return FALSE;
	}

	// ��ע����̿ռ������ڴ�
	pBaseAddress = ::VirtualAllocEx(hProcess, NULL, dwDllPathLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (pBaseAddress == NULL)
	{
		printf("VirtualAllocEx");
		return FALSE;
	}
	// ������Ŀռ���д��DLL·������ 
	WriteProcessMemory(hProcess, pBaseAddress, pszFilePath, dwDllPathLen, &dwRet);
	if (dwRet != dwDllPathLen)
	{
		printf("WriteProcessMemory");
		return FALSE;
	}

	// ��ȡ LoadLibrary ��ַ
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	if (!hKernel32)
	{
		return FALSE;
	}
	pLoadLibraryAFunc = ::GetProcAddress(hKernel32, "LoadLibraryA");
	if (NULL == pLoadLibraryAFunc)
	{
		printf("GetProcessAddress");
		return FALSE;
	}

	// �����߳�, ����APC
	for (i = 0; i < dwThreadIdLength; i++)
	{
		// ���߳�
		hThread = ::OpenThread(THREAD_ALL_ACCESS, FALSE, pThreadId[i]);
		if (hThread)
		{
			// ����APC
			::QueueUserAPC((PAPCFUNC)pLoadLibraryAFunc, hThread, (ULONG_PTR)pBaseAddress);
			// �ر��߳̾��
			::CloseHandle(hThread);
			hThread = NULL;
		}
	}

	if (hProcess)
	{
		::CloseHandle(hProcess);
		hProcess = NULL;
	}
	if (pThreadId)
	{
		delete[]pThreadId;
		pThreadId = NULL;
	}

	return TRUE;
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
