#pragma once
#include "DllInject.h"
#include "Main.h"

int main()
{
	DWORD dwPid = GetProcessIdByProcessName(L"errlook.exe");
	if (dwPid == 0)
	{
		printf("目标程序未启动\n");
		return false;
	}
	printf("%d\n", dwPid);

	//DWORD CurrentWindowThreadId = GetWindowThreadProcessId(FindMainWindow(dwPid), NULL);
	//printf("%d\n", CurrentWindowThreadId);

	//CDllInject::RemoteThreadInject(dwPid,"C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");
	CDllInject::ZwCreateThreadExInject(dwPid, "C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");
	//CDllInject::SetWindowsHookExInject(CurrentWindowThreadId, "C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");
	//CDllInject::QueueUserAPCInject(dwPid, "C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");

	return 0;
}