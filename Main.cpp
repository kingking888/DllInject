#include "DllInject.h"
#include "Main.h"

int main()
{
	//DWORD dwPid = GetProcessIdByProcessName(L"WinHex.exe");
	//printf("%d\n", dwPid);
	//CDllInject::RemoteThreadInject(dwPid,"C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");
	CDllInject::ZwCreateThreadExInject(1452, "C:\\Users\\Administrator\\Desktop\\Temp\\MessageBox.dll");
	return 0;
}