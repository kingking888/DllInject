#pragma once
#include <Windows.h>
#include <stdio.h>
//#include <ntdef.h>

//#define _WIN64


class CDllInject
{
public:
	static BOOL RemoteThreadInject(DWORD dwPid,const char* pszFilePath);
	static BOOL ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath);	//Ring3 ����ţ��
	static BOOL APCInject();
	static BOOL WindowsHookInject();
};


