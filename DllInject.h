#pragma once
#include <Windows.h>
#include <stdio.h>
//#include <ntdef.h>

class CDllInject
{
public:
	static BOOL CreateRemoteThreadInject(DWORD dwPid, const char* pszFilePath);
	static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	static BOOL ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath);	//Ring3 ³¬¼¶Å£Á¦
	static BOOL QueueUserAPCInject(DWORD dwPid, const char* pszFilePath);
	static BOOL SetWindowsHookExInject(DWORD dwPid, const char* pszFilePath);
};


