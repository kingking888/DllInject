#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <ntdef.h>

//#define _WIN64


class CDllInject
{
public:
	static BOOL CreateRemoteThreadInject(DWORD dwPid, const char* pszFilePath);
	static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	static BOOL ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath);	//Ring3 ³¬¼¶Å£Á¦
	static BOOL QueueUserAPCInject(DWORD dwPid, const char* pszFilePath);
	static BOOL SetWindowsHookExInject(DWORD dwPid, const char* pszFilePath);
};


