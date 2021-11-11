#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <ntdef.h>


//Ring3 注入
class CDllInject
{
public:
	//远线程注入
	static BOOL CreateRemoteThreadInject(DWORD dwPid, const char* pszFilePath);
	//static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	//加强版远线程注入
	static BOOL ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath);	//Ring3 超级牛力
	//APC注入
	static BOOL QueueUserAPCInject(DWORD dwPid, const char* pszFilePath);
	//消息钩子注入
	static BOOL SetWindowsHookExInject(DWORD dwPid, const char* pszFilePath);
	//注册表注入
	//输入法注入
	//。。。。。
};


