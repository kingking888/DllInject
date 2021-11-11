#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <ntdef.h>


//Ring3 注入
class DllInject
{
public:
	//远线程注入
	static BOOL CreateRemoteThreadDllInject(DWORD dwPid, const char* pszFilePath);
	//static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	//加强版远线程注入
	static BOOL ZwCreateThreadExDllInject(DWORD dwPid, const char* pszFilePath);	//Ring3 超级牛力
	//APC注入
	static BOOL QueueUserAPCDllInject(DWORD dwPid, const char* pszFilePath);
	//消息钩子注入
	static BOOL SetWindowsHookExDllInject(DWORD dwPid, const char* pszFilePath);
	//IAT DLL注入
	//IAT DLL劫持
	//注册表注入
	//输入法注入
	//。。。。。
};


