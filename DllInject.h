#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <ntdef.h>


//Ring3 ע��
class DllInject
{
public:
	//Զ�߳�ע��
	static BOOL CreateRemoteThreadDllInject(DWORD dwPid, const char* pszFilePath);
	//static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	//��ǿ��Զ�߳�ע��
	static BOOL ZwCreateThreadExDllInject(DWORD dwPid, const char* pszFilePath);	//Ring3 ����ţ��
	//APCע��
	static BOOL QueueUserAPCDllInject(DWORD dwPid, const char* pszFilePath);
	//��Ϣ����ע��
	static BOOL SetWindowsHookExDllInject(DWORD dwPid, const char* pszFilePath);
	//IAT DLLע��
	//IAT DLL�ٳ�
	//ע���ע��
	//���뷨ע��
	//����������
};


