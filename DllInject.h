#pragma once
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
//#include <ntdef.h>


//Ring3 ע��
class CDllInject
{
public:
	//Զ�߳�ע��
	static BOOL CreateRemoteThreadInject(DWORD dwPid, const char* pszFilePath);
	//static BOOL RtlCreateUserThreadInject(DWORD dwPid,const char* pszFilePath);
	//��ǿ��Զ�߳�ע��
	static BOOL ZwCreateThreadExInject(DWORD dwPid, const char* pszFilePath);	//Ring3 ����ţ��
	//APCע��
	static BOOL QueueUserAPCInject(DWORD dwPid, const char* pszFilePath);
	//��Ϣ����ע��
	static BOOL SetWindowsHookExInject(DWORD dwPid, const char* pszFilePath);
	//ע���ע��
	//���뷨ע��
	//����������
};


