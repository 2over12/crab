#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <tlhelp32.h>
DWORD getPid(char target[]);
void DLLInject(char dllName[],DWORD pid);
int main(int argc,char *argv[])
{	
	DWORD pid;
	pid=getPid("iexplore.exe");
	printf("%d\n",pid);
	DLLInject("box.dll",pid);
	printf("success\n");
	

	return 0;
}

void DLLInject(char dllName[],DWORD pid)
{
	HANDLE hHandle;
	HANDLE thread;
	char pathName[500];
	DWORD pathAddr;
	DWORD LibAddr;

	hHandle=OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
	GetFullPathName(TEXT(dllName),500,&pathName,NULL);
	pathAddr=VirtualAllocEx(hHandle,NULL,strlen(pathName),MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hHandle,pathAddr,pathName,strlen(pathName),NULL);
	LibAddr = GetProcAddress(GetModuleHandle(TEXT("kernel32.dll")), "LoadLibraryA");
	thread=CreateRemoteThread(hHandle,NULL,0,LibAddr,pathAddr,0,NULL);
	WaitForSingleObject(thread, INFINITE);
}

DWORD getPid(char target[])
{
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (stricmp(entry.szExeFile, target) == 0)
			{  
				return entry.th32ProcessID;
			}
		}
	}
	return -1;
}