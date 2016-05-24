#include <windows.h>
BOOL HookFunction(char dll[], char name[], DWORD proxy,LPVOID tramp);
typedef int (WINAPI *TdefOldWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);
TdefOldWinExec OldWinExec;
HRESULT ExecHook(LPCSTR lpCmdLine,UINT uCmdShow);
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
      // A process is loading the DLL.
		OldWinExec=(TdefOldWinExec)VirtualAlloc(NULL, 5, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		HookFunction("Kernel32.dll","WinExec",(DWORD)ExecHook,(LPVOID)OldWinExec);
		//WinExec("aaaaa",0x1);
		//MessageBoxA(NULL,"hey","hey",MB_OK);
		break;

		case DLL_THREAD_ATTACH:
      // A process is creating a new thread.
		break;

		case DLL_THREAD_DETACH:
      // A thread exits normally.
		break;

		case DLL_PROCESS_DETACH:
      // A process unloads the DLL.
		break;
	}
	return TRUE;
}

BOOL HookFunction(char dll[], char name[], DWORD proxy,LPVOID tramp)
{
	LPVOID OFuncAddr;
	OFuncAddr = GetProcAddress(GetModuleHandleA(TEXT(dll)), name);
	BYTE jump[2]={0xEB,0xF9};
	DWORD OriginalProtection;
	if(!VirtualProtect(OFuncAddr-5, 7, PAGE_EXECUTE_READWRITE, &OriginalProtection))
 		return FALSE;
 	
 	
	memcpy(OFuncAddr,jump,2);
	*(BYTE *)(OFuncAddr-5)=0xE9;

	DWORD addr=proxy;
	addr=addr - (DWORD)OFuncAddr;

    *(DWORD *)(OFuncAddr-4)=addr;
	//memcpy(OFuncAddr+1,&proxy,sizeof(DWORD));
	VirtualProtect(OFuncAddr-5, 7, OriginalProtection, &OriginalProtection);
	*(BYTE *)tramp=0xE9;
	*(DWORD *)(tramp+1)=((OFuncAddr+2)-(tramp))-5;
}


HRESULT ExecHook(LPCSTR lpCmdLine,UINT uCmdShow)
{
	MessageBoxA(NULL,"blocked","blocked", MB_OK);
	ExitProcess(0);
}