#include <windows.h>
BOOL HookFunction(CHAR *dll, CHAR *name, DWORD proxy);
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size);
int NewMessageBox(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
      // A process is loading the DLL.
		MessageBox(NULL,"dll","dll",MB_OK);
		//HookFunction("user32.dll","MessageBox",(DWORD)NewMessageBox);
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

BOOL HookFunction(CHAR *dll, CHAR *name, DWORD proxy)
{
	LPVOID OFuncAddr;

	OFuncAddr = GetProcAddress(GetModuleHandleA(dll), name);
	
	BYTE jump[7]={0xE9,0x00,0x00,0x00,0x00,0xEB,0xF9};
	DWORD OriginalProtection;
	if(!VirtualProtect(OFuncAddr-5, 7, PAGE_EXECUTE_READWRITE, &OriginalProtection))
 		return FALSE;
 	
 	
	memcpy(OFuncAddr,jump,7);
	memcpy(OFuncAddr+1,&proxy,sizeof(DWORD));
	VirtualProtect(OFuncAddr-5, 7, OriginalProtection, &OriginalProtection);
}

int NewMessageBox(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)
{
	ExitProcess(0);
	return 7;
}