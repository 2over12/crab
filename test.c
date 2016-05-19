#include <windows.h>
#include <stdio.h>
BOOL HookFunction(char dll[], char name[], DWORD proxy);
void SafeMemcpyPadded(LPVOID destination, LPVOID source, DWORD size);
int NewMessageBox(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType);
int main()
{
	MessageBoxA(NULL,"1","1",MB_OK);
	HookFunction("user32.dll","MessageBox",(DWORD)NewMessageBox);
	printf("here");
	MessageBoxA(NULL,"2","2",MB_OK);
}

BOOL HookFunction(char dll[], char name[], DWORD proxy)
{
	LPVOID OFuncAddr;

	OFuncAddr = GetProcAddress(GetModuleHandleA(TEXT("user32.dll")), "MessageBoxA");
	printf("0x%x",OFuncAddr);
	BYTE jump[2]={0xEB,0xF9};
	DWORD OriginalProtection;
	if(!VirtualProtect(OFuncAddr-5, 7, PAGE_EXECUTE_READWRITE, &OriginalProtection))
 		return FALSE;
 	
 	
	memcpy(OFuncAddr,jump,2);
	*(BYTE *)(OFuncAddr-5)=0xE9;

	DWORD addr=&NewMessageBox;
	addr=addr - (DWORD)OFuncAddr;

    *(DWORD *)(OFuncAddr-4)=addr;
	printf("\n%x\n",NewMessageBox);
	//memcpy(OFuncAddr+1,&proxy,sizeof(DWORD));
	VirtualProtect(OFuncAddr-5, 7, OriginalProtection, &OriginalProtection);
}

int NewMessageBox(HWND hWnd,LPCSTR lpText,LPCSTR lpCaption,UINT uType)
{
	ExitProcess(0);
	return 7;
}