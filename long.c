


#include "stdio.h"
#include "winsock2.h"
#include <tlhelp32.h>
#pragma comment(lib,"ws2_32.lib") //For winsock

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

void StartSniffing (SOCKET Sock); //This will sniff here and there

void ProcessPacket (char* , int); //This will decide how to digest
void ParseTcpPacket (char* , int);
void ConvertToHex (char* , unsigned int);
void PrintData (char* , int, char *,unsigned int);
char * getStr();
BOOL InjectDLL();
void ripCmd();
typedef struct ip_hdr
{
	unsigned char ip_header_len:4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version :4; // 4-bit IPv4 version
	unsigned char ip_tos; // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id; // Unique identifier

	unsigned char ip_frag_offset :5; // Fragment offset field

	unsigned char ip_more_fragment :1;
	unsigned char ip_dont_fragment :1;
	unsigned char ip_reserved_zero :1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl; // Time to live
	unsigned char ip_protocol; // Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr; // Source address
	unsigned int ip_destaddr; // Source address
} IPV4_HDR;

typedef struct udp_hdr
{
	unsigned short source_port; // Source port no.
	unsigned short dest_port; // Dest. port no.
	unsigned short udp_length; // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} UDP_HDR;

// TCP header
typedef struct tcp_header
{
	unsigned short source_port; // source port
	unsigned short dest_port; // destination port
	unsigned int sequence; // sequence number - 32 bits
	unsigned int acknowledge; // acknowledgement number - 32 bits

	unsigned char ns :1; //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1:3; //according to rfc
	unsigned char data_offset:4; /*The number of 32-bit words in the TCP header.
	This indicates where the data begins.
	The length of the TCP header is always a multiple
	of 32 bits.*/

	unsigned char fin :1; //Finish Flag
	unsigned char syn :1; //Synchronise Flag
	unsigned char rst :1; //Reset Flag
	unsigned char psh :1; //Push Flag
	unsigned char ack :1; //Acknowledgement Flag
	unsigned char urg :1; //Urgent Flag

	unsigned char ecn :1; //ECN-Echo Flag
	unsigned char cwr :1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
} TCP_HDR;

typedef struct icmp_hdr
{
	BYTE type; // ICMP Error type
	BYTE code; // Type sub code
	USHORT checksum;
	USHORT id;
	USHORT seq;
} ICMP_HDR;

FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
struct sockaddr_in source,dest;
char hex[2];

//Its free!
IPV4_HDR *iphdr;
TCP_HDR *tcpheader;
UDP_HDR *udpheader;
ICMP_HDR *icmpheader;
char *test;
char lip[20];
int main()
{
	test=getStr();
	SOCKET sniffer;
	struct in_addr addr;
	int in;

	char hostname[100];
	struct hostent *local;
	WSADATA wsa;

	logfile=fopen("log.txt","w");
	if(logfile == NULL)
	{
		printf("Unable to create file.");
	}

	//Initialise Winsock
	printf("\nInitialising Winsock...");
	if (WSAStartup(MAKEWORD(2,2), &wsa) != 0)
	{
		printf("WSAStartup() failed.\n");
		return 1;
	}
	printf("Initialised");

	//Create a RAW Socket
	printf("\nCreating RAW Socket...");
	sniffer = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
	if (sniffer == INVALID_SOCKET)
	{
		printf("Failed to create raw socket.\n");
		return 1;
	}
	printf("Created.");

	//Retrive the local hostname
	if (gethostname(hostname, sizeof(hostname)) == SOCKET_ERROR)
	{
		printf("Error : %d",WSAGetLastError());
		return 1;
	}
	printf("\nHost name : %s \n",hostname);

	//Retrive the available IPs of the local host
	local = gethostbyname(hostname);
	printf("\nAvailable Network Interfaces : \n");
	if (local == NULL)
	{
		printf("Error : %d.\n",WSAGetLastError());
		return 1;
	}

	for (i = 0; local->h_addr_list[i] != 0; ++i)
	{
		memcpy(&addr, local->h_addr_list[i], sizeof(struct in_addr));
		printf("Interface Number : %d Address : %s\n",i,inet_ntoa(addr));
	}

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d",&in);

	memset(&dest, 0, sizeof(dest));
	memcpy(&dest.sin_addr.s_addr,local->h_addr_list[in],sizeof(dest.sin_addr.s_addr));
	memcpy(&addr, local->h_addr_list[in], sizeof(struct in_addr));
	snprintf(lip,19,"%s",inet_ntoa(addr));
	dest.sin_family = AF_INET;
	dest.sin_port = 0;

	printf("\nBinding socket to local system and port 0 ...");
	if (bind(sniffer,(struct sockaddr *)&dest,sizeof(dest)) == SOCKET_ERROR)
	{
		printf("bind(%s) failed.\n", inet_ntoa(addr));
		return 1;
	}
	printf("Binding successful");

	//Enable this socket with the power to sniff : SIO_RCVALL is the key Receive ALL ;)

	j=1;
	printf("\nSetting socket to sniff...");
	if (WSAIoctl(sniffer, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
		printf("WSAIoctl() failed.\n");
		return 1;
	}
	printf("Socket set.");

	//Begin
	printf("\nStarted Sniffing\n");
	printf("Packet Capture Statistics...\n");
	printf("%s\n\n",test);
	StartSniffing(sniffer); //Happy Sniffing

	//End
	closesocket(sniffer);
	WSACleanup();

	return 0;
}

void StartSniffing(SOCKET sniffer)
{
	char *Buffer = (char *)malloc(65536); //Its Big!
	int mangobyte;

	if (Buffer == NULL)
	{
		printf("malloc() failed.\n");
		return;
	}

	do
	{
		mangobyte = recvfrom(sniffer , Buffer , 65536 , 0 , 0 , 0); //Eat as much as u can

		if(mangobyte > 0)
		{
			ProcessPacket(Buffer, mangobyte);
		}
		else
		{
			printf( "recvfrom() failed.\n");
		}
	}
	while (mangobyte > 0);

	free(Buffer);
}

void ProcessPacket(char* Buffer, int Size)
{
	iphdr = (IPV4_HDR *)Buffer;

	if(iphdr->ip_protocol==6) 
	{
		ParseTcpPacket(Buffer,Size);
	}
}


void ParseTcpPacket(char* Buffer, int Size)
{
	unsigned short iphdrlen;

	iphdr = (IPV4_HDR *)Buffer;
	iphdrlen = iphdr->ip_header_len*4;

	tcpheader=(TCP_HDR*)(Buffer+iphdrlen);

	//PrintIpHeader( Buffer );
	/*
	fprintf(logfile," |-Source Port : %u\n",ntohs(tcpheader->source_port));
	fprintf(logfile," |-Destination Port : %u\n",ntohs(tcpheader->dest_port));

	*/
	char sp[20];
	unsigned int bytes[4];
    unsigned int ip=iphdr->ip_srcaddr;
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;	
    snprintf(sp,19,"%d.%d.%d.%d",bytes[0], bytes[1], bytes[2], bytes[3]);   
    /*if(strstr(lip,sp)!=NULL)
    {
    	ip=iphdr->ip_srcaddr;
        bytes[0] = ip & 0xFF;
    	bytes[1] = (ip >> 8) & 0xFF;
    	bytes[2] = (ip >> 16) & 0xFF;
    	bytes[3] = (ip >> 24) & 0xFF;
    	memset(sp,'\0',20);
    	snprintf(sp,19,"%d.%d.%d.%d",bytes[0], bytes[1], bytes[2], bytes[3]);   
    }*/

	PrintData(Buffer+iphdrlen+tcpheader->data_offset*4
	,(Size-tcpheader->data_offset*4-iphdr->ip_header_len*4),sp,tcpheader->source_port);

	
}

void PrintData (char* data , int size, char *attacker, unsigned int port)
{
	FILE *fp;
	char path[1035];
	char portbuff[20];
	snprintf(portbuff,20,":%u",ntohs(port));
	if(strstr(data,test)!=NULL)
	{
		printf("attack detected from %s at %u!!",attacker,ntohs(port));
		ripCmd();
		fp = popen("Taskkill /IM cmd.exe /F", "r");
/*
		while (fgets(path, sizeof(path)-1, fp) != NULL) 	
		{
			if(strstr(path,portbuff)!=NULL)
				printf("%s",path);
		}*/

		pclose(fp);
	}
	

}

char * getStr()
{
	FILE *f;

	int i=system("C:\\Windows\\System32\\cmd.exe /C ver > ver.txt");
	char * ln=malloc(200);
	char * ln2=malloc(200);
	f=fopen("ver.txt","r");
	fgets(ln,199,f);
	fgets(ln2,199,f);
	int h;
	for (h = 0; h<200; h++)
	{
		if(ln2[h]=='\n')
			ln2[h]='\0';
	}
	return ln2;
}

BOOL InjectDLL(DWORD dwProcessId, LPCSTR lpszDLLPath)
{
    HANDLE  hProcess, hThread;
    LPVOID  lpBaseAddr, lpFuncAddr;
    DWORD   dwMemSize, dwExitCode;
    BOOL    bSuccess = FALSE;
    HMODULE hUserDLL;
 
    if((hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION
        |PROCESS_VM_WRITE|PROCESS_VM_READ, FALSE, dwProcessId)))
    {
        dwMemSize = lstrlen(lpszDLLPath) + 1;
        if((lpBaseAddr = VirtualAllocEx(hProcess, NULL, dwMemSize, MEM_COMMIT, PAGE_READWRITE)))
        {
            if(WriteProcessMemory(hProcess, lpBaseAddr, lpszDLLPath, dwMemSize, NULL))
            {
                if((hUserDLL = LoadLibrary(TEXT("kernel32.dll"))))
                {
                    if((lpFuncAddr = GetProcAddress(hUserDLL, TEXT("LoadLibraryA"))))
                    {
                        if((hThread = CreateRemoteThread(hProcess, NULL, 0, lpFuncAddr, lpBaseAddr, 0, NULL)))
                        {
                            WaitForSingleObject(hThread, INFINITE);
                            if(GetExitCodeThread(hThread, &dwExitCode)) {
                                bSuccess = (dwExitCode != 0) ? TRUE : FALSE;
                            }
                            CloseHandle(hThread);
                        }
                    }
                    FreeLibrary(hUserDLL);
                }
            }
            VirtualFreeEx(hProcess, lpBaseAddr, 0, MEM_RELEASE);
        }
        CloseHandle(hProcess);
    }
 
    return bSuccess;
}

void FindProcessId(const char *processname,DWORD result[10])
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    int count=0;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap) return;

    pe32.dwSize = sizeof(PROCESSENTRY32); // <----- IMPORTANT

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        printf("!!! Failed to gather information on system processes! \n");
        return;
    }

    do
    {
        printf("Checking process %s\n", pe32.szExeFile);
        if (0 == strcmp(processname, pe32.szExeFile))
        {
        	printf("\nfound\n");
            result[count] = pe32.th32ProcessID;
            count++;
            if(count>=9)
            	return;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

}

void ripCmd()
{
	DWORD result[10]={0,0,0,0,0,0,0,0,0,0};
	FindProcessId("cmd.exe",result);
	char *cmd=malloc(10);
	strcpy(cmd,"cmd.exe");
	int i;
	for(i=0;i<10;i++)
	{
		if(result[i]!=0)
		{
			printf("\ninjecting dll at %d,",result[i]);
			InjectDLL(result[i],"box.dll");
		}
	}
		
}