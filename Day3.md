---
layout: post
title: "7 days of Red- Day 3"
date: 2021-4-2 0:00:-00 -0400
categories: Writeup
---


​                                                                                                   

    /***
     *    ███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗ 
     *    ╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗
     *        ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║
     *       ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║
     *       ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝
     *       ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝ 
     *                                                                                                  
     */
                ██████╗  █████╗ ██╗   ██╗    ██████╗ 
                ██╔══██╗██╔══██╗╚██╗ ██╔╝    ╚════██╗       
                ██║  ██║███████║ ╚████╔╝      █████╔╝
                ██║  ██║██╔══██║  ╚██╔╝       ╚═══██╗
                ██████╔╝██║  ██║   ██║       ██████╔╝
                ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚═════╝ 



## Windows Anti-Emulation Tactics by abusing Non-Emulated API calls

While there are signature based AVs, in recent years there has been a
uprise in detection by emulation.Essentially putting a malicious program in a sandbox
to see what it might do and monitor its behavior. Due to this a lot of malware employ evasion techniques
to trick the emulator into letting it through. One such tactic employed is
using Non-Emulated Api calls to determine if the OS is legit or a sandbox.
Due to the complexity of the Windows API, sandboxes usually only employ
a select amount while emulating. An attacker can use one of the Api calls
not commonly checked for and based on if the function comes up valid or fails,can
make their malware goto sleep and not execute the malicious code path.Any WinApi can be used,                                  as long as it's obscure enough to not be emulated by the sandbox.One such function
that could be used for this check is **FsAlloc**.

This function is used to allocate Fiber Local Storage Index, which is a space of memory where a fiber can store and retrieve local variables. If you want more information on fibers and ways you can implement them check out Day 1 of this series. Due to lack of use of fibers in a normal process, this function may not be supported by a sandbox, but will be supported by the Windows Operating System.

Code:

```c
#include <windows.h>
int main(int argc, char **argv){
  DWORD test = FlsAlloc(NULL);
  if(test == FLS_OUT_OF_INDEXES){
    printf("Going to Sleep");
  }else{
      printf("About to load up malicious code");

  }
}
```

ref:https://docs.microsoft.com/en-us/windows/win32/api/fibersapi/nf-fibersapi-flsalloc
