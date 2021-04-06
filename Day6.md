





```


███████╗    ██████╗  █████╗ ██╗   ██╗███████╗     ██████╗ ███████╗    ██████╗ ███████╗██████╗     
╚════██║    ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔════╝    ██╔═══██╗██╔════╝    ██╔══██╗██╔════╝██╔══██╗    
    ██╔╝    ██║  ██║███████║ ╚████╔╝ ███████╗    ██║   ██║█████╗      ██████╔╝█████╗  ██║  ██║    
   ██╔╝     ██║  ██║██╔══██║  ╚██╔╝  ╚════██║    ██║   ██║██╔══╝      ██╔══██╗██╔══╝  ██║  ██║    
   ██║      ██████╔╝██║  ██║   ██║   ███████║    ╚██████╔╝██║         ██║  ██║███████╗██████╔╝    
   ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝     ╚═════╝ ╚═╝         ╚═╝  ╚═╝╚══════╝╚═════╝     
                                                                                                  
██████╗  █████╗ ██╗   ██╗     ██████╗                                                             
██╔══██╗██╔══██╗╚██╗ ██╔╝    ██╔════╝                                                             
██║  ██║███████║ ╚████╔╝     ███████╗                                                             
██║  ██║██╔══██║  ╚██╔╝      ██╔═══██╗                                                            
██████╔╝██║  ██║   ██║       ╚██████╔╝                                                            
╚═════╝ ╚═╝  ╚═╝   ╚═╝        ╚═════╝                                                             
                                                                                                  


```


### Sandbox Evasion by Enumerating the Existence of Registry Keys

#### Day 6

As stated on Day 3, sandbox evasion is a fundamental apart of any attacker's strategy to infilrate a network. The chance of a piece of malware touching a virtual environment is extremely high since most host antivirus and email antivirus programs utilize a sandbox. In order for an attacker to identify a virtual environment they will employ a series of checks included in their stage 0 payload. In this post we'll discuss enumerating registry keys and checking for artifacts to indicate a virtual environment.There are a number of virtual environment software such as VMware,VirtualBox,Sandboxie,Wine,Xen and many more. For each of these environments there are registry keys identifying them and their particular settings. For Example:

#### VMWare:

| HKLM\SYSTEM\CurrentControlSet\Enum\PCI\VEN_15AD*             |      |
| ------------------------------------------------------------ | ---- |
| HKCU\SOFTWARE\VMware, Inc.\VMware Tools                      |      |
| HKLM\SOFTWARE\VMware, Inc.\VMware Tools                      |      |
| HKLM\SYSTEM\ControlSet001\Services\vmdebug                   |      |
| HKLM\SYSTEM\ControlSet001\Services\vmmouse                   |      |
| HKLM\SYSTEM\ControlSet001\Services\VMTools                   |      |
| HKLM\SYSTEM\ControlSet001\Services\VMMEMCTL                  |      |
| HKLM\SYSTEM\ControlSet001\Services\vmware                    |      |
| HKLM\SYSTEM\ControlSet001\Services\vmci                      |      |
| HKLM\SYSTEM\ControlSet001\Services\vmx86                     |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_IDE_CD* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\CdRomNECVMWar_VMware_SATA_CD* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_IDE_Hard_Drive* |      |
| HKLM\SYSTEM\CurrentControlSet\Enum\IDE\DiskVMware_Virtual_SATA_Hard_Drive* |      |

*Credits to Checkpoint Security for the Table

You can query these keys using RegOpenKeyEx,RegOpenKey,RegQueryValue,RegQueryValueEx ,RegCloseKey and RegEnumKey and confirm the existence of these keys, if they don't exist you can continue running malware.If they do exist however you can make  your malware take another code path so it doesn't get detected. You can often run the same routine of checks again after a certain amount of time has pasted to see if your still in the same virtual environment or if you're on a actual host. The following code takes two of the registry key checks for VMWare and checks if they exist, if they exist the thread goes to sleep and checks again until the the check returns false.

Code:

```c
#include <windows.h>
#include <stdio.h>

int main(int argc,char **argv){
  HKEY hPrincipalKey;
  printf("Running Two checks for VMware environment....\n");
  LSTATUS success = RegOpenKeyEx(HKEY_CURRENT_USER,TEXT("SOFTWARE\\VMware, Inc.\\VMware Tools"),0,KEY_READ,&hPrincipalKey);
  while(success==ERROR_SUCCESS){
        printf("Key was successfully opened at 0x%p,SLEEPING\n",hPrincipalKey);
        Sleep(10000);

    }
  printf("The key did not open ,executing malware\n");
   Sleep(1000);


LSTATUS success2 = RegOpenKeyEx(HKEY_CURRENT_USER,TEXT("\\SYSTEM\\ControlSet001\\Services\\VMTools"),0,KEY_READ,&hPrincipalKey);
  while(success2==ERROR_SUCCESS){
        printf("Key was successfully opened at 0x%p,SLEEPING\n",hPrincipalKey);
        Sleep(10000);


    }

   printf("The key did not open ,executing malware\n");
   Sleep(1000);



}

```

