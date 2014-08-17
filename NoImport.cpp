
#include "NoImport.h"
//Just waiting for the constexpr (compile time string encryption)
//Pls do not use this in malware, only for a legal (Soft. protection, etc)
//+------------------------------------------------------------------+
//| String compare (char)                                            |
//+------------------------------------------------------------------+
int StrCmp(const char *first,const char *second)
  {
   for(;*first && (*first==*second);++first,++second)
      ;
   return  *first - *second;
  }

//+------------------------------------------------------------------+
//| String compare (wchar_t)                                         |
//+------------------------------------------------------------------+
int StrCmpW(const wchar_t *first,const wchar_t *second)
  {
   for(;*first && (*first==*second);++first,++second)
      ;
   return  *first - *second;
  }

//+------------------------------------------------------------------+
//| Convert string to lowercase                                      |
//+------------------------------------------------------------------+
void ToLower(wchar_t *str)
  {
   wchar_t *p=str;
   for(;*p; ++p) *p=*p>='A' && *p<='Z' ? *p|0x60 : *p;
  }

//+------------------------------------------------------------------+
//| Get string length for wchar_t                                    |
//+------------------------------------------------------------------+
size_t StrLenW(const wchar_t *s)
  {
   const wchar_t *p;
   p=s;
   while(*p)
      p++;
   return p - s;
  }

//+------------------------------------------------------------------+
//| Initialize bases                                                 |
//+------------------------------------------------------------------+
CNoImport::CNoImport(void):
   m_ldrGetProcAddress(NULL),
   m_ldrLoadDll(NULL)
  {
#if !defined ADVANCED
   GetBases();
#elif defined ADVANCED
   GetBasesAdvanced();
#endif
  }

//+------------------------------------------------------------------+
//|                                                                  |
//+------------------------------------------------------------------+
CNoImport::~CNoImport(void)
  {

  }

//+------------------------------------------------------------------+
//| LoadLibrary                                                      |
//+------------------------------------------------------------------+
HMODULE  CNoImport::LdrLoadDLL(wchar_t *dllName)
  {
   if(!m_ldrLoadDll)
     {
      UNICODE_STRING uDllFileName;
      RtlInitUnicodeString(&uDllFileName,dllName);
      m_ldrLoadDll=LdrGetProcAddr<origLdrLoadDll_t>(m_ntdllBase,"LdrLoadDll");
      m_ldrLoadDll(0,0,&uDllFileName,&m_curLibHandle);
     }
   else
     {
      UNICODE_STRING uDllFileName;
      RtlInitUnicodeString(&uDllFileName,dllName);
      m_ldrLoadDll(0,0,&uDllFileName,&m_curLibHandle);
     }
   return(HMODULE)m_curLibHandle;
  }

//+------------------------------------------------------------------+
//| ReactOS InitAnsiString                                           |
//+------------------------------------------------------------------+
void CNoImport::RtlInitAnsiString(PANSI_STRING DestinationString,const char* SourceString)
  {
   SIZE_T Size;
   if(SourceString)
     {
      Size=strlen(SourceString);
      if (Size > (USHRT_MAX - sizeof(CHAR))) Size=USHRT_MAX - sizeof(CHAR);
      DestinationString->Length=(USHORT)Size;
      DestinationString->MaximumLength=(USHORT)Size + sizeof(CHAR);
     }
   else
     {
      DestinationString->Length=0;
      DestinationString->MaximumLength=0;
     }
   DestinationString->Buffer=(PCHAR)SourceString;
  }

//+------------------------------------------------------------------+
//| ReactOS InitUnicodeString                                        |
//+------------------------------------------------------------------+
void CNoImport::RtlInitUnicodeString(PUNICODE_STRING DestinationString,PCWSTR SourceString)
  {
   SIZE_T Size;
   CONST SIZE_T MaxSize=(USHRT_MAX & ~1) - sizeof(UNICODE_NULL);

   if(SourceString)
     {
      Size=wcslen(SourceString) * sizeof(WCHAR);
      __analysis_assume(Size<=MaxSize);

      if (Size > MaxSize)
         Size=MaxSize;
      DestinationString->Length=(USHORT)Size;
      DestinationString->MaximumLength=(USHORT)Size + sizeof(UNICODE_NULL);
     }
   else
     {
      DestinationString->Length=0;
      DestinationString->MaximumLength=0;
     }

   DestinationString->Buffer=(PWCHAR)SourceString;
  }

//+------------------------------------------------------------------+
//| Fast implementation                                              |
//+------------------------------------------------------------------+
void CNoImport::GetBases(void)
  {
#if defined _M_IX86
   DWORD offset=0x30;
   DWORD moduleList=0x0C;
   DWORD moduleListFlink=0x14;
   DWORD kernelBaseOffset=0x10;
   DWORD ntdllBaseOffset=0x10;
#elif defined _M_X64
   DWORD offset=0x60;
   DWORD moduleList=0x18;
   DWORD moduleListFlink=0x20;
   DWORD kernelBaseOffset=0x20;
   DWORD ntdllBaseOffset=0x20;
#endif
   DWORD_PTR base=0;
   IMAGE_NT_HEADERS * pe=NULL;
   IMAGE_EXPORT_DIRECTORY * exportDir=NULL;
   DWORD * namePtr= NULL;
   DWORD funcRVA=NULL;
   WORD * ordPtr=NULL;

//--- retrieve ntdll base addr
   DWORD_PTR ntdllAddr=(*(DWORD_PTR *)(GetPebAddress + moduleList) + moduleListFlink);
   ntdllAddr=(*(DWORD_PTR *)ntdllAddr);
   ntdllAddr=(*(DWORD_PTR *)ntdllAddr);
   ntdllAddr=(*(DWORD_PTR*)(ntdllAddr + ntdllBaseOffset));
   m_ntdllBase=(HMODULE)ntdllAddr;
//---
   m_kernel32Base=*(HMODULE *)(*(DWORD_PTR *)(*(DWORD_PTR *)(*(DWORD_PTR *)(*(DWORD_PTR *)(GetPebAddress + moduleList) + moduleListFlink))) + kernelBaseOffset);
//--- retrieve GetProcAddress
   base=(DWORD_PTR) m_kernel32Base;
   pe=PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
   exportDir=PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   namePtr=(DWORD *) (base + exportDir->AddressOfNames);
   ordPtr=(WORD *) (base + exportDir->AddressOfNameOrdinals);
   //---
   for(;StrCmp((const char *) (base +*namePtr), "GetProcAddress"); ++namePtr, ++ordPtr);
   funcRVA=*(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);
//---
   m_getProcAddress=(GetProcAddress_t) (base + funcRVA);
//--- retrieve LdrGetProcedureAddress
   base=(DWORD_PTR) m_ntdllBase;
   pe=PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
   exportDir=PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   namePtr=(DWORD *) (base + exportDir->AddressOfNames);
   ordPtr=(WORD *) (base + exportDir->AddressOfNameOrdinals);
//---
   for(;StrCmp((const char *) (base +*namePtr), "LdrGetProcedureAddress"); ++namePtr, ++ordPtr);
   funcRVA=*(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);
//---
   m_ldrGetProcAddress=(origLdrGetProcedureAddress_t) (base + funcRVA);
  }

//+------------------------------------------------------------------+
//| More safe, but slow                                              |
//+------------------------------------------------------------------+
void CNoImport::GetBasesAdvanced(void)
  {
#if defined _M_IX86
   DWORD offset=0x30;
   DWORD moduleList=0x0C;
   DWORD moduleListFlink=0x10;
   DWORD kernelBaseAddr=0x10;
#elif defined _M_X64
   DWORD offset=0x60;
   DWORD moduleList=0x18;
   DWORD moduleListFlink=0x18;
   DWORD kernelBaseAddr=0x10;
#endif
//---
   DWORD_PTR peb    =GetPebAddress;
   DWORD_PTR mdllist=*(DWORD_PTR*)(peb + moduleList);
   DWORD_PTR mlink  =*(DWORD_PTR*)(mdllist + moduleListFlink);
   DWORD_PTR krnbase=*(DWORD_PTR*)(mlink + kernelBaseAddr);
//---
   DWORD_PTR base=0;
   IMAGE_NT_HEADERS * pe=NULL;
   IMAGE_EXPORT_DIRECTORY * exportDir=NULL;
   DWORD * namePtr= NULL;
   WORD * ordPtr=NULL;
   DWORD funcRVA= 0;
//--- iterate modules list
   LDR_MODULE *mdl=(LDR_MODULE*)mlink;
   do
     {
      mdl=(LDR_MODULE*)mdl->e[0].Flink;
      if(mdl->base!=NULL)
        {
         wchar_t buf[32];
         size_t size=StrLenW(mdl->dllname.Buffer);
         //--- skip incorrect modules
         if(size > sizeof(buf))
            continue;
         //--- copy to buf
         for(unsigned int i=0; i < size; i++)
            buf[i]=mdl->dllname.Buffer[i];
         buf[size]=0;
         //---
         ToLower(buf);
         //---
         if(!StrCmpW(buf,L"ntdll.dll"))
           {
            m_ntdllBase=mdl->base;
            continue;
           }

         if(!StrCmpW(buf,L"kernel32.dll"))
           {
            break;
           }
        }
     } while(mlink!=(DWORD_PTR)mdl);
//--- search for GetProcAddress
   m_kernel32Base=(HMODULE)mdl->base;
   base=(DWORD_PTR) m_kernel32Base;
   pe=PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
   exportDir=PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   namePtr=(DWORD *) (base + exportDir->AddressOfNames);
   ordPtr=(WORD *) (base + exportDir->AddressOfNameOrdinals);
   for(;StrCmp((const char *) (base +*namePtr), "GetProcAddress"); ++namePtr, ++ordPtr);
   funcRVA=*(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);
   m_getProcAddress=(GetProcAddress_t) (base + funcRVA);
//--- search for LdrGetProcedureAddress
   base=(DWORD_PTR) m_ntdllBase;
   pe=PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
   exportDir=PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
   namePtr=(DWORD *) (base + exportDir->AddressOfNames);
   ordPtr=(WORD *) (base + exportDir->AddressOfNameOrdinals);
   for(;StrCmp((const char *) (base +*namePtr), "LdrGetProcedureAddress"); ++namePtr, ++ordPtr);
   funcRVA=*(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);
   m_ldrGetProcAddress=(origLdrGetProcedureAddress_t) (base + funcRVA);
  }

//+------------------------------------------------------------------+
