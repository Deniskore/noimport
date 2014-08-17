#pragma once
#include <windows.h>
#if defined _M_IX86
#define GetPebAddress __readfsdword(0x30)
#else
#define GetPebAddress __readgsqword(0x60)
#endif
//---
#define ADVANCED
#undef ADVANCED
//---
typedef struct _ANSI_STRING
  {
   USHORT            Length;
   USHORT            MaximumLength;
   PSTR              Buffer;
  } ANSI_STRING, *PANSI_STRING;
//---
typedef struct _UNICODE_STRING
  {
   USHORT            Length;
   USHORT            MaximumLength;
   PWSTR             Buffer;
  } UNICODE_STRING, *PUNICODE_STRING;
//---
struct LDR_MODULE
  {
   LIST_ENTRY        e[3];
   HMODULE           base;
   void             *entry;
   UINT              size;
   UNICODE_STRING    dllPath;
   UNICODE_STRING    dllname;
  };
//---
typedef FARPROC (WINAPI * GetProcAddress_t) (HMODULE, const char *);
typedef DWORD (WINAPI * origLdrGetProcedureAddress_t) (HMODULE, PANSI_STRING, WORD ordinal, PVOID *funcAddr);
typedef NTSTATUS (WINAPI *origLdrLoadDll_t)(PWCHAR PathToFile,ULONG Flags,PUNICODE_STRING ModuleFileName,PHANDLE ModuleHandle);
typedef DWORD (WINAPI * myLdrGetProcedureAddress_t) (HMODULE, PANSI_STRING);
//---
int StrCmp(const char *first, const char *second);
int StrCmpW(const wchar_t *first, const wchar_t *second);

class CNoImport
  {
public:
                     CNoImport(void);
                    ~CNoImport(void);
   //---
   HMODULE           LdrLoadDLL(wchar_t *dllName);
   void              RtlInitAnsiString(PANSI_STRING DestinationString,const char* SourceString);
   void              RtlInitUnicodeString(PUNICODE_STRING DestinationString,PCWSTR SourceString);
   //---
   template<typename Proto>
   Proto GetProcAddr(HMODULE hLib, PCSTR pProcName)
     {
      return reinterpret_cast<Proto>(m_getProcAddress(hLib, pProcName));
     }
   //---
   template<typename Proto>
   Proto LdrGetProcAddr(HMODULE hLib, const char *procName)
     {
      ANSI_STRING str;
      RtlInitAnsiString(&str,procName);
      reinterpret_cast<origLdrGetProcedureAddress_t>(m_ldrGetProcAddress(hLib, &str, 0, (PVOID*)&m_funcAddr));
      return reinterpret_cast<Proto>(m_funcAddr);
     }
   //---
   inline HMODULE    GetKernel32Base() { return m_kernel32Base; }
   inline HMODULE    GetNTDLLBase() { return m_ntdllBase; }
   //---
private:
   void              GetBases();
   void              GetBasesAdvanced();
   //--
private:
   GetProcAddress_t  m_getProcAddress;
   origLdrGetProcedureAddress_t m_ldrGetProcAddress;
   origLdrLoadDll_t  m_ldrLoadDll;
   PVOID            *m_funcAddr;
   HMODULE           m_kernel32Base;
   HMODULE           m_ntdllBase;
   //---
   HANDLE            m_curLibHandle;
  };

//+------------------------------------------------------------------+
