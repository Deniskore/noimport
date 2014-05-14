#include "NoImport.h"

struct LDR_MODULE
  {
   LIST_ENTRY e[3];
   HMODULE    base;
   void      *entry;
   UINT       size;
   UNICODE_STRING dllPath;
   UNICODE_STRING dllname;
  };

static int StrCmp(const char *first,const char *second)
{
   for(;*first && (*first == *second);++first,++second)
      ;
   return  *first - *second;
}

static int StrCmpW(const wchar_t *first,const wchar_t *second)
{
   for(;*first && (*first == *second);++first,++second)
      ;
   return  *first - *second;
}
//Copy-pasted from StackOverflow
static void ToLower(wchar_t *str) {
   wchar_t *p = str;
   for ( ; *p; ++p) *p = *p >= 'A' && *p <= 'Z' ? *p|0x60 : *p;
}

NoImport::NoImport(void)
{
#if defined _M_IX86
  	DWORD offset = 0x30;
	DWORD ModuleList = 0x0C;
	DWORD ModuleListFlink = 0x14;
	DWORD KernelBaseAddr = 0x10;

	m_kernel32Base = *(HMODULE *) (*(DWORD *) (*(DWORD *) (*(DWORD *) (*(DWORD *) (__readfsdword(offset) + ModuleList) + ModuleListFlink))) + KernelBaseAddr);
	DWORD base = (DWORD) m_kernel32Base;
	IMAGE_NT_HEADERS * pe = PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
	IMAGE_EXPORT_DIRECTORY * exportDir = PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD * namePtr = (DWORD *) (base + exportDir->AddressOfNames);
	WORD * ordPtr = (WORD *) (base + exportDir->AddressOfNameOrdinals);
	for(;StrCmp((const char *) (base +*namePtr), "GetProcAddress"); ++namePtr, ++ordPtr);
	DWORD funcRVA = *(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);

	m_getProcAddress = (GetProcAddress_t) (base + funcRVA);
	
#elif defined _M_X64
   DWORD offset = 0x60;
   DWORD ModuleList = 0x18;
   DWORD ModuleListFlink = 0x18;
   DWORD KernelBaseAddr = 0x10;

   DWORD_PTR peb    =__readgsqword(offset);
   DWORD_PTR mdllist=*(DWORD_PTR*)(peb+ ModuleList);
   DWORD_PTR mlink  =*(DWORD_PTR*)(mdllist+ ModuleListFlink);
   DWORD_PTR krnbase=*(DWORD_PTR*)(mlink+ KernelBaseAddr);

   LDR_MODULE *mdl=(LDR_MODULE*)mlink;
   do 
   {
      mdl=(LDR_MODULE*)mdl->e[0].Flink;

      if(mdl->base!=NULL)
        {
         wchar_t buf[32];
         size_t size = wcslen(mdl->dllname.Buffer);
         for(int i = 0; i < size; i++)
            buf[i]=mdl->dllname.Buffer[i];
         buf[size]=0;

         ToLower(buf);
         if(!StrCmpW(buf,L"kernel32.dll"))
           {
            break;
           }
        }
   } while (mlink!=(DWORD_PTR)mdl);

	m_kernel32Base = (HMODULE)mdl->base;
	DWORD_PTR base = (DWORD_PTR) m_kernel32Base;
	IMAGE_NT_HEADERS * pe = PIMAGE_NT_HEADERS(base + PIMAGE_DOS_HEADER(base)->e_lfanew);
	IMAGE_EXPORT_DIRECTORY * exportDir = PIMAGE_EXPORT_DIRECTORY(base + pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD * namePtr = (DWORD *) (base + exportDir->AddressOfNames);
	WORD * ordPtr = (WORD *) (base + exportDir->AddressOfNameOrdinals);
	for(;StrCmp((const char *) (base +*namePtr), "GetProcAddress"); ++namePtr, ++ordPtr);
	DWORD funcRVA = *(DWORD *) (base + exportDir->AddressOfFunctions + *ordPtr * 4);

	m_getProcAddress = (GetProcAddress_t) (base + funcRVA);
	
#endif

}


NoImport::~NoImport(void)
{
}
