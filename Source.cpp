#include "NoImport.h"

#pragma comment(linker, "/entry:start")


void start ()
{
	NoImport noimp;

	HMODULE kernel32 = noimp.GetKernel32Base();

	auto myLoadLibraryW = noimp.GetProcAddr<HMODULE (WINAPI*) (_In_  LPCTSTR lpFileName)>(kernel32,"LoadLibraryW");

	HMODULE user32 = myLoadLibraryW(L"user32.dll");

	auto MessageBoxW = noimp.GetProcAddr<int (WINAPI*) (_In_opt_  HWND hWnd, _In_opt_  LPCTSTR lpText, _In_opt_  LPCTSTR lpCaption, _In_ UINT uType)>(user32,"MessageBoxW");

	MessageBoxW(0,L"Hello my friend!",L":)",0);
}