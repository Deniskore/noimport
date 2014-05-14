#include <windows.h>
#include <SubAuth.h>
typedef FARPROC (WINAPI * GetProcAddress_t) (HMODULE, const char *);
#pragma once
class NoImport
{
public:
	NoImport(void);
template<typename Proto>
Proto GetProcAddr(HMODULE hLib, PCSTR pProcName)
{
	return reinterpret_cast<Proto>(m_getProcAddress(hLib, pProcName));
}

inline HMODULE GetKernel32Base() { return m_kernel32Base; }

	~NoImport(void);

private:
	GetProcAddress_t m_getProcAddress;
	HMODULE m_kernel32Base;
};

