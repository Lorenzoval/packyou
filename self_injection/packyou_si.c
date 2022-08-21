#include <stdio.h>
#include <windows.h>

#include "payload.h"

#ifdef OBFUSCATE
#include "../obfuscation/obfuscate.h"
#endif

__attribute__((section("packyou"))) int unpack()
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

	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER *)base;
	/* dos_header->e_lfanew is is the offset of the next header */
	IMAGE_NT_HEADERS *nt_header =
		(IMAGE_NT_HEADERS *)(((BYTE *)dos_header) +
				     dos_header->e_lfanew);

	HMODULE curr_proc_base = GetModuleHandle(NULL);
	if (curr_proc_base == NULL)
		return GetLastError();

	/* Write payload header to the memory of current process */
	DWORD old_protect;
	VirtualProtect(curr_proc_base, nt_header->OptionalHeader.SizeOfHeaders,
		       PAGE_READWRITE, &old_protect);
	memcpy(curr_proc_base, base, nt_header->OptionalHeader.SizeOfHeaders);

#ifdef OBFUSCATE
	if (!clean(base))
		return GetLastError();
#else
	if (!VirtualFree(base, 0, MEM_RELEASE))
		return GetLastError();
#endif

	return ERROR_SUCCESS;
}

__attribute__((section("packyou"))) int main()
{
	int ret = unpack();

	if (ret != ERROR_SUCCESS)
		printf("Error %d\n", ret);

	return ret;
}
