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
	/* dos_header->e_lfanew is the RVA of the next header */
	IMAGE_NT_HEADERS *nt_header =
		(IMAGE_NT_HEADERS *)(((BYTE *)dos_header) +
				     dos_header->e_lfanew);

	BYTE *curr_proc_base = (BYTE *)GetModuleHandle(NULL);
	if (curr_proc_base == NULL)
		return GetLastError();

	/* Write payload header to the memory of current process */
	DWORD old_protect;
	if (!VirtualProtect(curr_proc_base,
			    nt_header->OptionalHeader.SizeOfHeaders,
			    PAGE_READWRITE, &old_protect))
		return GetLastError();
	memcpy(curr_proc_base, base, nt_header->OptionalHeader.SizeOfHeaders);

	/* The section header follows the optional header */
	IMAGE_SECTION_HEADER *sections =
		(IMAGE_SECTION_HEADER *)(((BYTE *)nt_header) +
					 sizeof(IMAGE_NT_HEADERS));

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		BYTE *dest = curr_proc_base + sections[i].VirtualAddress;
		if (!VirtualProtect(dest, sections[i].Misc.VirtualSize,
				    PAGE_READWRITE, &old_protect))
			return GetLastError();

		for (unsigned long j = 0; j < sections[i].Misc.VirtualSize;
		     j++) {
			if (j < sections[i].SizeOfRawData)
				dest[j] = *(base +
					    sections[i].PointerToRawData + j);
			else
				dest[j] = 0;
		}
	}

	/* Restore protection */
	if (!VirtualProtect(curr_proc_base,
			    nt_header->OptionalHeader.SizeOfHeaders,
			    PAGE_READONLY, &old_protect))
		return GetLastError();

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		BYTE *dest = curr_proc_base + sections[i].VirtualAddress;
		DWORD is_executable =
			sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE;
		DWORD is_writable =
			sections[i].Characteristics & IMAGE_SCN_MEM_WRITE;
		DWORD protect;
		if (is_executable)
			protect = is_writable ? PAGE_EXECUTE_READWRITE :
						PAGE_EXECUTE_READ;
		else
			protect = is_writable ? PAGE_READWRITE : PAGE_READONLY;

		if (!VirtualProtect(dest, sections[i].Misc.VirtualSize, protect,
				    &old_protect))
			return GetLastError();
	}

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
