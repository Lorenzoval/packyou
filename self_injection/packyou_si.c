#include <stdio.h>
#include <windows.h>

#include "payload.h"

#ifdef OBFUSCATE
#include "../obfuscation/obfuscate.h"
#endif

__attribute__((section("packyou"))) int unpack(void (**poep)(void))
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

	/* Write all sections and fill with 0 */
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

	/* Rebuild imports */
	IMAGE_DATA_DIRECTORY *data_directory =
		nt_header->OptionalHeader.DataDirectory;

	/* Get import descriptors array */
	IMAGE_IMPORT_DESCRIPTOR *import_descriptors =
		(IMAGE_IMPORT_DESCRIPTOR
			 *)(curr_proc_base +
			    data_directory[IMAGE_DIRECTORY_ENTRY_IMPORT]
				    .VirtualAddress);

	/* The last entry of the array has all fields set to 0 */
	int i = 0;
	while (import_descriptors[i].OriginalFirstThunk != 0) {
		/* Load current library */
		LPCSTR lib_name =
			(LPCSTR)(curr_proc_base + import_descriptors[i].Name);
		HMODULE library = LoadLibrary(lib_name);
		if (library == NULL)
			return GetLastError();

		/* OriginalFirstThunk contains the RVA of the ILT */
		IMAGE_THUNK_DATA *lookup_table =
			(IMAGE_THUNK_DATA *)(curr_proc_base +
					     import_descriptors[i]
						     .OriginalFirstThunk);

		/* FirstThunk contains the RVA of the IAT */
		IMAGE_THUNK_DATA *address_table =
			(IMAGE_THUNK_DATA *)(curr_proc_base +
					     import_descriptors[i].FirstThunk);

		int j = 0;
		while (lookup_table[j].u1.AddressOfData != 0) {
			FARPROC fp = NULL;

			/*
			 * The high bit of the IMAGE_THUNK_DATA value tells if an
			 * IMAGE_THUNK_DATA structure contains an import ordinal istead of
			 * an RVA to an IMAGE_IMPORT_BY_NAME structure.
			 * If set, the value is treated as an ordinal value.
			 * Otherwise, the value is an RVA to the IMAGE_IMPORT_BY_NAME.
			 */
			DWORD value = lookup_table[j].u1.AddressOfData;

			if ((value & IMAGE_ORDINAL_FLAG) == 0) {
				IMAGE_IMPORT_BY_NAME *image_import =
					(IMAGE_IMPORT_BY_NAME *)(curr_proc_base +
								 value);

				LPCSTR func_name = (LPCSTR) &
						   (image_import->Name);

				/* Get function address by name */
				fp = (void *)GetProcAddress(library, func_name);
			} else {
				/* Get function address by ordinal */
				fp = (void *)GetProcAddress(
					library,
					(LPCSTR)IMAGE_ORDINAL32(value));
			}

			if (fp == NULL)
				return GetLastError();

			/* Update the IAT */
			address_table[j].u1.Function = (DWORD)fp;
			j++;
		}
		i++;
	}

	/* Restore protection */
	if (!VirtualProtect(curr_proc_base,
			    nt_header->OptionalHeader.SizeOfHeaders,
			    PAGE_READONLY, &old_protect))
		return GetLastError();

	for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++) {
		BYTE *dest = curr_proc_base + sections[i].VirtualAddress;
		DWORD is_executable = sections[i].Characteristics &
				      IMAGE_SCN_MEM_EXECUTE;
		DWORD is_writable = sections[i].Characteristics &
				    IMAGE_SCN_MEM_WRITE;
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

	*poep = (void (*)(void))(curr_proc_base +
				 nt_header->OptionalHeader.AddressOfEntryPoint);

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
	void (*oep)(void);

	int ret = unpack(&oep);

	if (ret != ERROR_SUCCESS)
		printf("Error %d\n", ret);
	else
		oep();

	return ret;
}
