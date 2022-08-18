#include <memoryapi.h>
#include "obfuscate.h"

#include "../zstd/build/single_file_libs/zstddeclib.c"

BYTE *deobfuscate(BYTE *mem, SIZE_T packed_size, SIZE_T unpacked_size)
{
	LPVOID buffer =
		VirtualAlloc(NULL, unpacked_size, MEM_COMMIT, PAGE_READWRITE);

	if (ZSTD_isError(
		    ZSTD_decompress(buffer, unpacked_size, mem, packed_size))) {
		VirtualFree(mem, 0, MEM_RELEASE);
		return NULL;
	}

	return buffer;
}

BOOL clean(BYTE *mem)
{
	return VirtualFree(mem, 0, MEM_RELEASE);
}
