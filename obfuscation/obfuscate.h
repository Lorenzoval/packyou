#pragma once

#include <windef.h>

BYTE *deobfuscate(BYTE *mem, SIZE_T packed_size, SIZE_T unpacked_size);
BOOL clean(BYTE *mem);
