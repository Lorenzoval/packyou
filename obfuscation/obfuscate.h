#pragma once

#include <windef.h>

__attribute__((section("packyou"))) BYTE *
deobfuscate(BYTE *mem, SIZE_T packed_size, SIZE_T unpacked_size);

__attribute__((section("packyou"))) BOOL clean(BYTE *mem);
