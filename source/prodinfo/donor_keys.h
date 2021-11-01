/*
ISC License

Copyright (c) 2018, SciresM
Copyright (c) 2020-2021, CaramelDunes

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

// https://raw.githubusercontent.com/SciresM/hactool/master/extkeys.h

#ifndef HACTOOL_EXTKEYS_H
#define HACTOOL_EXTKEYS_H

#include <string.h>
#include "../config.h"

#include <libs/fatfs/ff.h>

#define NB_MASTER_KEYS KB_FIRMWARE_VERSION_MAX + 1

typedef struct read_keyset
{
    u8 device_key_4x[0x10];
} read_keyset_t;

bool parse_hex_key(unsigned char *key, const char *hex, unsigned int len);
void extkeys_initialize_settings(read_keyset_t *keyset, char *filebuffer);
int key_exists(const void *data);

bool read_keys(read_keyset_t *ks, const char* keyfile_path);

#endif
