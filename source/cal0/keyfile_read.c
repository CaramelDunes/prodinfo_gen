#include "../config/config.h"
#include "../gfx/di.h"
#include "../gfx/gfx.h"
#include "../gfx/tui.h"
#include "../storage/sdmmc.h"
#include "../storage/nx_sd.h"
#include "../utils/btn.h"
#include "../utils/sprintf.h"
#include "../utils/util.h"
#include "../mem/heap.h"
#include "../soc/fuse.h"

#include <string.h>
#include <stdlib.h>
#include "gcm.h"
#include "crc16.h"
#include "cal0.h"

// https://nachtimwald.com/2017/09/24/hex-encode-and-decode-in-c/
int hexchr2bin(const char hex, char *out)
{
    if (out == NULL)
        return 0;

    if (hex >= '0' && hex <= '9')
    {
        *out = hex - '0';
    }
    else if (hex >= 'A' && hex <= 'F')
    {
        *out = hex - 'A' + 10;
    }
    else if (hex >= 'a' && hex <= 'f')
    {
        *out = hex - 'a' + 10;
    }
    else
    {
        return 0;
    }

    return 1;
}

size_t hexs2bin(const char *hex, unsigned char *out)
{
    size_t len;
    char b1;
    char b2;
    size_t i;

    if (hex == NULL || *hex == '\0' || out == NULL)
        return 0;

    len = strlen(hex);
    if (len % 2 != 0)
        return 0;
    len /= 2;

    for (i = 0; i < len; i++)
    {
        if (!hexchr2bin(hex[i * 2], &b1) || !hexchr2bin(hex[i * 2 + 1], &b2))
        {
            return 0;
        }
        out[i] = (b1 << 4) | b2;
    }
    return len;
}

bool read_master_key_0(u8 *master_key_0)
{
    FILINFO fno;
    f_mkdir("sd:/switch");
    char prod_keys_path[] = "sd:/switch/prod.keys";
    if (f_stat(prod_keys_path, &fno) || fno.fsize < 0x40 || fno.fsize > 0x003FBC00)
        return false;

    // Read donor prodinfo.
    u32 keyfile_size = 0;
    char *keyfile_buffer = sd_file_read(prod_keys_path, &keyfile_size);

    const char *needle = "master_key_00 = ";
    char *position = strstr(keyfile_buffer, needle);

    if (!position)
        return false;

    position += strlen(needle);

    if ((void*)position - (void*)keyfile_buffer + 32 > keyfile_size)
        return false;

    position[32] = 0;
    return hexs2bin(position, master_key_0) == 16;
}
