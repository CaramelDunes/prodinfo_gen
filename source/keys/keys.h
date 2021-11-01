/*
 * Copyright (c) 2019-2021 shchmue
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _KEYS_H_
#define _KEYS_H_

#include <utils/types.h>

#include "../hos/hos.h"

#define AES_128_KEY_SIZE 16

typedef struct {
    u8 master_kek[AES_128_KEY_SIZE];
    u8 data[0x70];
    u8 package1_key[AES_128_KEY_SIZE];
} keyblob_t;

typedef struct {
    u8  temp_key[AES_128_KEY_SIZE],
        bis_key[4][AES_128_KEY_SIZE * 2],
        device_key[AES_128_KEY_SIZE],
        device_key_4x[AES_128_KEY_SIZE],
        sd_seed[AES_128_KEY_SIZE],
        // FS-related keys
        header_key[AES_128_KEY_SIZE * 2],
        save_mac_key[AES_128_KEY_SIZE],
        // other sysmodule keys
        eticket_rsa_kek[AES_128_KEY_SIZE],
        eticket_rsa_kek_personalized[AES_128_KEY_SIZE],
        ssl_rsa_kek[AES_128_KEY_SIZE],
        // keyblob-derived families
        keyblob_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        keyblob_mac_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        package1_key[KB_FIRMWARE_VERSION_600 + 1][AES_128_KEY_SIZE],
        // master key-derived families
        key_area_key[3][KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        master_kek[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        master_key[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        package2_key[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        titlekek[KB_FIRMWARE_VERSION_MAX + 1][AES_128_KEY_SIZE],
        tsec_key[AES_128_KEY_SIZE],
        tsec_root_key[AES_128_KEY_SIZE];
    u32 sbk[4];
    keyblob_t keyblob[KB_FIRMWARE_VERSION_600 + 1];
} key_derivation_ctx_t;

typedef struct {
    char rights_id[0x20];
    char equals[3];
    char titlekey[0x20];
    char newline[1];
} titlekey_text_buffer_t;

#define TPRINTF(text) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

#define TPRINTFARGS(text, args...) \
    end_time = get_tmr_us(); \
    gfx_printf(text" done in %d us\n", args, end_time - start_time); \
    start_time = get_tmr_us(); \
    minerva_periodic_training()

void dump_keys(key_derivation_ctx_t* output);

#endif
