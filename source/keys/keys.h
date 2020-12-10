/*
 * Copyright (c) 2019-2020 shchmue
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
#define RSA_2048_KEY_SIZE 256

// only tickets of type Rsa2048Sha256 are expected
typedef struct {
    u32 signature_type;   // always 0x10004
    u8 signature[RSA_2048_KEY_SIZE];
    u8 sig_padding[0x3C];
    char issuer[0x40];
    u8 titlekey_block[RSA_2048_KEY_SIZE];
    u8 format_version;
    u8 titlekey_type;
    u16 ticket_version;
    u8 license_type;
    u8 common_key_id;
    u16 property_mask;
    u64 reserved;
    u64 ticket_id;
    u64 device_id;
    u8 rights_id[0x10];
    u32 account_id;
    u32 sect_total_size;
    u32 sect_hdr_offset;
    u16 sect_hdr_count;
    u16 sect_hdr_entry_size;
    u8 padding[0x140];
} ticket_t;

typedef struct {
    u8 rights_id[0x10];
    u64 ticket_id;
    u32 account_id;
    u16 property_mask;
    u16 reserved;
} ticket_record_t;

typedef struct {
    u8 read_buffer[0x40000];
    u8 rights_ids[0x40000 / 0x10][0x10];
    u8 titlekeys[0x40000 / 0x10][0x10];
} titlekey_buffer_t;

typedef struct {
    u8 private_exponent[RSA_2048_KEY_SIZE];
    u8 modulus[RSA_2048_KEY_SIZE];
    u8 public_exponent[4];
    u8 reserved[0x14];
    u64 device_id;
    u8 gmac[0x10];
} rsa_keypair_t;

typedef struct {
    u8 master_kek[AES_128_KEY_SIZE];
    u8 data[0x70];
    u8 package1_key[AES_128_KEY_SIZE];
} keyblob_t;

typedef struct {
    u8 cmac[0x10];
    u8 iv[0x10];
    keyblob_t key_data;
    u8 unused[0x150];
} encrypted_keyblob_t;

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
        tsec_keys[AES_128_KEY_SIZE * 2];
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

// save key wrapper
#define SAVE_KEY(name) _save_key(#name, name, sizeof(name), text_buffer)
// save key with different name than variable
#define SAVE_KEY_VAR(name, varname) _save_key(#name, varname, sizeof(varname), text_buffer)
// save key family wrapper
#define SAVE_KEY_FAMILY(name, start) _save_key_family(#name, name, start, sizeof(name) / sizeof(name[0]), sizeof(name[0]), text_buffer)
// save key family with different name than variable
#define SAVE_KEY_FAMILY_VAR(name, varname, start) _save_key_family(#name, varname, start, sizeof(varname) / sizeof(varname[0]), sizeof(varname[0]), text_buffer)

void dump_keys();

#endif
