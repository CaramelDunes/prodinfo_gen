/*
 * Copyright (c) 2019-2020 CaramelDunes
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

#include "cal0.h"

#include <stdlib.h>
#include <string.h>
#include "gcm.h"
#include <sec/se.h>
#include <sec/se_t210.h>
#include <soc/fuse.h>

#include "cal_blocks.h"

#include "crc16.h"

static const u8 es_kek_source[0x10] = {0x7f, 0x5b, 0xb0, 0x84, 0x7b, 0x25, 0xaa, 0x67, 0xfa, 0xc8, 0x4b, 0xe2, 0x3d, 0x7b, 0x69, 0x03};
static const u8 prod_kekek_source[0x10] = {0xaf, 0x44, 0xf3, 0x3e, 0x82, 0x4e, 0x83, 0x92, 0xed, 0x38, 0xe1, 0x2f, 0x29, 0xcf, 0x6f, 0x4d};
static const u8 eticket_rsa_kekek_source[0x10] = {0x46, 0x6e, 0x57, 0xb7, 0x4a, 0x44, 0x7f, 0x02, 0xf3, 0x21, 0xcd, 0xe5, 0x8f, 0x2f, 0x55, 0x35};
static const u8 eticket_rsa_kek_source[0x10] = {0xdb, 0xa4, 0x51, 0x12, 0x4c, 0xa0, 0xa9, 0x83, 0x68, 0x14, 0xf5, 0xed, 0x95, 0xe3, 0x12, 0x5b};
static const u8 aes_kek_seed_01[0x10] = {
    0xA2, 0xAB, 0xBF, 0x9C, 0x92, 0x2F, 0xBB, 0xE3, 0x78, 0x79, 0x9B, 0xC0, 0xCC, 0xEA, 0xA5, 0x74};
static const u8 aes_kek_seed_03[0x10] = {
    0xE5, 0x4D, 0x9A, 0x02, 0xF0, 0x4F, 0x5F, 0xA8, 0xAD, 0x76, 0x0A, 0xF6, 0x32, 0x95, 0x59, 0xBB};
static const u8 aes_kek_generation_source[0x10] = {
    0x4D, 0x87, 0x09, 0x86, 0xC4, 0x5D, 0x20, 0x72, 0x2F, 0xBA, 0x10, 0x53, 0xDA, 0x92, 0xE8, 0xA9};

static const u32 prodinfo_min_size = 0x3D70;
static const u32 prodinfo_max_size = 0x003FBC00;

static inline uint64_t read64le(const volatile void *qword, size_t offset)
{
    return *(uint64_t *)((uintptr_t)qword + offset);
}

static inline void write64le(volatile void *qword, size_t offset, uint64_t value)
{
    *(uint64_t *)((uintptr_t)qword + offset) = value;
}

static inline void write64be(volatile void *qword, size_t offset, uint64_t value)
{
    write64le(qword, offset, __builtin_bswap64(value));
}

void device_id_string(char device_id_string[0x11])
{
    u64 device_id = fuse_get_device_id();
    device_id |= 0x6300000000000000ULL;

    static const char digits[] = "0123456789ABCDEF";
    int i = 0;
    u64 v = device_id;
    for (i = 0xF; i >= 0; i--)
    {
        device_id_string[i] = digits[v % 16];
        v /= 16;
    }
}

bool valid_donor_prodinfo(u8 *prodinfo_buffer, u32 prodinfo_size)
{
    return prodinfo_size >= prodinfo_min_size &&
           prodinfo_size <= prodinfo_max_size &&
           valid_cal0_signature(prodinfo_buffer, prodinfo_size) &&
           valid_crcs(prodinfo_buffer, prodinfo_size) &&
           valid_body_checksum(prodinfo_buffer, prodinfo_size);
}

bool valid_own_prodinfo(u8 *prodinfo_buffer, u32 prodinfo_size, u8 *master_key_0)
{
    return valid_donor_prodinfo(prodinfo_buffer, prodinfo_size) &&
           valid_extended_rsa_2048_eticket_key(prodinfo_buffer, master_key_0) &&
           valid_extended_ecc_b233_device_key(prodinfo_buffer, master_key_0);
}

bool valid_crcs(u8 *prodinfo_buffer, u32 prodinfo_size)
{
    int num_crc_blocks = sizeof(crc_blocks) / sizeof(crc_block_t);

    for (int i = 0; i < num_crc_blocks; i++)
    {
        if (crc_blocks[i].offset > prodinfo_size)
            continue;

        if (!has_valid_crc16(prodinfo_buffer, crc_blocks[i].offset, crc_blocks[i].size))
            return false;
    }

    return true;
}

static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed)
{
    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, kek_seed);
    se_aes_unwrap_key(ks, ks, key_source);
}

void unseal_key(const u8 *kek_source, const u8 *kekek_source, u8 *master_key_0, u8 *dest, u8 usecase)
{
    u8 temp_key[0x10] = {0};
    const u8 *seed = NULL;
    switch (usecase)
    {
    case 1:
        seed = aes_kek_seed_01;
        break;

    case 3:
        seed = aes_kek_seed_03;
        break;

    default:
        // gfx_printf("Invalid usescase: %c\n", usecase);
        break;
    }

    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ seed[i];

    _generate_kek(KEYSLOT_SWITCH_TEMPKEY, kek_source, master_key_0, temp_key);
    se_aes_crypt_block_ecb(KEYSLOT_SWITCH_TEMPKEY, 0, dest, kekek_source);
}

void ghash_calc(const u8 *plaintext, u32 plaintext_size, const u8 ctr[0x10], u8 *dest)
{
    /* J = GHASH(CTR); */
    uint8_t j_block[0x10];
    ghash(j_block, ctr, 0x10, NULL, false);

    /* MAC = GHASH(PLAINTEXT) ^ ENCRYPT(J) */
    /* Note: That MAC is calculated over plaintext_size is non-standard. */
    /* It is supposed to be over the ciphertext. */
    ghash(dest, plaintext, plaintext_size, j_block, true);
}

static int _is_valid_gcm_content(const u8 *ctr, u8 *ciphertext, u32 ciphertext_size, u32 ks)
{
    u32 plaintext_size = ciphertext_size;
    u8 *encrypted_ghash = ciphertext + ciphertext_size;

    u8 *plaintext = malloc(plaintext_size);

    se_aes_crypt_ctr(KEYSLOT_SWITCH_TEMPKEY, plaintext, plaintext_size, ciphertext, plaintext_size, ctr);

    uint8_t calc_mac[0x10];
    ghash_calc(plaintext, plaintext_size, ctr, calc_mac);
    int match = memcmp(encrypted_ghash, calc_mac, 0x10);

    free(plaintext);

    return match == 0;
}

static void _fix_gcm_content(const u8 *ctr, u8 *ciphertext, u32 ciphertext_size, u64 device_id, u32 ks)
{
    u8 *plaintext = ciphertext;
    u32 plaintext_size = ciphertext_size;
    u8 *encrypted_ghash = ciphertext + ciphertext_size;

    se_aes_crypt_ctr(KEYSLOT_SWITCH_TEMPKEY, plaintext, plaintext_size, ciphertext, plaintext_size, ctr);

    // u64 file_device_id = (read64be(plaintext, plaintext_size - 0x8) & 0x00FFFFFFFFFFFFFFULL);
    // gfx_hexdump(0, (const u8 *)&file_device_id, 0x08);

    // Replace device id
    write64be(plaintext, plaintext_size - 0x8, device_id);

    // Copy new GHASH
    ghash_calc(plaintext, plaintext_size, ctr, encrypted_ghash);

    // Reencrypt
    se_aes_crypt_ctr(KEYSLOT_SWITCH_TEMPKEY, ciphertext, plaintext_size, plaintext, plaintext_size, ctr);
}

bool valid_extended_rsa_2048_eticket_key(u8 *prodinfo_buffer, u8 *master_key_0)
{
    u8 the_key[0x10] = {0};
    unseal_key(eticket_rsa_kekek_source, eticket_rsa_kek_source, master_key_0, the_key, 3);
    se_aes_key_set(KEYSLOT_SWITCH_TEMPKEY, the_key, 0x10);

    u8 *ctr = prodinfo_buffer + 0x3890;
    u8 *ciphertext = ctr + 0x10;

    int valid = _is_valid_gcm_content(ctr, ciphertext, 0x220, KEYSLOT_SWITCH_TEMPKEY);

    return valid;
}

void write_extended_rsa_2048_eticket_key(u8 *prodinfo_buffer, u64 device_id, u8 *master_key_0)
{
    u8 the_key[0x10] = {0};
    unseal_key(eticket_rsa_kekek_source, eticket_rsa_kek_source, master_key_0, the_key, 3);
    se_aes_key_set(KEYSLOT_SWITCH_TEMPKEY, the_key, 0x10);

    u8 *ctr = prodinfo_buffer + 0x3890;
    u8 *ciphertext = ctr + 0x10;

    _fix_gcm_content(ctr, ciphertext, 0x220, device_id, KEYSLOT_SWITCH_TEMPKEY);
}

bool valid_extended_ecc_b233_device_key(u8 *prodinfo_buffer, u8 *master_key_0)
{
    u8 the_key[0x10] = {0};
    unseal_key(es_kek_source, prod_kekek_source, master_key_0, the_key, 1);
    se_aes_key_set(KEYSLOT_SWITCH_TEMPKEY, the_key, 0x10);

    u8 *ctr = prodinfo_buffer + 0x3770;
    u8 *ciphertext = ctr + 0x10;

    int valid = _is_valid_gcm_content(ctr, ciphertext, 0x30, KEYSLOT_SWITCH_TEMPKEY);

    return valid;
}

void write_extended_ecc_b233_device_key(u8 *prodinfo_buffer, u64 device_id, u8 *master_key_0)
{
    u8 the_key[0x10] = {0};
    unseal_key(es_kek_source, prod_kekek_source, master_key_0, the_key, 1);
    se_aes_key_set(KEYSLOT_SWITCH_TEMPKEY, the_key, 0x10);

    u8 *ctr = prodinfo_buffer + 0x3770;
    u8 *ciphertext = ctr + 0x10;

    _fix_gcm_content(ctr, ciphertext, 0x30, device_id, KEYSLOT_SWITCH_TEMPKEY);
}

bool valid_ecc_b233_device_certificate(u8 *prodinfo_buffer)
{
    return has_valid_crc16(prodinfo_buffer, 0x0480, 0x190);
}

bool valid_rsa_2048_eticket_certificate(u8 *prodinfo_buffer)
{
    return has_valid_crc16(prodinfo_buffer, 0x2A90, 0x250);
}

void write_body_checksum(u8 *prodinfo_buffer)
{
    u32 body_size = *((u32 *)(prodinfo_buffer + 0x08));

    se_calc_sha256_oneshot(prodinfo_buffer + 0x20, prodinfo_buffer + 0x40, body_size);
}

bool valid_cal0_signature(u8 *prodinfo_buffer, u32 prodinfo_size)
{
    return prodinfo_size > 4 && prodinfo_buffer[0] == 'C' && prodinfo_buffer[1] == 'A' && prodinfo_buffer[2] == 'L' && prodinfo_buffer[3] == '0';
}

bool valid_body_checksum(u8 *prodinfo_buffer, u32 prodinfo_size)
{
    // Check body size.
    u32 body_size = *((u32 *)(prodinfo_buffer + 0x08));
    if (prodinfo_size < body_size + 0x40)
    {
        return false;
    }

    // Check prodinfo hash.
    u8 body_checksum[0x20] = {0};
    se_calc_sha256_oneshot(body_checksum, prodinfo_buffer + 0x40, body_size);
    int is_body_corrupt = memcmp(body_checksum, prodinfo_buffer + 0x20, 0x20);

    return !is_body_corrupt;
}

void write_mac_addresses(u8 *prodinfo_buffer, u64 device_id)
{
    // Here we are using the device id to generate an almost unique, yet deterministic, MAC address.

    // WlanMacAddress
    u8 blank_nintendo_mac[] = {0xA4, 0x38, 0xCC};
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(WlanMacAddress), blank_nintendo_mac, 3);
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(WlanMacAddress) + 3, &device_id, 3);

    // BdAddress
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(BtMacAddress), blank_nintendo_mac, 3);
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(BtMacAddress) + 3, &device_id, 3);
}

void write_serial_number(u8 *prodinfo_buffer)
{
    const char serial_number[] = "XAW10000000000";
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(SerialNumber), serial_number, 14);
}

void write_device_certificate(u8 *prodinfo_buffer, const char *device_id_string)
{
    prodinfo_buffer[0x0480 + 0xC4] = 'N';
    prodinfo_buffer[0x0480 + 0xC5] = 'X';

    memcpy(prodinfo_buffer + 0x0480 + 0xC6, device_id_string, 0x10);

    prodinfo_buffer[0x0480 + 0xD6] = '-';
    prodinfo_buffer[0x0480 + 0xD7] = '0';
}

void write_ssl_certificate(u8 *prodinfo_buffer)
{
    u8 ssl_certificate_size[] = {0xE9, 0x05};
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(SslCertificateSize), ssl_certificate_size, sizeof(ssl_certificate_size));
}

void write_random_number(u8 *prodinfo_buffer, u64 device_id)
{
    memset(prodinfo_buffer + 0x1300, 0, 0x1000);
    u64 key[2] = {device_id, device_id};
    u8 ctr[0x10] = {0};

    se_aes_key_set(KEYSLOT_SWITCH_TEMPKEY, key, 0x10);
    se_aes_crypt_ctr(KEYSLOT_SWITCH_TEMPKEY, prodinfo_buffer + 0x1300, 0x1000, prodinfo_buffer + 0x1300, 0x1000, ctr);
}

void write_eticket_certificate(u8 *prodinfo_buffer, const char *device_id_string)
{
    prodinfo_buffer[OFFSET_OF_BLOCK(Rsa2048ETicketCertificate) + 0xC4] = 'N';
    prodinfo_buffer[OFFSET_OF_BLOCK(Rsa2048ETicketCertificate) + 0xC5] = 'X';

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(Rsa2048ETicketCertificate) + 0xC6, device_id_string, 0x10);

    prodinfo_buffer[OFFSET_OF_BLOCK(Rsa2048ETicketCertificate) + 0xD6] = '-';
    prodinfo_buffer[OFFSET_OF_BLOCK(Rsa2048ETicketCertificate) + 0xD7] = '0';
}

void write_config_id(u8 *prodinfo_buffer)
{
    const char default_config_id[] = "MP_00_01_00_00";

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(ConfigurationId1), default_config_id, sizeof(default_config_id));
}

void write_wlan_country_codes(u8 *prodinfo_buffer)
{
    const u8 default_wlan_country_codes[11] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x52, 0x31, 0x00};

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(WlanCountryCodes), default_wlan_country_codes, sizeof(default_wlan_country_codes));
}

void write_header(u8 *prodinfo_buffer)
{
    unsigned char header[32] = {
        'C', 'A', 'L', '0', 0x07, 0x00, 0x00, 0x00, 0x30, 0x3D, 0x00, 0x00,
        0x01, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x71, 0x0E};

    memcpy(prodinfo_buffer, header, sizeof(header));
}

void write_sensors_offset_scale(u8 *prodinfo_buffer)
{
    unsigned char sensors_offset_scale[32] = {
        0xFC, 0xFF, 0xFA, 0xFF, 0xC4, 0x00, 0x46, 0x06, 0xFF, 0x3F, 0xFF, 0x3F,
        0xFF, 0x3F, 0x15, 0xF4, 0xFD, 0xFF, 0xDD, 0xFF, 0xF3, 0xFF, 0x1B, 0x13,
        0xFF, 0x3F, 0xFF, 0x3F, 0xFF, 0x3F, 0x15, 0xF4};

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(AccelerometerOffset), sensors_offset_scale, sizeof(sensors_offset_scale));
}

void write_battery_lot(u8 *prodinfo_buffer)
{
    const char battery_lot[] = "BHACHZZADM402211310199";
    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(BatteryLot), battery_lot, sizeof(battery_lot));
}

void write_speaker_calibration_value(u8 *prodinfo_buffer)
{
    unsigned char speaker_calibration_value[80] = {
        0x00, 0x03, 0x00, 0x5A, 0xED, 0x87, 0x00, 0x00, 0xC1, 0x61, 0x1E, 0xAF,
        0x09, 0x5B, 0xC9, 0x60, 0x18, 0x8D, 0x00, 0x00, 0xDE, 0x2A, 0x0F, 0xDB,
        0xFC, 0xB6, 0x00, 0x00, 0x08, 0x93, 0x01, 0xF3, 0x1F, 0xAA, 0x00, 0x00,
        0x1F, 0xB4, 0x00, 0x4B, 0x1F, 0xB4, 0x08, 0x00, 0x08, 0x00, 0x00, 0xC1,
        0x60, 0x41, 0x1F, 0x80, 0x04, 0x80, 0x6B, 0x30, 0x04, 0x04, 0x12, 0x12,
        0x00, 0x00, 0x94, 0x94, 0x00, 0x00, 0xAA, 0xAA, 0x50, 0x00, 0x00, 0x80,
        0x2F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(SpeakerCalibrationValue), speaker_calibration_value, sizeof(speaker_calibration_value));
}

void write_short_values(u8 *prodinfo_buffer)
{
    prodinfo_buffer[OFFSET_OF_BLOCK(RegionCode)] = 1;
    prodinfo_buffer[OFFSET_OF_BLOCK(ProductModel)] = 1;

    unsigned char brightness_mapping[12] = {
        0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x0A, 0xD7, 0xA3, 0x3C};

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(LcdBacklightBrightnessMapping), brightness_mapping, sizeof(brightness_mapping));

    unsigned char lcd_vendor_id[3] = {
        0x0F, 0x94, 0x30};

    memcpy(prodinfo_buffer + OFFSET_OF_BLOCK(LcdVendorId), lcd_vendor_id, sizeof(lcd_vendor_id));
}

void write_all_crc(u8 *prodinfo_buffer, u32 prodinfo_size)
{
    int num_crc_blocks = sizeof(crc_blocks) / sizeof(crc_block_t);

    for (int i = 0; i < num_crc_blocks; i++)
    {
        if (crc_blocks[i].offset > prodinfo_size)
            continue;

        write_crc16(prodinfo_buffer, crc_blocks[i].offset, crc_blocks[i].size);
    }
}

void write_all_sha256(u8 *prodinfo_buffer)
{
    // RandomNumber
    se_calc_sha256_oneshot(prodinfo_buffer + 0x2300, prodinfo_buffer + 0x1300, 0x1000);

    // GameCardCertificate
    se_calc_sha256_oneshot(prodinfo_buffer + 0x2840, prodinfo_buffer + 0x2440, 0x400);

    // SslCertificate
    u32 ssl_certificate_size = *(u32 *)(prodinfo_buffer + OFFSET_OF_BLOCK(SslCertificateSize));
    se_calc_sha256_oneshot(prodinfo_buffer + 0x12E0, prodinfo_buffer + 0x0AE0, ssl_certificate_size);
}
