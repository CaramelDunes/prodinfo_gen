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

#include "cal0_donor.h"

#include "../config.h"
#include <gfx/di.h>
#include "../gfx/tui.h"
#include "../storage/emummc.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/util.h>
#include <mem/heap.h>
#include <soc/fuse.h>

#include <string.h>
#include "gcm.h"
#include "crc16.h"
#include "cal0.h"
#include "cal_blocks.h"
#include "../keys/extkeys.h"

extern hekate_config h_cfg;

extern bool clear_sector_cache;
extern bool lock_sector_cache;
extern u32 secindex;

static u32 color_idx = 0;
static u32 start_time, end_time;

static inline u32 _read_le_u32(const void *buffer, u32 offset)
{
    return (*(u8 *)(buffer + offset + 0)) |
           (*(u8 *)(buffer + offset + 1) << 0x08) |
           (*(u8 *)(buffer + offset + 2) << 0x10) |
           (*(u8 *)(buffer + offset + 3) << 0x18);
}

u8 *_master_key_from_key_generation(u8 donor_prodinfo_version, u8 key_generation, keyset_t *keyset);

void build_cal0_donor()
{
    sd_mount();

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 0, 1256);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kpr%kod%kin%kfo%k_g%ken%k v%d.%d.%d%k]\n\n",
               colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    tui_sbar(true);

    keyset_t keyset = {0};

    if (!read_keys(&keyset) || keyset.master_key_count == 0 || get_crc_16(keyset.master_keys[0], 0x10) != 0x801B)
    {
        gfx_printf("Couldn't get master_key_00 from sd:/switch/prod.keys\n", colors[(color_idx++) % 6]);
        goto out_wait;
    }

    color_idx = 0;

    start_time = get_tmr_us();
    u32 begin_time = get_tmr_us();

    u64 device_id_int = fuse_get_device_id();
    device_id_int |= 0x6300000000000000ULL;

    char device_id_as_string[0x11] = {0};
    device_id_string(device_id_as_string);

    gfx_printf("%kYour device id: %s\n", colors[(color_idx++) % 6], device_id_as_string);

    FILINFO fno;
    f_mkdir("sd:/switch");
    char donor_prodinfo_path[] = "sd:/switch/donor_prodinfo.bin";
    if (f_stat(donor_prodinfo_path, &fno))
    {
        gfx_printf("Couldn't find donor PRODINFO at sd:/switch/donor_prodinfo.bin");
        goto out_wait;
    }
    else if (fno.fsize < 0x40)
    {
        gfx_printf("Donor PRODINFO is too small!");
        goto out_wait;
    }
    else if (fno.fsize > 0x003FBC00)
    {
        gfx_printf("Donor PRODINFO is too big!");
        goto out_wait;
    }

    // Read donor prodinfo.
    u32 donor_prodinfo_size = 0;
    u8 *donor_prodinfo_buffer = sd_file_read(donor_prodinfo_path, &donor_prodinfo_size);

    u32 prodinfo_size = 0x3FBC00;
    u8 *prodinfo_buffer = malloc(prodinfo_size);
    memset(prodinfo_buffer, 0, prodinfo_size);

    u8 key_generation = 0;
    u8 *master_key = keyset.master_keys[0];

    if (!valid_prodinfo_checksums(donor_prodinfo_buffer, donor_prodinfo_size))
    {
        EPRINTF("Donor PRODINFO seems invalid.");
        goto free_buffers;
    }

    u32 donor_prodinfo_version = _read_le_u32(donor_prodinfo_buffer, 0x4);
    char donor_prodinfo_device_id[0x11] = {0};
    memcpy(donor_prodinfo_device_id, donor_prodinfo_buffer + OFFSET_OF_BLOCK(EccB233DeviceCertificate) + 0xC6, 0x10);

    gfx_printf("%kDonor PRODINFO looks valid\n version = %d\n device id = %s\n\n", colors[(color_idx++) % 6], donor_prodinfo_version, donor_prodinfo_device_id);

    if (donor_prodinfo_version >= 9 && !key_exists(keyset.donor_device_key_4x))
        WPRINTF("donor_device_key_4x has not been supplied, extended keys decryption might fail!");

    gfx_printf("%kWriting header\n", colors[(color_idx++) % 6]);
    write_header(prodinfo_buffer);

    gfx_printf("%kWriting config id\n", colors[(color_idx++) % 6]);
    write_config_id(prodinfo_buffer);

    gfx_printf("%kWriting Wlan country codes\n", colors[(color_idx++) % 6]);
    write_wlan_country_codes(prodinfo_buffer);

    gfx_printf("%kWriting MAC addresses\n", colors[(color_idx++) % 6]);
    write_mac_addresses(prodinfo_buffer, device_id_int);

    gfx_printf("%kWriting sensors calibration data\n", colors[(color_idx++) % 6]);
    write_sensors_offset_scale(prodinfo_buffer);

    gfx_printf("%kWriting blank serial number\n", colors[(color_idx++) % 6]);
    write_serial_number(prodinfo_buffer);

    gfx_printf("%kWriting random number\n", colors[(color_idx++) % 6]);
    write_random_number(prodinfo_buffer, device_id_int);

    gfx_printf("%kWriting battery lot\n", colors[(color_idx++) % 6]);
    write_battery_lot(prodinfo_buffer);

    gfx_printf("%kWriting speaker calibration data\n\n", colors[(color_idx++) % 6]);
    write_speaker_calibration_value(prodinfo_buffer);

    write_short_values(prodinfo_buffer);

    // Certificates
    gfx_printf("%kWriting empty SSL certificate\n", colors[(color_idx++) % 6]);
    write_ssl_certificate(prodinfo_buffer);

    gfx_printf("%kImporting device certificate\n", colors[(color_idx++) % 6]);
    import_device_certificate(donor_prodinfo_buffer, prodinfo_buffer); // Probably useless as we need to corrupt it for HOS to boot...
    write_device_certificate(prodinfo_buffer, device_id_as_string);

    gfx_printf("%kImporting ETicket certificate\n", colors[(color_idx++) % 6]);
    import_eticket_certificate(donor_prodinfo_buffer, prodinfo_buffer);

    gfx_printf("%kImporting Amiibo certificates\n", colors[(color_idx++) % 6]);
    import_amiiboo_certificates(donor_prodinfo_buffer, prodinfo_buffer);

    gfx_printf("%kImporting GameCard certificate\n\n", colors[(color_idx++) % 6]);
    import_gamecard_certificate(donor_prodinfo_buffer, prodinfo_buffer);

    // GCM blocks
    gfx_printf("%kImporting extended Device key\n", colors[(color_idx++) % 6]);
    key_generation = *(donor_prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedEccB233DeviceKey) + SIZE_OF_BLOCK(ExtendedEccB233DeviceKey) - 0x10) - 1;
    master_key = _master_key_from_key_generation(donor_prodinfo_version, key_generation, &keyset);

    if (!decrypt_extended_device_key(donor_prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedEccB233DeviceKey) + 0x10, master_key))
        WPRINTF("Could not decrypt donor extended Device key!");

    encrypt_extended_device_key(prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedEccB233DeviceKey) + 0x10, device_id_int, keyset.master_keys[0]);

    gfx_printf("%kImporting extended ETicket key\n", colors[(color_idx++) % 6]);

    key_generation = *(donor_prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedRsa2048ETicketKey) + SIZE_OF_BLOCK(ExtendedRsa2048ETicketKey) - 0x10) - 1;
    master_key = _master_key_from_key_generation(donor_prodinfo_version, key_generation, &keyset);

    if (!decrypt_extended_eticket_key(donor_prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedRsa2048ETicketKey) + 0x10, master_key))
        WPRINTF("Could not decrypt donor extended ETicket key!");

    encrypt_extended_eticket_key(prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedRsa2048ETicketKey) + 0x10, device_id_int, keyset.master_keys[0]);

    gfx_printf("%kImporting extended GameCard key\n", colors[(color_idx++) % 6]);

    key_generation = *(donor_prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedGameCardKey) + SIZE_OF_BLOCK(ExtendedGameCardKey) - 0x10) - 1;
    master_key = _master_key_from_key_generation(donor_prodinfo_version, key_generation, &keyset);

    if (!decrypt_extended_gamecard_key(donor_prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedGameCardKey) + 0x10, master_key))
        WPRINTF("Could not decrypt donor extended GameCard key!");

    encrypt_extended_gamecard_key(prodinfo_buffer, prodinfo_buffer + OFFSET_OF_BLOCK(ExtendedGameCardKey) + 0x10, device_id_int, keyset.master_keys[0]);

    gfx_printf("%k\nWriting checksums\n", colors[(color_idx++) % 6]);
    write_all_crc(prodinfo_buffer, prodinfo_size);
    write_all_sha256(prodinfo_buffer);

    write_body_checksum(prodinfo_buffer);

    if (!valid_own_prodinfo(prodinfo_buffer, prodinfo_size, keyset.master_keys[0]))
        WPRINTF("Something went wrong, writing output anyway...");

    gfx_printf("\n%kWriting output file...\n", colors[(color_idx++) % 6]);

    if (!sd_mount())
    {
        EPRINTF("Unable to mount SD.");
        goto free_buffers;
    }

    f_mkdir("sd:/switch");
    char prodinfo_path[] = "sd:/switch/generated_prodinfo_from_donor.bin";
    if (!sd_save_to_file(prodinfo_buffer, prodinfo_size, prodinfo_path) && !f_stat(prodinfo_path, &fno))
    {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, prodinfo_path);
    }
    else
        EPRINTF("Unable to save generated PRODINFO to SD.");

    end_time = get_tmr_us();
    gfx_printf("\n%kDone in %d us\n\n", colors[(color_idx++) % 6], end_time - begin_time);

free_buffers:
    free(prodinfo_buffer);

out_wait:
    gfx_printf("\n%kPress any key to return to the main menu.", colors[(color_idx++) % 6]);
    btn_wait();
}

u8 *_master_key_from_key_generation(u8 donor_prodinfo_version, u8 key_generation, keyset_t *keyset)
{
    u8 *master_key = keyset->master_keys[0];

    if (donor_prodinfo_version >= 9)
    {
        u8 offset_key_generation = key_generation - 3;

        if (offset_key_generation >= 0 && offset_key_generation < 0x8 && key_exists(keyset->donor_device_master_keys[offset_key_generation]))
        {
            master_key = keyset->donor_device_master_keys[offset_key_generation];
        }
    }

    return master_key;
}