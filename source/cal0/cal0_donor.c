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

#include "../config/config.h"
#include "../gfx/di.h"
#include "../gfx/gfx.h"
#include "../gfx/tui.h"
#include "../mem/heap.h"
#include "../mem/mc.h"
#include "../mem/minerva.h"
#include "../mem/sdram.h"
#include "../soc/smmu.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_sd.h"
#include "../storage/sdmmc.h"
#include "../utils/btn.h"
#include "../utils/list.h"
#include "../utils/sprintf.h"
#include "../utils/util.h"
#include "../soc/fuse.h"

#include <string.h>
#include "gcm.h"
#include "crc16.h"
#include "cal0.h"
#include "keyfile_read.h"

extern hekate_config h_cfg;

extern bool clear_sector_cache;
extern bool lock_sector_cache;
extern u32 secindex;

static u32 color_idx = 0;
static u32 start_time, end_time;

#define TPRINTF(text)                                           \
    end_time = get_tmr_us();                                    \
    gfx_printf(text " done in %d us\n", end_time - start_time); \
    start_time = get_tmr_us();                                  \
    minerva_periodic_training()

#define TPRINTFARGS(text, args...)                                    \
    end_time = get_tmr_us();                                          \
    gfx_printf(text " done in %d us\n", args, end_time - start_time); \
    start_time = get_tmr_us();                                        \
    minerva_periodic_training()

static inline u32 _read_le_u32(const void *buffer, u32 offset)
{
    return (*(u8 *)(buffer + offset + 0)) |
           (*(u8 *)(buffer + offset + 1) << 0x08) |
           (*(u8 *)(buffer + offset + 2) << 0x10) |
           (*(u8 *)(buffer + offset + 3) << 0x18);
}

void unseal_key(u8 *kek_source, u8 *kekek_source, u8 *master_key_0, u8 *dest, u8 usecase);

static inline uint64_t read64le(const volatile void *qword, size_t offset)
{
    return *(uint64_t *)((uintptr_t)qword + offset);
}

static inline uint64_t read64be(const volatile void *qword, size_t offset)
{
    return __builtin_bswap64(read64le(qword, offset));
}

static inline void write64le(volatile void *qword, size_t offset, uint64_t value)
{
    *(uint64_t *)((uintptr_t)qword + offset) = value;
}

static inline void write64be(volatile void *qword, size_t offset, uint64_t value)
{
    write64le(qword, offset, __builtin_bswap64(value));
}

void build_cal0_donor()
{
    sd_mount();

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_partial_grey(0x1B, 0, 1256);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kpr%kod%kin%kfo%k_g%ken%k v%d.%d.%d%k]\n\n",
               colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    tui_sbar(true);

    u8 master_key_0[0x10] = {0};
    if (!read_master_key_0(master_key_0) || get_crc_16(master_key_0, 0x10) != 0x801B)
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
    u32 prodinfo_size = 0;
    u8 *prodinfo_buffer = sd_file_read(donor_prodinfo_path, &prodinfo_size);

    if (!valid_donor_prodinfo(prodinfo_buffer, prodinfo_size))
        gfx_printf("Donor PRODINFO seems invalid.");
    else
        gfx_printf("%kLooks like a valid donor PRODINFO.\n", colors[(color_idx++) % 6]);

    gfx_printf("%kWriting device certificate\n", colors[(color_idx++) % 6]);
    write_device_certificate(prodinfo_buffer, device_id_as_string);

    gfx_printf("%kWriting ETicket certificate\n", colors[(color_idx++) % 6]);
    write_eticket_certificate(prodinfo_buffer, device_id_as_string);

    gfx_printf("%kWriting extended keys\n", colors[(color_idx++) % 6]);
    write_extended_ecc_b233_device_key(prodinfo_buffer, device_id_int, master_key_0);
    write_extended_rsa_2048_eticket_key(prodinfo_buffer, device_id_int, master_key_0);

    gfx_printf("%kWriting checksums\n", colors[(color_idx++) % 6]);
    write_all_crc(prodinfo_buffer, prodinfo_size);
    write_all_sha256(prodinfo_buffer);

    write_body_checksum(prodinfo_buffer);

    if (!valid_own_prodinfo(prodinfo_buffer, prodinfo_size, master_key_0))
        gfx_printf("%kSomething went wrong, writing output anyway...\n", colors[(color_idx++) % 6]);

    if (!sd_mount())
    {
        EPRINTF("Unable to mount SD.");
        goto free_buffers;
    }
    end_time = get_tmr_us();
    gfx_printf("%kDone in %d us\n\n", colors[(color_idx++) % 6], end_time - begin_time);

    f_mkdir("sd:/switch");
    char prodinfo_path[] = "sd:/switch/generated_prodinfo_from_donor.bin";
    if (!sd_save_to_file(prodinfo_buffer, prodinfo_size, prodinfo_path) && !f_stat(prodinfo_path, &fno))
    {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, prodinfo_path);
    }
    else
        EPRINTF("Unable to save generated PRODINFO to SD.");

free_buffers:
    free(prodinfo_buffer);

out_wait:
    gfx_printf("\n%kPress any key to return to the main menu.", colors[(color_idx++) % 6]);
    btn_wait();
}