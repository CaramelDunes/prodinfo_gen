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

#include "keys.h"

#include "../config.h"
#include <gfx/di.h>
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include "../hos/hos.h"
#include "../hos/pkg1.h"
#include "../hos/pkg2.h"
#include "../hos/sept.h"
#include <libs/fatfs/ff.h>
#include <libs/nx_savedata/save.h>
#include <mem/heap.h>
#include <mem/mc.h>
#include <mem/minerva.h>
#include <mem/sdram.h>
#include <sec/se.h>
#include <sec/se_t210.h>
#include <sec/tsec.h>
#include <soc/fuse.h>
#include <mem/smmu.h>
#include <soc/t210.h>
#include "../storage/emummc.h"
#include "../storage/nx_emmc.h"
#include "../storage/nx_emmc_bis.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/list.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "key_sources.inl"

#include <string.h>

extern hekate_config h_cfg;

static u32 _key_count = 0, _titlekey_count = 0;
static u32 start_time, end_time;
u32 color_idx = 0;

static ALWAYS_INLINE u32 _read_le_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 0)        ) |
           (*(u8*)(buffer + offset + 1) << 0x08) |
           (*(u8*)(buffer + offset + 2) << 0x10) |
           (*(u8*)(buffer + offset + 3) << 0x18);
}

static ALWAYS_INLINE u32 _read_be_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 3)        ) |
           (*(u8*)(buffer + offset + 2) << 0x08) |
           (*(u8*)(buffer + offset + 1) << 0x10) |
           (*(u8*)(buffer + offset + 0) << 0x18);
}

// key functions
static int   _key_exists(const void *data) { return memcmp(data, zeros, 0x10) != 0; };
static void  _save_key(const char *name, const void *data, u32 len, char *outbuf);
static void  _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf);
static void  _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);
static void  _get_device_key(u32 ks, void *out_device_key, u32 revision, const void *device_key, const void *master_key);
// titlekey functions
static bool  _test_key_pair(const void *E, const void *D, const void *N);

static ALWAYS_INLINE u8 *_find_tsec_fw(const u8 *pkg1) {
    const u32 tsec_fw_align = 0x100;
    const u32 tsec_fw_first_instruction = 0xCF42004D;

    for (const u32 *pos = (const u32 *)pkg1; (u8 *)pos < pkg1 + PKG1_MAX_SIZE; pos += tsec_fw_align / sizeof(u32))
        if (*pos == tsec_fw_first_instruction)
            return (u8 *)pos;

    return NULL;
}

static ALWAYS_INLINE u32 _get_tsec_fw_size(tsec_key_data_t *key_data) {
    return key_data->blob0_size + sizeof(tsec_key_data_t) + key_data->blob1_size + key_data->blob2_size + key_data->blob3_size + key_data->blob4_size;
}

static bool _get_titlekeys_from_save(u32 buf_size, const u8 *save_mac_key, titlekey_buffer_t *titlekey_buffer, rsa_keypair_t *rsa_keypair) {
    FIL fp;
    u64 br = buf_size;
    u64 offset = 0;
    u32 file_tkey_count = 0;
    u32 save_x = gfx_con.x, save_y = gfx_con.y;
    bool is_personalized = rsa_keypair != NULL;
    u32 start_titlekey_count = _titlekey_count;
    char titlekey_save_path[32] = "bis:/save/80000000000000E1";

    if (is_personalized) {
        titlekey_save_path[25] = '2';
        gfx_printf("\n%kPersonalized... ", colors[color_idx % 6]);
    } else {
        gfx_printf("\n%kCommon...       ", colors[color_idx % 6]);
    }

    if (f_open(&fp, titlekey_save_path, FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open e1 save. Skipping.");
        return false;
    }

    save_ctx_t *save_ctx = calloc(1, sizeof(save_ctx_t));
    save_init(save_ctx, &fp, save_mac_key, 0);

    bool save_process_success = save_process(save_ctx);
    TPRINTF("\n  Save process...");

    if (!save_process_success) {
        EPRINTF("Failed to process es save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    char ticket_bin_path[0x40] = "/ticket.bin";
    char ticket_list_bin_path[0x40] = "/ticket_list.bin";
    save_data_file_ctx_t ticket_file;

    if (!save_open_file(save_ctx, &ticket_file, ticket_list_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket_list.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    bool terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) || titlekey_buffer->read_buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        minerva_periodic_training();
        ticket_record_t *curr_ticket_record = (ticket_record_t *)titlekey_buffer->read_buffer;
        for (u32 i = 0; i < buf_size; i += sizeof(ticket_record_t), curr_ticket_record++) {
            if (curr_ticket_record->rights_id[0] == 0xFF) {
                terminator_reached = true;
                break;
            }
            file_tkey_count++;
        }
    }
    TPRINTF("  Count keys...");

    if (!save_open_file(save_ctx, &ticket_file, ticket_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket.bin in save.");
        f_close(&fp);
        save_free_contexts(save_ctx);
        free(save_ctx);
        return false;
    }

    const u32 ticket_sig_type_rsa2048_sha256 = 0x10004;

    offset = 0;
    terminator_reached = false;
    u32 pct = 0, last_pct = 0;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, titlekey_buffer->read_buffer, buf_size) || titlekey_buffer->read_buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        ticket_t *curr_ticket = (ticket_t *)titlekey_buffer->read_buffer;
        for (u32 j = 0; j < buf_size; j += sizeof(ticket_t), curr_ticket++) {
            minerva_periodic_training();
            pct = (_titlekey_count - start_titlekey_count) * 100 / file_tkey_count;
            if (pct > last_pct && pct <= 100) {
                last_pct = pct;
                tui_pbar(save_x, save_y, pct, COLOR_GREEN, 0xFF155500);
            }
            if (curr_ticket->signature_type != ticket_sig_type_rsa2048_sha256) {
                terminator_reached = true;
                break;
            }
            if (is_personalized) {
                se_rsa_exp_mod(0, curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block), curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block));
                if (se_rsa_oaep_decode(
                        curr_ticket->titlekey_block, sizeof(titlekey_buffer->titlekeys[0]),
                        null_hash, sizeof(null_hash),
                        curr_ticket->titlekey_block, sizeof(curr_ticket->titlekey_block)
                    ) != sizeof(titlekey_buffer->titlekeys[0])
                )
                    continue;
            }
            memcpy(titlekey_buffer->rights_ids[_titlekey_count], curr_ticket->rights_id, sizeof(titlekey_buffer->rights_ids[0]));
            memcpy(titlekey_buffer->titlekeys[_titlekey_count], curr_ticket->titlekey_block, sizeof(titlekey_buffer->titlekeys[0]));
            _titlekey_count++;
        }
    }
    tui_pbar(save_x, save_y, 100, COLOR_GREEN, 0xFF155500);
    f_close(&fp);
    save_free_contexts(save_ctx);
    free(save_ctx);

    gfx_con_setpos(0, save_y);

    if (is_personalized) {
        TPRINTFARGS("\n%kPersonalized... ", colors[(color_idx++) % 6]);
    } else {
        TPRINTFARGS("\n%kCommon...       ", colors[(color_idx++) % 6]);
    }

    gfx_printf("\n\n\n");

    return true;
}

#define RELOC_META_OFF 0x7C

void dump_keys() {
    u8  temp_key[0x10],
        bis_key[4][0x20] = {0},
        device_key[0x10] = {0},
        device_key_4x[0x10] = {0},
        sd_seed[0x10] = {0},
        // FS-related keys
        header_key[0x20] = {0},
        save_mac_key[0x10] = {0},
        // other sysmodule keys
        eticket_rsa_kek[0x10] = {0},
        eticket_rsa_kek_personalized[0x10] = {0},
        ssl_rsa_kek[0x10] = {0},
        // keyblob-derived families
        keyblob_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        keyblob_mac_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        package1_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        // master key-derived families
        key_area_key[3][KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        master_kek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        master_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        package2_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        titlekek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0};

    keyblob_t keyblob[KB_FIRMWARE_VERSION_600+1] = {0};

    sd_mount();

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    _key_count = 0;
    _titlekey_count = 0;
    color_idx = 0;

    start_time = get_tmr_us();
    u32 begin_time = get_tmr_us();
    u32 retries = 0;

    tsec_ctxt_t tsec_ctxt;
    sdmmc_t sdmmc;

    if (emummc_storage_init_mmc(&emmc_storage, &sdmmc)) {
        EPRINTF("Unable to init MMC.");
        goto out_wait;
    }
    TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);

    // Read package1.
    u8 *pkg1 = (u8 *)malloc(PKG1_MAX_SIZE);
    if (!emummc_storage_set_mmc_partition(&emmc_storage, EMMC_BOOT0)) {
        EPRINTF("Unable to set partition.");
        goto out_wait;
    }
    if (!emummc_storage_read(&emmc_storage, PKG1_OFFSET / NX_EMMC_BLOCKSIZE, PKG1_MAX_SIZE / NX_EMMC_BLOCKSIZE, pkg1)) {
        EPRINTF("Unable to read pkg1.");
        goto out_wait;
    }
    const pkg1_id_t *pkg1_id = pkg1_identify(pkg1);
    if (!pkg1_id) {
        EPRINTF("Unknown pkg1 version.\n Make sure you have the latest Lockpick_RCM.\n If a new firmware version just came out,\n Lockpick_RCM must be updated.\n Check Github for new release.");
        goto out_wait;
    }

    tsec_ctxt.fw = _find_tsec_fw(pkg1);
    if (!tsec_ctxt.fw) {
        EPRINTF("Unable to locate TSEC firmware.");
        goto out_wait;
    }

    minerva_periodic_training();

    tsec_ctxt.pkg1 = pkg1;
    tsec_ctxt.size = _get_tsec_fw_size((tsec_key_data_t *)(tsec_ctxt.fw + TSEC_KEY_DATA_OFFSET));
    if (tsec_ctxt.size > PKG1_MAX_SIZE) {
        EPRINTF("Unexpected TSEC firmware size.");
        goto out_wait;
    }

    u32 derivable_key_count = pkg1_id->kb >= KB_FIRMWARE_VERSION_620 ? pkg1_id->kb + 1 : 6;

    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_700) {
        sd_mount();
        if (!f_stat("sd:/sept/payload.bak", NULL)) {
            if (f_unlink("sd:/sept/payload.bin"))
                gfx_printf("%kNote: no payload.bin already in /sept\n", colors[(color_idx++) % 6]);
            f_rename("sd:/sept/payload.bak", "sd:/sept/payload.bin");
        }

        if (!h_cfg.sept_run) {
            // bundle lp0 fw for sept instead of loading it from SD as hekate does
            sdram_lp0_save_params(sdram_get_params_patched());

            FIL fp;
            if (f_stat("sd:/sept", NULL)) {
                EPRINTF("On firmware 7.x+ but Sept missing.\nSkipping new key derivation...");
                goto get_tsec;
            }
            // backup post-reboot payload
            if (!f_stat("sd:/sept/payload.bin", NULL)) {
                if (f_rename("sd:/sept/payload.bin", "sd:/sept/payload.bak")) {
                    EPRINTF("Unable to backup payload.bin.");
                    goto out_wait;
                }
            }
            // write self to payload.bin to run again when sept finishes
            volatile reloc_meta_t *relocator = (reloc_meta_t *)(IPL_LOAD_ADDR + RELOC_META_OFF);
            u32 payload_size = relocator->end - IPL_LOAD_ADDR;
            if (f_open(&fp, "sd:/sept/payload.bin", FA_CREATE_NEW | FA_WRITE)) {
                EPRINTF("Unable to open /sept/payload.bin to write.");
                goto out_wait;
            }
            gfx_printf("%kWrite self to /sept/payload.bin...", colors[(color_idx++) % 6]);
            if (f_write(&fp, (u8 *)IPL_LOAD_ADDR, payload_size, NULL)) {
                EPRINTF("Unable to write self to /sept/payload.bin.");
                f_close(&fp);
                goto out_wait;
            }
            gfx_printf(" done");
            f_close(&fp);
            gfx_printf("%k\nFirmware 7.x or higher detected.\n\n", colors[(color_idx++) % 6]);
            gfx_printf("%kRenamed /sept/payload.bin", colors[(color_idx++) % 6]);
            gfx_printf("\n     to /sept/payload.bak\n\n");
            gfx_printf("%kCopied self to /sept/payload.bin\n", colors[(color_idx++) % 6]);
            sdmmc_storage_end(&emmc_storage);
            if (!reboot_to_sept((u8 *)tsec_ctxt.fw, tsec_ctxt.size, pkg1_id->kb))
                goto out_wait;
        } else {
            se_aes_key_read(se_key_acc_ctrl_get(12) == 0x6A ? 13 : 12, master_key[KB_FIRMWARE_VERSION_MAX], 0x10);
        }
    }

get_tsec: ;
    u8 tsec_keys[0x10 * 2] = {0};

    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620) {
        u8 *tsec_paged = (u8 *)page_alloc(3);
        memcpy(tsec_paged, (void *)tsec_ctxt.fw, tsec_ctxt.size);
        tsec_ctxt.fw = tsec_paged;
    }

    int res = 0;

    mc_disable_ahb_redirect();

    while (tsec_query(tsec_keys, pkg1_id->kb, &tsec_ctxt) < 0) {
        memset(tsec_keys, 0x00, 0x20);
        retries++;
        if (retries > 15) {
            res = -1;
            break;
        }
    }
    free(pkg1);

    mc_enable_ahb_redirect();

    if (res < 0) {
        EPRINTFARGS("ERROR %x dumping TSEC.\n", res);
        goto out_wait;
    }

    TPRINTFARGS("%kTSEC key(s)...  ", colors[(color_idx++) % 6]);

    // Master key derivation

    // on firmware 6.2.0 only, tsec_query delivers the tsec_root_key
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620 && _key_exists(tsec_keys + 0x10)) {
        se_aes_key_set(8, tsec_keys + 0x10, 0x10); // mkek6 = unwrap(mkeks6, tsecroot)
        se_aes_crypt_block_ecb(8, 0, master_kek[6], master_kek_sources[0]);
        se_aes_key_set(8, master_kek[6], 0x10); // mkey = unwrap(mkek, mks)
        se_aes_crypt_block_ecb(8, 0, master_key[6], master_key_source);
    }

    if (pkg1_id->kb >= KB_FIRMWARE_VERSION_620) {
        // derive all lower master keys in case keyblobs are bad
        if (_key_exists(master_key[pkg1_id->kb])) {
            for (u32 i = pkg1_id->kb; i > 0; i--) {
                se_aes_key_set(8, master_key[i], 0x10);
                se_aes_crypt_block_ecb(8, 0, master_key[i-1], master_key_vectors[i]);
            }
            se_aes_key_set(8, master_key[0], 0x10);
            se_aes_crypt_block_ecb(8, 0, temp_key, master_key_vectors[0]);
            if (_key_exists(temp_key)) {
                EPRINTFARGS("Unable to derive master key. kb = %d.\n Put current sept files on SD and retry.", pkg1_id->kb);
                memset(master_key, 0, sizeof(master_key));
            }
        } else if (_key_exists(master_key[KB_FIRMWARE_VERSION_MAX])) {
            // handle sept version differences
            for (u32 kb = KB_FIRMWARE_VERSION_MAX; kb >= KB_FIRMWARE_VERSION_620; kb--) {
                for (u32 i = kb; i > 0; i--) {
                    se_aes_key_set(8, master_key[i], 0x10);
                    se_aes_crypt_block_ecb(8, 0, master_key[i-1], master_key_vectors[i]);
                }
                se_aes_key_set(8, master_key[0], 0x10);
                se_aes_crypt_block_ecb(8, 0, temp_key, master_key_vectors[0]);
                if (!_key_exists(temp_key)) {
                    break;
                }
                memcpy(master_key[kb-1], master_key[kb], 0x10);
                memset(master_key[kb], 0, 0x10);
            }
            if (_key_exists(temp_key)) {
                EPRINTF("Unable to derive master keys via sept.");
                memset(master_key, 0, sizeof(master_key));
            }
        }
    }

    u8 *keyblob_block = (u8 *)calloc(KB_FIRMWARE_VERSION_600 + 1, NX_EMMC_BLOCKSIZE);
    encrypted_keyblob_t *current_keyblob = (encrypted_keyblob_t *)keyblob_block;
    u8 keyblob_mac[0x10] = {0};
    u32 sbk[4] = {FUSE(FUSE_PRIVATE_KEY0), FUSE(FUSE_PRIVATE_KEY1),
                  FUSE(FUSE_PRIVATE_KEY2), FUSE(FUSE_PRIVATE_KEY3)};
    se_aes_key_set(8, tsec_keys, sizeof(tsec_keys) / 2);
    se_aes_key_set(9, sbk, sizeof(sbk));

    if (!emummc_storage_read(&emmc_storage, KEYBLOB_OFFSET / NX_EMMC_BLOCKSIZE, KB_FIRMWARE_VERSION_600 + 1, keyblob_block)) {
        EPRINTF("Unable to read keyblob.");
    }

    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++, current_keyblob++) {
        minerva_periodic_training();
        se_aes_crypt_block_ecb(8, 0, keyblob_key[i], keyblob_key_source[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(9, 0, keyblob_key[i], keyblob_key[i]); // kbk = unwrap(temp, sbk)
        se_aes_key_set(7, keyblob_key[i], sizeof(keyblob_key[i]));
        se_aes_crypt_block_ecb(7, 0, keyblob_mac_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0) {
            se_aes_crypt_block_ecb(7, 0, device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)
            se_aes_crypt_block_ecb(7, 0, device_key_4x, device_master_key_source_kek_source);
        }

        // verify keyblob is not corrupt
        se_aes_key_set(10, keyblob_mac_key[i], sizeof(keyblob_mac_key[i]));
        se_aes_cmac(10, keyblob_mac, sizeof(keyblob_mac), current_keyblob->iv, sizeof(current_keyblob->iv) + sizeof(keyblob_t));
        if (memcmp(current_keyblob, keyblob_mac, sizeof(keyblob_mac)) != 0) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            continue;
        }

        // decrypt keyblobs
        se_aes_key_set(6, keyblob_key[i], sizeof(keyblob_key[i]));
        se_aes_crypt_ctr(6, &keyblob[i], sizeof(keyblob_t), &current_keyblob->key_data, sizeof(keyblob_t), current_keyblob->iv);

        memcpy(package1_key[i], keyblob[i].package1_key, sizeof(package1_key[i]));
        memcpy(master_kek[i], keyblob[i].master_kek, sizeof(master_kek[i]));
        se_aes_key_set(7, master_kek[i], sizeof(master_kek[i]));
        se_aes_crypt_block_ecb(7, 0, master_key[i], master_key_source);
    }
    free(keyblob_block);

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    /*  key = unwrap(source, wrapped_key):
        key_set(ks, wrapped_key), block_ecb(ks, 0, key, source) -> final key in key
    */
    minerva_periodic_training();
    u32 key_generation = fuse_read_odm_keygen_rev();
    if (key_generation)
        key_generation--;

    if (_key_exists(device_key)) {
        if (key_generation) {
            _get_device_key(8, temp_key, key_generation, device_key_4x, master_key[0]);
        } else
            memcpy(temp_key, device_key, 0x10);
        se_aes_key_set(8, temp_key, 0x10);
        se_aes_unwrap_key(8, 8, retail_specific_aes_key_source); // kek = unwrap(rsaks, devkey)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x00, bis_key_source[0] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[0] + 0x10, bis_key_source[0] + 0x10);
        // kek = generate_kek(bkeks, devkey, aeskek, aeskey)
        _generate_kek(8, bis_kek_source, temp_key, aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x00, bis_key_source[1] + 0x00); // bkey = unwrap(bkeys, kek)
        se_aes_crypt_block_ecb(8, 0, bis_key[1] + 0x10, bis_key_source[1] + 0x10);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x00, bis_key_source[2] + 0x00);
        se_aes_crypt_block_ecb(8, 0, bis_key[2] + 0x10, bis_key_source[2] + 0x10);
        memcpy(bis_key[3], bis_key[2], 0x20);
    }

    TPRINTFARGS("%kFS keys...      ", colors[(color_idx++) % 6]);

    if (_key_exists(master_key[0])) {
        _generate_kek(8, header_kek_source, master_key[0], aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x00, header_key_source + 0x00);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x10, header_key_source + 0x10);
    }

    if (_key_exists(device_key)) {
        _generate_kek(8, save_mac_kek_source, device_key, aes_kek_generation_source, NULL);
        se_aes_crypt_block_ecb(8, 0, save_mac_key, save_mac_key_source);
    }

    if (_key_exists(master_key[derivable_key_count])) {
        derivable_key_count = KB_FIRMWARE_VERSION_MAX + 1;
    }
    for (u32 i = 0; i < derivable_key_count; i++) {
        if (!_key_exists(master_key[i]))
            continue;
        for (u32 j = 0; j < 3; j++) {
            _generate_kek(8, key_area_key_sources[j], master_key[i], aes_kek_generation_source, NULL);
            se_aes_crypt_block_ecb(8, 0, key_area_key[j][i], aes_key_generation_source);
        }
        se_aes_key_set(8, master_key[i], 0x10);
        se_aes_crypt_block_ecb(8, 0, package2_key[i], package2_key_source);
        se_aes_crypt_block_ecb(8, 0, titlekek[i], titlekek_source);
    }

    if (!_key_exists(header_key) || !_key_exists(bis_key[2]))
    {
        EPRINTF("Missing FS keys. Skipping ES/SSL keys.");
        goto key_output;
    }

    FILINFO fno;
    FIL fp;
    u32 read_bytes = 0;

    // derive eticket_rsa_kek and ssl_rsa_kek
    if (_key_exists(master_key[0])) {
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        _generate_kek(7, eticket_rsa_kekek_source, master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, eticket_rsa_kek, eticket_rsa_kek_source);

        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
        _generate_kek(7, ssl_rsa_kek_source_x, master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, ssl_rsa_kek, ssl_rsa_kek_source_y);
    }

    // Set BIS keys.
    // PRODINFO/PRODINFOF
    se_aes_key_set(0, bis_key[0] + 0x00, 0x10);
    se_aes_key_set(1, bis_key[0] + 0x10, 0x10);
    // SAFE
    se_aes_key_set(2, bis_key[1] + 0x00, 0x10);
    se_aes_key_set(3, bis_key[1] + 0x10, 0x10);
    // SYSTEM/USER
    se_aes_key_set(4, bis_key[2] + 0x00, 0x10);
    se_aes_key_set(5, bis_key[2] + 0x10, 0x10);

    // Set header key for NCA decryption.
    se_aes_key_set(8, header_key + 0x00, 0x10);
    se_aes_key_set(9, header_key + 0x10, 0x10);

    if (!emummc_storage_set_mmc_partition(&emmc_storage, EMMC_GPP)) {
        EPRINTF("Unable to set partition.");
        goto out_wait;
    }
    // Parse eMMC GPT.
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &emmc_storage);

    emmc_part_t *system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Unable to locate System partition.");
        goto key_output;
    }

    nx_emmc_bis_init(system_part);

    if (f_mount(&emmc_fs, "bis:", 1)) {
        EPRINTF("Unable to mount system partition.");
        goto key_output;
    }

    char private_path[200] = "sd:/";
    if (emu_cfg.nintendo_path && (emu_cfg.enabled || !h_cfg.emummc_force_disable)) {
        strcat(private_path, emu_cfg.nintendo_path);
    } else {
        strcat(private_path, "Nintendo");
    }
    strcat(private_path, "/Contents/private");
    if (f_open(&fp, private_path, FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open SD seed vector. Skipping.");
        goto get_titlekeys;
    }
    // get sd seed verification vector
    if (f_read(&fp, temp_key, 0x10, &read_bytes) || read_bytes != 0x10) {
        EPRINTF("Unable to read SD seed vector. Skipping.");
        f_close(&fp);
        goto get_titlekeys;
    }
    f_close(&fp);

    // this file is so small that parsing the savedata properly would take longer
    if (f_open(&fp, "bis:/save/8000000000000043", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open ns_appman save.\nSkipping SD seed.");
        goto get_titlekeys;
    }

    u8 read_buf[0x20] = {0};
    for (u32 i = 0x8000; i < f_size(&fp); i += 0x4000) {
        if (f_lseek(&fp, i) || f_read(&fp, read_buf, 0x20, &read_bytes) || read_bytes != 0x20)
            break;
        if (!memcmp(temp_key, read_buf, sizeof(temp_key))) {
            memcpy(sd_seed, read_buf + 0x10, sizeof(sd_seed));
            break;
        }
    }
    f_close(&fp);

    TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

get_titlekeys:
    if (!_key_exists(eticket_rsa_kek))
        goto dismount;

    gfx_printf("%kTitlekeys...     \n", colors[(color_idx++) % 6]);

    u32 buf_size = 0x4000;
    rsa_keypair_t rsa_keypair = {0};

    titlekey_buffer_t *titlekey_buffer = (titlekey_buffer_t *)TITLEKEY_BUF_ADR;

    if (!emummc_storage_read(&emmc_storage, NX_EMMC_CALIBRATION_OFFSET / NX_EMMC_BLOCKSIZE, NX_EMMC_CALIBRATION_SIZE / NX_EMMC_BLOCKSIZE, titlekey_buffer->read_buffer)) {
        EPRINTF("Unable to read PRODINFO.");
        goto dismount;
    }

    se_aes_xts_crypt(1, 0, 0, 0, titlekey_buffer->read_buffer, titlekey_buffer->read_buffer, XTS_CLUSTER_SIZE, NX_EMMC_CALIBRATION_SIZE / XTS_CLUSTER_SIZE);

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)titlekey_buffer->read_buffer;
    if (cal0->magic != 0x304C4143) {
        EPRINTF("Invalid CAL0 magic. Check BIS key 0.");
        goto dismount;
    }

    // settings sysmodule manually zeroes this out below cal version 9
    u32 keypair_generation = cal0->version <= 8 ? 0 : cal0->ext_ecc_rsa2048_eticket_key_ver;

    if (keypair_generation) {
        keypair_generation--;
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        u8 temp_device_key[0x10] = {0};
        _get_device_key(7, temp_device_key, keypair_generation, device_key_4x, master_key[0]);
        _generate_kek(7, eticket_rsa_kekek_source, temp_device_key, temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, eticket_rsa_kek_personalized, eticket_rsa_kek_source);
        memcpy(temp_key, eticket_rsa_kek_personalized, sizeof(temp_key));
    } else {
        memcpy(temp_key, eticket_rsa_kek, sizeof(temp_key));
    }

    se_aes_key_set(6, temp_key, sizeof(temp_key));
    se_aes_crypt_ctr(6, &rsa_keypair, sizeof(rsa_keypair), cal0->ext_ecc_rsa2048_eticket_key, sizeof(cal0->ext_ecc_rsa2048_eticket_key), cal0->ext_ecc_rsa2048_eticket_key_iv);

    // Check public exponent is 65537 big endian
    if (_read_be_u32(rsa_keypair.public_exponent, 0) != 65537) {
        EPRINTF("Invalid public exponent.");
        goto dismount;
    }

    if (!_test_key_pair(rsa_keypair.public_exponent, rsa_keypair.private_exponent, rsa_keypair.modulus)) {
        EPRINTF("Invalid keypair. Check eticket_rsa_kek.");
        goto dismount;
    }

    se_rsa_key_set(0, rsa_keypair.modulus, sizeof(rsa_keypair.modulus), rsa_keypair.private_exponent, sizeof(rsa_keypair.private_exponent));

    _get_titlekeys_from_save(buf_size, save_mac_key, titlekey_buffer, NULL);
    _get_titlekeys_from_save(buf_size, save_mac_key, titlekey_buffer, &rsa_keypair);

    gfx_printf("\n%k  Found %d titlekeys.\n", colors[(color_idx++) % 6], _titlekey_count);

dismount: ;

    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);

key_output: ;
    char *text_buffer = NULL;
    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        goto free_buffers;
    }

    typedef struct {
        char rights_id[0x20];
        char equals[3];
        char titlekey[0x20];
        char newline[1];
    } titlekey_text_buffer_t;

    u32 text_buffer_size = MAX(_titlekey_count * sizeof(titlekey_text_buffer_t) + 1, 0x4000);
    text_buffer = (char *)calloc(1, text_buffer_size);

    SAVE_KEY(aes_kek_generation_source);
    SAVE_KEY(aes_key_generation_source);
    SAVE_KEY(bis_kek_source);
    SAVE_KEY_FAMILY(bis_key, 0);
    SAVE_KEY_FAMILY(bis_key_source, 0);
    SAVE_KEY(device_key);
    SAVE_KEY(device_key_4x);
    SAVE_KEY(eticket_rsa_kek);
    SAVE_KEY(eticket_rsa_kek_personalized);
    SAVE_KEY(eticket_rsa_kek_source);
    SAVE_KEY(eticket_rsa_kekek_source);
    SAVE_KEY(header_kek_source);
    SAVE_KEY(header_key);
    SAVE_KEY(header_key_source);
    SAVE_KEY_FAMILY_VAR(key_area_key_application, key_area_key[0], 0);
    SAVE_KEY_VAR(key_area_key_application_source, key_area_key_sources[0]);
    SAVE_KEY_FAMILY_VAR(key_area_key_ocean, key_area_key[1], 0);
    SAVE_KEY_VAR(key_area_key_ocean_source, key_area_key_sources[1]);
    SAVE_KEY_FAMILY_VAR(key_area_key_system, key_area_key[2], 0);
    SAVE_KEY_VAR(key_area_key_system_source, key_area_key_sources[2]);
    SAVE_KEY_FAMILY(keyblob, 0);
    SAVE_KEY_FAMILY(keyblob_key, 0);
    SAVE_KEY_FAMILY(keyblob_key_source, 0);
    SAVE_KEY_FAMILY(keyblob_mac_key, 0);
    SAVE_KEY(keyblob_mac_key_source);
    SAVE_KEY_FAMILY(master_kek, 0);
    SAVE_KEY_FAMILY_VAR(master_kek_source, master_kek_sources, KB_FIRMWARE_VERSION_620);
    SAVE_KEY_FAMILY(master_key, 0);
    SAVE_KEY(master_key_source);
    SAVE_KEY_FAMILY(package1_key, 0);
    SAVE_KEY_FAMILY(package2_key, 0);
    SAVE_KEY(package2_key_source);
    SAVE_KEY(per_console_key_source);
    SAVE_KEY(retail_specific_aes_key_source);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
    SAVE_KEY_VAR(rsa_oaep_kek_generation_source, temp_key);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
    SAVE_KEY_VAR(rsa_private_kek_generation_source, temp_key);
    SAVE_KEY(save_mac_kek_source);
    SAVE_KEY(save_mac_key);
    SAVE_KEY(save_mac_key_source);
    SAVE_KEY(save_mac_sd_card_kek_source);
    SAVE_KEY(save_mac_sd_card_key_source);
    SAVE_KEY(sd_card_custom_storage_key_source);
    SAVE_KEY(sd_card_kek_source);
    SAVE_KEY(sd_card_nca_key_source);
    SAVE_KEY(sd_card_save_key_source);
    SAVE_KEY(sd_seed);
    SAVE_KEY_VAR(secure_boot_key, sbk);
    SAVE_KEY(ssl_rsa_kek);
    SAVE_KEY(ssl_rsa_kek_source_x);
    SAVE_KEY(ssl_rsa_kek_source_y);
    SAVE_KEY_FAMILY(titlekek, 0);
    SAVE_KEY(titlekek_source);
    _save_key("tsec_key", tsec_keys, 0x10, text_buffer);
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620)
        _save_key("tsec_root_key", tsec_keys + 0x10, 0x10, text_buffer);

    end_time = get_tmr_us();
    gfx_printf("\n%k  Found %d keys.\n\n", colors[(color_idx++) % 6], _key_count);
    gfx_printf("%kLockpick totally done in %d us\n\n", colors[(color_idx++) % 6], end_time - begin_time);
    gfx_printf("%kFound through master_key_%02x.\n\n", colors[(color_idx++) % 6], derivable_key_count - 1);

    f_mkdir("sd:/switch");
    char keyfile_path[30] = "sd:/switch/";
    if (!(fuse_read_odm(4) & 3))
        sprintf(&keyfile_path[11], "prod.keys");
    else
        sprintf(&keyfile_path[11], "dev.keys");
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else
        EPRINTF("Unable to save keys to SD.");

    if (_titlekey_count == 0)
        goto free_buffers;
    memset(text_buffer, 0, text_buffer_size);

    titlekey_text_buffer_t *titlekey_text = (titlekey_text_buffer_t *)text_buffer;

    for (u32 i = 0; i < _titlekey_count; i++) {
        for (u32 j = 0; j < 0x10; j++)
            sprintf(&titlekey_text[i].rights_id[j * 2], "%02x", titlekey_buffer->rights_ids[i][j]);
        sprintf(titlekey_text[i].equals, " = ");
        for (u32 j = 0; j < 0x10; j++)
            sprintf(&titlekey_text[i].titlekey[j * 2], "%02x", titlekey_buffer->titlekeys[i][j]);
        sprintf(titlekey_text[i].newline, "\n");
    }
    sprintf(&keyfile_path[11], "title.keys");
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else
        EPRINTF("Unable to save titlekeys to SD.");

free_buffers:
    free(text_buffer);

out_wait:
    emummc_load_cfg();
    // Ignore whether emummc is enabled.
    h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
    emu_cfg.enabled = !h_cfg.emummc_force_disable;
    emummc_storage_end(&emmc_storage);
    gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx) % 6], colors[(color_idx + 1) % 6], colors[(color_idx + 2) % 6]);
    btn_wait();
    gfx_clear_grey(0x1B);
}

static void _save_key(const char *name, const void *data, u32 len, char *outbuf) {
    if (!_key_exists(data))
        return;
    u32 pos = strlen(outbuf);
    pos += sprintf(&outbuf[pos], "%s = ", name);
    for (u32 i = 0; i < len; i++)
        pos += sprintf(&outbuf[pos], "%02x", *(u8*)(data + i));
    sprintf(&outbuf[pos], "\n");
    _key_count++;
}

static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf) {
    char temp_name[0x40] = {0};
    for (u32 i = 0; i < num_keys; i++) {
        sprintf(temp_name, "%s_%02x", name, i + start_key);
        _save_key(temp_name, data + i * len, len, outbuf);
    }
}

static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed) {
    if (!_key_exists(key_source) || !_key_exists(master_key) || !_key_exists(kek_seed))
        return;

    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, kek_seed);
    se_aes_unwrap_key(ks, ks, key_source);
    if (key_seed && _key_exists(key_seed))
        se_aes_unwrap_key(ks, ks, key_seed);
}

static void _get_device_key(u32 ks, void *out_device_key, u32 revision, const void *device_key, const void *master_key) {
    if (revision < KB_FIRMWARE_VERSION_400)
        memcpy(out_device_key, device_key, 0x10);

    revision -= KB_FIRMWARE_VERSION_400;
    u8 temp_key[0x10] = {0};
    se_aes_key_set(ks, device_key, 0x10);
    se_aes_crypt_ecb(ks, 0, temp_key, 0x10, device_master_key_source_sources[revision], 0x10);
    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, device_master_kek_sources[revision]);
    se_aes_crypt_ecb(ks, 0, out_device_key, 0x10, temp_key, 0x10);
}

static bool _test_key_pair(const void *public_exponent, const void *private_exponent, const void *modulus) {
    u8 plaintext[0x100] = {0}, ciphertext[0x100] = {0}, work[0x100] = {0};

    // 0xCAFEBABE
    plaintext[0xfc] = 0xca; plaintext[0xfd] = 0xfe; plaintext[0xfe] = 0xba; plaintext[0xff] = 0xbe;

    se_rsa_key_set(0, modulus, 0x100, private_exponent, 0x100);
    se_rsa_exp_mod(0, ciphertext, 0x100, plaintext, 0x100);

    se_rsa_key_set(0, modulus, 0x100, public_exponent, 4);
    se_rsa_exp_mod(0, work, 0x100, ciphertext, 0x100);

    return !memcmp(plaintext, work, 0x100);
}
