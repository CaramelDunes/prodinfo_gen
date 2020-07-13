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

#define SAVE_KEY(name, src, len) _save_key(name, src, len, text_buffer)
#define SAVE_KEY_FAMILY(name, src, start, count, len) _save_key_family(name, src, start, count, len, text_buffer)

static inline u32 _read_le_u32(const void *buffer, u32 offset) {
    return (*(u8*)(buffer + offset + 0)        ) |
           (*(u8*)(buffer + offset + 1) << 0x08) |
           (*(u8*)(buffer + offset + 2) << 0x10) |
           (*(u8*)(buffer + offset + 3) << 0x18);
}

// key functions
static int   _key_exists(const void *data) { return memcmp(data, zeros, 0x10) != 0; };
static void  _save_key(const char *name, const void *data, u32 len, char *outbuf);
static void  _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf);
static void  _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);
static void  _get_device_key(u32 ks, void *out_device_key, u32 revision, const void *device_key, const void *master_key);
// titlekey functions
static bool  _test_key_pair(const void *E, const void *D, const void *N);
static void  _mgf1_xor(void *masked, u32 masked_size, const void *seed, u32 seed_size);

static inline const u8 *_find_tsec_fw(const u8 *pkg1) {
    const u32 tsec_fw_align = 0x100;
    const u32 tsec_fw_first_instruction = 0xCF42004D;

    for (const u32 *pos = (const u32 *)pkg1; (u8 *)pos < pkg1 + PKG1_MAX_SIZE; pos += tsec_fw_align / sizeof(u32))
        if (*pos == tsec_fw_first_instruction)
            return (const u8 *)pos;

    return NULL;
}

static inline u32 _get_tsec_fw_size(tsec_key_data_t *key_data) {
    return 0x100 + key_data->blob0_size + key_data->blob1_size + key_data->blob2_size + key_data->blob3_size + key_data->blob4_size;
}

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
        keyblob[KB_FIRMWARE_VERSION_600+1][0x90] = {0},
        keyblob_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        keyblob_mac_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        package1_key[KB_FIRMWARE_VERSION_600+1][0x10] = {0},
        // master key-derived families
        key_area_key[3][KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        master_kek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        master_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        package2_key[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0},
        titlekek[KB_FIRMWARE_VERSION_MAX+1][0x10] = {0};

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

    u32 max_derivable_key_index = pkg1_id->kb >= KB_FIRMWARE_VERSION_620 ? pkg1_id->kb + 1 : 6;

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
            u32 payload_size = _read_le_u32((u8 *)IPL_LOAD_ADDR, 0x84) - IPL_LOAD_ADDR;
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
                se_aes_crypt_block_ecb(8, 0, master_key[i-1], mkey_vectors[i]);
            }
            se_aes_key_set(8, master_key[0], 0x10);
            se_aes_crypt_block_ecb(8, 0, temp_key, mkey_vectors[0]);
            if (_key_exists(temp_key)) {
                EPRINTFARGS("Unable to derive master key. kb = %d.\n Put current sept files on SD and retry.", pkg1_id->kb);
                memset(master_key, 0, sizeof(master_key));
            }
        } else if (_key_exists(master_key[KB_FIRMWARE_VERSION_MAX])) {
            // handle sept version differences
            for (u32 kb = KB_FIRMWARE_VERSION_MAX; kb >= KB_FIRMWARE_VERSION_620; kb--) {
                for (u32 i = kb; i > 0; i--) {
                    se_aes_key_set(8, master_key[i], 0x10);
                    se_aes_crypt_block_ecb(8, 0, master_key[i-1], mkey_vectors[i]);
                }
                se_aes_key_set(8, master_key[0], 0x10);
                se_aes_crypt_block_ecb(8, 0, temp_key, mkey_vectors[0]);
                if (!_key_exists(temp_key)) {
                    break;
                }
                memcpy(master_key[kb-1], master_key[kb], 0x10);
                memset(master_key[kb], 0, 0x10);
            }
            if (_key_exists(temp_key)) {
                EPRINTF("Unable to derive master key.");
                memset(master_key, 0, sizeof(master_key));
            }
        }
    }

    u8 *keyblob_block = (u8 *)calloc(NX_EMMC_BLOCKSIZE, 1);
    u8 keyblob_mac[0x10] = {0};
    u32 sbk[4] = {FUSE(FUSE_PRIVATE_KEY0), FUSE(FUSE_PRIVATE_KEY1),
                  FUSE(FUSE_PRIVATE_KEY2), FUSE(FUSE_PRIVATE_KEY3)};
    se_aes_key_set(8, tsec_keys, 0x10);
    se_aes_key_set(9, sbk, 0x10);
    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++) {
        minerva_periodic_training();
        se_aes_crypt_block_ecb(8, 0, keyblob_key[i], keyblob_key_source[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(9, 0, keyblob_key[i], keyblob_key[i]); // kbk = unwrap(temp, sbk)
        se_aes_key_set(7, keyblob_key[i], 0x10);
        se_aes_crypt_block_ecb(7, 0, keyblob_mac_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0) {
            se_aes_crypt_block_ecb(7, 0, device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)
            se_aes_crypt_block_ecb(7, 0, device_key_4x, per_console_key_source_4x);
        }

        // verify keyblob is not corrupt
        if (!emummc_storage_read(&emmc_storage, 0x180000 / NX_EMMC_BLOCKSIZE + i, 1, keyblob_block)) {
            EPRINTFARGS("Unable to read keyblob %x.", i);
            continue;
        }
        se_aes_key_set(10, keyblob_mac_key[i], 0x10);
        se_aes_cmac(10, keyblob_mac, 0x10, keyblob_block + 0x10, 0xa0);
        if (memcmp(keyblob_block, keyblob_mac, 0x10) != 0) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            gfx_hexdump(i, keyblob_block, 0x10);
            gfx_hexdump(i, keyblob_mac, 0x10);
            continue;
        }

        // decrypt keyblobs
        se_aes_key_set(6, keyblob_key[i], 0x10);
        se_aes_crypt_ctr(6, keyblob[i], 0x90, keyblob_block + 0x20, 0x90, keyblob_block + 0x10);

        memcpy(package1_key[i], keyblob[i] + 0x80, 0x10);
        memcpy(master_kek[i], keyblob[i], 0x10);
        se_aes_key_set(7, master_kek[i], 0x10);
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

    u8 *rights_ids = NULL, *titlekeys = NULL;

    TPRINTFARGS("%kFS keys...      ", colors[(color_idx++) % 6]);

    if (_key_exists(fs_keys[FS_HEADER_KEK_SOURCE]) && _key_exists(fs_keys[FS_HEADER_KEY_SOURCE]) && _key_exists(master_key[0])) {
        _generate_kek(8, fs_keys[FS_HEADER_KEK_SOURCE], master_key[0], aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x00, fs_keys[FS_HEADER_KEY_SOURCE] + 0x00);
        se_aes_crypt_block_ecb(8, 0, header_key + 0x10, fs_keys[FS_HEADER_KEY_SOURCE] + 0x10);
    }

    if (_key_exists(fs_keys[FS_SAVE_MAC_KEK_SOURCE]) && _key_exists(fs_keys[FS_SAVE_MAC_KEY_SOURCE]) && _key_exists(device_key)) {
        _generate_kek(8, fs_keys[FS_SAVE_MAC_KEK_SOURCE], device_key, aes_kek_generation_source, NULL);
        se_aes_crypt_block_ecb(8, 0, save_mac_key, fs_keys[FS_SAVE_MAC_KEY_SOURCE]);
    }

    if (_key_exists(master_key[max_derivable_key_index])) {
        max_derivable_key_index = KB_FIRMWARE_VERSION_MAX + 1;
    }
    for (u32 i = 0; i < max_derivable_key_index; i++) {
        if (!_key_exists(master_key[i]))
            continue;
        if (_key_exists(fs_keys[FS_KEY_AREA_KEY_APPLI_SOURCE]) && _key_exists(fs_keys[FS_KEY_AREA_KEY_OCEAN_SOURCE]) && _key_exists(fs_keys[FS_KEY_AREA_KEY_SYSTE_SOURCE])) {
            for (u32 j = 0; j < 3; j++) {
                _generate_kek(8, fs_keys[FS_KEY_AREA_KEY_APPLI_SOURCE + j], master_key[i], aes_kek_generation_source, NULL);
                se_aes_crypt_block_ecb(8, 0, key_area_key[j][i], aes_key_generation_source);
            }
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
    save_ctx_t *save_ctx = NULL;
    bool save_process_success = false;
    u32 read_bytes = 0;

    // derive eticket_rsa_kek and ssl_rsa_kek
    if (_key_exists(master_key[0])) {
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        _generate_kek(7, es_keys[1], master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, eticket_rsa_kek, es_keys[0]);

        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
        _generate_kek(7, es_keys[2], master_key[0], temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, ssl_rsa_kek, ssl_keys);
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
        if (!memcmp(temp_key, read_buf, 0x10)) {
            memcpy(sd_seed, read_buf + 0x10, 0x10);
            break;
        }
    }
    f_close(&fp);

    TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

get_titlekeys:
    if (!_key_exists(eticket_rsa_kek))
        goto dismount;

    gfx_printf("%kTitlekeys...     ", colors[(color_idx++) % 6]);
    u32 save_x = gfx_con.x, save_y = gfx_con.y;
    gfx_printf("\n%kCommon...       ", colors[color_idx % 6]);

    u8 null_hash[0x20] = {
        0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14, 0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
        0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C, 0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55};

    u32 buf_size = 0x4000;
    u8 *buffer = (u8 *)MIXD_BUF_ALIGNED;

    u8 keypair[0x230] = {0};

    if (!emummc_storage_read(&emmc_storage, 0x4400 / NX_EMMC_BLOCKSIZE, 0x4000 / NX_EMMC_BLOCKSIZE, buffer)) {
        EPRINTF("Unable to read PRODINFO.");
        goto dismount;
    }

    se_aes_xts_crypt(1, 0, 0, 0, buffer, buffer, 0x4000, 1);

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)buffer;
    if (cal0->magic != 0x304C4143) {
        EPRINTF("CAL0 magic not found. Check BIS key 0.");
        goto dismount;
    }

    u32 keypair_generation = cal0->ext_ecc_rsa2048_eticket_key_ver;
    if (cal0->version <= 8)
        keypair_generation = 0; // settings zeroes this out below cal version 9

    if (keypair_generation) {
        keypair_generation--;
        for (u32 i = 0; i < 0x10; i++)
            temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        u8 temp_device_key[0x10] = {0};
        _get_device_key(7, temp_device_key, keypair_generation, device_key_4x, master_key[0]);
        _generate_kek(7, es_keys[1], temp_device_key, temp_key, NULL);
        se_aes_crypt_block_ecb(7, 0, eticket_rsa_kek_personalized, es_keys[0]);
        memcpy(temp_key, eticket_rsa_kek_personalized, 0x10);
    } else {
        memcpy(temp_key, eticket_rsa_kek, 0x10);
    }

    se_aes_key_set(6, temp_key, 0x10);
    se_aes_crypt_ctr(6, keypair, 0x230, cal0->ext_ecc_rsa2048_eticket_key + 0x10, 0x230, cal0->ext_ecc_rsa2048_eticket_key);

    u8 *D = keypair, *N = keypair + 0x100, *E = keypair + 0x200;

    // Check public exponent is 0x10001 big endian
    if (E[0] != 0 || E[1] != 1 || E[2] != 0 || E[3] != 1) {
        EPRINTF("Invalid public exponent.");
        goto dismount;
    }

    if (!_test_key_pair(E, D, N)) {
        EPRINTF("Invalid keypair. Check eticket_rsa_kek.");
        goto dismount;
    }

    se_rsa_key_set(0, N, 0x100, D, 0x100);

    u64 br = buf_size;
    u32 file_tkey_count = 0;
    u64 offset = 0;
    rights_ids = (u8 *)(MIXD_BUF_ALIGNED + 0x40000);
    titlekeys = (u8 *)(MIXD_BUF_ALIGNED + 0x80000);
    save_ctx = calloc(1, sizeof(save_ctx_t));
    u8 M[0x100];
    if (f_open(&fp, "bis:/save/80000000000000E1", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open e1 save. Skipping.");
        goto dismount;
    }

    u32 pct = 0, last_pct = 0;

    save_ctx->file = &fp;
    save_ctx->action = 0;
    memcpy(save_ctx->save_mac_key, save_mac_key, 0x10);

    save_process_success = save_process(save_ctx);

    if (!save_process_success) {
        EPRINTF("Failed to process e1 save.");
        f_close(&fp);
        goto dismount;
    }

    char ticket_bin_path[0x40] = "/ticket.bin";
    char ticket_list_bin_path[0x40] = "/ticket_list.bin";
    save_data_file_ctx_t ticket_file;

    if (!save_open_file(save_ctx, &ticket_file, ticket_list_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket_list.bin in e1.");
        f_close(&fp);
        goto dismount;
    }

    bool terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, buffer, buf_size) || buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        minerva_periodic_training();
        for (u32 j = 0; j < buf_size; j += 0x20) {
            if (buffer[j] == 0xff && buffer[j+1] == 0xff && buffer[j+2] == 0xff && buffer[j+3] == 0xff) {
                terminator_reached = true;
                break;
            }
            file_tkey_count++;
        }
    }

    if (!save_open_file(save_ctx, &ticket_file, ticket_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket.bin in e1 save.");
        f_close(&fp);
        goto dismount;
    }

    offset = 0;
    terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, buffer, buf_size) || buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        for (u32 j = 0; j < buf_size; j += 0x400) {
            pct = _titlekey_count * 100 / file_tkey_count;
            if (pct > last_pct && pct <= 100) {
                last_pct = pct;
                tui_pbar(save_x, save_y, pct, COLOR_GREEN, 0xFF155500);
            }
            minerva_periodic_training();
            if (buffer[j] == 4 && buffer[j+1] == 0 && buffer[j+2] == 1 && buffer[j+3] == 0) {
                memcpy(rights_ids + 0x10 * _titlekey_count, buffer + j + 0x2a0, 0x10);
                memcpy(titlekeys + 0x10 * _titlekey_count, buffer + j + 0x180, 0x10);
                _titlekey_count++;
            } else {
                terminator_reached = true;
                break;
            }
        }
    }
    tui_pbar(save_x, save_y, 100, COLOR_GREEN, 0xFF155500);
    f_close(&fp);
    save_free_contexts(save_ctx);
    save_process_success = false;
    memset(save_ctx, 0, sizeof(save_ctx_t));

    gfx_con_setpos(0, save_y);
    TPRINTFARGS("\n%kCommon...       ", colors[(color_idx++) % 6]);
    save_x = gfx_con.x + 16 * 17;
    save_y = gfx_con.y;
    gfx_printf("\n%kPersonalized... ", colors[color_idx % 6]);

    u32 common_titlekey_count = _titlekey_count;
    if (f_open(&fp, "bis:/save/80000000000000E2", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open e2 save. Skipping.");
        goto dismount;
    }

    save_ctx->file = &fp;
    save_ctx->action = 0;
    memcpy(save_ctx->save_mac_key, save_mac_key, 0x10);

    save_process_success = save_process(save_ctx);
    if (!save_process_success) {
        EPRINTF("Failed to process e2 save.");
        f_close(&fp);
        goto dismount;
    }

    if (!save_open_file(save_ctx, &ticket_file, ticket_list_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket_list.bin in e2 save.");
        f_close(&fp);
        goto dismount;
    }

    offset = 0;
    file_tkey_count = 0;
    terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, buffer, buf_size) || buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        minerva_periodic_training();
        for (u32 j = 0; j < buf_size; j += 0x20) {
            if (buffer[j] == 0xff && buffer[j+1] == 0xff && buffer[j+2] == 0xff && buffer[j+3] == 0xff) {
                terminator_reached = true;
                break;
            }
            file_tkey_count++;
        }
    }

   if (!save_open_file(save_ctx, &ticket_file, ticket_bin_path, OPEN_MODE_READ)) {
        EPRINTF("Unable to locate ticket.bin in e2 save.");
        f_close(&fp);
        goto dismount;
    }

    offset = 0;
    pct = 0;
    last_pct = 0;
    terminator_reached = false;
    while (offset < ticket_file.size && !terminator_reached) {
        if (!save_data_file_read(&ticket_file, &br, offset, buffer, buf_size) || buffer[0] == 0 || br != buf_size)
            break;
        offset += br;
        for (u32 j = 0; j < buf_size; j += 0x400) {
            pct = (_titlekey_count - common_titlekey_count) * 100 / file_tkey_count;
            if (pct > last_pct && pct <= 100) {
                last_pct = pct;
                tui_pbar(save_x, save_y, pct, COLOR_GREEN, 0xFF155500);
            }
            minerva_periodic_training();
            if (buffer[j] == 4 && buffer[j+1] == 0 && buffer[j+2] == 1 && buffer[j+3] == 0) {
                memcpy(rights_ids + 0x10 * _titlekey_count, buffer + j + 0x2a0, 0x10);

                u8 *titlekey_block = buffer + j + 0x180;
                se_rsa_exp_mod(0, M, 0x100, titlekey_block, 0x100);
                u8 *salt = M + 1;
                u8 *db = M + 0x21;
                _mgf1_xor(salt, 0x20, db, 0xdf);
                _mgf1_xor(db, 0xdf, salt, 0x20);
                if (memcmp(db, null_hash, 0x20) != 0)
                    continue;
                memcpy(titlekeys + 0x10 * _titlekey_count, db + 0xcf, 0x10);
                _titlekey_count++;
            } else {
                terminator_reached = true;
                break;
            }
        }
    }
    tui_pbar(save_x, save_y, 100, COLOR_GREEN, 0xFF155500);
    f_close(&fp);

    gfx_con_setpos(0, save_y);
    TPRINTFARGS("\n%kPersonalized... ", colors[(color_idx++) % 6]);
    gfx_printf("\n%k  Found %d titlekeys.\n", colors[(color_idx++) % 6], _titlekey_count);

dismount: ;
    if (save_process_success)
        save_free_contexts(save_ctx);

    if (save_ctx)
        free(save_ctx);

    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);

key_output: ;
    char *text_buffer = NULL;
    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        goto free_buffers;
    }
    u32 text_buffer_size = MAX(_titlekey_count * 68 + 1, 0x4000);
    text_buffer = (char *)calloc(1, text_buffer_size);

    SAVE_KEY("aes_kek_generation_source", aes_kek_generation_source, 0x10);
    SAVE_KEY("aes_key_generation_source", aes_key_generation_source, 0x10);
    SAVE_KEY("bis_kek_source", bis_kek_source, 0x10);
    SAVE_KEY_FAMILY("bis_key", bis_key, 0, 4, 0x20);
    SAVE_KEY_FAMILY("bis_key_source", bis_key_source, 0, 3, 0x20);
    SAVE_KEY("device_key", device_key, 0x10);
    SAVE_KEY("device_key_4x", device_key_4x, 0x10);
    SAVE_KEY("eticket_rsa_kek", eticket_rsa_kek, 0x10);
    SAVE_KEY("eticket_rsa_kek_personalized", eticket_rsa_kek_personalized, 0x10);
    SAVE_KEY("eticket_rsa_kek_source", es_keys[0], 0x10);
    SAVE_KEY("eticket_rsa_kekek_source", es_keys[1], 0x10);
    SAVE_KEY("header_kek_source", fs_keys[FS_HEADER_KEK_SOURCE], 0x10);
    SAVE_KEY("header_key", header_key, 0x20);
    SAVE_KEY("header_key_source", fs_keys[FS_HEADER_KEY_SOURCE], 0x20);
    SAVE_KEY_FAMILY("key_area_key_application", key_area_key[0], 0, max_derivable_key_index, 0x10);
    SAVE_KEY("key_area_key_application_source", fs_keys[FS_KEY_AREA_KEY_APPLI_SOURCE], 0x10);
    SAVE_KEY_FAMILY("key_area_key_ocean", key_area_key[1], 0, max_derivable_key_index, 0x10);
    SAVE_KEY("key_area_key_ocean_source", fs_keys[FS_KEY_AREA_KEY_OCEAN_SOURCE], 0x10);
    SAVE_KEY_FAMILY("key_area_key_system", key_area_key[2], 0, max_derivable_key_index, 0x10);
    SAVE_KEY("key_area_key_system_source", fs_keys[FS_KEY_AREA_KEY_SYSTE_SOURCE], 0x10);
    SAVE_KEY_FAMILY("keyblob", keyblob, 0, 6, 0x90);
    SAVE_KEY_FAMILY("keyblob_key", keyblob_key, 0, 6, 0x10);
    SAVE_KEY_FAMILY("keyblob_key_source", keyblob_key_source, 0, 6, 0x10);
    SAVE_KEY_FAMILY("keyblob_mac_key", keyblob_mac_key, 0, 6, 0x10);
    SAVE_KEY("keyblob_mac_key_source", keyblob_mac_key_source, 0x10);
    SAVE_KEY_FAMILY("master_kek", master_kek, 0, max_derivable_key_index, 0x10);
    SAVE_KEY_FAMILY("master_kek_source", master_kek_sources, KB_FIRMWARE_VERSION_620, sizeof(master_kek_sources) / 0x10, 0x10);
    SAVE_KEY_FAMILY("master_key", master_key, 0, max_derivable_key_index, 0x10);
    SAVE_KEY("master_key_source", master_key_source, 0x10);
    SAVE_KEY_FAMILY("package1_key", package1_key, 0, 6, 0x10);
    SAVE_KEY_FAMILY("package2_key", package2_key, 0, max_derivable_key_index, 0x10);
    SAVE_KEY("package2_key_source", package2_key_source, 0x10);
    SAVE_KEY("per_console_key_source", per_console_key_source, 0x10);
    SAVE_KEY("retail_specific_aes_key_source", retail_specific_aes_key_source, 0x10);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
    SAVE_KEY("rsa_oaep_kek_generation_source", temp_key, 0x10);
    for (u32 i = 0; i < 0x10; i++)
        temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
    SAVE_KEY("rsa_private_kek_generation_source", temp_key, 0x10);
    SAVE_KEY("save_mac_kek_source", fs_keys[FS_SAVE_MAC_KEK_SOURCE], 0x10);
    SAVE_KEY("save_mac_key", save_mac_key, 0x10);
    SAVE_KEY("save_mac_key_source", fs_keys[FS_SAVE_MAC_KEY_SOURCE], 0x10);
    SAVE_KEY("save_mac_sd_card_kek_source", fs_keys[FS_SAVE_MAC_SD_KEK_SOURCE], 0x10);
    SAVE_KEY("save_mac_sd_card_key_source", fs_keys[FS_SAVE_MAC_SD_KEY_SOURCE], 0x10);
    SAVE_KEY("sd_card_custom_storage_key_source", fs_keys[FS_SD_CUSTOM_KEY_SOURCE], 0x20);
    SAVE_KEY("sd_card_kek_source", fs_keys[FS_SD_KEK_SOURCE], 0x10);
    SAVE_KEY("sd_card_nca_key_source", fs_keys[FS_SD_NCA_KEY_SOURCE], 0x20);
    SAVE_KEY("sd_card_save_key_source", fs_keys[FS_SD_SAVE_KEY_SOURCE], 0x20);
    SAVE_KEY("sd_seed", sd_seed, 0x10);
    SAVE_KEY("secure_boot_key", sbk, 0x10);
    SAVE_KEY("ssl_rsa_kek", ssl_rsa_kek, 0x10);
    SAVE_KEY("ssl_rsa_kek_source_x", es_keys[2], 0x10);
    SAVE_KEY("ssl_rsa_kek_source_y", ssl_keys, 0x10);
    SAVE_KEY_FAMILY("titlekek", titlekek, 0, max_derivable_key_index, 0x10);
    SAVE_KEY("titlekek_source", titlekek_source, 0x10);
    SAVE_KEY("tsec_key", tsec_keys, 0x10);
    if (pkg1_id->kb == KB_FIRMWARE_VERSION_620)
        SAVE_KEY("tsec_root_key", tsec_keys + 0x10, 0x10);

    //gfx_con.fntsz = 8; gfx_puts(text_buffer); gfx_con.fntsz = 16;

    end_time = get_tmr_us();
    gfx_printf("\n%k  Found %d keys.\n\n", colors[(color_idx++) % 6], _key_count);
    gfx_printf("%kLockpick totally done in %d us\n\n", colors[(color_idx++) % 6], end_time - begin_time);
    gfx_printf("%kFound through master_key_%02x.\n\n", colors[(color_idx++) % 6], max_derivable_key_index - 1);

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
    for (u32 i = 0; i < _titlekey_count; i++) {
        for (u32 j = 0; j < 0x10; j++)
            sprintf(&text_buffer[i * 68 + j * 2], "%02x", rights_ids[i * 0x10 + j]);
        sprintf(&text_buffer[i * 68 + 0x20], " = ");
        for (u32 j = 0; j < 0x10; j++)
            sprintf(&text_buffer[i * 68 + 0x23 + j * 2], "%02x", titlekeys[i * 0x10 + j]);
        sprintf(&text_buffer[i * 68 + 0x43], "\n");
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
    se_aes_crypt_ecb(ks, 0, temp_key, 0x10, new_device_key_sources[revision], 0x10);
    se_aes_key_set(ks, master_key, 0x10);
    se_aes_unwrap_key(ks, ks, new_device_keygen_sources[revision]);
    se_aes_crypt_ecb(ks, 0, out_device_key, 0x10, temp_key, 0x10);
}

static bool _test_key_pair(const void *E, const void *D, const void *N) {
    u8 X[0x100] = {0}, Y[0x100] = {0}, Z[0x100] = {0};

    // 0xCAFEBABE
    X[0xfc] = 0xca; X[0xfd] = 0xfe; X[0xfe] = 0xba; X[0xff] = 0xbe;
    se_rsa_key_set(0, N, 0x100, D, 0x100);
    se_rsa_exp_mod(0, Y, 0x100, X, 0x100);
    se_rsa_key_set(0, N, 0x100, E, 4);
    se_rsa_exp_mod(0, Z, 0x100, Y, 0x100);

    return !memcmp(X, Z, 0x100);
}

// _mgf1_xor() was derived from Atmosphère's calculate_mgf1_and_xor
static void _mgf1_xor(void *masked, u32 masked_size, const void *seed, u32 seed_size) {
    u8 cur_hash[0x20];
    u8 hash_buf[0xe4];

    u32 hash_buf_size = seed_size + 4;
    memcpy(hash_buf, seed, seed_size);
    u32 round_num = 0;

    u8 *p_out = (u8 *)masked;

    while (masked_size) {
        u32 cur_size = MIN(masked_size, 0x20);

        for (u32 i = 0; i < 4; i++)
            hash_buf[seed_size + 3 - i] = (round_num >> (8 * i)) & 0xff;
        round_num++;

        se_calc_sha256(cur_hash, hash_buf, hash_buf_size);

        for (unsigned int i = 0; i < cur_size; i++) {
            *p_out ^= cur_hash[i];
            p_out++;
        }

        masked_size -= cur_size;
    }
}
