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

#include "keys.h"

#include "../../keygen/tsec_keygen.h"

#include "../config.h"
#include <display/di.h>
#include <gfx_utils.h>
#include "../gfx/tui.h"
#include "../hos/hos.h"
#include <libs/fatfs/ff.h>
#include <libs/nx_savedata/save.h>
#include <mem/heap.h>
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
static int  _key_exists(const void *data) { return memcmp(data, "\x00\x00\x00\x00\x00\x00\x00\x00", 8) != 0; };
static void _save_key(const char *name, const void *data, u32 len, char *outbuf);
static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf);
static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);
static void _generate_specific_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 key_generation);
static void _get_device_key(u32 ks, key_derivation_ctx_t *keys, void *out_device_key, u32 revision);
// titlekey functions
static bool _test_key_pair(const void *E, const void *D, const void *N);

static void _derive_master_key_mariko(key_derivation_ctx_t *keys, bool is_dev) {
    // Relies on the SBK being properly set in slot 14
    se_aes_crypt_block_ecb(14, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
    // Derive all master keys based on Mariko KEK
    for (u32 i = KB_FIRMWARE_VERSION_600; i < ARRAY_SIZE(mariko_master_kek_sources) + KB_FIRMWARE_VERSION_600; i++) {
        // Relies on the Mariko KEK being properly set in slot 12
        se_aes_crypt_block_ecb(12, DECRYPT, keys->master_kek[i], is_dev ? &mariko_master_kek_sources_dev[i - KB_FIRMWARE_VERSION_600] : &mariko_master_kek_sources[i - KB_FIRMWARE_VERSION_600]); // mkek = unwrap(mariko_kek, mariko_kek_source)
        se_aes_key_set(8, keys->master_kek[i], AES_128_KEY_SIZE); // mkey = unwrap(mkek, mkeys)
        se_aes_crypt_block_ecb(8, DECRYPT, keys->master_key[i], master_key_source);
    }
}

static int _run_ams_keygen(key_derivation_ctx_t *keys) {
    tsec_ctxt_t tsec_ctxt;
    tsec_ctxt.fw = tsec_keygen;
    tsec_ctxt.size = sizeof(tsec_keygen);
    tsec_ctxt.type = TSEC_FW_TYPE_NEW;

    u32 retries = 0;
    while (tsec_query(keys->temp_key, &tsec_ctxt) < 0) {
        retries++;
        if (retries > 15) {
            EPRINTF("Failed to run keygen.");
            return -1;
        }
    }

    return 0;
}

static void _derive_master_keys_from_latest_key(key_derivation_ctx_t *keys, bool is_dev) {
    if (!h_cfg.t210b01) {
        u32 tsec_root_key_slot = is_dev ? 11 : 13;
        // Derive all master keys based on current root key
        for (u32 i = KB_FIRMWARE_VERSION_810 - KB_FIRMWARE_VERSION_620; i < ARRAY_SIZE(master_kek_sources); i++) {
            se_aes_crypt_block_ecb(tsec_root_key_slot, DECRYPT, keys->master_kek[i + KB_FIRMWARE_VERSION_620], master_kek_sources[i]); // mkek = unwrap(tsec_root, mkeks)
            se_aes_key_set(8, keys->master_kek[i + KB_FIRMWARE_VERSION_620], AES_128_KEY_SIZE); // mkey = unwrap(mkek, mkeys)
            se_aes_crypt_block_ecb(8, DECRYPT, keys->master_key[i + KB_FIRMWARE_VERSION_620], master_key_source);
        }
    }

    // Derive all lower master keys
    for (u32 i = KB_FIRMWARE_VERSION_MAX; i > 0; i--) {
        se_aes_key_set(8, keys->master_key[i], AES_128_KEY_SIZE);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->master_key[i - 1], is_dev ? master_key_vectors_dev[i] : master_key_vectors[i]);
    }
    se_aes_key_set(8, keys->master_key[0], AES_128_KEY_SIZE);
    se_aes_crypt_block_ecb(8, DECRYPT, keys->temp_key, is_dev ? master_key_vectors_dev[0] : master_key_vectors[0]);

    if (_key_exists(keys->temp_key)) {
        EPRINTFARGS("Unable to derive master keys for %s.", is_dev ? "dev" : "prod");
        memset(keys->master_key, 0, sizeof(keys->master_key));
    }
}

static void _derive_keyblob_keys(key_derivation_ctx_t *keys) {
    u8 *keyblob_block = (u8 *)calloc(KB_FIRMWARE_VERSION_600 + 1, NX_EMMC_BLOCKSIZE);
    u32 keyblob_mac[AES_128_KEY_SIZE / 4] = {0};
    bool have_keyblobs = true;

    if (FUSE(FUSE_PRIVATE_KEY0) == 0xFFFFFFFF) {
        u8 *aes_keys = (u8 *)calloc(0x1000, 1);
        se_get_aes_keys(aes_keys + 0x800, aes_keys, AES_128_KEY_SIZE);
        memcpy(keys->sbk, aes_keys + 14 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        free(aes_keys);
    } else {
        keys->sbk[0] = FUSE(FUSE_PRIVATE_KEY0);
        keys->sbk[1] = FUSE(FUSE_PRIVATE_KEY1);
        keys->sbk[2] = FUSE(FUSE_PRIVATE_KEY2);
        keys->sbk[3] = FUSE(FUSE_PRIVATE_KEY3);
    }

    if (!emmc_storage.initialized) {
        have_keyblobs = false;
    } else if (!emummc_storage_read(KEYBLOB_OFFSET / NX_EMMC_BLOCKSIZE, KB_FIRMWARE_VERSION_600 + 1, keyblob_block)) {
        EPRINTF("Unable to read keyblobs.");
        have_keyblobs = false;
    } else {
        have_keyblobs = true;
    }

    encrypted_keyblob_t *current_keyblob = (encrypted_keyblob_t *)keyblob_block;
    for (u32 i = 0; i <= KB_FIRMWARE_VERSION_600; i++, current_keyblob++) {
        minerva_periodic_training();
        se_aes_crypt_block_ecb(12, DECRYPT, keys->keyblob_key[i], keyblob_key_sources[i]); // temp = unwrap(kbks, tsec)
        se_aes_crypt_block_ecb(14, DECRYPT, keys->keyblob_key[i], keys->keyblob_key[i]); // kbk = unwrap(temp, sbk)
        se_aes_key_set(7, keys->keyblob_key[i], sizeof(keys->keyblob_key[i]));
        se_aes_crypt_block_ecb(7, DECRYPT, keys->keyblob_mac_key[i], keyblob_mac_key_source); // kbm = unwrap(kbms, kbk)
        if (i == 0) {
            se_aes_crypt_block_ecb(7, DECRYPT, keys->device_key, per_console_key_source); // devkey = unwrap(pcks, kbk0)
            se_aes_crypt_block_ecb(7, DECRYPT, keys->device_key_4x, device_master_key_source_kek_source);
        }

        if (!have_keyblobs) {
            continue;
        }

        // verify keyblob is not corrupt
        se_aes_key_set(10, keys->keyblob_mac_key[i], sizeof(keys->keyblob_mac_key[i]));
        se_aes_cmac(10, keyblob_mac, sizeof(keyblob_mac), current_keyblob->iv, sizeof(current_keyblob->iv) + sizeof(keyblob_t));
        if (memcmp(current_keyblob->cmac, keyblob_mac, sizeof(keyblob_mac)) != 0) {
            EPRINTFARGS("Keyblob %x corrupt.", i);
            continue;
        }

        // decrypt keyblobs
        se_aes_key_set(6, keys->keyblob_key[i], sizeof(keys->keyblob_key[i]));
        se_aes_crypt_ctr(6, &keys->keyblob[i], sizeof(keyblob_t), &current_keyblob->key_data, sizeof(keyblob_t), current_keyblob->iv);

        memcpy(keys->package1_key[i], keys->keyblob[i].package1_key, sizeof(keys->package1_key[i]));
        memcpy(keys->master_kek[i], keys->keyblob[i].master_kek, sizeof(keys->master_kek[i]));
        se_aes_key_set(7, keys->master_kek[i], sizeof(keys->master_kek[i]));
        if (!_key_exists(keys->master_key[i])) {
            se_aes_crypt_block_ecb(7, DECRYPT, keys->master_key[i], master_key_source);
        }
    }
    free(keyblob_block);
}

static void _derive_bis_keys(key_derivation_ctx_t *keys) {
    /*  key = unwrap(source, wrapped_key):
        key_set(ks, wrapped_key), block_ecb(ks, 0, key, source) -> final key in key
    */
    minerva_periodic_training();
    u32 key_generation = fuse_read_odm_keygen_rev();
    if (key_generation)
        key_generation--;

    if (!(_key_exists(keys->device_key) || (key_generation && _key_exists(keys->master_key[0]) && _key_exists(keys->device_key_4x)))) {
        return;
    }
    _generate_specific_aes_key(8, keys, &keys->bis_key[0], &bis_key_sources[0], key_generation);
    // kek = generate_kek(bkeks, devkey, aeskek, aeskey)
    _generate_kek(8, bis_kek_source, keys->temp_key, aes_kek_generation_source, aes_key_generation_source);
    se_aes_crypt_ecb(8, DECRYPT, keys->bis_key[1], AES_128_KEY_SIZE * 2, bis_key_sources[1], AES_128_KEY_SIZE * 2); // bkey = unwrap(bkeys, kek)
    se_aes_crypt_ecb(8, DECRYPT, keys->bis_key[2], AES_128_KEY_SIZE * 2, bis_key_sources[2], AES_128_KEY_SIZE * 2);
    memcpy(keys->bis_key[3], keys->bis_key[2], 0x20);
}

static void _derive_non_unique_keys(key_derivation_ctx_t *keys, bool is_dev) {
    if (_key_exists(keys->master_key[0])) {
        _generate_kek(8, header_kek_source, keys->master_key[0], aes_kek_generation_source, aes_key_generation_source);
        se_aes_crypt_ecb(8, DECRYPT, keys->header_key, AES_128_KEY_SIZE * 2, header_key_source, AES_128_KEY_SIZE * 2);
    }
}

static void _derive_misc_keys(key_derivation_ctx_t *keys, bool is_dev) {
    if (_key_exists(keys->device_key) || (_key_exists(keys->master_key[0]) && _key_exists(keys->device_key_4x))) {
        _get_device_key(8, keys, keys->temp_key, 0);
        _generate_kek(8, save_mac_kek_source, keys->temp_key, aes_kek_generation_source, NULL);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->save_mac_key, save_mac_key_source);
    }

    if (_key_exists(keys->master_key[0])) {
        for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
            keys->temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        _generate_kek(8, eticket_rsa_kekek_source, keys->master_key[0], keys->temp_key, NULL);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->eticket_rsa_kek, is_dev ? eticket_rsa_kek_source_dev : eticket_rsa_kek_source);

        for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
            keys->temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
        _generate_kek(8, ssl_rsa_kek_source_x, keys->master_key[0], keys->temp_key, NULL);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->ssl_rsa_kek, ssl_rsa_kek_source_y);
    }
}

static void _derive_per_generation_keys(key_derivation_ctx_t *keys) {
    for (u32 i = 0; i < KB_FIRMWARE_VERSION_MAX + 1; i++) {
        if (!_key_exists(keys->master_key[i]))
            continue;
        for (u32 j = 0; j < 3; j++) {
            _generate_kek(8, key_area_key_sources[j], keys->master_key[i], aes_kek_generation_source, NULL);
            se_aes_crypt_block_ecb(8, DECRYPT, keys->key_area_key[j][i], aes_key_generation_source);
        }
        se_aes_key_set(8, keys->master_key[i], AES_128_KEY_SIZE);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->package2_key[i], package2_key_source);
        se_aes_crypt_block_ecb(8, DECRYPT, keys->titlekek[i], titlekek_source);
    }
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

    const char ticket_bin_path[32] = "/ticket.bin";
    const char ticket_list_bin_path[32] = "/ticket_list.bin";
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
    u32 pct = 0, last_pct = 0, i = 0;
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
            if (i == file_tkey_count || curr_ticket->signature_type == 0) {
                terminator_reached = true;
                break;
            }
            if (curr_ticket->signature_type != ticket_sig_type_rsa2048_sha256) {
                i++;
                continue;
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
            i++;
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

static bool _derive_sd_seed(key_derivation_ctx_t *keys) {
    FIL fp;
    u32 read_bytes = 0;
    char *private_path = malloc(200);
    strcpy(private_path, "sd:/");

    if (emu_cfg.nintendo_path && (emu_cfg.enabled || !h_cfg.emummc_force_disable)) {
        strcat(private_path, emu_cfg.nintendo_path);
    } else {
        strcat(private_path, "Nintendo");
    }
    strcat(private_path, "/Contents/private");
    FRESULT fr = f_open(&fp, private_path, FA_READ | FA_OPEN_EXISTING);
    free(private_path);
    if (fr) {
        EPRINTF("Unable to open SD seed vector. Skipping.");
        return false;
    }
    // get sd seed verification vector
    if (f_read(&fp, keys->temp_key, AES_128_KEY_SIZE, &read_bytes) || read_bytes != AES_128_KEY_SIZE) {
        EPRINTF("Unable to read SD seed vector. Skipping.");
        f_close(&fp);
        return false;
    }
    f_close(&fp);

    // this file is small enough that parsing the savedata properly is slower
    if (f_open(&fp, "bis:/save/8000000000000043", FA_READ | FA_OPEN_EXISTING)) {
        EPRINTF("Unable to open ns_appman save.\nSkipping SD seed.");
        return false;
    }

    u8 read_buf[0x20] __attribute__((aligned(4))) = {0};
    for (u32 i = 0x8000; i < f_size(&fp); i += 0x4000) {
        if (f_lseek(&fp, i) || f_read(&fp, read_buf, 0x20, &read_bytes) || read_bytes != 0x20)
            break;
        if (!memcmp(keys->temp_key, read_buf, sizeof(keys->temp_key))) {
            memcpy(keys->sd_seed, read_buf + 0x10, sizeof(keys->sd_seed));
            break;
        }
    }
    f_close(&fp);

    TPRINTFARGS("%kSD Seed...      ", colors[(color_idx++) % 6]);

    return true;
}

static bool _derive_titlekeys(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer) {
    if (!_key_exists(keys->eticket_rsa_kek)) {
        return false;
    }

    gfx_printf("%kTitlekeys...     \n", colors[(color_idx++) % 6]);

    rsa_keypair_t rsa_keypair = {0};

    if (!emummc_storage_read(NX_EMMC_CALIBRATION_OFFSET / NX_EMMC_BLOCKSIZE, NX_EMMC_CALIBRATION_SIZE / NX_EMMC_BLOCKSIZE, titlekey_buffer->read_buffer)) {
        EPRINTF("Unable to read PRODINFO.");
        return false;
    }

    se_aes_xts_crypt(1, 0, DECRYPT, 0, titlekey_buffer->read_buffer, titlekey_buffer->read_buffer, XTS_CLUSTER_SIZE, NX_EMMC_CALIBRATION_SIZE / XTS_CLUSTER_SIZE);

    nx_emmc_cal0_t *cal0 = (nx_emmc_cal0_t *)titlekey_buffer->read_buffer;
    if (cal0->magic != MAGIC_CAL0) {
        EPRINTF("Invalid CAL0 magic. Check BIS key 0.");
        return false;
    }

    // settings sysmodule manually zeroes this out below cal version 9
    u32 keypair_generation = cal0->version <= 8 ? 0 : cal0->ext_ecc_rsa2048_eticket_key_ver;

    if (keypair_generation) {
        keypair_generation--;
        for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
            keys->temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
        u32 temp_device_key[AES_128_KEY_SIZE / 4] = {0};
        _get_device_key(7, keys, temp_device_key, keypair_generation);
        _generate_kek(7, eticket_rsa_kekek_source, temp_device_key, keys->temp_key, NULL);
        se_aes_crypt_block_ecb(7, DECRYPT, keys->eticket_rsa_kek_personalized, eticket_rsa_kek_source);
        memcpy(keys->temp_key, keys->eticket_rsa_kek_personalized, sizeof(keys->temp_key));
    } else {
        memcpy(keys->temp_key, keys->eticket_rsa_kek, sizeof(keys->temp_key));
    }

    se_aes_key_set(6, keys->temp_key, sizeof(keys->temp_key));
    se_aes_crypt_ctr(6, &rsa_keypair, sizeof(rsa_keypair), cal0->ext_ecc_rsa2048_eticket_key, sizeof(cal0->ext_ecc_rsa2048_eticket_key), cal0->ext_ecc_rsa2048_eticket_key_iv);

    // Check public exponent is 65537 big endian
    if (_read_be_u32(rsa_keypair.public_exponent, 0) != 65537) {
        EPRINTF("Invalid public exponent.");
        return false;
    }

    if (!_test_key_pair(rsa_keypair.public_exponent, rsa_keypair.private_exponent, rsa_keypair.modulus)) {
        EPRINTF("Invalid keypair. Check eticket_rsa_kek.");
        return false;
    }

    se_rsa_key_set(0, rsa_keypair.modulus, sizeof(rsa_keypair.modulus), rsa_keypair.private_exponent, sizeof(rsa_keypair.private_exponent));

    const u32 buf_size = 0x4000;
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, NULL);
    _get_titlekeys_from_save(buf_size, keys->save_mac_key, titlekey_buffer, &rsa_keypair);

    gfx_printf("\n%k  Found %d titlekeys.\n\n", colors[(color_idx++) % 6], _titlekey_count);

    return true;
}

static bool _derive_emmc_keys(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer) {
    // Set BIS keys.
    // PRODINFO/PRODINFOF
    se_aes_key_set(0, keys->bis_key[0] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(1, keys->bis_key[0] + 0x10, AES_128_KEY_SIZE);
    // SAFE
    se_aes_key_set(2, keys->bis_key[1] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(3, keys->bis_key[1] + 0x10, AES_128_KEY_SIZE);
    // SYSTEM/USER
    se_aes_key_set(4, keys->bis_key[2] + 0x00, AES_128_KEY_SIZE);
    se_aes_key_set(5, keys->bis_key[2] + 0x10, AES_128_KEY_SIZE);

    if (!emummc_storage_set_mmc_partition(EMMC_GPP)) {
        EPRINTF("Unable to set partition.");
        return false;
    }
    // Parse eMMC GPT.
    LIST_INIT(gpt);
    nx_emmc_gpt_parse(&gpt, &emmc_storage);

    emmc_part_t *system_part = nx_emmc_part_find(&gpt, "SYSTEM");
    if (!system_part) {
        EPRINTF("Unable to locate System partition.");
        nx_emmc_gpt_free(&gpt);
        return false;
    }

    nx_emmc_bis_init(system_part);

    if (f_mount(&emmc_fs, "bis:", 1)) {
        EPRINTF("Unable to mount system partition.");
        nx_emmc_gpt_free(&gpt);
        return false;
    }

    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
    } else if (!_derive_sd_seed(keys)) {
        EPRINTF("Unable to get SD seed.");
    }

    bool res = _derive_titlekeys(keys, titlekey_buffer);
    if (!res) {
        EPRINTF("Unable to derive titlekeys.");
    }
    f_mount(NULL, "bis:", 1);
    nx_emmc_gpt_free(&gpt);

    return res;
}

// The security engine supports partial key override for locked keyslots
// This allows for a manageable brute force on a PC
// Then the Mariko AES class keys, KEK, BEK, unique SBK and SSK can be recovered
static void _save_mariko_partial_keys(u32 start, u32 count, bool append) {
    if (start + count > SE_AES_KEYSLOT_COUNT) {
        return;
    }

    u32 pos = 0;
    u32 zeros[AES_128_KEY_SIZE / 4] = {0};
    u8 *data = malloc(4 * AES_128_KEY_SIZE);
    char *text_buffer = calloc(1, 0x100 * count);

    for (u32 ks = start; ks < start + count; ks++) {
        // Check if key is as expected
        if (ks < ARRAY_SIZE(mariko_key_vectors)) {
            se_aes_crypt_block_ecb(ks, DECRYPT, &data[0], mariko_key_vectors[ks]);
            if (_key_exists(data)) {
                continue;
            }
        }

        // Encrypt zeros with complete key
        se_aes_crypt_block_ecb(ks, ENCRYPT, &data[3 * AES_128_KEY_SIZE], zeros);

        // We only need to overwrite 3 of the dwords of the key
        for (u32 i = 0; i < 3; i++) {
            // Overwrite ith dword of key with zeros
            se_aes_key_partial_set(ks, i, 0);
            // Encrypt zeros with more of the key zeroed out
            se_aes_crypt_block_ecb(ks, ENCRYPT, &data[(2 - i) * AES_128_KEY_SIZE], zeros);
        }

        // Skip saving key if two results are the same indicating unsuccessful overwrite or empty slot
        if (memcmp(&data[0], &data[SE_KEY_128_SIZE], AES_128_KEY_SIZE) == 0) {
            continue;
        }

        pos += s_printf(&text_buffer[pos], "%d\n", ks);
        for (u32 i = 0; i < 4; i++) {
            for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
                pos += s_printf(&text_buffer[pos], "%02x", data[i * AES_128_KEY_SIZE + j]);
            pos += s_printf(&text_buffer[pos], " ");
        }
        pos += s_printf(&text_buffer[pos], "\n");
    }
    free(data);

    if (strlen(text_buffer) == 0) {
        EPRINTF("Failed to dump partial keys.");
        return;
    }

    FIL fp;
    u32 res = 0;
    BYTE mode = FA_WRITE;

    if (append) {
        mode |= FA_OPEN_APPEND;
    } else {
        mode |= FA_CREATE_ALWAYS;
    }

    res = f_open(&fp, "sd:/switch/partialaes.keys", mode);
    if (res) {
        EPRINTF("Unable to write partial keys to SD.");
        return;
    }

    f_write(&fp, text_buffer, strlen(text_buffer), NULL);
    f_close(&fp);

    gfx_printf("%kWrote partials to sd:/switch/partialaes.keys\n", colors[(color_idx++) % 6]);

    free(text_buffer);
}

static void _save_keys_to_sd(key_derivation_ctx_t *keys, titlekey_buffer_t *titlekey_buffer, bool is_dev) {
    char *text_buffer = NULL;
    if (!sd_mount()) {
        EPRINTF("Unable to mount SD.");
        return;
    }

    u32 text_buffer_size = MAX(_titlekey_count * sizeof(titlekey_text_buffer_t) + 1, 0x4000);
    text_buffer = (char *)calloc(1, text_buffer_size);

    SAVE_KEY(aes_kek_generation_source);
    SAVE_KEY(aes_key_generation_source);
    SAVE_KEY(bis_kek_source);
    SAVE_KEY_FAMILY_VAR(bis_key, keys->bis_key, 0);
    SAVE_KEY_FAMILY_VAR(bis_key_source, bis_key_sources, 0);
    SAVE_KEY_VAR(device_key, keys->device_key);
    SAVE_KEY_VAR(device_key_4x, keys->device_key_4x);
    SAVE_KEY_VAR(eticket_rsa_kek, keys->eticket_rsa_kek);
    SAVE_KEY_VAR(eticket_rsa_kek_personalized, keys->eticket_rsa_kek_personalized);
    if (is_dev) {
        SAVE_KEY_VAR(eticket_rsa_kek_source, eticket_rsa_kek_source_dev);
    } else {
        SAVE_KEY(eticket_rsa_kek_source);
    }
    SAVE_KEY(eticket_rsa_kekek_source);
    SAVE_KEY(header_kek_source);
    SAVE_KEY_VAR(header_key, keys->header_key);
    SAVE_KEY(header_key_source);
    SAVE_KEY_FAMILY_VAR(key_area_key_application, keys->key_area_key[0], 0);
    SAVE_KEY_VAR(key_area_key_application_source, key_area_key_sources[0]);
    SAVE_KEY_FAMILY_VAR(key_area_key_ocean, keys->key_area_key[1], 0);
    SAVE_KEY_VAR(key_area_key_ocean_source, key_area_key_sources[1]);
    SAVE_KEY_FAMILY_VAR(key_area_key_system, keys->key_area_key[2], 0);
    SAVE_KEY_VAR(key_area_key_system_source, key_area_key_sources[2]);
    SAVE_KEY_FAMILY_VAR(keyblob, keys->keyblob, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key, keys->keyblob_key, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_key_source, keyblob_key_sources, 0);
    SAVE_KEY_FAMILY_VAR(keyblob_mac_key, keys->keyblob_mac_key, 0);
    SAVE_KEY(keyblob_mac_key_source);
    if (is_dev) {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources_dev, 5);
    } else {
        SAVE_KEY_FAMILY_VAR(mariko_master_kek_source, mariko_master_kek_sources, 5);
    }
    SAVE_KEY_FAMILY_VAR(master_kek, keys->master_kek, 0);
    SAVE_KEY_FAMILY_VAR(master_kek_source, master_kek_sources, KB_FIRMWARE_VERSION_620);
    SAVE_KEY_FAMILY_VAR(master_key, keys->master_key, 0);
    SAVE_KEY(master_key_source);
    SAVE_KEY_FAMILY_VAR(package1_key, keys->package1_key, 0);
    SAVE_KEY_FAMILY_VAR(package2_key, keys->package2_key, 0);
    SAVE_KEY(package2_key_source);
    SAVE_KEY(per_console_key_source);
    SAVE_KEY(retail_specific_aes_key_source);
    for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
        keys->temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_03[i];
    SAVE_KEY_VAR(rsa_oaep_kek_generation_source, keys->temp_key);
    for (u32 i = 0; i < AES_128_KEY_SIZE; i++)
        keys->temp_key[i] = aes_kek_generation_source[i] ^ aes_kek_seed_01[i];
    SAVE_KEY_VAR(rsa_private_kek_generation_source, keys->temp_key);
    SAVE_KEY(save_mac_kek_source);
    SAVE_KEY_VAR(save_mac_key, keys->save_mac_key);
    SAVE_KEY(save_mac_key_source);
    SAVE_KEY(save_mac_sd_card_kek_source);
    SAVE_KEY(save_mac_sd_card_key_source);
    SAVE_KEY(sd_card_custom_storage_key_source);
    SAVE_KEY(sd_card_kek_source);
    SAVE_KEY(sd_card_nca_key_source);
    SAVE_KEY(sd_card_save_key_source);
    SAVE_KEY_VAR(sd_seed, keys->sd_seed);
    SAVE_KEY_VAR(secure_boot_key, keys->sbk);
    SAVE_KEY_VAR(ssl_rsa_kek, keys->ssl_rsa_kek);
    SAVE_KEY(ssl_rsa_kek_source_x);
    SAVE_KEY(ssl_rsa_kek_source_y);
    SAVE_KEY_FAMILY_VAR(titlekek, keys->titlekek, 0);
    SAVE_KEY(titlekek_source);
    SAVE_KEY_VAR(tsec_key, keys->tsec_key);

    const u32 root_key_ver = 2;
    char root_key_name[21] = "tsec_root_key_00";
    s_printf(root_key_name + 14, "%02x", root_key_ver);
    _save_key(root_key_name, keys->tsec_root_key, AES_128_KEY_SIZE, text_buffer);

    gfx_printf("\n%k  Found %d %s keys.\n\n", colors[(color_idx++) % 6], _key_count, is_dev ? "dev" : "prod");
    gfx_printf("%kFound through master_key_%02x.\n\n", colors[(color_idx++) % 6], KB_FIRMWARE_VERSION_MAX);

    f_mkdir("sd:/switch");
    char keyfile_path[30] = "sd:/switch/prod.keys";
    if (is_dev) {
        s_printf(&keyfile_path[11], "dev.keys");
    }

    FILINFO fno;
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else
        EPRINTF("Unable to save keys to SD.");

    if (h_cfg.t210b01) {
        _save_mariko_partial_keys(12, 4, true);
    }

    if (_titlekey_count == 0 || !titlekey_buffer) {
        free(text_buffer);
        return;
    }
    memset(text_buffer, 0, text_buffer_size);

    titlekey_text_buffer_t *titlekey_text = (titlekey_text_buffer_t *)text_buffer;

    for (u32 i = 0; i < _titlekey_count; i++) {
        for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
            s_printf(&titlekey_text[i].rights_id[j * 2], "%02x", titlekey_buffer->rights_ids[i][j]);
        s_printf(titlekey_text[i].equals, " = ");
        for (u32 j = 0; j < AES_128_KEY_SIZE; j++)
            s_printf(&titlekey_text[i].titlekey[j * 2], "%02x", titlekey_buffer->titlekeys[i][j]);
        s_printf(titlekey_text[i].newline, "\n");
    }
    s_printf(&keyfile_path[11], "title.keys");
    if (!sd_save_to_file(text_buffer, strlen(text_buffer), keyfile_path) && !f_stat(keyfile_path, &fno)) {
        gfx_printf("%kWrote %d bytes to %s\n", colors[(color_idx++) % 6], (u32)fno.fsize, keyfile_path);
    } else
        EPRINTF("Unable to save titlekeys to SD.");

    free(text_buffer);
}

static bool _check_keyslot_access() {
    u8 test_data[AES_128_KEY_SIZE] = {0};
    const u8 test_ciphertext[AES_128_KEY_SIZE] = {0};
    se_aes_key_set(8, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(8, DECRYPT, test_data, test_ciphertext);

    return memcmp(test_data, "\x7b\x1d\x29\xa1\x6c\xf8\xcc\xab\x84\xf0\xb8\xa5\x98\xe4\x2f\xa6", SE_KEY_128_SIZE) == 0;
}

static void _derive_keys() {
    if (!f_stat("sd:/switch/partialaes.keys", NULL)) {
        f_unlink("sd:/switch/partialaes.keys");
    }

    minerva_periodic_training();

    if (h_cfg.t210b01) {
        _save_mariko_partial_keys(0, 12, false);
    }

    minerva_periodic_training();

    if (!_check_keyslot_access()) {
        EPRINTF("Unable to set crypto keyslots!\nTry launching payload differently\n or flash Spacecraft-NX if using a modchip.");
        return;
    }

    u32 start_whole_operation_time = get_tmr_us();

    if (emummc_storage_init_mmc()) {
        EPRINTF("Unable to init MMC.");
    } else {
        TPRINTFARGS("%kMMC init...     ", colors[(color_idx++) % 6]);
    }

    minerva_periodic_training();

    if (emmc_storage.initialized && !emummc_storage_set_mmc_partition(EMMC_BOOT0)) {
        EPRINTF("Unable to set partition.");
        emummc_storage_end();
    }

    bool is_dev = fuse_read_hw_state() == FUSE_NX_HW_STATE_DEV;

    key_derivation_ctx_t __attribute__((aligned(4))) prod_keys = {0}, dev_keys = {0};
    key_derivation_ctx_t *keys = is_dev ? &dev_keys : &prod_keys;

    // Master key derivation
    if (h_cfg.t210b01) {
        _derive_master_key_mariko(keys, is_dev);
        minerva_periodic_training();
        _derive_master_keys_from_latest_key(keys, is_dev);
    } else {
        int res = _run_ams_keygen(keys);
        if (res) {
            return;
        }

        u8 *aes_keys = (u8 *)calloc(0x1000, 1);
        se_get_aes_keys(aes_keys + 0x800, aes_keys, AES_128_KEY_SIZE);
        memcpy(&dev_keys.tsec_root_key, aes_keys + 11 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        memcpy(keys->tsec_key, aes_keys + 12 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        memcpy(&prod_keys.tsec_root_key, aes_keys + 13 * AES_128_KEY_SIZE, AES_128_KEY_SIZE);
        free(aes_keys);

        _derive_master_keys_from_latest_key(&prod_keys, false);
        minerva_periodic_training();
        _derive_master_keys_from_latest_key(&dev_keys, true);
        minerva_periodic_training();
        _derive_keyblob_keys(keys);
    }

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    _derive_bis_keys(keys);

    TPRINTFARGS("%kBIS keys...     ", colors[(color_idx++) % 6]);

    minerva_periodic_training();
    _derive_misc_keys(keys, is_dev);

    minerva_periodic_training();
    _derive_non_unique_keys(&prod_keys, is_dev);
    minerva_periodic_training();
    _derive_non_unique_keys(&dev_keys, is_dev);
    minerva_periodic_training();
    _derive_per_generation_keys(&prod_keys);
    minerva_periodic_training();
    _derive_per_generation_keys(&dev_keys);

    titlekey_buffer_t *titlekey_buffer = (titlekey_buffer_t *)TITLEKEY_BUF_ADR;

    // Requires BIS key for SYSTEM partition
    if (!emmc_storage.initialized) {
        EPRINTF("eMMC not initialized.\nSkipping SD seed and titlekeys.");
    } else if (_key_exists(keys->bis_key[2])) {
        _derive_emmc_keys(keys, titlekey_buffer);
    } else {
        EPRINTF("Missing needed BIS keys.\nSkipping SD seed and titlekeys.");
    }

    end_time = get_tmr_us();
    gfx_printf("%kLockpick totally done in %d us\n", colors[(color_idx++) % 6], end_time - start_whole_operation_time);

    if (h_cfg.t210b01) {
        // On Mariko, save only relevant key set
        _save_keys_to_sd(keys, titlekey_buffer, is_dev);
    } else {
        // On Erista, save both prod and dev key sets
        _save_keys_to_sd(&prod_keys, titlekey_buffer, false);
        _key_count = 0;
        _save_keys_to_sd(&dev_keys, NULL, true);
    }
}

void dump_keys() {
    minerva_change_freq(FREQ_1600);

    display_backlight_brightness(h_cfg.backlight, 1000);
    gfx_clear_grey(0x1B);
    gfx_con_setpos(0, 0);

    gfx_printf("[%kLo%kck%kpi%kck%k_R%kCM%k v%d.%d.%d%k]\n\n",
        colors[0], colors[1], colors[2], colors[3], colors[4], colors[5], 0xFFFF00FF, LP_VER_MJ, LP_VER_MN, LP_VER_BF, 0xFFCCCCCC);

    _key_count = 0;
    _titlekey_count = 0;
    color_idx = 0;

    start_time = get_tmr_us();

    _derive_keys();

    emummc_load_cfg();
    // Ignore whether emummc is enabled.
    h_cfg.emummc_force_disable = emu_cfg.sector == 0 && !emu_cfg.path;
    emu_cfg.enabled = !h_cfg.emummc_force_disable;
    if (emmc_storage.initialized) {
        emummc_storage_end();
    }

    minerva_change_freq(FREQ_800);
    gfx_printf("\n%kPress a button to return to the menu.", colors[(color_idx) % 6], colors[(color_idx + 1) % 6], colors[(color_idx + 2) % 6]);
    btn_wait();
    gfx_clear_grey(0x1B);
}

static void _save_key(const char *name, const void *data, u32 len, char *outbuf) {
    if (!_key_exists(data))
        return;
    u32 pos = strlen(outbuf);
    pos += s_printf(&outbuf[pos], "%s = ", name);
    for (u32 i = 0; i < len; i++)
        pos += s_printf(&outbuf[pos], "%02x", *(u8*)(data + i));
    s_printf(&outbuf[pos], "\n");
    _key_count++;
}

static void _save_key_family(const char *name, const void *data, u32 start_key, u32 num_keys, u32 len, char *outbuf) {
    char *temp_name = calloc(1, 0x40);
    for (u32 i = 0; i < num_keys; i++) {
        s_printf(temp_name, "%s_%02x", name, i + start_key);
        _save_key(temp_name, data + i * len, len, outbuf);
    }
    free(temp_name);
}

static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed) {
    if (!_key_exists(key_source) || !_key_exists(master_key) || !_key_exists(kek_seed))
        return;

    se_aes_key_set(ks, master_key, AES_128_KEY_SIZE);
    se_aes_unwrap_key(ks, ks, kek_seed);
    se_aes_unwrap_key(ks, ks, key_source);
    if (key_seed && _key_exists(key_seed))
        se_aes_unwrap_key(ks, ks, key_seed);
}

static void _get_secure_data(key_derivation_ctx_t *keys, void *dst) {
    se_aes_key_set(6, keys->device_key, AES_128_KEY_SIZE);
    u8 *d = (u8 *)dst;
    se_aes_crypt_ctr(6, d + 0x00, AES_128_KEY_SIZE, secure_data_source, AES_128_KEY_SIZE, secure_data_counters[0]);
    se_aes_crypt_ctr(6, d + 0x10, AES_128_KEY_SIZE, secure_data_source, AES_128_KEY_SIZE, secure_data_counters[0]);

    // Apply tweak
    for (u32 i = 0; i < AES_128_KEY_SIZE; i++) {
        d[AES_128_KEY_SIZE + i] ^= secure_data_tweaks[0][i];
    }
}

static void _generate_specific_aes_key(u32 ks, key_derivation_ctx_t *keys, void *out_key, const void *key_source, u32 key_generation) {
    if (fuse_read_bootrom_rev() >= 0x7F) {
        _get_device_key(ks, keys, keys->temp_key, key_generation);
        se_aes_key_set(ks, keys->temp_key, AES_128_KEY_SIZE);
        se_aes_unwrap_key(ks, ks, retail_specific_aes_key_source); // kek = unwrap(rsaks, devkey)
        se_aes_crypt_ecb(ks, DECRYPT, out_key, AES_128_KEY_SIZE * 2, key_source, AES_128_KEY_SIZE * 2); // bkey = unwrap(bkeys, kek)
    } else {
        _get_secure_data(keys, out_key);
    }
}

static void _get_device_key(u32 ks, key_derivation_ctx_t *keys, void *out_device_key, u32 revision) {
    if (revision == KB_FIRMWARE_VERSION_100 && !h_cfg.t210b01) {
        memcpy(out_device_key, keys->device_key, AES_128_KEY_SIZE);
        return;
    }

    if (revision >= KB_FIRMWARE_VERSION_400) {
        revision -= KB_FIRMWARE_VERSION_400;
    } else {
        revision = 0;
    }
    u32 temp_key[AES_128_KEY_SIZE / 4] = {0};
    se_aes_key_set(ks, keys->device_key_4x, AES_128_KEY_SIZE);
    se_aes_crypt_block_ecb(ks, DECRYPT, temp_key, device_master_key_source_sources[revision]);
    se_aes_key_set(ks, keys->master_key[0], AES_128_KEY_SIZE);
    const void *kek_source = fuse_read_hw_state() == FUSE_NX_HW_STATE_PROD ? device_master_kek_sources[revision] : device_master_kek_sources_dev[revision];
    se_aes_unwrap_key(ks, ks, kek_source);
    se_aes_crypt_block_ecb(ks, DECRYPT, out_device_key, temp_key);
}

static bool _test_key_pair(const void *public_exponent, const void *private_exponent, const void *modulus) {
    u8  plaintext[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0},
        ciphertext[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0},
        work[RSA_2048_KEY_SIZE] __attribute__((aligned(4))) = {0};

    // 0xCAFEBABE
    plaintext[0xfc] = 0xca; plaintext[0xfd] = 0xfe; plaintext[0xfe] = 0xba; plaintext[0xff] = 0xbe;

    se_rsa_key_set(0, modulus, RSA_2048_KEY_SIZE, private_exponent, RSA_2048_KEY_SIZE);
    se_rsa_exp_mod(0, ciphertext, RSA_2048_KEY_SIZE, plaintext, RSA_2048_KEY_SIZE);

    se_rsa_key_set(0, modulus, RSA_2048_KEY_SIZE, public_exponent, 4);
    se_rsa_exp_mod(0, work, RSA_2048_KEY_SIZE, ciphertext, RSA_2048_KEY_SIZE);

    return !memcmp(plaintext, work, RSA_2048_KEY_SIZE);
}
