/*
 * Copyright (c) 2019-2021 shchmue
 * Copyright (c) 2021 CaramelDunes
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
#include "../frontend/gui.h"
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

static u32 start_time, end_time;
extern u32 color_idx;

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
static void _generate_kek(u32 ks, const void *key_source, void *master_key, const void *kek_seed, const void *key_seed);
static void _get_device_key(u32 ks, key_derivation_ctx_t *keys, void *out_device_key, u32 revision);

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

static bool _check_keyslot_access() {
    u8 test_data[AES_128_KEY_SIZE] = {0};
    const u8 test_ciphertext[AES_128_KEY_SIZE] = {0};
    se_aes_key_set(8, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", SE_KEY_128_SIZE);
    se_aes_crypt_block_ecb(8, DECRYPT, test_data, test_ciphertext);

    return memcmp(test_data, "\x7b\x1d\x29\xa1\x6c\xf8\xcc\xab\x84\xf0\xb8\xa5\x98\xe4\x2f\xa6", SE_KEY_128_SIZE) == 0;
}

void dump_keys(key_derivation_ctx_t* output) {
    minerva_periodic_training();

    if (!_check_keyslot_access()) {
        EPRINTF("Unable to set crypto keyslots!\nTry launching payload differently\n or flash Spacecraft-NX if using a modchip.");
        return;
    }

    u32 start_whole_operation_time = get_tmr_us();
    start_time = get_tmr_us();

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
    }

    TPRINTFARGS("%kMaster keys...  ", colors[(color_idx++) % 6]);

    minerva_periodic_training();
    _derive_misc_keys(keys, is_dev);

    end_time = get_tmr_us();
    gfx_printf("%kKeygen part done in %d us\n\n", colors[(color_idx++) % 6], end_time - start_whole_operation_time);
    memcpy(output, keys, sizeof(key_derivation_ctx_t));
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
