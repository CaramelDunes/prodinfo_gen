#ifndef _CAL0_H_
#define _CAL0_H_

#include "../utils/types.h"

void device_id_string(char device_id_string[0x11]);

void write_ssl_certificate(u8 *prodinfo_buffer);
void write_random_number(u8 *prodinfo_buffer, u64 device_id);
void write_eticket_certificate(u8 *prodinfo_buffer, const char *device_id_string);
void write_device_certificate(u8 *prodinfo_buffer, const char *device_id_string);

void write_header(u8 *prodinfo_buffer);
void write_config_id(u8 *prodinfo_buffer);
void write_wlan_country_codes(u8 *prodinfo_buffer);
void write_mac_addresses(u8 *prodinfo_buffer, u64 device_id);
void write_sensors_offset_scale(u8 *prodinfo_buffer);
void write_serial_number(u8 *prodinfo_buffer);

void write_battery_lot(u8 *prodinfo_buffer);
void write_speaker_calibration_value(u8 *prodinfo_buffer);
void write_short_values(u8 *prodinfo_buffer);

void write_all_crc(u8 *prodinfo_buffer, u32 prodinfo_size);
void write_all_sha256(u8 *prodinfo_buffer);

//Check
bool valid_donor_prodinfo(u8 *prodinfo_buffer, u32 prodinfo_size);
bool valid_own_prodinfo(u8 *prodinfo_buffer, u32 prodinfo_size, u8 *master_key_0);

bool valid_crcs(u8 *prodinfo_buffer, u32 prodinfo_size);
bool valid_extended_rsa_2048_eticket_key(u8 *prodinfo_buffer, u8 *master_key_0);
bool valid_extended_ecc_b233_device_key(u8 *prodinfo_buffer, u8 *master_key_0);
bool valid_ecc_b233_device_certificate(u8 *prodinfo_buffer);
bool valid_rsa_2048_eticket_certificate(u8 *prodinfo_buffer);
bool valid_cal0_signature(u8 *prodinfo_buffer, u32 prodinfo_size);
bool valid_body_checksum(u8 *prodinfo_buffer, u32 prodinfo_size);
bool valid_extended_gamecard_key(u8 *prodinfo_buffer, u8 *master_key_0);

// Write
void write_extended_ecc_b233_device_key(u8 *prodinfo_buffer, u64 device_id, u8 *master_key_0);
void write_extended_rsa_2048_eticket_key(u8 *prodinfo_buffer, u64 device_id, u8 *master_key_0);
void write_body_checksum(u8 *prodinfo_buffer);
void write_extended_gamecard_key(u8 *prodinfo_buffer, u64 device_id, u8 *master_key_0);

#endif