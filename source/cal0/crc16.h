#ifndef _CRC_16_H
#define _CRC_16_H

#include "../utils/types.h"

u16 get_crc_16(u8 *p, int n);

void write_crc16(u8 *buffer, u16 block_offset, u16 block_size);
int has_valid_crc16(u8 *buffer, u16 block_offset, u16 block_size);

#endif