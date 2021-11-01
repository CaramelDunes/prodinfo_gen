#include "crc16.h"

#include <string.h>

unsigned int crc_16_table[16] = {
    0x0000, 0xCC01, 0xD801, 0x1400, 0xF001, 0x3C00, 0x2800, 0xE401,
    0xA001, 0x6C00, 0x7800, 0xB401, 0x5000, 0x9C01, 0x8801, 0x4400};

unsigned short int get_crc_16(unsigned char *p, int n)
{
  unsigned short int crc = 0x55AA;
  int r;

  while (n-- > 0)
  {
    r = crc_16_table[crc & 0xF];
    crc = (crc >> 4) & 0x0FFF;
    crc = crc ^ r ^ crc_16_table[*p & 0xF];

    r = crc_16_table[crc & 0xF];
    crc = (crc >> 4) & 0x0FFF;
    crc = crc ^ r ^ crc_16_table[(*p >> 4) & 0xF];

    p++;
  }

  return (crc);
}

void write_crc16(u8 *buffer, u16 block_offset, u16 block_size)
{
  u16 crc = get_crc_16(buffer + block_offset, block_size - 2);

  memcpy(buffer + block_offset + block_size - 2, &crc, 2);
}

bool has_valid_crc16(u8 *buffer, u16 block_offset, u16 block_size)
{
  u16 crc = get_crc_16(buffer + block_offset, block_size - 2);

  return crc == *((u16 *)(buffer + block_offset + block_size - 2));
}