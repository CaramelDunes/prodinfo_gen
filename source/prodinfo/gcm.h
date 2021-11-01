
/*
 * Copyright (c) 2018-2020 Atmosphère-NX
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

#ifndef EXOSPHERE_GCM_H
#define EXOSPHERE_GCM_H

// #include <stdbool.h>
#include <stdint.h>

#define KEYSLOT_SWITCH_LP0TZRAMKEY 0x2
#define KEYSLOT_SWITCH_SRKGENKEY 0x8
#define KEYSLOT_SWITCH_PACKAGE2KEY 0x8
#define KEYSLOT_SWITCH_TEMPKEY 0x9
#define KEYSLOT_SWITCH_SESSIONKEY 0xA
#define KEYSLOT_SWITCH_RNGKEY 0xB
#define KEYSLOT_SWITCH_MASTERKEY 0xC
#define KEYSLOT_SWITCH_DEVICEKEY 0xD

void ghash(void *dst, const void *data, size_t data_size, const void *j_block, bool encrypt);

#endif
