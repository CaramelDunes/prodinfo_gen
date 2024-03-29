/*
* Copyright (c) 2018 naehrwert
* Copyright (c) 2018-2021 CTCaer
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

#ifndef _TYPES_H_
#define _TYPES_H_

#include <assert.h>

#define NULL ((void *)0)

#define ALWAYS_INLINE inline __attribute__((always_inline))

#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))
#define BIT(n) (1U << (n))
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#define DIV_ROUND_UP(a, b) ((a + b - 1) / b)

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))
#define LOG2(n) (32 - __builtin_clz(n) - 1)
#define CLZ(n) __builtin_clz(n)
#define CLO(n) __builtin_clz(~n)

#define OFFSET_OF(t, m) ((u32)&((t *)NULL)->m)
#define CONTAINER_OF(mp, t, mn) ((t *)((u32)mp - OFFSET_OF(t, mn)))

#define COLOR_RED    0xFFE70000
#define COLOR_ORANGE 0xFFFF8C00
#define COLOR_YELLOW 0xFFFFFF40
#define COLOR_GREEN  0xFF40FF00
#define COLOR_BLUE   0xFF00DDFF
#define COLOR_VIOLET 0xFF8040FF

typedef signed char s8;
typedef short s16;
typedef short SHORT;
typedef int s32;
typedef int INT;
typedef long LONG;
typedef long long int s64;
typedef unsigned char u8;
typedef unsigned char BYTE;
typedef unsigned short u16;
typedef unsigned short WORD;
typedef unsigned short WCHAR;
typedef unsigned int u32;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef unsigned long long QWORD;
typedef unsigned long long int u64;
typedef volatile unsigned char vu8;
typedef volatile unsigned short vu16;
typedef volatile unsigned int vu32;

#ifdef __aarch64__
typedef u64 uptr;
#else /* __arm__ or __thumb__ */
typedef u32 uptr;
#endif

static const u32 colors[6] = {COLOR_RED, COLOR_ORANGE, COLOR_YELLOW, COLOR_GREEN, COLOR_BLUE, COLOR_VIOLET};

typedef int bool;
#define true  1
#define false 0

#define DISABLE 0
#define ENABLE  1

#define BOOT_CFG_AUTOBOOT_EN BIT(0)
#define BOOT_CFG_FROM_LAUNCH BIT(1)
#define BOOT_CFG_FROM_ID     BIT(2)
#define BOOT_CFG_TO_EMUMMC   BIT(3)

#define EXTRA_CFG_DUMP_EMUMMC BIT(0)

typedef struct __attribute__((__packed__)) _boot_cfg_t
{
	u8 boot_cfg;
	u8 autoboot;
	u8 autoboot_list;
	u8 extra_cfg;
	union
	{
		struct
		{
			char id[8]; // 7 char ASCII null teminated.
			char emummc_path[0x78]; // emuMMC/XXX, ASCII null teminated.
		};
		u8 ums; // nyx_ums_type.
		u8 xt_str[0x80];
	};
} boot_cfg_t;

static_assert(sizeof(boot_cfg_t) == 0x84, "Boot CFG size is wrong!");

typedef struct __attribute__((__packed__)) _ipl_ver_meta_t
{
	u32 magic;
	u32 version;
	u16 rsvd0;
	u16 rsvd1;
} ipl_ver_meta_t;

typedef struct __attribute__((__packed__)) _reloc_meta_t
{
	u32 start;
	u32 stack;
	u32 end;
	u32 ep;
} reloc_meta_t;

typedef enum
{
	VALIDITY_UNCHECKED = 0,
	VALIDITY_INVALID,
	VALIDITY_VALID
} validity_t;

typedef enum
{
	OPEN_MODE_READ          = 1,
	OPEN_MODE_WRITE         = 2,
	OPEN_MODE_ALLOW_APPEND  = 4,
	OPEN_MODE_READ_WRITE    = OPEN_MODE_READ | OPEN_MODE_WRITE,
	OPEN_MODE_ALL           = OPEN_MODE_READ | OPEN_MODE_WRITE | OPEN_MODE_ALLOW_APPEND
} open_mode_t;

#endif
