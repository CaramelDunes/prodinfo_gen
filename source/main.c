/*
 * Copyright (c) 2018 naehrwert
 *
 * Copyright (c) 2018-2020 CTCaer
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

#include <string.h>

#include "config.h"
#include <gfx/di.h>
#include <gfx_utils.h>
#include "gfx/tui.h"
#include <libs/fatfs/ff.h>
#include <mem/heap.h>
#include <mem/minerva.h>
#include <power/bq24193.h>
#include <power/max17050.h>
#include <power/max77620.h>
#include <rtc/max77620-rtc.h>
#include <soc/bpmp.h>
#include <soc/hw_init.h>
#include "storage/emummc.h"
#include "storage/nx_emmc.h"
#include <storage/nx_sd.h>
#include <storage/sdmmc.h>
#include <utils/btn.h>
#include <utils/dirlist.h>
#include <utils/ini.h>
#include <utils/sprintf.h>
#include <utils/util.h>

#include "cal0/cal0_donor.h"
#include "cal0/cal0_scratch.h"

hekate_config h_cfg;
boot_cfg_t __attribute__((section ("._boot_cfg"))) b_cfg;

volatile nyx_storage_t *nyx_str = (nyx_storage_t *)NYX_STORAGE_ADDR;
sdmmc_storage_t storage;
emmc_part_t *system_part;

// This is a safe and unused DRAM region for our payloads.
#define RELOC_META_OFF      0x7C
#define PATCHED_RELOC_SZ    0x94
#define PATCHED_RELOC_STACK 0x40007000
#define PATCHED_RELOC_ENTRY 0x40010000
#define EXT_PAYLOAD_ADDR    0xC0000000
#define RCM_PAYLOAD_ADDR    (EXT_PAYLOAD_ADDR + ALIGN(PATCHED_RELOC_SZ, 0x10))
#define COREBOOT_END_ADDR   0xD0000000
#define CBFS_DRAM_EN_ADDR   0x4003e000
#define  CBFS_DRAM_MAGIC    0x4452414D // "DRAM"

static void *coreboot_addr;

void reloc_patcher(u32 payload_dst, u32 payload_src, u32 payload_size)
{
	memcpy((u8 *)payload_src, (u8 *)IPL_LOAD_ADDR, PATCHED_RELOC_SZ);

	volatile reloc_meta_t *relocator = (reloc_meta_t *)(payload_src + RELOC_META_OFF);

	relocator->start = payload_dst - ALIGN(PATCHED_RELOC_SZ, 0x10);
	relocator->stack = PATCHED_RELOC_STACK;
	relocator->end   = payload_dst + payload_size;
	relocator->ep    = payload_dst;

	if (payload_size == 0x7000)
	{
		memcpy((u8 *)(payload_src + ALIGN(PATCHED_RELOC_SZ, 0x10)), coreboot_addr, 0x7000); //Bootblock
		*(vu32 *)CBFS_DRAM_EN_ADDR = CBFS_DRAM_MAGIC;
	}
}

int launch_payload(char *path)
{
	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);
	if (!path)
		return 1;

	if (sd_mount())
	{
		FIL fp;
		if (f_open(&fp, path, FA_READ))
		{
			EPRINTFARGS("Payload file is missing!\n(%s)", path);
			sd_unmount();

			return 1;
		}

		// Read and copy the payload to our chosen address
		void *buf;
		u32 size = f_size(&fp);

		if (size < 0x30000)
			buf = (void *)RCM_PAYLOAD_ADDR;
		else
		{
			coreboot_addr = (void *)(COREBOOT_END_ADDR - size);
			buf = coreboot_addr;
		}

		if (f_read(&fp, buf, size, NULL))
		{
			f_close(&fp);
			sd_unmount();

			return 1;
		}

		f_close(&fp);

		sd_unmount();

		if (size < 0x30000)
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, ALIGN(size, 0x10));

			hw_reinit_workaround(false, byte_swap_32(*(u32 *)(buf + size - sizeof(u32))));
		}
		else
		{
			reloc_patcher(PATCHED_RELOC_ENTRY, EXT_PAYLOAD_ADDR, 0x7000);
			hw_reinit_workaround(true, 0);
		}

		// Some cards (Sandisk U1), do not like a fast power cycle. Wait min 100ms.
		sdmmc_storage_init_wait_sd();

		void (*ext_payload_ptr)() = (void *)EXT_PAYLOAD_ADDR;

		// Launch our payload.
		(*ext_payload_ptr)();
	}

	return 1;
}

void launch_tools()
{
	u8 max_entries = 61;
	char *filelist = NULL;
	char *file_sec = NULL;
	char *dir = NULL;

	ment_t *ments = (ment_t *)malloc(sizeof(ment_t) * (max_entries + 3));

	gfx_clear_grey(0x1B);
	gfx_con_setpos(0, 0);

	if (sd_mount())
	{
		dir = (char *)malloc(256);

		memcpy(dir, "sd:/bootloader/payloads", 24);

		filelist = dirlist(dir, NULL, false, false);

		u32 i = 0;
		u32 i_off = 2;

		if (filelist)
		{
			// Build configuration menu.
			u32 color_idx = 0;

			ments[0].type = MENT_BACK;
			ments[0].caption = "Back";
			ments[0].color = colors[(color_idx++) % 6];
			ments[1].type = MENT_CHGLINE;
			ments[1].color = colors[(color_idx++) % 6];
			if (!f_stat("sd:/atmosphere/reboot_payload.bin", NULL))
			{
				ments[i_off].type = INI_CHOICE;
				ments[i_off].caption = "reboot_payload.bin";
				ments[i_off].color = colors[(color_idx++) % 6];
				ments[i_off].data = "sd:/atmosphere/reboot_payload.bin";
				i_off++;
			}
			if (!f_stat("sd:/ReiNX.bin", NULL))
			{
				ments[i_off].type = INI_CHOICE;
				ments[i_off].caption = "ReiNX.bin";
				ments[i_off].color = colors[(color_idx++) % 6];
				ments[i_off].data = "sd:/ReiNX.bin";
				i_off++;
			}

			while (true)
			{
				if (i > max_entries || !filelist[i * 256])
					break;
				ments[i + i_off].type = INI_CHOICE;
				ments[i + i_off].caption = &filelist[i * 256];
				ments[i + i_off].color = colors[(color_idx++) % 6];
				ments[i + i_off].data = &filelist[i * 256];

				i++;
			}
		}

		if (i > 0)
		{
			memset(&ments[i + i_off], 0, sizeof(ment_t));
			menu_t menu = { ments, "Choose a file to launch", 0, 0 };

			file_sec = (char *)tui_do_menu(&menu);

			if (!file_sec)
			{
				free(ments);
				free(dir);
				free(filelist);
				sd_unmount();
				return;
			}
		}
		else
			EPRINTF("No payloads or modules found.");

		free(ments);
		free(filelist);
	}
	else
	{
		free(ments);
		goto out;
	}

	if (file_sec)
	{
		if (memcmp("sd:/", file_sec, 4) != 0)
		{
			memcpy(dir + strlen(dir), "/", 2);
			memcpy(dir + strlen(dir), file_sec, strlen(file_sec) + 1);
		}
		else
			memcpy(dir, file_sec, strlen(file_sec) + 1);

		if (launch_payload(dir))
		{
			EPRINTF("Failed to launch payload.");
			free(dir);
		}
	}

out:
	sd_unmount();
	free(dir);

	btn_wait();
}

ment_t ment_top[] = {
	MDEF_HANDLER("Build PRODINFO file from donor", build_cal0_donor, COLOR_RED),
	MDEF_HANDLER("Build PRODINFO file from scratch", build_cal0_scratch, COLOR_ORANGE),
	MDEF_CAPTION("---------------", COLOR_YELLOW),
	MDEF_HANDLER("Payloads...", launch_tools, COLOR_GREEN),
	MDEF_CAPTION("---------------", COLOR_BLUE),
	MDEF_HANDLER("Reboot (Normal)", reboot_normal, COLOR_VIOLET),
	MDEF_HANDLER("Reboot (RCM)", reboot_rcm, COLOR_RED),
	MDEF_HANDLER("Power off", power_off, COLOR_ORANGE),
	MDEF_END()
};

menu_t menu_top = { ment_top, NULL, 0, 0 };

extern void pivot_stack(u32 stack_top);

void ipl_main()
{
	// Do initial HW configuration. This is compatible with consecutive reruns without a reset.
	hw_init();

	// Pivot the stack so we have enough space.
	pivot_stack(IPL_STACK_TOP);

	// Tegra/Horizon configuration goes to 0x80000000+, package2 goes to 0xA9800000, we place our heap in between.
	heap_init(IPL_HEAP_START);

#ifdef DEBUG_UART_PORT
	uart_send(DEBUG_UART_PORT, (u8 *)"hekate: Hello!\r\n", 16);
	uart_wait_idle(DEBUG_UART_PORT, UART_TX_IDLE);
#endif

	// Set bootloader's default configuration.
	set_default_configuration();

	// Mount SD Card.
	h_cfg.errors |= !sd_mount() ? ERR_SD_BOOT_EN : 0;

	// Train DRAM and switch to max frequency.
	if (minerva_init()) //!TODO: Add Tegra210B01 support to minerva.
		h_cfg.errors |= ERR_LIBSYS_MTC;
	minerva_change_freq(FREQ_1600);

	display_init();

	u32 *fb = display_init_framebuffer_pitch();
	gfx_init_ctxt(fb, 720, 1280, 720);

	gfx_con_init();

	display_backlight_pwm_init();

	// Overclock BPMP.
	bpmp_clk_rate_set(BPMP_CLK_DEFAULT_BOOST);

	// Grey out reboot to RCM option if on Mariko or patched console.
	if (h_cfg.t210b01 || h_cfg.rcm_patched)
	{
		ment_top[6].type = MENT_CAPTION;
		ment_top[6].color = 0xFF555555;
		ment_top[6].handler = NULL;
	}

	if (h_cfg.rcm_patched)
	{
		ment_top[5].handler = reboot_full;
	}

	while (true)
		tui_do_menu(&menu_top);

	// Halt BPMP if we managed to get out of execution.
	while (true)
		bpmp_halt();
}
