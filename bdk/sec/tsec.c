/*
 * Copyright (c) 2018 naehrwert
 * Copyright (c) 2018-2021 CTCaer
 * Copyright (c) 2018 balika011
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

#include "tsec.h"
#include "tsec_t210.h"
#include <sec/se_t210.h>
#include <soc/bpmp.h>
#include <soc/clock.h>
#include <soc/kfuse.h>
#include <soc/t210.h>
#include <mem/heap.h>
#include <mem/mc.h>
#include <mem/smmu.h>
#include <utils/util.h>

// #include <gfx_utils.h>

#define PKG11_MAGIC 0x31314B50
#define KB_TSEC_FW_EMU_COMPAT 6 // KB ID for HOS 6.2.0.

static int _tsec_dma_wait_idle()
{
	u32 timeout = get_tmr_ms() + 10000;

	while (!(TSEC(TSEC_DMATRFCMD) & TSEC_DMATRFCMD_IDLE))
		if (get_tmr_ms() > timeout)
			return 0;

	return 1;
}

static int _tsec_dma_pa_to_internal_100(int not_imem, int i_offset, int pa_offset)
{
	u32 cmd;

	if (not_imem)
		cmd = TSEC_DMATRFCMD_SIZE_256B; // DMA 256 bytes
	else
		cmd = TSEC_DMATRFCMD_IMEM;      // DMA IMEM (Instruction memmory)

	TSEC(TSEC_DMATRFMOFFS) = i_offset;
	TSEC(TSEC_DMATRFFBOFFS) = pa_offset;
	TSEC(TSEC_DMATRFCMD) = cmd;

	return _tsec_dma_wait_idle();
}

int tsec_query(u8 *tsec_keys, u8 kb, tsec_ctxt_t *tsec_ctxt)
{
	int res = 0;
	u8 *fwbuf = NULL;

	bpmp_mmu_disable();
	bpmp_freq_t prev_fid = bpmp_clk_rate_set(BPMP_CLK_NORMAL);

	// Enable clocks.
	clock_enable_host1x();
	usleep(2);
	clock_enable_tsec();
	clock_enable_sor_safe();
	clock_enable_sor0();
	clock_enable_sor1();
	clock_enable_kfuse();

	kfuse_wait_ready();

	//Configure Falcon.
	TSEC(TSEC_DMACTL) = 0;
	TSEC(TSEC_IRQMSET) =
		TSEC_IRQMSET_EXT(0xFF) |
		TSEC_IRQMSET_WDTMR |
		TSEC_IRQMSET_HALT |
		TSEC_IRQMSET_EXTERR |
		TSEC_IRQMSET_SWGEN0 |
		TSEC_IRQMSET_SWGEN1;
	TSEC(TSEC_IRQDEST) =
		TSEC_IRQDEST_EXT(0xFF) |
		TSEC_IRQDEST_HALT |
		TSEC_IRQDEST_EXTERR |
		TSEC_IRQDEST_SWGEN0 |
		TSEC_IRQDEST_SWGEN1;
	TSEC(TSEC_ITFEN) = TSEC_ITFEN_CTXEN | TSEC_ITFEN_MTHDEN;
	if (!_tsec_dma_wait_idle())
	{
		res = -1;
		goto out;
	}

	//Load firmware or emulate memio environment for newer TSEC fw.
	if (kb == KB_TSEC_FW_EMU_COMPAT)
		TSEC(TSEC_DMATRFBASE) = (u32)tsec_ctxt->fw >> 8;
	else
	{
		fwbuf = (u8 *)malloc(0x4000);
		u8 *fwbuf_aligned = (u8 *)ALIGN((u32)fwbuf, 0x100);
		memcpy(fwbuf_aligned, tsec_ctxt->fw, tsec_ctxt->size);
		TSEC(TSEC_DMATRFBASE) = (u32)fwbuf_aligned >> 8;
	}

	for (u32 addr = 0; addr < tsec_ctxt->size; addr += 0x100)
	{
		if (!_tsec_dma_pa_to_internal_100(false, addr, addr))
		{
			res = -2;
			goto out_free;
		}
	}

	//Execute firmware.
	HOST1X(HOST1X_CH0_SYNC_SYNCPT_160) = 0x34C2E1DA;
	TSEC(TSEC_STATUS) = 0;
	TSEC(TSEC_BOOTKEYVER) = 1; // HOS uses key version 1.
	TSEC(TSEC_BOOTVEC) = 0;
	TSEC(TSEC_CPUCTL) = TSEC_CPUCTL_STARTCPU;

	if (!_tsec_dma_wait_idle())
	{
		res = -3;
		goto out_free;
	}
	u32 timeout = get_tmr_ms() + 4000;
	while (!(TSEC(TSEC_CPUCTL) & TSEC_CPUCTL_KEYGEN_DONE))
		if (get_tmr_ms() > timeout)
		{
			res = -4;
			goto out_free;
		}
	if (TSEC(TSEC_STATUS) != 0xB0B0B0B0)
	{
		res = -5;
		goto out_free;
	}

	//Fetch result.
	HOST1X(HOST1X_CH0_SYNC_SYNCPT_160) = 0;

out_free:;
	free(fwbuf);

out:;

	//Disable clocks.
	clock_disable_kfuse();
	clock_disable_sor1();
	clock_disable_sor0();
	clock_disable_sor_safe();
	clock_disable_tsec();
	bpmp_mmu_enable();
	bpmp_clk_rate_set(prev_fid);

	return res;
}

int tsec_run_fw(tsec_ctxt_t *tsec_ctxt)
{
	/* Ensure that the ahb redirect is enabled. */
	mc_enable_ahb_redirect();

	/* Get bom/tom */
	u32 bom = MC(MC_IRAM_BOM);
	u32 tom = MC(MC_IRAM_TOM);

	/* Override the ahb redirect extents. */
	MC(MC_IRAM_BOM) = 0x40000000;
	MC(MC_IRAM_TOM) = 0x80000000;

	/* Run the fw. */
	int res = tsec_query(NULL, 0, tsec_ctxt);

	/* Reset the ahb redirect extents. */
	MC(MC_IRAM_BOM) = bom;
	MC(MC_IRAM_TOM) = tom;

	return res;
}
