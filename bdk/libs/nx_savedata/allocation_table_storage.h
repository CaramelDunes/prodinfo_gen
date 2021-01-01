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

/*
ISC License

hactool Copyright (c) 2018, SciresM

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#ifndef _ALLOCATION_TABLE_STORAGE_H_
#define _ALLOCATION_TABLE_STORAGE_H_

#include "allocation_table.h"
#include "storage.h"

#include <stdint.h>

typedef struct {
    substorage *base_storage;
    uint32_t block_size;
    uint32_t initial_block;
    allocation_table_ctx_t *fat;
    uint64_t _length;
} allocation_table_storage_ctx_t;

static ALWAYS_INLINE void save_allocation_table_storage_get_size(allocation_table_storage_ctx_t *ctx, uint64_t *out_size) {
    *out_size = ctx->_length;
}

bool save_allocation_table_storage_init(allocation_table_storage_ctx_t *ctx, substorage *data, allocation_table_ctx_t *table, uint32_t block_size, uint32_t initial_block);
uint32_t save_allocation_table_storage_read(allocation_table_storage_ctx_t *ctx, void *buffer, uint64_t offset, uint64_t count);
uint32_t save_allocation_table_storage_write(allocation_table_storage_ctx_t *ctx, const void *buffer, uint64_t offset, uint64_t count);
bool save_allocation_table_storage_set_size(allocation_table_storage_ctx_t *ctx, uint64_t size);

#endif
