/*
   SSSD

   Authors:
        Simo Sorce <ssorce@redhat.com>

   Copyright (C) Red Hat, Inc 2007

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _SHARED_SAFEALIGN_H
#define _SHARED_SAFEALIGN_H

/* CAUTION:
 * This file is also used in sss_client (pam, nss). Therefore it have to be
 * minimalist and cannot include DEBUG macros or header file util.h.
 */

#include <string.h>
#include <stdint.h>

/* Use this macro to suppress alignment warnings (use it
 * only to suppress false-positives) */
#define DISCARD_ALIGN(ptr, type) ((type)(void *)(ptr))

#define IS_ALIGNED(ptr, type) \
    ((uintptr_t)(ptr) % sizeof(type) == 0)

#define PADDING_SIZE(base, type) \
    ((sizeof(type) - ((base) % sizeof(type))) % sizeof(type))

#define SIZE_T_OVERFLOW(current, add) \
                        (((size_t)(add)) > (SIZE_MAX - ((size_t)(current))))

static inline void
safealign_memcpy(void *dest, const void *src, size_t n, size_t *counter)
{
    memcpy(dest, src, n);
    if (counter) {
        *counter += n;
    }
}

#define SAFEALIGN_SETMEM_VALUE(dest, value, type, pctr) do { \
    type CV_MACRO_val = (type)(value); \
    safealign_memcpy(dest, &CV_MACRO_val, sizeof(type), pctr); \
} while(0)

/* SAFEALIGN_COPY_INT64(void *dest, void *src, size_t *pctr)
 * This macro will safely copy sizeof(int64_t) bytes from memory
 * location pointed by 'src' to memory location pointed by 'dest'.
 * If the 'pctr' pointer is not NULL, the value it points to will
 * be incremented by sizeof(int64_t). */
#define SAFEALIGN_COPY_INT64(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int64_t), pctr)

/* SAFEALIGN_SETMEM_INT64(void *dest, int64_t value, size_t *pctr)
 * This macro will safely assign an int64_t value to the memory
 * location pointed by 'dest'. If the 'pctr' pointer is not NULL,
 * the value it points to will be incremented by sizeof(int64_t). */
#define SAFEALIGN_SETMEM_INT64(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, int64_t, pctr)

/* SAFEALIGN_COPY_UINT32(void *dest, void *src, size_t *pctr) */
#define SAFEALIGN_COPY_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)

/* SAFEALIGN_SETMEM_UINT32(void *dest, uint32_t value, size_t *pctr) */
#define SAFEALIGN_SETMEM_UINT32(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, uint32_t, pctr)

/* SAFEALIGN_COPY_INT32(void *dest, void *src, size_t *pctr) */
#define SAFEALIGN_COPY_INT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr)

/* SAFEALIGN_SETMEM_INT32(void *dest, int32_t value, size_t *pctr) */
#define SAFEALIGN_SETMEM_INT32(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, int32_t, pctr)

/* SAFEALIGN_COPY_UINT16(void *dest, void *src, size_t *pctr) */
#define SAFEALIGN_COPY_UINT16(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr)

/* SAFEALIGN_SETMEM_UINT16(void *dest, uint16_t value, size_t *pctr) */
#define SAFEALIGN_SETMEM_UINT16(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, uint16_t, pctr)

/* SAFEALIGN_SETMEM_UINT8(void *dest, uint8_t value, size_t *pctr) */
#define SAFEALIGN_SETMEM_UINT8(dest, value, pctr) \
    SAFEALIGN_SETMEM_VALUE(dest, value, uint8_t, pctr)

/* These macros are the same as their equivalents without _CHECK suffix,
 * but additionally make the caller return EINVAL immediately if *pctr
 * would exceed len. */
#define SAFEALIGN_COPY_UINT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint32_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr); \
} while(0)

#define SAFEALIGN_COPY_INT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(int32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(int32_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr); \
} while(0)

#define SAFEALIGN_COPY_UINT16_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint16_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint16_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr); \
} while(0)

#define SAFEALIGN_SETMEM_STRING(dest, value, length, pctr) do { \
    const char *CV_MACRO_val = (const char *)(value); \
    safealign_memcpy(dest, CV_MACRO_val, sizeof(char) * length, pctr); \
} while(0)

#define SAFEALIGN_MEMCPY_CHECK(dest, src, srclen, len, pctr) do { \
    if ((*(pctr) + srclen) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), srclen)) { return EINVAL; } \
    safealign_memcpy(dest, src, srclen, pctr); \
} while(0)

#define SAFEALIGN_COPY_UINT8_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint8_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint8_t))) { return EINVAL; } \
    safealign_memcpy(dest, src, sizeof(uint8_t), pctr); \
} while(0)

/* Aliases for backward compatibility. */
#define SAFEALIGN_SET_VALUE SAFEALIGN_SETMEM_VALUE
#define SAFEALIGN_SET_INT64 SAFEALIGN_SETMEM_INT64
#define SAFEALIGN_SET_UINT32 SAFEALIGN_SETMEM_UINT32
#define SAFEALIGN_SET_INT32 SAFEALIGN_SETMEM_INT32
#define SAFEALIGN_SET_UINT16 SAFEALIGN_SETMEM_UINT16
#define SAFEALIGN_SET_STRING SAFEALIGN_SETMEM_STRING

#endif /* _SHARED_SAFEALIGN_H */
