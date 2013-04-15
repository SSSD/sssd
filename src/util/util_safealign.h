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

/* CAUTION:
 * This file is also used in sss_client (pam, nss). Therefore it has to be
 * minimalist and cannot include DEBUG macros or header file util.h.
 */


#ifndef _UTIL_SAFEALIGN_H
#define _UTIL_SAFEALIGN_H

#include <string.h>

#define SIZE_T_MAX ((size_t) -1)

#define SIZE_T_OVERFLOW(current, add) \
                        (((size_t)(add)) > (SIZE_T_MAX - ((size_t)(current))))

static inline void
safealign_memcpy(void *dest, const void *src, size_t n, size_t *counter)
{
    memcpy(dest, src, n);
    if (counter) {
        *counter += n;
    }
}

#define SAFEALIGN_VAR2BUF(dest, value, type, pctr) do { \
    type CV_MACRO_val = (type)(value); \
    safealign_memcpy(dest, &CV_MACRO_val, sizeof(type), pctr); \
} while(0)

#define SAFEALIGN_BUF2VAR_INT64(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int64_t), pctr)

#define SAFEALIGN_VAR2BUF_INT64(dest, value, pctr) \
    SAFEALIGN_VAR2BUF(dest, value, int64_t, pctr)

#define SAFEALIGN_BUF2VAR_UINT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr)

#define SAFEALIGN_VAR2BUF_UINT32(dest, value, pctr) \
    SAFEALIGN_VAR2BUF(dest, value, uint32_t, pctr)

#define SAFEALIGN_BUF2VAR_INT32(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr)

#define SAFEALIGN_VAR2BUF_INT32(dest, value, pctr) \
    SAFEALIGN_VAR2BUF(dest, value, int32_t, pctr)

#define SAFEALIGN_BUF2VAR_UINT16(dest, src, pctr) \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr)

#define SAFEALIGN_VAR2BUF_UINT16(dest, value, pctr) \
    SAFEALIGN_VAR2BUF(dest, value, uint16_t, pctr)

#define SAFEALIGN_BUF2VAR_UINT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint32_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(uint32_t), pctr); \
} while(0)

#define SAFEALIGN_BUF2VAR_INT32_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(int32_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(int32_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(int32_t), pctr); \
} while(0)

#define SAFEALIGN_BUF2VAR_UINT16_CHECK(dest, src, len, pctr) do { \
    if ((*(pctr) + sizeof(uint16_t)) > (len) || \
        SIZE_T_OVERFLOW(*(pctr), sizeof(uint16_t))) return EINVAL; \
    safealign_memcpy(dest, src, sizeof(uint16_t), pctr); \
} while(0)


/* Do not use these aliases in new code. Use the macros above instead. */
#define SAFEALIGN_SET_VALUE         SAFEALIGN_VAR2BUF
#define SAFEALIGN_COPY_INT64        SAFEALIGN_BUF2VAR_INT64
#define SAFEALIGN_SET_INT64         SAFEALIGN_VAR2BUF_INT64
#define SAFEALIGN_COPY_UINT32       SAFEALIGN_BUF2VAR_UINT32
#define SAFEALIGN_SET_UINT32        SAFEALIGN_VAR2BUF_UINT32
#define SAFEALIGN_COPY_INT32        SAFEALIGN_BUF2VAR_INT32
#define SAFEALIGN_SET_INT32         SAFEALIGN_VAR2BUF_INT32
#define SAFEALIGN_COPY_UINT16       SAFEALIGN_BUF2VAR_UINT16
#define SAFEALIGN_SET_UINT16        SAFEALIGN_VAR2BUF_UINT16
#define SAFEALIGN_COPY_UINT32_CHECK SAFEALIGN_BUF2VAR_UINT32_CHECK
#define SAFEALIGN_COPY_INT32_CHECK  SAFEALIGN_BUF2VAR_INT32_CHECK
#define SAFEALIGN_COPY_UINT16_CHECK SAFEALIGN_BUF2VAR_UINT16_CHECK

#endif /* _UTIL_SAFEALIGN_H */
