/*
   SSSD

   Mmap Cache Common header

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2011

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _MMAP_CACHE_H_
#define _MMAP_CACHE_H_

#include "shared/murmurhash3.h"


/* NOTE: all the code here assumes that writing a uint32_t nto mmapped
 * memory is an atomic operation and can't be split in multiple
 * non-atomic operations */
typedef uint32_t rel_ptr_t;

/* align macros */
#define MC_8 sizeof(uint8_t)
#define MC_32 sizeof(uint32_t)
#define MC_64 sizeof(uint64_t)
#define MC_ALIGN32(size) ( ((size) + MC_32 -1) & (~(MC_32 -1)) )
#define MC_ALIGN64(size) ( ((size) + MC_64 -1) & (~(MC_64 -1)) )
#define MC_HEADER_SIZE MC_ALIGN64(sizeof(struct sss_mc_header))

#define MC_HT_SIZE(elems) ( (elems) * MC_32 )
#define MC_HT_ELEMS(size) ( (size) / MC_32 )

#define MC_PTR_ADD(ptr, bytes) (void *)((uint8_t *)(ptr) + (bytes))
#define MC_PTR_DIFF(ptr, base) ((uint8_t *)(ptr) - (uint8_t *)(base))

#define MC_INVALID_VAL64 ((uint64_t)-1)
#define MC_INVALID_VAL32 ((uint32_t)-1)
#define MC_INVALID_VAL8 ((uint8_t)-1)
#define MC_INVALID_VAL MC_INVALID_VAL32

/*
 * 40 seem a good compromise for slot size
 * 4 blocks are enough for the average passwd entry of 42 bytes
 * passwd records have 84 bytes of overhead, 160 - 82 = 78 bytes
 * 3 blocks can contain a very minimal entry, 120 - 82 = 38 bytes
 *
 * 3 blocks are enough for groups w/o users (private user groups)
 * group records have 68 bytes of overhead, 120 - 66 = 54 bytes
 */
#define MC_SLOT_SIZE 40
#define MC_SIZE_TO_SLOTS(len) (((len) + (MC_SLOT_SIZE - 1)) / MC_SLOT_SIZE)
#define MC_PTR_TO_SLOT(base, ptr) (MC_PTR_DIFF(ptr, base) / MC_SLOT_SIZE)
#define MC_SLOT_TO_PTR(base, slot, type) \
                                (type *)((base) + ((slot) * MC_SLOT_SIZE))

#define MC_SLOT_WITHIN_BOUNDS(slot, dt_size) \
    ((slot) < ((dt_size) / MC_SLOT_SIZE))

#define MC_VALID_BARRIER(val) (((val) & 0xff000000) == 0xf0000000)

#define MC_CHECK_RECORD_LENGTH(mc_ctx, rec) \
        ((rec)->len >= MC_HEADER_SIZE && (rec)->len != MC_INVALID_VAL32 \
         && ((rec)->len <= ((mc_ctx)->dt_size \
                            - MC_PTR_DIFF(rec, (mc_ctx)->data_table))))


#define SSS_MC_MAJOR_VNO    1
#define SSS_MC_MINOR_VNO    1

#define SSS_MC_HEADER_UNINIT    0   /* after ftruncate or before reset */
#define SSS_MC_HEADER_ALIVE     1   /* current and in use */
#define SSS_MC_HEADER_RECYCLED  2   /* file was recycled, reopen asap */

#pragma pack(1)
struct sss_mc_header {
    uint32_t b1;            /* barrier 1 */
    uint32_t major_vno;     /* major version number */
    uint32_t minor_vno;     /* minor version number */
    uint32_t status;        /* database status */
    uint32_t seed;          /* random seed used to avoid collision attacks */
    uint32_t dt_size;       /* data table size */
    uint32_t ft_size;       /* free table size */
    uint32_t ht_size;       /* hash table size */
    rel_ptr_t data_table;   /* data table pointer relative to mmap base */
    rel_ptr_t free_table;   /* free table pointer relative to mmap base */
    rel_ptr_t hash_table;   /* hash table pointer relative to mmap base */
    rel_ptr_t reserved;     /* reserved for future changes */
    uint32_t b2;            /* barrier 2 */
};

struct sss_mc_rec {
    uint32_t b1;            /* barrier 1 */
    uint32_t len;           /* total record length including record data */
    uint64_t expire;        /* record expiration time (cast to time_t) */
    rel_ptr_t next1;        /* ptr of next record rel to data_table */
                            /* next1 is related to hash1 */
    rel_ptr_t next2;        /* ptr of next record rel to data_table */
                            /* next2 is related to hash2 */
    uint32_t hash1;         /* val of first hash (usually name of record) */
    uint32_t hash2;         /* val of second hash (usually id of record) */
    uint32_t padding;       /* padding & reserved for future changes */
    uint32_t b2;            /* barrier 2 - 32 bytes mark, fits a slot */
    char data[0];
};

struct sss_mc_pwd_data {
    rel_ptr_t name;         /* ptr to name string, rel. to struct base addr */
    uint32_t uid;
    uint32_t gid;
    uint32_t strs_len;      /* length of strs */
    char strs[0];           /* concatenation of all passwd strings, each
                             * string is zero terminated ordered as follows:
                             * name, passwd, gecos, dir, shell */
};

struct sss_mc_grp_data {
    rel_ptr_t name;         /* ptr to name string, rel. to struct base addr */
    uint32_t gid;
    uint32_t members;       /* number of members in strs */
    uint32_t strs_len;      /* length of strs */
    char strs[0];           /* concatenation of all group strings, each
                             * string is zero terminated ordered as follows:
                             * name, passwd, member1, member2, ... */
};

struct sss_mc_initgr_data {
    rel_ptr_t unique_name;  /* ptr to unique name string, rel. to struct base addr */
    rel_ptr_t name;         /* ptr to raw name string, rel. to struct base addr */
    rel_ptr_t strs;         /* ptr to concatenation of all strings */
    uint32_t strs_len;      /* length of strs */
    uint32_t data_len;      /* all initgroups data len */
    uint32_t num_groups;    /* number of groups */
    uint32_t gids[0];       /* array of all groups
                             * string with name and unique_name is stored
                             * after gids */
};

struct sss_mc_sid_data {
    rel_ptr_t name;         /* ptr to SID string, rel. to struct base addr */
    uint32_t type;          /* enum sss_id_type */
    uint32_t id;            /* gid or uid */
    uint32_t populated_by;  /* 0 - by_id(), 1 - by_uid/gid() lookup */
    uint32_t sid_len;       /* length of sid */
    char sid[0];
};

#pragma pack()


#endif /* _MMAP_CACHE_H_ */
