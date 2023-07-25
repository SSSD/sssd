/*
    SSSD

    ad_gpo_ndr.c

    Authors:
    Yassir Elley <yelley@redhat.com>

    Copyright (C) 2014 Red Hat

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

/*
 * This file contains a copy of samba's ndr_pull_* functions needed
 * to parse a security_descriptor. We are copying them here so that we don't
 * have to link against libsamba-security, which is a private samba library
 * These functions are taken from:
 *  librpc/ndr/gen_ndr/ndr_security.c
 *  librpc/ndr/ndr_misc.c
 *  librpc/ndr/ndr_sec_helper.c
 */

#include "util/util.h"
#include <ndr.h>
#include <gen_ndr/security.h>

static enum ndr_err_code
ndr_pull_GUID(struct ndr_pull *ndr,
              int ndr_flags,
              struct GUID *r)
{
    uint32_t size_clock_seq_0 = 0;
    uint32_t size_node_0 = 0;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->time_low));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_mid));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->time_hi_and_version));
        size_clock_seq_0 = 2;
        NDR_CHECK(ndr_pull_array_uint8(ndr,
                                       NDR_SCALARS,
                                       r->clock_seq,
                                       size_clock_seq_0));
        size_node_0 = 6;
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->node, size_node_0));
        NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
    }

    return NDR_ERR_SUCCESS;
}

static enum ndr_err_code
ndr_pull_security_ace_flags(struct ndr_pull *ndr,
                            int ndr_flags,
                            uint8_t *r)
{
    uint8_t v;
    NDR_CHECK(ndr_pull_uint8(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_ace_type(struct ndr_pull *ndr,
                           int ndr_flags,
                           enum security_ace_type *r)
{
    uint8_t v;
    NDR_CHECK(ndr_pull_enum_uint8(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_ace_object_flags(struct ndr_pull *ndr,
                                   int ndr_flags,
                                   uint32_t *r)
{
    uint32_t v;
    NDR_CHECK(ndr_pull_uint32(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_ace_object_type(struct ndr_pull *ndr,
                                  int ndr_flags,
                                  union security_ace_object_type *r)
{
    uint32_t level;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        /* This token is not used again (except perhaps below in the NDR_BUFFERS case) */
#ifdef SMB_HAS_NEW_NDR_PULL_STEAL_SWITCH
        NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));
#else
        level = ndr_pull_steal_switch_value(ndr, r);
#endif
        NDR_CHECK(ndr_pull_union_align(ndr, 4));
        switch (level) {
        case SEC_ACE_OBJECT_TYPE_PRESENT: {
            NDR_CHECK(ndr_pull_GUID(ndr, NDR_SCALARS, &r->type));
            break; }
        default: {
            break; }
        }
    }
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_ace_object_inherited_type(struct ndr_pull *ndr,
                                            int ndr_flags,
                                            union security_ace_object_inherited_type *r)
{
    uint32_t level;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        /* This token is not used again (except perhaps below in the NDR_BUFFERS case) */
#ifdef SMB_HAS_NEW_NDR_PULL_STEAL_SWITCH
        NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));
#else
        level = ndr_pull_steal_switch_value(ndr, r);
#endif
        NDR_CHECK(ndr_pull_union_align(ndr, 4));
        switch (level) {
        case SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT: {
            NDR_CHECK(ndr_pull_GUID(ndr,
                                    NDR_SCALARS,
                                    &r->inherited_type));
            break; }
        default: {
            break; }
        }
    }
    return NDR_ERR_SUCCESS;
}

static enum ndr_err_code
ndr_pull_security_ace_object(struct ndr_pull *ndr,
                             int ndr_flags,
                             struct security_ace_object *r)
{
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_security_ace_object_flags
                  (ndr, NDR_SCALARS, &r->flags));
        NDR_CHECK(ndr_pull_set_switch_value
                  (ndr, &r->type, r->flags & SEC_ACE_OBJECT_TYPE_PRESENT));
        NDR_CHECK(ndr_pull_security_ace_object_type
                  (ndr, NDR_SCALARS, &r->type));
        NDR_CHECK(ndr_pull_set_switch_value
                  (ndr,
                   &r->inherited_type,
                   r->flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT));
        NDR_CHECK(ndr_pull_security_ace_object_inherited_type
                  (ndr, NDR_SCALARS, &r->inherited_type));
        NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
    }
    if (ndr_flags & NDR_BUFFERS) {
        NDR_CHECK(ndr_pull_set_switch_value
                  (ndr,
                   &r->type,
                   r->flags & SEC_ACE_OBJECT_TYPE_PRESENT));
        NDR_CHECK(ndr_pull_security_ace_object_type
                  (ndr, NDR_BUFFERS, &r->type));
        NDR_CHECK(ndr_pull_set_switch_value
                  (ndr,
                   &r->inherited_type,
                   r->flags & SEC_ACE_INHERITED_OBJECT_TYPE_PRESENT));
        NDR_CHECK(ndr_pull_security_ace_object_inherited_type
                  (ndr, NDR_BUFFERS, &r->inherited_type));
    }
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_ace_object_ctr(struct ndr_pull *ndr,
                                 int ndr_flags,
                                 union security_ace_object_ctr *r)
{
    uint32_t level = 0;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        /* This token is not used again (except perhaps below in the NDR_BUFFERS case) */
#ifdef SMB_HAS_NEW_NDR_PULL_STEAL_SWITCH
        NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));
#else
        level = ndr_pull_steal_switch_value(ndr, r);
#endif
        NDR_CHECK(ndr_pull_union_align(ndr, 4));
        switch (level) {
        case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT: {
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_SCALARS, &r->object));
            break; }
        case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT: {
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_SCALARS, &r->object));
            break; }
        case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT: {
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_SCALARS, &r->object));
            break; }
        case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT: {
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_SCALARS, &r->object));
            break; }
        default: {
            break; }
        }
    }
    if (ndr_flags & NDR_BUFFERS) {
        if (!(ndr_flags & NDR_SCALARS)) {
            /* We didn't get it above, and the token is not needed after this. */
#ifdef SMB_HAS_NEW_NDR_PULL_STEAL_SWITCH
            NDR_CHECK(ndr_pull_steal_switch_value(ndr, r, &level));
#else
            level = ndr_pull_steal_switch_value(ndr, r);
#endif
        }
        switch (level) {
        case SEC_ACE_TYPE_ACCESS_ALLOWED_OBJECT:
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_BUFFERS, &r->object));
            break;
        case SEC_ACE_TYPE_ACCESS_DENIED_OBJECT:
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_BUFFERS, &r->object));
            break;
        case SEC_ACE_TYPE_SYSTEM_AUDIT_OBJECT:
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_BUFFERS, &r->object));
            break;
        case SEC_ACE_TYPE_SYSTEM_ALARM_OBJECT:
            NDR_CHECK(ndr_pull_security_ace_object
                      (ndr, NDR_BUFFERS, &r->object));
            break;
        default:
            break;
        }
    }
    return NDR_ERR_SUCCESS;
}

enum ndr_err_code
ndr_pull_dom_sid(struct ndr_pull *ndr,
                 int ndr_flags,
                 struct dom_sid *r)
{
    uint32_t cntr_sub_auths_0;
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_uint8(ndr, NDR_SCALARS, &r->sid_rev_num));
        NDR_CHECK(ndr_pull_int8(ndr, NDR_SCALARS, &r->num_auths));
        if (r->num_auths < 0 || r->num_auths > N_ELEMENTS(r->sub_auths)) {
            return ndr_pull_error(ndr, NDR_ERR_RANGE, "value out of range");
        }
        NDR_CHECK(ndr_pull_array_uint8(ndr, NDR_SCALARS, r->id_auth, 6));
        memset(&r->sub_auths, 0, sizeof(r->sub_auths));
        for (cntr_sub_auths_0 = 0;
             cntr_sub_auths_0 < r->num_auths;
             cntr_sub_auths_0++) {
            NDR_CHECK(ndr_pull_uint32
                      (ndr, NDR_SCALARS, &r->sub_auths[cntr_sub_auths_0]));
        }
    }
    return NDR_ERR_SUCCESS;
}

static enum ndr_err_code
ndr_pull_security_ace(struct ndr_pull *ndr,
                      int ndr_flags,
                      struct security_ace *r)
{
    if (ndr_flags & NDR_SCALARS) {
        uint32_t start_ofs = ndr->offset;
        uint32_t size = 0;
        uint32_t pad = 0;
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_security_ace_type(ndr, NDR_SCALARS, &r->type));
        NDR_CHECK(ndr_pull_security_ace_flags(ndr, NDR_SCALARS, &r->flags));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->access_mask));
        NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->object, r->type));
        NDR_CHECK(ndr_pull_security_ace_object_ctr
                  (ndr, NDR_SCALARS, &r->object));
        NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, &r->trustee));
        size = ndr->offset - start_ofs;
        if (r->size < size) {
            return ndr_pull_error(ndr, NDR_ERR_BUFSIZE,
                                  "ndr_pull_security_ace: r->size %u < size %u",
                                  (unsigned)r->size, size);
        }
        pad = r->size - size;
        NDR_PULL_NEED_BYTES(ndr, pad);
        ndr->offset += pad;
    }
    if (ndr_flags & NDR_BUFFERS) {
        NDR_CHECK(ndr_pull_set_switch_value(ndr, &r->object, r->type));
        NDR_CHECK(ndr_pull_security_ace_object_ctr
                  (ndr, NDR_BUFFERS, &r->object));
    }
    return NDR_ERR_SUCCESS;
}

static enum ndr_err_code
ndr_pull_security_acl_revision(struct ndr_pull *ndr,
                               int ndr_flags,
                               enum security_acl_revision *r)
{
    uint16_t v;
    NDR_CHECK(ndr_pull_enum_uint1632(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_acl(struct ndr_pull *ndr,
                      int ndr_flags,
                      struct security_acl *r)
{
    uint32_t size_aces_0 = 0;
    uint32_t cntr_aces_0;
    TALLOC_CTX *_mem_save_aces_0;
    NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
    if (ndr_flags & NDR_SCALARS) {
        NDR_CHECK(ndr_pull_align(ndr, 4));
        NDR_CHECK(ndr_pull_security_acl_revision
                  (ndr, NDR_SCALARS, &r->revision));
        NDR_CHECK(ndr_pull_uint16(ndr, NDR_SCALARS, &r->size));
        NDR_CHECK(ndr_pull_uint32(ndr, NDR_SCALARS, &r->num_aces));
        if (r->num_aces > 2000) {
            return ndr_pull_error(ndr, NDR_ERR_RANGE, "value out of range");
        }
        size_aces_0 = r->num_aces;
        NDR_PULL_ALLOC_N(ndr, r->aces, size_aces_0);
        _mem_save_aces_0 = NDR_PULL_GET_MEM_CTX(ndr);
        NDR_PULL_SET_MEM_CTX(ndr, r->aces, 0);
        for (cntr_aces_0 = 0; cntr_aces_0 < size_aces_0; cntr_aces_0++) {
            NDR_CHECK(ndr_pull_security_ace
                      (ndr, NDR_SCALARS, &r->aces[cntr_aces_0]));
        }
        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_aces_0, 0);
        NDR_CHECK(ndr_pull_trailer_align(ndr, 4));
    }
    if (ndr_flags & NDR_BUFFERS) {
        size_aces_0 = r->num_aces;
        _mem_save_aces_0 = NDR_PULL_GET_MEM_CTX(ndr);
        NDR_PULL_SET_MEM_CTX(ndr, r->aces, 0);
        for (cntr_aces_0 = 0; cntr_aces_0 < size_aces_0; cntr_aces_0++) {
            NDR_CHECK(ndr_pull_security_ace
                      (ndr, NDR_BUFFERS, &r->aces[cntr_aces_0]));
        }
        NDR_PULL_SET_MEM_CTX(ndr, _mem_save_aces_0, 0);
    }
    return NDR_ERR_SUCCESS;
}


static enum ndr_err_code
ndr_pull_security_descriptor_revision(struct ndr_pull *ndr,
                                      int ndr_flags,
                                      enum security_descriptor_revision *r)
{
    uint8_t v;
    NDR_CHECK(ndr_pull_enum_uint8(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}



static enum ndr_err_code
ndr_pull_security_descriptor_type(struct ndr_pull *ndr,
                                  int ndr_flags,
                                  uint16_t *r)
{
    uint16_t v;
    NDR_CHECK(ndr_pull_uint16(ndr, ndr_flags, &v));
    *r = v;
    return NDR_ERR_SUCCESS;
}


enum ndr_err_code
ad_gpo_ndr_pull_security_descriptor(struct ndr_pull *ndr,
                                    int ndr_flags,
                                    struct security_descriptor *r)
{
    uint32_t _ptr_owner_sid;
    TALLOC_CTX *_mem_save_owner_sid_0;
    uint32_t _ptr_group_sid;
    TALLOC_CTX *_mem_save_group_sid_0;
    uint32_t _ptr_sacl;
    TALLOC_CTX *_mem_save_sacl_0;
    uint32_t _ptr_dacl;
    TALLOC_CTX *_mem_save_dacl_0;
    {
        uint32_t _flags_save_STRUCT = ndr->flags;
        ndr_set_flags(&ndr->flags, LIBNDR_FLAG_LITTLE_ENDIAN);
        NDR_PULL_CHECK_FLAGS(ndr, ndr_flags);
        if (ndr_flags & NDR_SCALARS) {
            NDR_CHECK(ndr_pull_align(ndr, 5));
            NDR_CHECK(ndr_pull_security_descriptor_revision(ndr,
                                                            NDR_SCALARS,
                                                            &r->revision));
            NDR_CHECK(ndr_pull_security_descriptor_type(ndr,
                                                        NDR_SCALARS,
                                                        &r->type));
            NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_owner_sid));
            if (_ptr_owner_sid) {
                NDR_PULL_ALLOC(ndr, r->owner_sid);
                NDR_CHECK(ndr_pull_relative_ptr1(ndr,
                                                 r->owner_sid,
                                                 _ptr_owner_sid));
            } else {
                r->owner_sid = NULL;
            }
            NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_group_sid));
            if (_ptr_group_sid) {
                NDR_PULL_ALLOC(ndr, r->group_sid);
                NDR_CHECK(ndr_pull_relative_ptr1(ndr,
                                                 r->group_sid,
                                                 _ptr_group_sid));
            } else {
                r->group_sid = NULL;
            }
            NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_sacl));
            if (_ptr_sacl) {
                NDR_PULL_ALLOC(ndr, r->sacl);
                NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->sacl, _ptr_sacl));
            } else {
                r->sacl = NULL;
            }
            NDR_CHECK(ndr_pull_generic_ptr(ndr, &_ptr_dacl));
            if (_ptr_dacl) {
                NDR_PULL_ALLOC(ndr, r->dacl);
                NDR_CHECK(ndr_pull_relative_ptr1(ndr, r->dacl, _ptr_dacl));
            } else {
                r->dacl = NULL;
            }
            NDR_CHECK(ndr_pull_trailer_align(ndr, 5));
        }
        if (ndr_flags & NDR_BUFFERS) {
            if (r->owner_sid) {
                uint32_t _relative_save_offset;
                _relative_save_offset = ndr->offset;
                NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->owner_sid));
                _mem_save_owner_sid_0 = NDR_PULL_GET_MEM_CTX(ndr);
                NDR_PULL_SET_MEM_CTX(ndr, r->owner_sid, 0);
                NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, r->owner_sid));
                NDR_PULL_SET_MEM_CTX(ndr, _mem_save_owner_sid_0, 0);
                if (ndr->offset > ndr->relative_highest_offset) {
                    ndr->relative_highest_offset = ndr->offset;
                }
                ndr->offset = _relative_save_offset;
            }
            if (r->group_sid) {
                uint32_t _relative_save_offset;
                _relative_save_offset = ndr->offset;
                NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->group_sid));
                _mem_save_group_sid_0 = NDR_PULL_GET_MEM_CTX(ndr);
                NDR_PULL_SET_MEM_CTX(ndr, r->group_sid, 0);
                NDR_CHECK(ndr_pull_dom_sid(ndr, NDR_SCALARS, r->group_sid));
                NDR_PULL_SET_MEM_CTX(ndr, _mem_save_group_sid_0, 0);
                if (ndr->offset > ndr->relative_highest_offset) {
                    ndr->relative_highest_offset = ndr->offset;
                }
                ndr->offset = _relative_save_offset;
            }
            if (r->sacl) {
                uint32_t _relative_save_offset;
                _relative_save_offset = ndr->offset;
                NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->sacl));
                _mem_save_sacl_0 = NDR_PULL_GET_MEM_CTX(ndr);
                NDR_PULL_SET_MEM_CTX(ndr, r->sacl, 0);
                NDR_CHECK(ndr_pull_security_acl(ndr,
                                                NDR_SCALARS|NDR_BUFFERS,
                                                r->sacl));
                NDR_PULL_SET_MEM_CTX(ndr, _mem_save_sacl_0, 0);
                if (ndr->offset > ndr->relative_highest_offset) {
                    ndr->relative_highest_offset = ndr->offset;
                }
                ndr->offset = _relative_save_offset;
            }
            if (r->dacl) {
                uint32_t _relative_save_offset;
                _relative_save_offset = ndr->offset;
                NDR_CHECK(ndr_pull_relative_ptr2(ndr, r->dacl));
                _mem_save_dacl_0 = NDR_PULL_GET_MEM_CTX(ndr);
                NDR_PULL_SET_MEM_CTX(ndr, r->dacl, 0);
                NDR_CHECK(ndr_pull_security_acl(ndr,
                                                NDR_SCALARS|NDR_BUFFERS,
                                                r->dacl));
                NDR_PULL_SET_MEM_CTX(ndr, _mem_save_dacl_0, 0);
                if (ndr->offset > ndr->relative_highest_offset) {
                    ndr->relative_highest_offset = ndr->offset;
                }
                ndr->offset = _relative_save_offset;
            }
        }
        ndr->flags = _flags_save_STRUCT;
    }
    return NDR_ERR_SUCCESS;
}
