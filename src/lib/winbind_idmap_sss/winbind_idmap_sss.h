/*
    SSSD

    ID-mapping plugin for winbind

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2016 Red Hat

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

#ifndef _WINBIND_SSS_IDMAP_H_
#define _WINBIND_SSS_IDMAP_H_

#include <stdint.h>
#include <stdbool.h>

#include <core/ntstatus.h>
#include <ndr.h>
#include <gen_ndr/security.h>

#include "config.h"

/* The following definitions are taken from the Samba header files
 * - winbindd/idmap_proto.h
 * - idmap.d
 * - gen_ndr/idmap.h
 *  and can be removed if the related Samba header files become public headers
 *  or if this plugin is build inside the Samba source tree. */

enum id_type {
    ID_TYPE_NOT_SPECIFIED,
    ID_TYPE_UID,
    ID_TYPE_GID,
    ID_TYPE_BOTH
};

struct unixid {
    uint32_t id;
    enum id_type type;
};

enum id_mapping {
    ID_UNKNOWN,
    ID_MAPPED,
    ID_UNMAPPED,
    ID_EXPIRED
};

struct id_map {
    struct dom_sid *sid;
    struct unixid xid;
    enum id_mapping status;
};

#ifndef SMB_IDMAP_INTERFACE_VERSION
#error Missing Samba idmap interface version
#endif

#if SMB_IDMAP_INTERFACE_VERSION == 6
struct wbint_userinfo;
#endif

struct idmap_domain {
    const char *name;
#if SMB_IDMAP_INTERFACE_VERSION == 6 && defined(SMB_IDMAP_DOMAIN_HAS_DOM_SID)
    /*
     * dom_sid is currently only initialized in the unixids_to_sids request,
     * so don't rely on this being filled out everywhere!
     */
    struct dom_sid dom_sid;
#endif
    struct idmap_methods *methods;
#if SMB_IDMAP_INTERFACE_VERSION == 6
    NTSTATUS (*query_user)(struct idmap_domain *domain,
                           struct wbint_userinfo *info);
#endif
    uint32_t low_id;
    uint32_t high_id;
    bool read_only;
    void *private_data;
};

/* Filled out by IDMAP backends */
struct idmap_methods {

    /* Called when backend is first loaded */
    NTSTATUS (*init)(struct idmap_domain *dom);

    /* Map an array of uids/gids to SIDs.  The caller specifies
       the uid/gid and type. Gets back the SID. */
    NTSTATUS (*unixids_to_sids)(struct idmap_domain *dom, struct id_map **ids);

    /* Map an arry of SIDs to uids/gids.  The caller sets the SID
       and type and gets back a uid or gid. */
    NTSTATUS (*sids_to_unixids)(struct idmap_domain *dom, struct id_map **ids);

    /* Allocate a Unix-ID. */
    NTSTATUS (*allocate_id)(struct idmap_domain *dom, struct unixid *id);
};

NTSTATUS smb_register_idmap(int version, const char *name,
                            struct idmap_methods *methods);
#endif /* _WINBIND_SSS_IDMAP_H_ */
