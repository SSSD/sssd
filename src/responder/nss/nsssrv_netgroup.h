/*
    SSSD

    nssrv_netgroup.h

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#ifndef NSSRV_NETGROUP_H_
#define NSSRV_NETGROUP_H_

#define SSS_COL_NETGR 5000

int nss_cmd_setnetgrent(struct cli_ctx *cctx);
int nss_cmd_getnetgrent(struct cli_ctx *cctx);
int nss_cmd_endnetgrent(struct cli_ctx *cctx);

void netgroup_hash_delete_cb(hash_entry_t *item,
                             hash_destroy_enum deltype, void *pvt);

errno_t nss_orphan_netgroups(struct nss_ctx *nctx);

#endif /* NSSRV_NETGROUP_H_ */
