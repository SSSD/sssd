/*
    SSSD

    LDAP handler for autofs

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2012 Red Hat

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

#ifndef _SDAP_AUTOFS_H_
#define _SDAP_AUTOFS_H_

errno_t sdap_autofs_init(TALLOC_CTX *mem_ctx,
                         struct be_ctx *be_ctx,
                         struct sdap_id_ctx *id_ctx,
                         struct dp_method *dp_methods);

struct tevent_req *
sdap_autofs_setautomntent_send(TALLOC_CTX *memctx,
                               struct tevent_context *ev,
                               struct sss_domain_info *dom,
                               struct sysdb_ctx *sysdb,
                               struct sdap_handle *sh,
                               struct sdap_id_op *op,
                               struct sdap_options *opts,
                               const char *mapname);

errno_t
sdap_autofs_setautomntent_recv(struct tevent_req *req);

struct tevent_req *sdap_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                                            struct sdap_id_ctx *id_ctx,
                                            const char *mapname);

errno_t sdap_autofs_get_map_recv(struct tevent_req *req,
                                 int *dp_error);

struct tevent_req *sdap_autofs_get_entry_send(TALLOC_CTX *mem_ctx,
                                              struct sdap_id_ctx *id_ctx,
                                              const char *mapname,
                                              const char *entryname);

errno_t sdap_autofs_get_entry_recv(struct tevent_req *req,
                                   int *dp_error);

#endif /* _SDAP_AUTOFS_H_ */
