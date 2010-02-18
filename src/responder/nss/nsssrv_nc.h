/*
   SSSD

   NSS Responder

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef _NSS_NEG_CACHE_H_
#define _NSS_NEG_CACHE_H_

struct nss_nc_ctx;

/* init the in memory negative cache */
int nss_ncache_init(TALLOC_CTX *memctx, struct nss_nc_ctx **_ctx);

/* check if the user is expired according to the passed in time to live */
int nss_ncache_check_user(struct nss_nc_ctx *ctx, int ttl,
                          const char *domain, const char *name);
int nss_ncache_check_group(struct nss_nc_ctx *ctx, int ttl,
                          const char *domain, const char *name);
int nss_ncache_check_uid(struct nss_nc_ctx *ctx, int ttl, uid_t uid);
int nss_ncache_check_gid(struct nss_nc_ctx *ctx, int ttl, gid_t gid);

/* add a new neg-cache entry setting the timestamp to "now" unless
 * "permanent" is set to true, in which case the timestamps is set to 0
 * and the negative cache never expires (used to permanently filter out
 * users and groups) */
int nss_ncache_set_user(struct nss_nc_ctx *ctx, bool permanent,
                        const char *domain, const char *name);
int nss_ncache_set_group(struct nss_nc_ctx *ctx, bool permanent,
                        const char *domain, const char *name);
int nss_ncache_set_uid(struct nss_nc_ctx *ctx, bool permanent, uid_t uid);
int nss_ncache_set_gid(struct nss_nc_ctx *ctx, bool permanent, gid_t gid);

int nss_ncache_reset_permament(struct nss_nc_ctx *ctx);

#endif /* _NSS_NEG_CACHE_H_ */
