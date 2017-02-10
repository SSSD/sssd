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

struct sss_nc_ctx;

/* init the in memory negative cache */
int sss_ncache_init(TALLOC_CTX *memctx, uint32_t timeout,
                    uint32_t local_timeout, struct sss_nc_ctx **_ctx);

uint32_t sss_ncache_get_timeout(struct sss_nc_ctx *ctx);

/* check if the user is expired according to the passed in time to live */
int sss_ncache_check_user(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                          const char *name);
int sss_ncache_check_group(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name);
int sss_ncache_check_netgr(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name);
int sss_ncache_check_uid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         uid_t uid);
int sss_ncache_check_gid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         gid_t gid);
int sss_ncache_check_sid(struct sss_nc_ctx *ctx, const char *sid);
int sss_ncache_check_cert(struct sss_nc_ctx *ctx, const char *cert);

int sss_ncache_check_service(struct sss_nc_ctx *ctx,
                             struct sss_domain_info *dom,
                             const char *name,
                             const char *proto);
int sss_ncache_check_service_port(struct sss_nc_ctx *ctx,
                                  struct sss_domain_info *dom,
                                  uint16_t port,
                                  const char *proto);

/* add a new neg-cache entry setting the timestamp to "now" unless
 * "permanent" is set to true, in which case the timestamps is set to 0
 * and the negative cache never expires (used to permanently filter out
 * users and groups) */
int sss_ncache_set_user(struct sss_nc_ctx *ctx, bool permanent,
                        struct sss_domain_info *dom, const char *name);
int sss_ncache_set_group(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name);
int sss_ncache_set_netgr(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name);
int sss_ncache_set_uid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, uid_t uid);
int sss_ncache_set_gid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, gid_t gid);
int sss_ncache_set_sid(struct sss_nc_ctx *ctx, bool permanent, const char *sid);
int sss_ncache_set_cert(struct sss_nc_ctx *ctx, bool permanent,
                        const char *cert);
int sss_ncache_set_service_name(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                const char *name, const char *proto);
int sss_ncache_set_service_port(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                uint16_t port, const char *proto);

int sss_ncache_reset_permanent(struct sss_nc_ctx *ctx);
int sss_ncache_reset_users(struct sss_nc_ctx *ctx);
int sss_ncache_reset_groups(struct sss_nc_ctx *ctx);

struct resp_ctx;

/* Set up the negative cache with values from filter_users and
 * filter_groups in the sssd.conf
 */
errno_t sss_ncache_prepopulate(struct sss_nc_ctx *ncache,
                               struct confdb_ctx *cdb,
                               struct resp_ctx *rctx);

/* Flush the negcache and then repopulate */
errno_t sss_ncache_reset_repopulate_permanent(struct resp_ctx *rctx,
                                              struct sss_nc_ctx *ncache);

#endif /* _NSS_NEG_CACHE_H_ */
