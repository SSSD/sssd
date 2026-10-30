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
struct resp_ctx;

/* Init the in memory negative cache.
 *
 * When the cache holds max_entries entries, adding a new one recreates it
 * from scratch; max_entries == 0 disables the limit. rctx is the responder
 * context used to restore the permanent entries on such a recreate (and by
 * sss_ncache_reset()); it may be NULL only when the limit is disabled and
 * the cache is never reset (e.g. in unit tests). */
int sss_ncache_init(TALLOC_CTX *memctx, uint32_t timeout,
                    uint32_t max_entries, struct resp_ctx *rctx,
                    struct sss_nc_ctx **_ctx);

/* check if the user is expired according to the passed in time to live */
int sss_ncache_check_user(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                          const char *name);
int sss_ncache_check_upn(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         const char *name);
int sss_ncache_check_group(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name);
int sss_ncache_check_netgr(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                           const char *name);
int sss_ncache_check_uid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         uid_t uid);
int sss_ncache_check_gid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         gid_t gid);
int sss_ncache_check_sid(struct sss_nc_ctx *ctx, struct sss_domain_info *dom,
                         const char *sid);
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
int sss_ncache_set_upn(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, const char *name);
int sss_ncache_set_group(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name);
int sss_ncache_set_netgr(struct sss_nc_ctx *ctx, bool permanent,
                         struct sss_domain_info *dom, const char *name);
int sss_ncache_set_uid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, uid_t uid);
int sss_ncache_set_gid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, gid_t gid);
int sss_ncache_set_sid(struct sss_nc_ctx *ctx, bool permanent,
                       struct sss_domain_info *dom, const char *sid);
int sss_ncache_set_cert(struct sss_nc_ctx *ctx, bool permanent,
                        const char *cert);
int sss_ncache_set_service_name(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                const char *name, const char *proto);
int sss_ncache_set_service_port(struct sss_nc_ctx *ctx, bool permanent,
                                struct sss_domain_info *dom,
                                uint16_t port, const char *proto);
/*
 * Mark the lookup_type as not supporting the negative cache. This
 * would be used by the corresponding checker to avoid needless
 * subsequent calls to the locator for configurations that do not
 * support the locator plugin.
 *
 * @param ctx   The negative cache.
 * @param dom   The top-level domain. It is expected that the caller
 *              would use the top-level domain head here, because
 *              this negative cache is "per-request-type" which is the
 *              same for all subdomains of a domain.
 * @param lookup_type   Lookup type, e.g. getpwuid, getgrnam.
 *
 * @return EOK on success, errno on failure.
 */
int sss_ncache_set_domain_locate_type(struct sss_nc_ctx *ctx,
                                      struct sss_domain_info *dom,
                                      const char *lookup_type);
/*
 * Check if the lookup_type supports the domain locator request.
 *
 * @param ctx   The negative cache.
 * @param dom   The top-level domain. It is expected that the caller
 *              would use the top-level domain head here, because
 *              this negative cache is "per-request-type" which is the
 *              same for all subdomains of a domain.
 * @param lookup_type   Lookup type, e.g. getpwuid, getgrnam.
 *
 * @return      ENOENT if the request supports the locator (or we
 *              haven't checked yet), EEXIST if the request does
 *              not support the domain locator request.
 */
int sss_ncache_check_domain_locate_type(struct sss_nc_ctx *ctx,
                                        struct sss_domain_info *dom,
                                        const char *key);

/*
 * Call these two functions to mark a GID as checked until the negative
 * cache expires. This function is used to avoid a situation where
 * GID would be found in a subsequent domain, so any request that
 * searches for this GID again (even if it was cached) would first
 * run the locator again.
 *
 * While this negative cache entry is valid, it is expected that
 * the negatively cached entries in the domain's GID negative
 * cache (if any) are valid.
 *
 * The sss_ncache_set_locate_gid() is called by the locator request
 * when it finishes, the sss_ncache_check_locate_gid() is called
 * by the caller of the locator request to find if the locator
 * should be called at all.
 */
int sss_ncache_set_locate_gid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              gid_t gid);
int sss_ncache_check_locate_gid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                gid_t gid);
int sss_ncache_check_locate_uid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                uid_t uid);
int sss_ncache_set_locate_uid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              uid_t uid);
int sss_ncache_check_locate_sid(struct sss_nc_ctx *ctx,
                                struct sss_domain_info *dom,
                                const char *sid);
int sss_ncache_set_locate_sid(struct sss_nc_ctx *ctx,
                              struct sss_domain_info *dom,
                              const char *sid);

/* Set up the negative cache with values from filter_users, filter_groups,
 * filter_uids and filter_gids in the sssd.conf. The confdb and the domain
 * list are taken from the responder context passed to sss_ncache_init().
 */
errno_t sss_ncache_prepopulate(struct sss_nc_ctx *ncache);

/* Recreate the negcache from scratch, dropping all non-permanent entries,
 * and repopulate the permanent entries. The responder context used for the
 * repopulation is the one passed to sss_ncache_init(). */
errno_t sss_ncache_reset(struct sss_nc_ctx *ncache);

#endif /* _NSS_NEG_CACHE_H_ */
