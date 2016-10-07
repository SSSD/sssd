/*
   Unix SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2015

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

struct wbcContext *wbcCtxCreate(void)
{
    WBC_SSSD_DEV_LOG;
    return NULL;
}

void wbcCtxFree(struct wbcContext *ctx)
{
    WBC_SSSD_DEV_LOG;
    return;
}

wbcErr wbcCtxPing(struct wbcContext *ctx)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

struct wbcContext *wbcGetGlobalCtx(void)
{
    WBC_SSSD_DEV_LOG;
    return NULL;
}

wbcErr wbcCtxInterfaceDetails(struct wbcContext *ctx,
                              struct wbcInterfaceDetails **details)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupName(struct wbcContext *ctx,
                        const char *dom_name,
                        const char *name,
                        struct wbcDomainSid *sid,
                        enum wbcSidType *name_type)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupSid(struct wbcContext *ctx,
               const struct wbcDomainSid *sid,
               char **domain,
               char **name,
               enum wbcSidType *name_type)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupSids(struct wbcContext *ctx,
            const struct wbcDomainSid *sids, int num_sids,
            struct wbcDomainInfo **domains, int *num_domains,
            struct wbcTranslatedName **names)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupRids(struct wbcContext *ctx,
            struct wbcDomainSid *dom_sid,
            int num_rids,
            uint32_t *rids,
            const char **domain_name,
            const char ***names,
            enum wbcSidType **types)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupUserSids(struct wbcContext *ctx,
                const struct wbcDomainSid *user_sid,
                bool domain_groups_only,
                uint32_t *num_sids,
                struct wbcDomainSid **sids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetSidAliases(struct wbcContext *ctx,
               const struct wbcDomainSid *dom_sid,
               struct wbcDomainSid *sids,
               uint32_t num_sids,
               uint32_t **alias_rids,
               uint32_t *num_alias_rids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxListUsers(struct wbcContext *ctx,
               const char *domain_name,
               uint32_t *num_users,
               const char ***users)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxListGroups(struct wbcContext *ctx,
            const char *domain_name,
            uint32_t *num_groups,
            const char ***groups)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetDisplayName(struct wbcContext *ctx,
                const struct wbcDomainSid *sid,
                char **pdomain,
                char **pfullname,
                enum wbcSidType *pname_type)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxSidToUid(struct wbcContext *ctx,
              const struct wbcDomainSid *sid,
              uid_t *puid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxUidToSid(struct wbcContext *ctx, uid_t uid,
              struct wbcDomainSid *sid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxSidToGid(struct wbcContext *ctx,
              const struct wbcDomainSid *sid,
              gid_t *pgid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGidToSid(struct wbcContext *ctx, gid_t gid,
           struct wbcDomainSid *sid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxSidsToUnixIds(struct wbcContext *ctx,
               const struct wbcDomainSid *sids, uint32_t num_sids,
               struct wbcUnixId *ids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxUnixIdsToSids(struct wbcContext *ctx,
                           const struct wbcUnixId *ids, uint32_t num_ids,
                           struct wbcDomainSid *sids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxAllocateUid(struct wbcContext *ctx, uid_t *puid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxAllocateGid(struct wbcContext *ctx, gid_t *pgid)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetpwnam(struct wbcContext *ctx,
              const char *name, struct passwd **pwd)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetpwuid(struct wbcContext *ctx,
              uid_t uid, struct passwd **pwd)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetpwsid(struct wbcContext *ctx,
                      struct wbcDomainSid * sid, struct passwd **pwd)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetgrnam(struct wbcContext *ctx,
              const char *name, struct group **grp)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetgrgid(struct wbcContext *ctx,
              gid_t gid, struct group **grp)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxSetpwent(struct wbcContext *ctx)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxEndpwent(struct wbcContext *ctx)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetpwent(struct wbcContext *ctx, struct passwd **pwd)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxSetgrent(struct wbcContext *ctx)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxEndgrent(struct wbcContext *ctx)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetgrent(struct wbcContext *ctx, struct group **grp)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetgrlist(struct wbcContext *ctx, struct group **grp)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxGetGroups(struct wbcContext *ctx,
               const char *account,
               uint32_t *num_groups,
               gid_t **_groups)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxDomainInfo(struct wbcContext *ctx,
            const char *domain,
            struct wbcDomainInfo **dinfo)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxDcInfo(struct wbcContext *ctx,
            const char *domain, size_t *num_dcs,
            const char ***dc_names, const char ***dc_ips)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxListTrusts(struct wbcContext *ctx,
            struct wbcDomainInfo **domains,
            size_t *num_domains)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupDomainController(struct wbcContext *ctx,
                    const char *domain,
                    uint32_t flags,
                    struct wbcDomainControllerInfo **dc_info)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLookupDomainControllerEx(struct wbcContext *ctx,
                      const char *domain,
                      struct wbcGuid *guid,
                      const char *site,
                      uint32_t flags,
                      struct wbcDomainControllerInfoEx **dc_info)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxAuthenticateUser(struct wbcContext *ctx,
                  const char *username,
                  const char *password)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxAuthenticateUserEx(struct wbcContext *ctx,
                const struct wbcAuthUserParams *params,
                struct wbcAuthUserInfo **info,
                struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLogonUser(struct wbcContext *ctx,
               const struct wbcLogonUserParams *params,
               struct wbcLogonUserInfo **info,
               struct wbcAuthErrorInfo **error,
               struct wbcUserPasswordPolicyInfo **policy)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLogoffUser(struct wbcContext *ctx,
            const char *username, uid_t uid,
            const char *ccfilename)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxLogoffUserEx(struct wbcContext *ctx,
              const struct wbcLogoffUserParams *params,
                  struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxChangeUserPassword(struct wbcContext *ctx,
                const char *username,
                const char *old_password,
                const char *new_password)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxChangeUserPasswordEx(struct wbcContext *ctx,
                  const struct wbcChangePasswordParams *params,
                  struct wbcAuthErrorInfo **error,
                  enum wbcPasswordChangeRejectReason *reject_reason,
                  struct wbcUserPasswordPolicyInfo **policy)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxCredentialCache(struct wbcContext *ctx,
                 struct wbcCredentialCacheParams *params,
                             struct wbcCredentialCacheInfo **info,
                             struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxCredentialSave(struct wbcContext *ctx,
                const char *user, const char *password)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxResolveWinsByName(struct wbcContext *ctx,
                   const char *name, char **ip)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxResolveWinsByIP(struct wbcContext *ctx,
                 const char *ip, char **name)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxCheckTrustCredentials(struct wbcContext *ctx, const char *domain,
                   struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxChangeTrustCredentials(struct wbcContext *ctx, const char *domain,
                    struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxPingDc(struct wbcContext *ctx, const char *domain,
            struct wbcAuthErrorInfo **error)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcCtxPingDc2(struct wbcContext *ctx, const char *domain,
             struct wbcAuthErrorInfo **error,
             char **dcname)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}
