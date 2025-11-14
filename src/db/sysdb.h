/*
   SSSD

   System Database Header

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

#ifndef __SYS_DB_H__
#define __SYS_DB_H__

#include "util/util.h"
#include "confdb/confdb.h"
#include "sss_client/sss_cli.h"
#include <ldb.h>
#include <tevent.h>

#define CACHE_SYSDB_FILE "cache_%s.ldb"
#define CACHE_TIMESTAMPS_FILE "timestamps_%s.ldb"
#define LOCAL_SYSDB_FILE "sssd.ldb"

#define SYSDB_INDEXES "@INDEXLIST"
#define SYSDB_IDXATTR "@IDXATTR"

#define SYSDB_BASE "cn=sysdb"
#define SYSDB_DOM_BASE "cn=%s,cn=sysdb"
#define SYSDB_USERS_CONTAINER "cn=users"
#define SYSDB_GROUPS_CONTAINER "cn=groups"
#define SYSDB_CUSTOM_CONTAINER "cn=custom"
#define SYSDB_NETGROUP_CONTAINER "cn=Netgroups"
#define SYSDB_RANGE_CONTAINER "cn=ranges"
#define SYSDB_VIEW_CONTAINER "cn=views"
#define SYSDB_CERTMAP_CONTAINER "cn=certmap"
#define SYSDB_TMPL_USER_BASE SYSDB_USERS_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_GROUP_BASE SYSDB_GROUPS_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_CUSTOM_BASE SYSDB_CUSTOM_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_NETGROUP_BASE SYSDB_NETGROUP_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_RANGE_BASE SYSDB_RANGE_CONTAINER","SYSDB_BASE
#define SYSDB_TMPL_VIEW_BASE SYSDB_VIEW_CONTAINER","SYSDB_BASE
#define SYSDB_TMPL_VIEW_SEARCH_BASE "cn=%s,"SYSDB_TMPL_VIEW_BASE
#define SYSDB_TMPL_CERTMAP_BASE SYSDB_CERTMAP_CONTAINER","SYSDB_BASE

#define SYSDB_SUBDOMAIN_CLASS "subdomain"
#define SYSDB_USER_CLASS "user"
#define SYSDB_GROUP_CLASS "group"
#define SYSDB_NETGROUP_CLASS "netgroup"
#define SYSDB_HOST_CLASS "host"
#define SYSDB_HOSTGROUP_CLASS "hostgroup"
#define SYSDB_SELINUX_USERMAP_CLASS "selinuxusermap"
#define SYSDB_SELINUX_CLASS "selinux"
#define SYSDB_ID_RANGE_CLASS "idRange"
#define SYSDB_DOMAIN_ID_RANGE_CLASS "domainIDRange"
#define SYSDB_TRUSTED_AD_DOMAIN_RANGE_CLASS "TrustedADDomainRange"
#define SYSDB_CERTMAP_CLASS "certificateMappingRule"

#define SYSDB_DN "dn"
#define SYSDB_NAME "name"
#define SYSDB_NAME_ALIAS "nameAlias"
#define SYSDB_OBJECTCLASS "objectClass"

#define SYSDB_NEXTID "nextID"
#define SYSDB_UIDNUM "uidNumber"
#define SYSDB_GIDNUM "gidNumber"
#define SYSDB_CREATE_TIME "createTimestamp"

#define SYSDB_PWD "userPassword"
#define SYSDB_FULLNAME "fullName"
#define SYSDB_HOMEDIR "homeDirectory"
#define SYSDB_SHELL "loginShell"
#define SYSDB_MEMBEROF "memberOf"
#define SYSDB_DISABLED "disabled"

#define SYSDB_MEMBER "member"
#define SYSDB_MEMBERUID "memberUid"
#define SYSDB_GHOST "ghost"
#define SYSDB_POSIX "isPosix"
#define SYSDB_USER_CATEGORY "userCategory"
#define SYSDB_HOST_CATEGORY "hostCategory"
#define SYSDB_GROUP_TYPE "groupType"
#define SYSDB_EXTERNAL_MEMBER "externalMember"

#define SYSDB_GECOS "gecos"
#define SYSDB_LAST_LOGIN "lastLogin"
#define SYSDB_LAST_ONLINE_AUTH "lastOnlineAuth"
#define SYSDB_LAST_FAILED_LOGIN "lastFailedLogin"
#define SYSDB_FAILED_LOGIN_ATTEMPTS "failedLoginAttempts"
#define SYSDB_LAST_ONLINE_AUTH_WITH_CURR_TOKEN "lastOnlineAuthWithCurrentToken"

#define SYSDB_LAST_UPDATE "lastUpdate"
#define SYSDB_CACHE_EXPIRE "dataExpireTimestamp"
#define SYSDB_INITGR_EXPIRE "initgrExpireTimestamp"
#define SYSDB_ENUM_EXPIRE "enumerationExpireTimestamp"
#define SYSDB_IFP_CACHED "ifpCached"

#define SYSDB_AUTHORIZED_SERVICE "authorizedService"
#define SYSDB_AUTHORIZED_HOST "authorizedHost"
#define SYSDB_AUTHORIZED_RHOST "authorizedRHost"

#define SYSDB_NETGROUP_TRIPLE "netgroupTriple"
#define SYSDB_ORIG_NETGROUP_MEMBER "originalMemberNisNetgroup"
#define SYSDB_ORIG_NETGROUP_EXTERNAL_HOST "originalExternalHost"
#define SYSDB_NETGROUP_DOMAIN "nisDomain"
#define SYSDB_NETGROUP_MEMBER "memberNisNetgroup"
#define SYSDB_DESCRIPTION   "description"

#define SYSDB_FQDN "fqdn"
#define SYSDB_SERVERHOSTNAME "serverHostname"

#define SYSDB_CACHEDPWD "cachedPassword"
#define SYSDB_CACHEDPWD_TYPE "cachedPasswordType"
#define SYSDB_CACHEDPWD_FA2_LEN "cachedPasswordSecondFactorLen"

#define SYSDB_UUID "uniqueID"
#define SYSDB_SID "objectSID"
#define SYSDB_PRIMARY_GROUP "ADPrimaryGroupID"
#define SYSDB_PRIMARY_GROUP_GIDNUM "origPrimaryGroupGidNumber"
#define SYSDB_SID_STR "objectSIDString"
#define SYSDB_PAC_BLOB "pacBlob"
#define SYSDB_PAC_BLOB_EXPIRE "pacBlobExpireTimestamp"
#define SYSDB_UPN "userPrincipalName"
#define SYSDB_CANONICAL_UPN "canonicalUserPrincipalName"
#define SYSDB_CCACHE_FILE "ccacheFile"
#define SYSDB_DN_FOR_MEMBER_HASH_TABLE "dnForMemberHashTable"

#define SYSDB_ORIG_DN "originalDN"
#define SYSDB_ORIG_OBJECTCLASS "originalObjectClass"
#define SYSDB_ORIG_MODSTAMP "originalModifyTimestamp"
#define SYSDB_ORIG_MEMBEROF "originalMemberOf"
#define SYSDB_ORIG_MEMBER "orig_member"
#define SYSDB_ORIG_MEMBER_USER "originalMemberUser"
#define SYSDB_ORIG_MEMBER_HOST "originalMemberHost"

#define SYSDB_USN "entryUSN"
#define SYSDB_HIGH_USN "highestUSN"

#define SYSDB_SSH_PUBKEY "sshPublicKey"

#define SYSDB_SUBID_UID_COUND   "subUidCount"
#define SYSDB_SUBID_GID_COUNT   "subGidCount"
#define SYSDB_SUBID_UID_NUMBER  "subUidNumber"
#define SYSDB_SUBID_GID_NUMBER  "subGidNumber"
#define SYSDB_SUBID_OWNER       "subidOwner"

#define SYSDB_AUTH_TYPE "authType"
#define SYSDB_USER_CERT "userCertificate"
#define SYSDB_USER_MAPPED_CERT "userMappedCertificate"
#define SYSDB_USER_EMAIL "mail"

#define SYSDB_USER_PASSKEY "userPasskey"

/* Local auth types */
#define SYSDB_LOCAL_SMARTCARD_AUTH "localSmartcardAuth"
#define SYSDB_LOCAL_PASSKEY_AUTH "localPasskeyAuth"

#define SYSDB_SUBDOMAIN_REALM "realmName"
#define SYSDB_SUBDOMAIN_FLAT "flatName"
#define SYSDB_SUBDOMAIN_DNS "dnsName"
#define SYSDB_SUBDOMAIN_ID "domainID"
#define SYSDB_SUBDOMAIN_MPG "mpg"
#define SYSDB_SUBDOMAIN_ENUM "enumerate"
#define SYSDB_SUBDOMAIN_FOREST "memberOfForest"
#define SYSDB_SUBDOMAIN_TRUST_DIRECTION "trustDirection"
#define SYSDB_SUBDOMAIN_TRUST_TYPE "trustType"
#define SYSDB_UPN_SUFFIXES "upnSuffixes"
#define SYSDB_SITE "site"
#define SYSDB_ENABLED "enabled"

#define SYSDB_BASE_ID "baseID"
#define SYSDB_ID_RANGE_SIZE "idRangeSize"
#define SYSDB_BASE_RID "baseRID"
#define SYSDB_SECONDARY_BASE_RID "secondaryBaseRID"
#define SYSDB_DOMAIN_ID "domainID"
#define SYSDB_ID_RANGE_TYPE "idRangeType"
#define SYSDB_ID_RANGE_MPG "idRangeMPG"

#define SYSDB_CERTMAP_PRIORITY "priority"
#define SYSDB_CERTMAP_MATCHING_RULE "matchingRule"
#define SYSDB_CERTMAP_MAPPING_RULE "mappingRule"
#define SYSDB_CERTMAP_DOMAINS "domains"
#define SYSDB_CERTMAP_USER_NAME_HINT "userNameHint"

#define ORIGINALAD_PREFIX "originalAD"
#define OVERRIDE_PREFIX "override"
#define SYSDB_DEFAULT_OVERRIDE_NAME "defaultOverrideName"

#define SYSDB_ORIG_AD_GID_NUMBER "originalADgidNumber"

#define SYSDB_AD_ACCOUNT_EXPIRES "adAccountExpires"
#define SYSDB_AD_USER_ACCOUNT_CONTROL "adUserAccountControl"

#define SYSDB_DEFAULT_VIEW_NAME "default"
#define SYSDB_LOCAL_VIEW_NAME "LOCAL" /* reserved for client-side overrides */
#define SYSDB_VIEW_CLASS "view"
#define SYSDB_VIEW_NAME "viewName"
#define SYSDB_OVERRIDE_CLASS "override"
#define SYSDB_OVERRIDE_ANCHOR_UUID "overrideAnchorUUID"
#define SYSDB_OVERRIDE_ANCHOR "overrideAnchor"
#define SYSDB_OVERRIDE_USER_CLASS "userOverride"
#define SYSDB_OVERRIDE_GROUP_CLASS "groupOverride"
#define SYSDB_OVERRIDE_DN "overrideDN"
#define SYSDB_OVERRIDE_OBJECT_DN "overrideObjectDN"
#define SYSDB_USE_DOMAIN_RESOLUTION_ORDER "useDomainResolutionOrder"
#define SYSDB_DOMAIN_RESOLUTION_ORDER "domainResolutionOrder"
#define SYSDB_DOMAIN_TEMPLATE_SHELL "templateLoginShell"
#define SYSDB_DOMAIN_TEMPLATE_HOMEDIR "templateHomeDirectory"
#define SYSDB_PASSKEY_USER_VERIFICATION "passkeyUserVerification"
#define SYSDB_SESSION_RECORDING "sessionRecording"

#define SYSDB_NEXTID_FILTER "("SYSDB_NEXTID"=*)"

#define SYSDB_OBJECTCATEGORY "objectCategory"
#define SYSDB_UC SYSDB_OBJECTCATEGORY"="SYSDB_USER_CLASS
#define SYSDB_GC SYSDB_OBJECTCATEGORY"="SYSDB_GROUP_CLASS
#define SYSDB_NC SYSDB_OBJECTCLASS"="SYSDB_NETGROUP_CLASS
#define SYSDB_MPGC "|("SYSDB_UC")("SYSDB_GC")"

#define SYSDB_PWNAM_FILTER "(&("SYSDB_UC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_PWUID_FILTER "(&("SYSDB_UC")("SYSDB_UIDNUM"=%lu))"
#define SYSDB_PWSID_FILTER "(&("SYSDB_UC")("SYSDB_SID_STR"=%s))"
#define SYSDB_PWUPN_FILTER "(&("SYSDB_UC")(|("SYSDB_UPN"=%s)("SYSDB_CANONICAL_UPN"=%s)("SYSDB_USER_EMAIL"=%s)))"
#define SYSDB_PWENT_FILTER "("SYSDB_UC")"

#define SYSDB_GRNAM_FILTER "(&("SYSDB_GC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRGID_FILTER "(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRORIGGID_FILTER "(&("SYSDB_GC")("ORIGINALAD_PREFIX SYSDB_GIDNUM"=%lu))"
#define SYSDB_GRSID_FILTER "(&("SYSDB_GC")("SYSDB_SID_STR"=%s))"
#define SYSDB_GRENT_FILTER "("SYSDB_GC")"
#define SYSDB_GRNAM_MPG_FILTER "(&("SYSDB_MPGC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_GRGID_MPG_FILTER "(|(&("SYSDB_GC")("SYSDB_GIDNUM"=%lu))(&("SYSDB_UC")("SYSDB_GIDNUM"=%lu)("SYSDB_UIDNUM"=%lu)))"
#define SYSDB_GRENT_MPG_FILTER "("SYSDB_MPGC")"

#define SYSDB_INITGR_FILTER "("SYSDB_GC")"

#define SYSDB_NETGR_FILTER "(&("SYSDB_NC")(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_NETGR_TRIPLES_FILTER "(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)("SYSDB_NAME_ALIAS"=%s)("SYSDB_MEMBEROF"=%s))"

#define SYSDB_SID_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))("SYSDB_SID_STR"=%s))"
#define SYSDB_UUID_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))("SYSDB_UUID"=%s))"
#define SYSDB_NAME_FILTER "(&(|("SYSDB_UC")("SYSDB_GC"))(|("SYSDB_NAME_ALIAS"=%s)("SYSDB_NAME"=%s)))"
#define SYSDB_ID_FILTER "(|(&("SYSDB_UC")("SYSDB_UIDNUM"=%u))(&("SYSDB_GC")("SYSDB_GIDNUM"=%u)))"
#define SYSDB_USER_CERT_FILTER "(&("SYSDB_UC")%s)"

#define SYSDB_HAS_ENUMERATED "has_enumerated"
#define SYSDB_HAS_ENUMERATED_ID       0x00000001
#define SYSDB_HAS_ENUMERATED_RESOLVER 0x00000002

#define SYSDB_DEFAULT_ATTRS SYSDB_LAST_UPDATE, \
                            SYSDB_CACHE_EXPIRE, \
                            SYSDB_INITGR_EXPIRE, \
                            SYSDB_OBJECTCLASS, \
                            SYSDB_OBJECTCATEGORY

#define SYSDB_PW_ATTRS {SYSDB_NAME, SYSDB_UIDNUM, \
                        SYSDB_GIDNUM, SYSDB_GECOS, \
                        SYSDB_HOMEDIR, SYSDB_SHELL, \
                        SYSDB_DEFAULT_ATTRS, \
                        SYSDB_PRIMARY_GROUP_GIDNUM, \
                        SYSDB_SID_STR, \
                        SYSDB_UPN, \
                        SYSDB_USER_CERT, \
                        SYSDB_USER_EMAIL, \
                        SYSDB_OVERRIDE_DN, \
                        SYSDB_OVERRIDE_OBJECT_DN, \
                        SYSDB_DEFAULT_OVERRIDE_NAME, \
                        SYSDB_SESSION_RECORDING, \
                        SYSDB_UUID, \
                        SYSDB_ORIG_DN, \
                        NULL}

/* Strictly speaking it should return 'const char * const *' but
 * that gets really unreadable.
 */
__attribute__((always_inline))
static inline const char **SYSDB_GRSRC_ATTRS(const struct sss_domain_info *domain)
{
    static const char * __SYSDB_GRSRC_ATTRS_NO_MEMBERS[] = {
        SYSDB_NAME, SYSDB_GIDNUM,
        SYSDB_DEFAULT_ATTRS,
        SYSDB_SID_STR,
        SYSDB_OVERRIDE_DN,
        SYSDB_OVERRIDE_OBJECT_DN,
        SYSDB_DEFAULT_OVERRIDE_NAME,
        SYSDB_UUID,
        NULL
    };
    static const char * __SYSDB_GRSRC_ATTRS_WITH_MEMBERS[] = {
        SYSDB_NAME, SYSDB_GIDNUM,
        SYSDB_MEMBERUID,
        SYSDB_MEMBER,
        SYSDB_GHOST,
        SYSDB_DEFAULT_ATTRS,
        SYSDB_SID_STR,
        SYSDB_OVERRIDE_DN,
        SYSDB_OVERRIDE_OBJECT_DN,
        SYSDB_DEFAULT_OVERRIDE_NAME,
        SYSDB_UUID,
        ORIGINALAD_PREFIX SYSDB_NAME,
        ORIGINALAD_PREFIX SYSDB_GIDNUM,
        NULL
    };

    if (domain && domain->ignore_group_members) {
        return __SYSDB_GRSRC_ATTRS_NO_MEMBERS;
    } else {
        return __SYSDB_GRSRC_ATTRS_WITH_MEMBERS;
    }
}

#define SYSDB_NETGR_ATTRS {SYSDB_NAME, SYSDB_NETGROUP_TRIPLE, \
                           SYSDB_NETGROUP_MEMBER, \
                           SYSDB_DEFAULT_ATTRS, \
                           NULL}

#define SYSDB_INITGR_ATTR SYSDB_MEMBEROF
#define SYSDB_INITGR_ATTRS {SYSDB_GIDNUM, SYSDB_POSIX, \
                            SYSDB_DEFAULT_ATTRS, \
                            SYSDB_ORIG_DN, \
                            SYSDB_SID_STR, \
                            SYSDB_NAME, \
                            SYSDB_OVERRIDE_DN, \
                            NULL}

#define SYSDB_TMPL_USER SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE
#define SYSDB_TMPL_GROUP SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE
#define SYSDB_TMPL_NETGROUP SYSDB_NAME"=%s,"SYSDB_TMPL_NETGROUP_BASE
#define SYSDB_TMPL_CUSTOM_SUBTREE "cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_CUSTOM SYSDB_NAME"=%s,cn=%s,"SYSDB_TMPL_CUSTOM_BASE
#define SYSDB_TMPL_RANGE SYSDB_NAME"=%s,"SYSDB_TMPL_RANGE_BASE
#define SYSDB_TMPL_OVERRIDE SYSDB_OVERRIDE_ANCHOR_UUID"=%s,"SYSDB_TMPL_VIEW_SEARCH_BASE
#define SYSDB_TMPL_CERTMAP SYSDB_NAME"=%s,"SYSDB_TMPL_CERTMAP_BASE

#define SYSDB_MOD_ADD LDB_FLAG_MOD_ADD
#define SYSDB_MOD_DEL LDB_FLAG_MOD_DELETE
#define SYSDB_MOD_REP LDB_FLAG_MOD_REPLACE

/* sysdb version check macros */
#define SYSDB_VERSION_ERROR_HINT \
    ERROR("Removing cache files in "DB_PATH" should fix the issue, " \
          "but note that removing cache files will also remove all of your " \
          "cached credentials.\n")

#define SYSDB_VERSION_LOWER_ERROR(ret) do { \
    if (ret == ERR_SYSDB_VERSION_TOO_NEW) { \
        ERROR("Lower version of database is expected!\n"); \
        SYSDB_VERSION_ERROR_HINT; \
    } \
} while(0)

#define SYSDB_VERSION_HIGHER_ERROR(ret) do { \
    if (ret == ERR_SYSDB_VERSION_TOO_OLD) { \
        ERROR("Higher version of database is expected!\n"); \
        ERROR("In order to upgrade the database, you must run SSSD.\n"); \
        SYSDB_VERSION_ERROR_HINT; \
    } \
} while(0)

/* use this in daemons */
#define SYSDB_VERSION_ERROR_DAEMON(ret) \
    SYSDB_VERSION_LOWER_ERROR(ret)

/* use this in tools */
#define SYSDB_VERSION_ERROR(ret) \
    SYSDB_VERSION_LOWER_ERROR(ret); \
    SYSDB_VERSION_HIGHER_ERROR(ret)

struct confdb_ctx;
struct sysdb_ctx;

struct sysdb_attrs {
    int num;
    struct ldb_message_element *a;
};

/* sysdb_attrs helper functions */
struct sysdb_attrs *sysdb_new_attrs(TALLOC_CTX *mem_ctx);

struct range_info {
    char *name;
    uint32_t base_id;
    uint32_t id_range_size;
    uint32_t base_rid;
    uint32_t secondary_base_rid;
    char *trusted_dom_sid;
    char *range_type;
    enum sss_domain_mpg_mode mpg_mode;
};

struct certmap_info {
    char *name;
    uint32_t priority;
    char *match_rule;
    char *map_rule;
    const char **domains;
};

enum sysdb_member_type {
    SYSDB_MEMBER_USER,
    SYSDB_MEMBER_GROUP,
    SYSDB_MEMBER_NETGROUP,
    SYSDB_MEMBER_SERVICE,
    SYSDB_MEMBER_HOST,
    SYSDB_MEMBER_IP_NETWORK,
};

enum sysdb_index_actions {
    SYSDB_IDX_CREATE,
    SYSDB_IDX_DELETE,
    SYSDB_IDX_LIST
};

enum sysdb_obj_type {
    SYSDB_UNKNOWN = 0,
    SYSDB_USER,
    SYSDB_GROUP
};

/* These attributes are stored in the timestamp cache */
extern const char *sysdb_ts_cache_attrs[];

/* values are copied in the structure, allocated on "attrs" */
int sysdb_attrs_add_empty(struct sysdb_attrs *attrs, const char *name);
int sysdb_attrs_add_val(struct sysdb_attrs *attrs,
                        const char *name, const struct ldb_val *val);
int sysdb_attrs_add_val_safe(struct sysdb_attrs *attrs,
                             const char *name, const struct ldb_val *val);
int sysdb_attrs_add_string_safe(struct sysdb_attrs *attrs,
                                const char *name, const char *str);
int sysdb_attrs_add_string(struct sysdb_attrs *attrs,
                           const char *name, const char *str);
int sysdb_attrs_add_lower_case_string(struct sysdb_attrs *attrs, bool safe,
                                      const char *name, const char *str);
int sysdb_attrs_add_mem(struct sysdb_attrs *attrs, const char *name,
                        const void *mem, size_t size);
int sysdb_attrs_add_base64_blob(struct sysdb_attrs *attrs, const char *name,
                                const char *base64_str);
int sysdb_attrs_add_bool(struct sysdb_attrs *attrs,
                         const char *name, bool value);
int sysdb_attrs_add_long(struct sysdb_attrs *attrs,
                         const char *name, long value);
int sysdb_attrs_add_uint32(struct sysdb_attrs *attrs,
                           const char *name, uint32_t value);
int sysdb_attrs_add_time_t(struct sysdb_attrs *attrs,
                           const char *name, time_t value);
int sysdb_attrs_add_lc_name_alias(struct sysdb_attrs *attrs,
                                  const char *value);
int sysdb_attrs_add_lc_name_alias_safe(struct sysdb_attrs *attrs,
                                       const char *value);
int sysdb_attrs_copy_values(struct sysdb_attrs *src,
                            struct sysdb_attrs *dst,
                            const char *name);
errno_t sysdb_attrs_copy(struct sysdb_attrs *src, struct sysdb_attrs *dst);
int sysdb_attrs_get_el(struct sysdb_attrs *attrs, const char *name,
                       struct ldb_message_element **el);
int sysdb_attrs_get_el_ext(struct sysdb_attrs *attrs, const char *name,
                           bool alloc, struct ldb_message_element **el);
int sysdb_attrs_steal_string(struct sysdb_attrs *attrs,
                             const char *name, char *str);
int sysdb_attrs_get_string(struct sysdb_attrs *attrs, const char *name,
                           const char **string);
const char **sss_ldb_el_to_string_list(TALLOC_CTX *mem_ctx,
                                       struct ldb_message_element *el);
int sysdb_attrs_get_string_array(struct sysdb_attrs *attrs, const char *name,
                                 TALLOC_CTX *mem_ctx, const char ***string);
errno_t sysdb_attrs_get_bool(struct sysdb_attrs *attrs, const char *name,
                             bool *value);
int sysdb_attrs_get_uint16_t(struct sysdb_attrs *attrs, const char *name,
                             uint16_t *value);
int sysdb_attrs_get_int32_t(struct sysdb_attrs *attrs, const char *name,
                             int32_t *value);
int sysdb_attrs_get_uint32_t(struct sysdb_attrs *attrs, const char *name,
                             uint32_t *value);

int sysdb_attrs_replace_name(struct sysdb_attrs *attrs, const char *oldname,
                                 const char *newname);

int sysdb_attrs_users_from_str_list(struct sysdb_attrs *attrs,
                                    const char *attr_name,
                                    const char *domain,
                                    const char *const *list);
errno_t sysdb_attrs_get_aliases(TALLOC_CTX *mem_ctx,
                                struct sysdb_attrs *attrs,
                                const char *primary,
                                bool lowercase,
                                const char ***_aliases);
errno_t sysdb_get_real_name(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *name_or_upn,
                            const char **_cname);

errno_t sysdb_msg2attrs(TALLOC_CTX *mem_ctx, size_t count,
                        struct ldb_message **msgs,
                        struct sysdb_attrs ***attrs);

int sysdb_compare_usn(const char *a, const char *b);

errno_t sysdb_get_highest_usn(TALLOC_CTX *mem_ctx,
                              struct sysdb_attrs **attrs,
                              size_t num_attrs,
                              char **_usn);

/* DNs related helper functions */
errno_t sysdb_get_rdn(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx,
                      const char *dn, char **_name, char **_val);
struct ldb_dn *sysdb_user_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                             const char *name);
struct ldb_dn *sysdb_user_base_dn(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom);
struct ldb_dn *sysdb_group_dn(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                              const char *name);
struct ldb_dn *sysdb_group_base_dn(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *dom);
struct ldb_dn *sysdb_netgroup_dn(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom, const char *name);
struct ldb_dn *sysdb_netgroup_base_dn(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *dom);
errno_t sysdb_group_dn_name(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx,
                            const char *dn_str, char **name);
struct ldb_dn *sysdb_domain_dn(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *dom);
struct ldb_dn *sysdb_base_dn(struct sysdb_ctx *sysdb, TALLOC_CTX *mem_ctx);
struct ldb_dn *sysdb_custom_dn(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *dom,
                               const char *object_name,
                               const char *subtree_name);
struct ldb_dn *sysdb_custom_subtree_dn(TALLOC_CTX *mem_ctx,
                                       struct sss_domain_info *dom,
                                       const char *subtree_name);

char *sysdb_user_strdn(TALLOC_CTX *mem_ctx,
                       const char *domain, const char *name);
char *sysdb_group_strdn(TALLOC_CTX *mem_ctx,
                        const char *domain, const char *name);


struct ldb_context *sysdb_ctx_get_ldb(struct sysdb_ctx *sysdb);

int compare_ldb_dn_comp_num(const void *m1, const void *m2);

/* functions to start and finish transactions */
int sysdb_transaction_start(struct sysdb_ctx *sysdb);
int sysdb_transaction_commit(struct sysdb_ctx *sysdb);
int sysdb_transaction_cancel(struct sysdb_ctx *sysdb);

/* functions related to subdomains */
errno_t sysdb_domain_create(struct sysdb_ctx *sysdb, const char *domain_name);

errno_t sysdb_domain_get_domain_resolution_order(
                                        TALLOC_CTX *mem_ctx,
                                        struct sysdb_ctx *sysdb,
                                        const char *domain_name,
                                        const char **_domain_resolution_order);

errno_t sysdb_domain_update_domain_resolution_order(
                                        struct sysdb_ctx *sysdb,
                                        const char *domain_name,
                                        const char *domain_resolution_order);


errno_t
sysdb_get_site(TALLOC_CTX *mem_ctx,
               struct sss_domain_info *dom,
               const char **_site);

errno_t
sysdb_set_site(struct sss_domain_info *dom,
               const char *site);

errno_t
sysdb_domain_set_enabled(struct sysdb_ctx *sysdb,
                         const char *name,
                         bool enabled);

errno_t
sysdb_list_subdomains(TALLOC_CTX *mem_ctx,
                      struct sysdb_ctx *sysdb,
                      const char ***_names);

errno_t sysdb_subdomain_store(struct sysdb_ctx *sysdb,
                              const char *name, const char *realm,
                              const char *flat_name, const char *dns_name,
                              const char *domain_id,
                              enum sss_domain_mpg_mode mpg_mode,
                              bool enumerate, const char *forest,
                              uint32_t trust_direction,
                              uint32_t trust_type,
                              struct ldb_message_element *upn_suffixes);

errno_t sysdb_update_subdomains(struct sss_domain_info *domain,
                                struct confdb_ctx *confdb);

errno_t sysdb_master_domain_update(struct sss_domain_info *domain);

errno_t sysdb_master_domain_add_info(struct sss_domain_info *domain,
                                     const char *realm,
                                     const char *flat,
                                     const char *dns,
                                     const char *id,
                                     const char *forest,
                                     struct ldb_message_element *alt_dom_suf);

errno_t sysdb_subdomain_delete(struct sysdb_ctx *sysdb, const char *name);

errno_t sysdb_subdomain_content_delete(struct sysdb_ctx *sysdb,
                                       const char *name);

errno_t
sysdb_subdomain_get_id_by_name(TALLOC_CTX *mem_ctx,
                               struct sysdb_ctx *sysdb,
                               const char *name,
                               const char **_id);

/* The utility function to create a subdomain sss_domain_info object is handy
 * for unit tests, so it should be available in a headerr.
 */
struct sss_domain_info *new_subdomain(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *parent,
                                      const char *name,
                                      const char *realm,
                                      const char *flat_name,
                                      const char *dns_name,
                                      const char *id,
                                      enum sss_domain_mpg_mode mpg_mode,
                                      bool enumerate,
                                      const char *forest,
                                      const char **upn_suffixes,
                                      uint32_t trust_direction,
                                      uint32_t trust_type,
                                      struct confdb_ctx *confdb,
                                      bool enabled);


errno_t sysdb_get_ranges(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                             size_t *range_count,
                             struct range_info ***range_list);
errno_t sysdb_get_range(TALLOC_CTX *mem_ctx,
                        struct sysdb_ctx *sysdb,
                        const char *forest,
                        struct range_info **_range);
errno_t sysdb_range_create(struct sysdb_ctx *sysdb, struct range_info *range);
errno_t sysdb_update_ranges(struct sysdb_ctx *sysdb,
                            struct range_info **ranges);

errno_t sysdb_update_view_name(struct sysdb_ctx *sysdb, const char *view_name);

errno_t sysdb_get_view_name(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                            char **view_name);

errno_t sysdb_update_override_template(struct sysdb_ctx *sysdb,
                                       const char *view_name,
                                       const char *anchor,
                                       const char *home_dir,
                                       const char *login_shell);

errno_t sysdb_domain_update_domain_template(struct sss_domain_info *parent,
                                            struct sysdb_ctx *sysdb,
                                            const char *subdom_name,
                                            const char *home_dir,
                                            const char *login_shell);

errno_t sysdb_update_domain_template(struct sysdb_ctx *sysdb,
                                     struct ldb_dn *dn,
                                     const char *home_dir,
                                     const char *login_shell);

errno_t sysdb_update_view_domain_resolution_order(
                                        struct sysdb_ctx *sysdb,
                                        const char *domain_resolution_order);

errno_t sysdb_get_view_domain_resolution_order(
                                        TALLOC_CTX *mem_ctx,
                                        struct sysdb_ctx *sysdb,
                                        const char **_domain_resolution_order);

static inline bool is_default_view(const char *view_name)
{
    /* NULL is treated as default */
    if (view_name == NULL
            || strcmp(view_name, SYSDB_DEFAULT_VIEW_NAME) == 0) {
        return true;
    } else {
        return false;
    }
}

static inline bool is_local_view(const char *view_name)
{
    /* NULL is treated as default */
    if (view_name != NULL
            && strcmp(view_name, SYSDB_LOCAL_VIEW_NAME) == 0) {
        return true;
    } else {
        return false;
    }
}

errno_t sysdb_delete_view_tree(struct sysdb_ctx *sysdb, const char *view_name);

errno_t sysdb_invalidate_overrides(struct sysdb_ctx *sysdb);

errno_t sysdb_apply_default_override(struct sss_domain_info *domain,
                                     struct sysdb_attrs *override_attrs,
                                     const char *global_template_homedir,
                                     const char *global_template_shell,
                                     struct ldb_dn *obj_dn);

errno_t sysdb_search_by_orig_dn(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                enum sysdb_member_type type,
                                const char *member_dn,
                                const char **attrs,
                                size_t *msgs_counts,
                                struct ldb_message ***msgs);

#define sysdb_search_users_by_orig_dn(mem_ctx, domain, member_dn, attrs, msgs_counts, msgs) \
    sysdb_search_by_orig_dn(mem_ctx, domain, SYSDB_MEMBER_USER, member_dn, attrs, msgs_counts, msgs);

#define sysdb_search_groups_by_orig_dn(mem_ctx, domain, member_dn, attrs, msgs_counts, msgs) \
    sysdb_search_by_orig_dn(mem_ctx, domain, SYSDB_MEMBER_GROUP, member_dn, attrs, msgs_counts, msgs);

errno_t sysdb_search_user_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            const char **attrs,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj);

errno_t sysdb_search_group_override_attrs_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            const char **attrs,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj);

errno_t sysdb_search_user_override_by_name(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain,
                                           const char *name,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj);

errno_t sysdb_search_group_override_by_name(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            const char *name,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj);

errno_t sysdb_search_user_override_by_uid(TALLOC_CTX *mem_ctx,
                                          struct sss_domain_info *domain,
                                          uid_t uid,
                                           struct ldb_result **override_obj,
                                           struct ldb_result **orig_obj);

errno_t sysdb_search_group_override_by_gid(TALLOC_CTX *mem_ctx,
                                            struct sss_domain_info *domain,
                                            gid_t gid,
                                            struct ldb_result **override_obj,
                                            struct ldb_result **orig_obj);

errno_t sysdb_search_override_by_cert(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *cert,
                                      const char **attrs,
                                      struct ldb_result **override_obj,
                                      struct ldb_result **orig_obj);

errno_t sysdb_add_overrides_to_object(struct sss_domain_info *domain,
                                      struct ldb_message *obj,
                                      struct ldb_message *override_obj,
                                      const char **req_attrs);

errno_t sysdb_add_group_member_overrides(struct sss_domain_info *domain,
                                         struct ldb_message *obj);

errno_t sysdb_getpwnam_with_views(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name,
                                  struct ldb_result **res);

errno_t sysdb_getpwuid_with_views(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  uid_t uid,
                                  struct ldb_result **res);

int sysdb_getgrnam_with_views(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *name,
                              struct ldb_result **res);

int sysdb_getgrgid_with_views(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              gid_t gid,
                              struct ldb_result **res);

struct ldb_message_element *
sss_view_ldb_msg_find_element(struct sss_domain_info *dom,
                              const struct ldb_message *msg,
                              const char *attr_name);

const char *sss_view_ldb_msg_find_attr_as_string_ex(struct sss_domain_info *dom,
                                                  const struct ldb_message *msg,
                                                  const char *attr_name,
                                                  const char *default_value,
                                                  bool *is_override);

const char *sss_view_ldb_msg_find_attr_as_string(struct sss_domain_info *dom,
                                                 const struct ldb_message *msg,
                                                 const char *attr_name,
                                                 const char * default_value);

uint64_t sss_view_ldb_msg_find_attr_as_uint64(struct sss_domain_info *dom,
                                              const struct ldb_message *msg,
                                              const char *attr_name,
                                              uint64_t default_value);

errno_t sysdb_update_certmap(struct sysdb_ctx *sysdb,
                             struct certmap_info **certmaps,
                             bool user_name_hint);

errno_t sysdb_ldb_msg_attr_to_certmap_info(TALLOC_CTX *mem_ctx,
                                           struct ldb_message *msg,
                                           const char **attr_map,
                                           struct certmap_info **certmap);

errno_t sysdb_get_certmap(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                          struct certmap_info ***certmaps,
                          bool *user_name_hint);

/* Sysdb initialization.
 * call this function *only* once to initialize the database and get
 * the sysdb ctx */
int sysdb_init(TALLOC_CTX *mem_ctx,
               struct sss_domain_info *domains);

/* Same as sysdb_init, but additionally allows to change
 * file ownership of the sysdb databases and allow the
 * upgrade via passing a context. */
struct sysdb_upgrade_ctx {
    struct confdb_ctx *cdb;
};

int sysdb_init_ext(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domains,
                   struct sysdb_upgrade_ctx *upgrade_ctx,
                   bool chown_dbfile,
                   uid_t uid, gid_t gid);

/* used to initialize only one domain database.
 * Do NOT use if sysdb_init has already been called */
int sysdb_domain_init(TALLOC_CTX *mem_ctx,
                      struct sss_domain_info *domain,
                      const char *db_path,
                      struct sysdb_ctx **_ctx);

/* functions to retrieve information from sysdb
 * These functions automatically starts an operation
 * therefore they cannot be called within a transaction */
int sysdb_getpwnam(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **res);

int sysdb_getpwuid(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   uid_t uid,
                   struct ldb_result **res);

int sysdb_getpwupn(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   bool domain_scope,
                   const char *upn,
                   struct ldb_result **res);

int sysdb_enumpwent(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **res);

int sysdb_enumpwent_filter(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *attr,
                           const char *attr_filter,
                           const char *addtl_filter,
                           struct ldb_result **res);

int sysdb_enumpwent_with_views(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               struct ldb_result **res);

int sysdb_enumpwent_filter_with_views(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *attr,
                                      const char *attr_filter,
                                      const char *addtl_filter,
                                      struct ldb_result **res);

int sysdb_getgrnam(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   const char *name,
                   struct ldb_result **res);

int sysdb_getgrgid(TALLOC_CTX *mem_ctx,
                   struct sss_domain_info *domain,
                   gid_t gid,
                   struct ldb_result **res);

int sysdb_getgrgid_attrs(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         gid_t gid,
                         const char **attrs,
                         struct ldb_result **res);

int sysdb_enumgrent(TALLOC_CTX *mem_ctx,
                    struct sss_domain_info *domain,
                    struct ldb_result **res);

int sysdb_enumgrent_filter(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *name_filter,
                           const char *addtl_filter,
                           struct ldb_result **res);

int sysdb_enumgrent_with_views(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               struct ldb_result **res);

int sysdb_enumgrent_filter_with_views(TALLOC_CTX *mem_ctx,
                                      struct sss_domain_info *domain,
                                      const char *name_filter,
                                      const char *addtl_filter,
                                      struct ldb_result **res);

struct sysdb_netgroup_ctx {
    enum {SYSDB_NETGROUP_TRIPLE_VAL, SYSDB_NETGROUP_GROUP_VAL} type;
    union {
        struct {
            char *hostname;
            char *username;
            char *domainname;
        } triple;
        char *groupname;
    } value;
};

errno_t sysdb_getnetgr(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *netgroup,
                       struct ldb_result **res);

int sysdb_initgroups(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     const char *name,
                     struct ldb_result **res);

int sysdb_initgroups_by_upn(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *upn,
                            struct ldb_result **res);

int sysdb_initgroups_with_views(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *name,
                                struct ldb_result **res);

int sysdb_get_user_attr(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *name,
                        const char **attributes,
                        struct ldb_result **res);

int sysdb_get_user_attr_with_views(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char *name,
                                   const char **attributes,
                                   struct ldb_result **res);

int sysdb_search_user_by_cert_with_views(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domain,
                                         const char *cert,
                                         struct ldb_result **res);

int sysdb_get_netgroup_attr(TALLOC_CTX *mem_ctx,
                            struct sss_domain_info *domain,
                            const char *netgrname,
                            const char **attributes,
                            struct ldb_result **res);

/* functions that modify the database
 * they have to be called within a transaction
 * See sysdb_transaction_send()/_recv() */

/* Permissive modify */
int sss_ldb_modify_permissive(struct ldb_context *ldb,
                              struct ldb_message *msg);

/* Delete Entry */
int sysdb_delete_entry(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       bool ignore_not_found);

int sysdb_delete_recursive(struct sysdb_ctx *sysdb,
                           struct ldb_dn *dn,
                           bool ignore_not_found);

int sysdb_delete_recursive_with_filter(struct sysdb_ctx *sysdb,
                                       struct ldb_dn *dn,
                                       bool ignore_not_found,
                                       const char *filter);

/* Mark entry as expired */
errno_t sysdb_mark_entry_as_expired_ldb_dn(struct sss_domain_info *dom,
                                           struct ldb_dn *ldbdn);
errno_t sysdb_mark_entry_as_expired_ldb_val(struct sss_domain_info *dom,
                                            struct ldb_val *dn_val);

/* Search Entry */
int sysdb_search_entry(TALLOC_CTX *mem_ctx,
                       struct sysdb_ctx *sysdb,
                       struct ldb_dn *base_dn,
                       enum ldb_scope scope,
                       const char *filter,
                       const char **attrs,
                       size_t *_msgs_count,
                       struct ldb_message ***_msgs);

#define SSS_LDB_SEARCH(ret, ldb, mem_ctx, _result, base, scope, attrs,    \
                       exp_fmt, ...) do {                                 \
    int _sls_lret;                                                        \
                                                                          \
    _sls_lret = ldb_search(ldb, mem_ctx, _result, base, scope, attrs,     \
                           exp_fmt, ##__VA_ARGS__);                       \
    ret = sysdb_error_to_errno(_sls_lret);                                \
    if (ret == EOK && (*_result)->count == 0) {                           \
        ret = ENOENT;                                                     \
    }                                                                     \
} while(0)

/* Search User (by uid, sid or name) */
int sysdb_search_user_by_name(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              const char *name,
                              const char **attrs,
                              struct ldb_message **msg);

int sysdb_search_user_by_uid(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             uid_t uid,
                             const char **attrs,
                             struct ldb_message **msg);

int sysdb_search_user_by_sid_str(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 const char *sid_str,
                                 const char **attrs,
                                 struct ldb_message **msg);

int sysdb_search_user_by_upn_res(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 bool domain_scope,
                                 const char *upn,
                                 const char **attrs,
                                 struct ldb_result **out_res);

int sysdb_search_user_by_upn(TALLOC_CTX *mem_ctx,
                             struct sss_domain_info *domain,
                             bool domain_scope,
                             const char *sid_str,
                             const char **attrs,
                             struct ldb_message **msg);

/* Search Group (by gid, sid or name) */
int sysdb_search_group_by_name(TALLOC_CTX *mem_ctx,
                               struct sss_domain_info *domain,
                               const char *name,
                               const char **attrs,
                               struct ldb_message **msg);

int sysdb_search_group_by_gid(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *domain,
                              gid_t gid,
                              const char **attrs,
                              struct ldb_message **msg);

int sysdb_search_group_by_origgid(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  gid_t gid,
                                  const char **attrs,
                                  struct ldb_message **msg);

int sysdb_search_group_by_sid_str(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *sid_str,
                                  const char **attrs,
                                  struct ldb_message **msg);

/* Search Netgroup (by name) */
int sysdb_search_netgroup_by_name(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *name,
                                  const char **attrs,
                                  struct ldb_message **msg);

/* Replace entry attrs */
int sysdb_set_entry_attr(struct sysdb_ctx *sysdb,
                         struct ldb_dn *entry_dn,
                         struct sysdb_attrs *attrs,
                         int mod_op);

/* User/group invalidation of cache by direct writing to persistent cache
 * WARNING: This function can cause performance issue!!
 * is_user = true --> user invalidation
 * is_user = false --> group invalidation
 */
int sysdb_invalidate_cache_entry(struct sss_domain_info *domain,
                                 const char *name,
                                 bool is_user);

/* Replace user attrs */
int sysdb_set_user_attr(struct sss_domain_info *domain,
                        const char *name,
                        struct sysdb_attrs *attrs,
                        int mod_op);

errno_t sysdb_update_user_shadow_last_change(struct sss_domain_info *domain,
                                             const char *name,
                                             const char *attrname);

/* Replace group attrs */
int sysdb_set_group_attr(struct sss_domain_info *domain,
                         const char *name,
                         struct sysdb_attrs *attrs,
                         int mod_op);

/* Replace netgroup attrs */
int sysdb_set_netgroup_attr(struct sss_domain_info *domain,
                            const char *name,
                            struct sysdb_attrs *attrs,
                            int mod_op);

/* Add user (only basic attrs and w/o checks) */
int sysdb_add_basic_user(struct sss_domain_info *domain,
                         const char *name,
                         uid_t uid, gid_t gid,
                         const char *gecos,
                         const char *homedir,
                         const char *shell);

/* Add user (all checks) */
int sysdb_add_user(struct sss_domain_info *domain,
                   const char *name,
                   uid_t uid, gid_t gid,
                   const char *gecos,
                   const char *homedir,
                   const char *shell,
                   const char *orig_dn,
                   struct sysdb_attrs *attrs,
                   int cache_timeout,
                   time_t now);

/* Add group (only basic attrs and w/o checks) */
int sysdb_add_basic_group(struct sss_domain_info *domain,
                          const char *name,
                          bool is_posix,
                          gid_t gid);

/* Add group (all checks) */
int sysdb_add_group(struct sss_domain_info *domain,
                    const char *name, gid_t gid,
                    struct sysdb_attrs *attrs,
                    int cache_timeout,
                    time_t now);

int sysdb_add_incomplete_group(struct sss_domain_info *domain,
                               const char *name,
                               gid_t gid,
                               const char *original_dn,
                               const char *sid_str,
                               const char *uuid,
                               bool posix,
                               time_t now);

/* Add netgroup (only basic attrs and w/o checks) */
int sysdb_add_basic_netgroup(struct sss_domain_info *domain,
                             const char *name, const char *description);

int sysdb_add_netgroup(struct sss_domain_info *domain,
                       const char *name,
                       const char *description,
                       struct sysdb_attrs *attrs,
                       char **missing,
                       int cache_timeout,
                       time_t now);

/* mod_op must be either LDB_FLAG_MOD_ADD or LDB_FLAG_MOD_DELETE */
int sysdb_mod_group_member(struct sss_domain_info *domain,
                           struct ldb_dn *member_dn,
                           struct ldb_dn *group_dn,
                           int mod_op);

int sysdb_store_user(struct sss_domain_info *domain,
                     const char *name,
                     const char *pwd,
                     uid_t uid, gid_t gid,
                     const char *gecos,
                     const char *homedir,
                     const char *shell,
                     const char *orig_dn,
                     struct sysdb_attrs *attrs,
                     char **remove_attrs,
                     uint64_t cache_timeout,
                     time_t now);

int sysdb_store_group(struct sss_domain_info *domain,
                      const char *name,
                      gid_t gid,
                      struct sysdb_attrs *attrs,
                      uint64_t cache_timeout,
                      time_t now);

int sysdb_add_group_member(struct sss_domain_info *domain,
                           const char *group,
                           const char *member,
                           enum sysdb_member_type type,
                           bool is_dn);

int sysdb_remove_group_member(struct sss_domain_info *domain,
                              const char *group,
                              const char *member,
                              enum sysdb_member_type type,
                              bool is_dn);

errno_t sysdb_update_members(struct sss_domain_info *domain,
                             const char *member,
                             enum sysdb_member_type type,
                             const char *const *add_groups,
                             const char *const *del_groups);

errno_t sysdb_update_members_dn(struct sss_domain_info *member_domain,
                                const char *member,
                                enum sysdb_member_type type,
                                const char *const *add_groups,
                                const char *const *del_groups);

errno_t sysdb_store_override(struct sss_domain_info *domain,
                             const char *view_name,
                             enum sysdb_member_type type,
                             struct sysdb_attrs *attrs, struct ldb_dn *obj_dn);

errno_t sysdb_store_override_template(struct sss_domain_info *domain,
                                      struct sysdb_attrs *attrs,
                                      const char *global_template_homedir,
                                      const char *global_template_shell,
                                      const char *view_name,
                                      struct ldb_dn *obj_dn);

/*
 * Cache the time of last initgroups invocation. Typically this is not done when
 * the provider-specific request itself finishes, because currently the request
 * might hand over to other requests from a different provider (e.g. an AD user
 * from a trusted domain might need to also call an IPA request to fetch the
 * external groups). Instead, the caller of the initgroups request, typically
 * the DP or the periodical refresh task sets the timestamp.
 */
errno_t sysdb_set_initgr_expire_timestamp(struct sss_domain_info *domain,
                                          const char *name_or_upn_or_sid);

/* Password caching function.
 * If you are in a transaction ignore sysdb and pass in the handle.
 * If you are not in a transaction pass NULL in handle and provide sysdb,
 * in this case a transaction will be automatically started and the
 * function will be completely wrapped in it's own sysdb transaction */
int sysdb_cache_password(struct sss_domain_info *domain,
                         const char *username,
                         const char *password);

int sysdb_cache_password_ex(struct sss_domain_info *domain,
                            const char *username,
                            const char *password,
                            enum sss_authtok_type authtok_type,
                            size_t second_factor_size);

errno_t check_failed_login_attempts(struct confdb_ctx *cdb,
                                    struct ldb_message *ldb_msg,
                                    uint32_t *failed_login_attempts,
                                    time_t *delayed_until);
int sysdb_cache_auth(struct sss_domain_info *domain,
                     const char *name,
                     const char *password,
                     struct confdb_ctx *cdb,
                     bool just_check,
                     time_t *_expire_date,
                     time_t *_delayed_until);

int sysdb_store_custom(struct sss_domain_info *domain,
                       const char *object_name,
                       const char *subtree_name,
                       struct sysdb_attrs *attrs);

int sysdb_search_custom(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *filter,
                        const char *subtree_name,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs);

int sysdb_search_custom_by_name(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *object_name,
                                const char *subtree_name,
                                const char **attrs,
                                size_t *_count,
                                struct ldb_message ***_msgs);

int sysdb_delete_custom(struct sss_domain_info *domain,
                        const char *object_name,
                        const char *subtree_name);

int sysdb_asq_search(TALLOC_CTX *mem_ctx,
                     struct sss_domain_info *domain,
                     struct ldb_dn *base_dn,
                     const char *expression,
                     const char *asq_attribute,
                     const char **attrs,
                     size_t *msgs_count,
                     struct ldb_message ***msgs);

int sysdb_search_users(TALLOC_CTX *mem_ctx,
                       struct sss_domain_info *domain,
                       const char *sub_filter,
                       const char **attrs,
                       size_t *msgs_count,
                       struct ldb_message ***msgs);

enum sysdb_cache_type {
    SYSDB_CACHE_TYPE_NONE,
    SYSDB_CACHE_TYPE_TIMESTAMP,
    SYSDB_CACHE_TYPE_PERSISTENT
};

errno_t sysdb_search_with_ts_attr(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  struct ldb_dn *base_dn,
                                  enum ldb_scope scope,
                                  enum sysdb_cache_type search_cache,
                                  const char *filter,
                                  const char *attrs[],
                                  struct ldb_result **_result);

int sysdb_search_users_by_timestamp(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *sub_filter,
                                    const char *ts_sub_filter,
                                    const char **attrs,
                                    size_t *_msgs_count,
                                    struct ldb_message ***_msgs);

int sysdb_delete_user(struct sss_domain_info *domain,
                      const char *name, uid_t uid);

int sysdb_search_groups(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *sub_filter,
                        const char **attrs,
                        size_t *msgs_count,
                        struct ldb_message ***msgs);

int sysdb_search_groups_by_timestamp(TALLOC_CTX *mem_ctx,
                                     struct sss_domain_info *domain,
                                     const char *sub_filter,
                                     const char *ts_sub_filter,
                                     const char **attrs,
                                     size_t *_msgs_count,
                                     struct ldb_message ***_msgs);

int sysdb_delete_group(struct sss_domain_info *domain,
                       const char *name, gid_t gid);

int sysdb_search_netgroups(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *sub_filter,
                           const char **attrs,
                           size_t *msgs_count,
                           struct ldb_message ***msgs);

int sysdb_delete_netgroup(struct sss_domain_info *domain,
                          const char *name);

int sysdb_delete_by_sid(struct sysdb_ctx *sysdb,
                        struct sss_domain_info *domain,
                        const char *sid_str);

errno_t sysdb_attrs_to_list(TALLOC_CTX *mem_ctx,
                            struct sysdb_attrs **attrs,
                            int attr_count,
                            const char *attr_name,
                            char ***_list);

errno_t sysdb_netgr_to_entries(TALLOC_CTX *mem_ctx,
                               struct ldb_result *res,
                               struct sysdb_netgroup_ctx ***entries,
                               size_t *netgroup_count);

errno_t sysdb_dn_sanitize(TALLOC_CTX *mem_ctx, const char *input,
                          char **sanitized);

errno_t sysdb_get_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *attr_name,
                       bool *value);

errno_t sysdb_set_bool(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *cn_value,
                       const char *attr_name,
                       bool value);

errno_t sysdb_get_uint(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *attr_name,
                       uint32_t *value);

errno_t sysdb_set_uint(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *cn_value,
                       const char *attr_name,
                       uint32_t value);

errno_t sysdb_has_enumerated(struct sss_domain_info *domain,
                             uint32_t provider,
                             bool *has_enumerated);

errno_t sysdb_set_enumerated(struct sss_domain_info *domain,
                             uint32_t provider,
                             bool has_enumerated);

errno_t sysdb_remove_attrs(struct sss_domain_info *domain,
                           const char *name,
                           enum sysdb_member_type type,
                           char **remove_attrs);

/**
 * @brief Return name of direct parents of an object in the cache
 *
 * @param[in]  mem_ctx         Memory context the result should be allocated
 *                             on
 * @param[in]  dom             domain the object is in
 * @param[in]  parent_dom      domain which should be searched for direct
 *                             parents if NULL all domains in the given cache
 *                             are searched
 * @param[in]  mtype           Type of the object, SYSDB_MEMBER_USER or
 *                             SYSDB_MEMBER_GROUP
 * @param[in]  name            Name of the object
 * @param[out] _direct_parents List of names of the direct parent groups
 *
 *
 * @return
 *  - EOK:    success
 *  - EINVAL: wrong mtype
 *  - ENOMEM: Memory allocation failed
 */
errno_t sysdb_get_direct_parents(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *dom,
                                 struct sss_domain_info *parent_dom,
                                 enum sysdb_member_type mtype,
                                 const char *name,
                                 char ***_direct_parents);

/**
 * @brief Return requested attribute of direct parents of an object in the cache
 *
 * @param[in]  mem_ctx         Memory context the result should be allocated
 *                             on
 * @param[in]  dom             domain the object is in
 * @param[in]  parent_dom      domain which should be searched for direct
 *                             parents if NULL all domains in the given cache
 *                             are searched
 * @param[in]  mtype           Type of the object, SYSDB_MEMBER_USER or
 *                             SYSDB_MEMBER_GROUP
 * @param[in]  name            Name of the object
 * @param[in]  attr_name       Name of the attribute to return, if NULL
 *                             SYSDB_NAME will be used
 * @param[out] _direct_parents List of the requested attribute of the direct
 *                             parent groups
 *
 *
 * @return
 *  - EOK:    success
 *  - EINVAL: wrong mtype
 *  - ENOMEM: Memory allocation failed
 */
errno_t sysdb_get_direct_parents_ex(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *dom,
                                    struct sss_domain_info *parent_dom,
                                    enum sysdb_member_type mtype,
                                    const char *name,
                                    const char *attr_name,
                                    char ***_direct_parents);

/* === Functions related to ID-mapping === */

#define SYSDB_IDMAP_CONTAINER "cn=id_mappings"

#define SYSDB_IDMAP_SUBTREE "idmap"
#define SYSDB_IDMAP_MAPPING_OC "id_mapping"
#define SYSDB_IDMAP_FILTER "(objectClass="SYSDB_IDMAP_MAPPING_OC")"
#define SYSDB_IDMAP_SID_ATTR "objectSID"
#define SYSDB_IDMAP_SLICE_ATTR "slice"

#define SYSDB_IDMAP_ATTRS { \
    SYSDB_NAME, \
    SYSDB_IDMAP_SID_ATTR, \
    SYSDB_IDMAP_SLICE_ATTR, \
    NULL }

#define SYSDB_TMPL_IDMAP_BASE SYSDB_IDMAP_CONTAINER",cn=%s,"SYSDB_BASE
#define SYSDB_TMPL_IDMAP SYSDB_IDMAP_SID_ATTR"=%s,"SYSDB_TMPL_IDMAP_BASE

errno_t sysdb_idmap_store_mapping(struct sss_domain_info *domain,
                                  const char *dom_name,
                                  const char *dom_sid,
                                  id_t slice_num);

errno_t sysdb_idmap_get_mappings(TALLOC_CTX *mem_ctx,
                                 struct sss_domain_info *domain,
                                 struct ldb_result **_result);

errno_t sysdb_search_object_by_id(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  uint32_t id,
                                  const char **attrs,
                                  struct ldb_result **res);

errno_t sysdb_search_object_by_name(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *name,
                                    const char **attrs,
                                    struct ldb_result **res);

errno_t sysdb_search_object_by_sid(TALLOC_CTX *mem_ctx,
                                   struct sss_domain_info *domain,
                                   const char *sid_str,
                                   const char **attrs,
                                   struct ldb_result **res);

errno_t sysdb_search_object_by_uuid(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *uuid_str,
                                    const char **attrs,
                                    struct ldb_result **res);

errno_t sysdb_search_object_by_cert(TALLOC_CTX *mem_ctx,
                                    struct sss_domain_info *domain,
                                    const char *cert,
                                    const char **attrs,
                                    struct ldb_result **res);

errno_t sysdb_search_user_by_cert(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *cert,
                                  struct ldb_result **res);

errno_t sysdb_remove_cert(struct sss_domain_info *domain,
                          const char *cert);

errno_t sysdb_remove_mapped_data(struct sss_domain_info *domain,
                                 struct sysdb_attrs *mapped_attr);

/* === Functions related to GPOs === */

#define SYSDB_GPO_CONTAINER "cn=gpos,cn=ad,cn=custom"

/* === Functions related to GPO entries === */

#define SYSDB_GPO_OC "gpo"
#define SYSDB_GPO_FILTER "(objectClass="SYSDB_GPO_OC")"
#define SYSDB_GPO_GUID_FILTER "(&(objectClass="SYSDB_GPO_OC")("SYSDB_GPO_GUID_ATTR"=%s))"
#define SYSDB_GPO_GUID_ATTR "gpoGUID"
#define SYSDB_GPO_VERSION_ATTR "gpoVersion"
#define SYSDB_GPO_TIMEOUT_ATTR "gpoPolicyFileTimeout"

#define SYSDB_TMPL_GPO_BASE SYSDB_GPO_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_GPO SYSDB_GPO_GUID_ATTR"=%s,"SYSDB_TMPL_GPO_BASE

#define SYSDB_GPO_ATTRS { \
        SYSDB_NAME, \
        SYSDB_GPO_GUID_ATTR, \
        SYSDB_GPO_VERSION_ATTR, \
        SYSDB_GPO_TIMEOUT_ATTR, \
        NULL }

errno_t sysdb_gpo_store_gpo(struct sss_domain_info *domain,
                            const char *gpo_guid,
                            int gpo_version,
                            int cache_timeout,
                            time_t now);

errno_t sysdb_gpo_get_gpo_by_guid(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *domain,
                                  const char *gpo_guid,
                                  struct ldb_result **_result);

errno_t sysdb_gpo_get_gpos(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           struct ldb_result **_result);

/* === Functions related to GPO Result object === */

#define SYSDB_GPO_RESULT_OC "gpo_result"
#define SYSDB_GPO_RESULT_FILTER "(objectClass="SYSDB_GPO_RESULT_OC")"

#define SYSDB_TMPL_GPO_RESULT_BASE SYSDB_GPO_CONTAINER","SYSDB_DOM_BASE
#define SYSDB_TMPL_GPO_RESULT "cn=%s,"SYSDB_TMPL_GPO_RESULT_BASE

errno_t sysdb_gpo_delete_gpo_result_object(TALLOC_CTX *mem_ctx,
                                           struct sss_domain_info *domain);

errno_t sysdb_gpo_store_gpo_result_setting(struct sss_domain_info *domain,
                                           const char *policy_setting_key,
                                           const char *policy_setting_value);

errno_t sysdb_gpo_get_gpo_result_setting(TALLOC_CTX *mem_ctx,
                                         struct sss_domain_info *domain,
                                         const char *policy_setting_key,
                                         const char **policy_setting_value);

errno_t sysdb_get_sids_of_members(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom,
                                  const char *group_name,
                                  const char ***_sids,
                                  const char ***_dns,
                                  size_t *_n);

errno_t sysdb_handle_original_uuid(const char *orig_name,
                                   struct sysdb_attrs *src_attrs,
                                   const char *src_name,
                                   struct sysdb_attrs *dest_attrs,
                                   const char *dest_name);

errno_t sysdb_cert_derb64_to_ldap_filter(TALLOC_CTX *mem_ctx,
                                         const char *derb64,
                                         const char *attr_name,
                                         char **ldap_filter);

/* define old name for backward compatibility */
#define sysdb_error_to_errno(ldberr) sss_ldb_error_to_errno(ldberr)

void ldb_debug_messages(void *context, enum ldb_debug_level level,
                        const char *fmt, va_list ap);

/* Try to detect the object domain from the object's SYSDB_NAME attribute and
 * return the matching sss_domain_info. This should work reliable with user
 * and group objects since fully-qualified names are used here. If the proper
 * domain cannot be detected the given domain is returned. */
struct sss_domain_info *find_domain_by_msg(struct sss_domain_info *dom,
                                           struct ldb_message *msg);

#endif /* __SYS_DB_H__ */
