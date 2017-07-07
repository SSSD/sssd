/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007
   Copyright (C) Volker Lendecke 2009
   Copyright (C) Matthew Newton 2015

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

#ifndef _WBCLIENT_H
#define _WBCLIENT_H

#include <pwd.h>
#include <grp.h>

/* Define error types */

/**
 *  @brief Status codes returned from wbc functions
 **/

enum _wbcErrType {
    WBC_ERR_SUCCESS = 0,             /**< Successful completion **/
    WBC_ERR_NOT_IMPLEMENTED,         /**< Function not implemented **/
    WBC_ERR_UNKNOWN_FAILURE,         /**< General failure **/
    WBC_ERR_NO_MEMORY,               /**< Memory allocation error **/
    WBC_ERR_INVALID_SID,             /**< Invalid SID format **/
    WBC_ERR_INVALID_PARAM,           /**< An Invalid parameter was supplied **/
    WBC_ERR_WINBIND_NOT_AVAILABLE,   /**< Winbind daemon is not available **/
    WBC_ERR_DOMAIN_NOT_FOUND,        /**< Domain is not trusted or cannot be found **/
    WBC_ERR_INVALID_RESPONSE,        /**< Winbind returned an invalid response **/
    WBC_ERR_NSS_ERROR,               /**< NSS_STATUS error **/
    WBC_ERR_AUTH_ERROR,              /**< Authentication failed **/
    WBC_ERR_UNKNOWN_USER,            /**< User account cannot be found */
    WBC_ERR_UNKNOWN_GROUP,           /**< Group account cannot be found */
    WBC_ERR_PWD_CHANGE_FAILED        /**< Password Change has failed */
};

typedef enum _wbcErrType wbcErr;

#define WBC_ERROR_IS_OK(x) ((x) == WBC_ERR_SUCCESS)

const char *wbcErrorString(wbcErr error);

/**
 *  @brief Some useful details about the wbclient library
 *
 *  0.1: Initial version
 *  0.2: Added wbcRemoveUidMapping()
 *       Added wbcRemoveGidMapping()
 *  0.3: Added wbcGetpwsid()
 *     Added wbcGetSidAliases()
 *  0.4: Added wbcSidTypeString()
 *  0.5: Added wbcChangeTrustCredentials()
 *  0.6: Made struct wbcInterfaceDetails char* members non-const
 *  0.7: Added wbcSidToStringBuf()
 *  0.8: Added wbcSidsToUnixIds() and wbcLookupSids()
 *  0.9: Added support for WBC_ID_TYPE_BOTH
 *  0.10: Added wbcPingDc2()
 *  0.11: Extended wbcAuthenticateUserEx to provide PAC parsing
 *  0.12: Added wbcCtxCreate and friends
 *  0.13: Added wbcCtxUnixIdsToSids and wbcUnixIdsToSids
 *  0.14: Added "authoritative" to wbcAuthErrorInfo
 *        Added WBC_SID_NAME_LABEL
 **/
#define WBCLIENT_MAJOR_VERSION 0
#define WBCLIENT_MINOR_VERSION 14
#define WBCLIENT_VENDOR_VERSION "Samba libwbclient"
struct wbcLibraryDetails {
    uint16_t major_version;
    uint16_t minor_version;
    const char *vendor_version;
};

/**
 *  @brief Some useful details about the running winbindd
 *
 **/
struct wbcInterfaceDetails {
    uint32_t interface_version;
    char *winbind_version;
    char winbind_separator;
    char *netbios_name;
    char *netbios_domain;
    char *dns_domain;
};

/**
 *  @brief Library context data
 *
 **/

struct wbcContext;

/*
 * Data types used by the Winbind Client API
 */

#ifndef WBC_MAXSUBAUTHS
#define WBC_MAXSUBAUTHS 15 /* max sub authorities in a SID */
#endif

/**
 *  @brief Windows Security Identifier
 *
 **/

struct wbcDomainSid {
    uint8_t   sid_rev_num;
    uint8_t   num_auths;
    uint8_t   id_auth[6];
    uint32_t  sub_auths[WBC_MAXSUBAUTHS];
};

/**
 * @brief Security Identifier type
 **/

enum wbcSidType {
    WBC_SID_NAME_USE_NONE=0,
    WBC_SID_NAME_USER=1,
    WBC_SID_NAME_DOM_GRP=2,
    WBC_SID_NAME_DOMAIN=3,
    WBC_SID_NAME_ALIAS=4,
    WBC_SID_NAME_WKN_GRP=5,
    WBC_SID_NAME_DELETED=6,
    WBC_SID_NAME_INVALID=7,
    WBC_SID_NAME_UNKNOWN=8,
    WBC_SID_NAME_COMPUTER=9,
    WBC_SID_NAME_LABEL=10
};

/**
 * @brief Security Identifier with attributes
 **/

struct wbcSidWithAttr {
    struct wbcDomainSid sid;
    uint32_t attributes;
};

/* wbcSidWithAttr->attributes */

#define WBC_SID_ATTR_GROUP_MANDATORY             0x00000001
#define WBC_SID_ATTR_GROUP_ENABLED_BY_DEFAULT    0x00000002
#define WBC_SID_ATTR_GROUP_ENABLED               0x00000004
#define WBC_SID_ATTR_GROUP_OWNER                 0x00000008
#define WBC_SID_ATTR_GROUP_USEFOR_DENY_ONLY      0x00000010
#define WBC_SID_ATTR_GROUP_RESOURCE              0x20000000
#define WBC_SID_ATTR_GROUP_LOGON_ID              0xC0000000

/**
 *  @brief Windows GUID
 *
 **/

struct wbcGuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq[2];
    uint8_t node[6];
};

/**
 * @brief Domain Information
 **/

struct wbcDomainInfo {
    char *short_name;
    char *dns_name;
    struct wbcDomainSid sid;
    uint32_t domain_flags;
    uint32_t trust_flags;
    uint32_t trust_type;
};

/* wbcDomainInfo->domain_flags */

#define WBC_DOMINFO_DOMAIN_UNKNOWN    0x00000000
#define WBC_DOMINFO_DOMAIN_NATIVE     0x00000001
#define WBC_DOMINFO_DOMAIN_AD         0x00000002
#define WBC_DOMINFO_DOMAIN_PRIMARY    0x00000004
#define WBC_DOMINFO_DOMAIN_OFFLINE    0x00000008

/* wbcDomainInfo->trust_flags */

#define WBC_DOMINFO_TRUST_TRANSITIVE  0x00000001
#define WBC_DOMINFO_TRUST_INCOMING    0x00000002
#define WBC_DOMINFO_TRUST_OUTGOING    0x00000004

/* wbcDomainInfo->trust_type */

#define WBC_DOMINFO_TRUSTTYPE_NONE       0x00000000
#define WBC_DOMINFO_TRUSTTYPE_FOREST     0x00000001
#define WBC_DOMINFO_TRUSTTYPE_IN_FOREST  0x00000002
#define WBC_DOMINFO_TRUSTTYPE_EXTERNAL   0x00000003

/**
 * @brief Generic Blob
 **/

struct wbcBlob {
    uint8_t *data;
    size_t length;
};

/**
 * @brief Named Blob
 **/

struct wbcNamedBlob {
    const char *name;
    uint32_t flags;
    struct wbcBlob blob;
};

/**
 * @brief Auth User Parameters
 **/

struct wbcAuthUserParams {
    const char *account_name;
    const char *domain_name;
    const char *workstation_name;

    uint32_t flags;

    uint32_t parameter_control;

    enum wbcAuthUserLevel {
        WBC_AUTH_USER_LEVEL_PLAIN = 1,
        WBC_AUTH_USER_LEVEL_HASH = 2,
        WBC_AUTH_USER_LEVEL_RESPONSE = 3,
        WBC_AUTH_USER_LEVEL_PAC = 4
    } level;
    union {
        const char *plaintext;
        struct {
            uint8_t nt_hash[16];
            uint8_t lm_hash[16];
        } hash;
        struct {
            uint8_t challenge[8];
            uint32_t nt_length;
            uint8_t *nt_data;
            uint32_t lm_length;
            uint8_t *lm_data;
        } response;
        struct wbcBlob pac;
    } password;
};

/**
 * @brief Logon User Parameters
 **/

struct wbcLogonUserParams {
    const char *username;
    const char *password;
    size_t num_blobs;
    struct wbcNamedBlob *blobs;
};

/**
 * @brief ChangePassword Parameters
 **/

struct wbcChangePasswordParams {
    const char *account_name;
    const char *domain_name;

    uint32_t flags;

    enum wbcChangePasswordLevel {
        WBC_CHANGE_PASSWORD_LEVEL_PLAIN = 1,
        WBC_CHANGE_PASSWORD_LEVEL_RESPONSE = 2
    } level;

    union {
        const char *plaintext;
        struct {
            uint32_t old_nt_hash_enc_length;
            uint8_t *old_nt_hash_enc_data;
            uint32_t old_lm_hash_enc_length;
            uint8_t *old_lm_hash_enc_data;
        } response;
    } old_password;
    union {
        const char *plaintext;
        struct {
            uint32_t nt_length;
            uint8_t *nt_data;
            uint32_t lm_length;
            uint8_t *lm_data;
        } response;
    } new_password;
};

/* wbcAuthUserParams->parameter_control */

#define WBC_MSV1_0_CLEARTEXT_PASSWORD_ALLOWED         0x00000002
#define WBC_MSV1_0_UPDATE_LOGON_STATISTICS            0x00000004
#define WBC_MSV1_0_RETURN_USER_PARAMETERS             0x00000008
#define WBC_MSV1_0_ALLOW_SERVER_TRUST_ACCOUNT         0x00000020
#define WBC_MSV1_0_RETURN_PROFILE_PATH                0x00000200
#define WBC_MSV1_0_ALLOW_WORKSTATION_TRUST_ACCOUNT    0x00000800
#define WBC_MSV1_0_ALLOW_MSVCHAPV2                    0x00010000

/* wbcAuthUserParams->flags */

#define WBC_AUTH_PARAM_FLAGS_INTERACTIVE_LOGON        0x00000001

/**
 * @brief Auth User Information
 *
 * Some of the strings are maybe NULL
 **/

struct wbcAuthUserInfo {
    uint32_t user_flags;

    char *account_name;
    char *user_principal;
    char *full_name;
    char *domain_name;
    char *dns_domain_name;

    uint32_t acct_flags;
    uint8_t user_session_key[16];
    uint8_t lm_session_key[8];

    uint16_t logon_count;
    uint16_t bad_password_count;

    uint64_t logon_time;
    uint64_t logoff_time;
    uint64_t kickoff_time;
    uint64_t pass_last_set_time;
    uint64_t pass_can_change_time;
    uint64_t pass_must_change_time;

    char *logon_server;
    char *logon_script;
    char *profile_path;
    char *home_directory;
    char *home_drive;

    /*
     * the 1st one is the account sid
     * the 2nd one is the primary_group sid
     * followed by the rest of the groups
     */
    uint32_t num_sids;
    struct wbcSidWithAttr *sids;
};

/**
 * @brief Logon User Information
 *
 * Some of the strings are maybe NULL
 **/

struct wbcLogonUserInfo {
    struct wbcAuthUserInfo *info;
    size_t num_blobs;
    struct wbcNamedBlob *blobs;
};

/* wbcAuthUserInfo->user_flags */

#define WBC_AUTH_USER_INFO_GUEST                       0x00000001
#define WBC_AUTH_USER_INFO_NOENCRYPTION                0x00000002
#define WBC_AUTH_USER_INFO_CACHED_ACCOUNT              0x00000004
#define WBC_AUTH_USER_INFO_USED_LM_PASSWORD            0x00000008
#define WBC_AUTH_USER_INFO_EXTRA_SIDS                  0x00000020
#define WBC_AUTH_USER_INFO_SUBAUTH_SESSION_KEY         0x00000040
#define WBC_AUTH_USER_INFO_SERVER_TRUST_ACCOUNT        0x00000080
#define WBC_AUTH_USER_INFO_NTLMV2_ENABLED              0x00000100
#define WBC_AUTH_USER_INFO_RESOURCE_GROUPS             0x00000200
#define WBC_AUTH_USER_INFO_PROFILE_PATH_RETURNED       0x00000400
#define WBC_AUTH_USER_INFO_GRACE_LOGON                 0x01000000

/* wbcAuthUserInfo->acct_flags */

#define WBC_ACB_DISABLED                   0x00000001 /* 1 User account disabled */
#define WBC_ACB_HOMDIRREQ                  0x00000002 /* 1 Home directory required */
#define WBC_ACB_PWNOTREQ                   0x00000004 /* 1 User password not required */
#define WBC_ACB_TEMPDUP                    0x00000008 /* 1 Temporary duplicate account */
#define WBC_ACB_NORMAL                     0x00000010 /* 1 Normal user account */
#define WBC_ACB_MNS                        0x00000020 /* 1 MNS logon user account */
#define WBC_ACB_DOMTRUST                   0x00000040 /* 1 Interdomain trust account */
#define WBC_ACB_WSTRUST                    0x00000080 /* 1 Workstation trust account */
#define WBC_ACB_SVRTRUST                   0x00000100 /* 1 Server trust account */
#define WBC_ACB_PWNOEXP                    0x00000200 /* 1 User password does not expire */
#define WBC_ACB_AUTOLOCK                   0x00000400 /* 1 Account auto locked */
#define WBC_ACB_ENC_TXT_PWD_ALLOWED        0x00000800 /* 1 Encryped text password is allowed */
#define WBC_ACB_SMARTCARD_REQUIRED         0x00001000 /* 1 Smart Card required */
#define WBC_ACB_TRUSTED_FOR_DELEGATION     0x00002000 /* 1 Trusted for Delegation */
#define WBC_ACB_NOT_DELEGATED              0x00004000 /* 1 Not delegated */
#define WBC_ACB_USE_DES_KEY_ONLY           0x00008000 /* 1 Use DES key only */
#define WBC_ACB_DONT_REQUIRE_PREAUTH       0x00010000 /* 1 Preauth not required */
#define WBC_ACB_PW_EXPIRED                 0x00020000 /* 1 Password Expired */
#define WBC_ACB_NO_AUTH_DATA_REQD          0x00080000   /* 1 = No authorization data required */

struct wbcAuthErrorInfo {
    uint32_t nt_status;
    char *nt_string;
    int32_t pam_error;
    char *display_string;
    uint8_t authoritative;
};

/**
 * @brief User Password Policy Information
 **/

/* wbcUserPasswordPolicyInfo->password_properties */

#define WBC_DOMAIN_PASSWORD_COMPLEX           0x00000001
#define WBC_DOMAIN_PASSWORD_NO_ANON_CHANGE    0x00000002
#define WBC_DOMAIN_PASSWORD_NO_CLEAR_CHANGE   0x00000004
#define WBC_DOMAIN_PASSWORD_LOCKOUT_ADMINS    0x00000008
#define WBC_DOMAIN_PASSWORD_STORE_CLEARTEXT   0x00000010
#define WBC_DOMAIN_REFUSE_PASSWORD_CHANGE     0x00000020

struct wbcUserPasswordPolicyInfo {
    uint32_t min_length_password;
    uint32_t password_history;
    uint32_t password_properties;
    uint64_t expire;
    uint64_t min_passwordage;
};

/**
 * @brief Change Password Reject Reason
 **/

enum wbcPasswordChangeRejectReason {
    WBC_PWD_CHANGE_NO_ERROR=0,
    WBC_PWD_CHANGE_PASSWORD_TOO_SHORT=1,
    WBC_PWD_CHANGE_PWD_IN_HISTORY=2,
    WBC_PWD_CHANGE_USERNAME_IN_PASSWORD=3,
    WBC_PWD_CHANGE_FULLNAME_IN_PASSWORD=4,
    WBC_PWD_CHANGE_NOT_COMPLEX=5,
    WBC_PWD_CHANGE_MACHINE_NOT_DEFAULT=6,
    WBC_PWD_CHANGE_FAILED_BY_FILTER=7,
    WBC_PWD_CHANGE_PASSWORD_TOO_LONG=8
};

/* Note: this defines exist for compatibility reasons with existing code */
#define WBC_PWD_CHANGE_REJECT_OTHER      WBC_PWD_CHANGE_NO_ERROR
#define WBC_PWD_CHANGE_REJECT_TOO_SHORT  WBC_PWD_CHANGE_PASSWORD_TOO_SHORT
#define WBC_PWD_CHANGE_REJECT_IN_HISTORY WBC_PWD_CHANGE_PWD_IN_HISTORY
#define WBC_PWD_CHANGE_REJECT_COMPLEXITY WBC_PWD_CHANGE_NOT_COMPLEX

/**
 * @brief Logoff User Parameters
 **/

struct wbcLogoffUserParams {
    const char *username;
    size_t num_blobs;
    struct wbcNamedBlob *blobs;
};

/** @brief Credential cache log-on parameters
 *
 */

struct wbcCredentialCacheParams {
        const char *account_name;
        const char *domain_name;
        enum wbcCredentialCacheLevel {
                WBC_CREDENTIAL_CACHE_LEVEL_NTLMSSP = 1
        } level;
        size_t num_blobs;
        struct wbcNamedBlob *blobs;
};


/** @brief Info returned by credential cache auth
 *
 */

struct wbcCredentialCacheInfo {
        size_t num_blobs;
        struct wbcNamedBlob *blobs;
};

/*
 * DomainControllerInfo struct
 */
struct wbcDomainControllerInfo {
    char *dc_name;
};

/*
 * DomainControllerInfoEx struct
 */
struct wbcDomainControllerInfoEx {
    const char *dc_unc;
    const char *dc_address;
    uint16_t dc_address_type;
    struct wbcGuid *domain_guid;
    const char *domain_name;
    const char *forest_name;
    uint32_t dc_flags;
    const char *dc_site_name;
    const char *client_site_name;
};

/**********************************************************
 * Memory Management
 **********************************************************/

/**
 * @brief Free library allocated memory
 *
 * @param * Pointer to free
 *
 * @return void
 **/
void wbcFreeMemory(void*);


/**********************************************************
 * Context Management
 **********************************************************/

/**
 * @brief Create a new wbcContext context
 *
 * @return wbcContext
 **/
struct wbcContext *wbcCtxCreate(void);

/**
 * @brief Free a library context
 *
 * @param ctx           wbcContext to free
 *
 * @return void
 **/
void wbcCtxFree(struct wbcContext *ctx);



/*
 * Utility functions for dealing with SIDs
 */

/**
 * @brief Get a string representation of the SID type
 *
 * @param type        type of the SID
 *
 * @return string representation of the SID type
 */
const char* wbcSidTypeString(enum wbcSidType type);

#define WBC_SID_STRING_BUFLEN (15*11+25)

/*
 * @brief Print a sid into a buffer
 *
 * @param sid        Binary Security Identifier
 * @param buf        Target buffer
 * @param buflen    Target buffer length
 *
 * @return Resulting string length.
 */
int wbcSidToStringBuf(const struct wbcDomainSid *sid, char *buf, int buflen);

/**
 * @brief Convert a binary SID to a character string
 *
 * @param sid           Binary Security Identifier
 * @param **sid_string  Resulting character string
 *
 * @return #wbcErr
 **/
wbcErr wbcSidToString(const struct wbcDomainSid *sid,
                      char **sid_string);

/**
 * @brief Convert a character string to a binary SID
 *
 * @param *sid_string   Character string in the form of S-...
 * @param sid           Resulting binary SID
 *
 * @return #wbcErr
 **/
wbcErr wbcStringToSid(const char *sid_string,
                      struct wbcDomainSid *sid);

/*
 * Utility functions for dealing with GUIDs
 */

/**
 * @brief Convert a binary GUID to a character string
 *
 * @param guid           Binary Guid
 * @param **guid_string  Resulting character string
 *
 * @return #wbcErr
 **/
wbcErr wbcGuidToString(const struct wbcGuid *guid,
                       char **guid_string);

/**
 * @brief Convert a character string to a binary GUID
 *
 * @param *guid_string  Character string
 * @param guid          Resulting binary GUID
 *
 * @return #wbcErr
 **/
wbcErr wbcStringToGuid(const char *guid_string,
                       struct wbcGuid *guid);

/**
 * @brief Ping winbindd to see if the daemon is running
 *
 * @param *ctx        wbclient Context
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxPing(struct wbcContext *ctx);

/**
 * @brief Ping winbindd to see if the daemon is running
 *
 * @return #wbcErr
 **/
wbcErr wbcPing(void);

wbcErr wbcLibraryDetails(struct wbcLibraryDetails **details);

wbcErr wbcCtxInterfaceDetails(struct wbcContext *ctx,
                              struct wbcInterfaceDetails **details);
wbcErr wbcInterfaceDetails(struct wbcInterfaceDetails **details);

/**********************************************************
 * Name/SID conversion
 **********************************************************/

/**
 * @brief Convert a domain and name to SID
 *
 * @param *ctx        wbclient Context
 * @param dom_name    Domain name (possibly "")
 * @param name        User or group name
 * @param *sid        Pointer to the resolved domain SID
 * @param *name_type  Pointer to the SID type
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLookupName(struct wbcContext *ctx,
                        const char *dom_name,
                        const char *name,
                        struct wbcDomainSid *sid,
                        enum wbcSidType *name_type);

/**
 * @brief Convert a domain and name to SID
 *
 * @param dom_name    Domain name (possibly "")
 * @param name        User or group name
 * @param *sid        Pointer to the resolved domain SID
 * @param *name_type  Pointer to the SID type
 *
 * @return #wbcErr
 **/
wbcErr wbcLookupName(const char *dom_name,
                     const char *name,
                     struct wbcDomainSid *sid,
                     enum wbcSidType *name_type);

/**
 * @brief Convert a SID to a domain and name
 *
 * @param *ctx       wbclient Context
 * @param *sid       Pointer to the domain SID to be resolved
 * @param domain     Resolved Domain name (possibly "")
 * @param name       Resolved User or group name
 * @param *name_type Pointer to the resolved SID type
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLookupSid(struct wbcContext *ctx,
                       const struct wbcDomainSid *sid,
                       char **domain,
                       char **name,
                       enum wbcSidType *name_type);

/**
 * @brief Convert a SID to a domain and name
 *
 * @param *sid       Pointer to the domain SID to be resolved
 * @param domain     Resolved Domain name (possibly "")
 * @param name       Resolved User or group name
 * @param *name_type Pointer to the resolved SID type
 *
 * @return #wbcErr
 **/
wbcErr wbcLookupSid(const struct wbcDomainSid *sid,
                    char **domain,
                    char **name,
                    enum wbcSidType *name_type);

struct wbcTranslatedName {
        enum wbcSidType type;
        char *name;
        int domain_index;
};

wbcErr wbcCtxLookupSids(struct wbcContext *ctx,
                        const struct wbcDomainSid *sids, int num_sids,
                        struct wbcDomainInfo **domains, int *num_domains,
                        struct wbcTranslatedName **names);

wbcErr wbcLookupSids(const struct wbcDomainSid *sids, int num_sids,
                     struct wbcDomainInfo **domains, int *num_domains,
                     struct wbcTranslatedName **names);

/**
 * @brief Translate a collection of RIDs within a domain to names
 */
wbcErr wbcCtxLookupRids(struct wbcContext *ctx,
                        struct wbcDomainSid *dom_sid,
                        int num_rids,
                        uint32_t *rids,
                        const char **domain_name,
                        const char ***names,
                        enum wbcSidType **types);

/**
 * @brief Translate a collection of RIDs within a domain to names
 */
wbcErr wbcLookupRids(struct wbcDomainSid *dom_sid,
                     int num_rids,
                     uint32_t *rids,
                     const char **domain_name,
                     const char ***names,
                     enum wbcSidType **types);

/*
 * @brief Get the groups a user belongs to
 **/
wbcErr wbcCtxLookupUserSids(struct wbcContext *ctx,
                            const struct wbcDomainSid *user_sid,
                            bool domain_groups_only,
                            uint32_t *num_sids,
                            struct wbcDomainSid **sids);

/*
 * @brief Get the groups a user belongs to
 **/
wbcErr wbcLookupUserSids(const struct wbcDomainSid *user_sid,
                         bool domain_groups_only,
                         uint32_t *num_sids,
                         struct wbcDomainSid **sids);

/*
 * @brief Get alias membership for sids
 **/
wbcErr wbcCtxGetSidAliases(struct wbcContext *ctx,
                           const struct wbcDomainSid *dom_sid,
                           struct wbcDomainSid *sids,
                           uint32_t num_sids,
                           uint32_t **alias_rids,
                           uint32_t *num_alias_rids);

/*
 * @brief Get alias membership for sids
 **/
wbcErr wbcGetSidAliases(const struct wbcDomainSid *dom_sid,
                        struct wbcDomainSid *sids,
                        uint32_t num_sids,
                        uint32_t **alias_rids,
                        uint32_t *num_alias_rids);

/**
 * @brief Lists Users
 **/
wbcErr wbcCtxListUsers(struct wbcContext *ctx,
                       const char *domain_name,
                       uint32_t *num_users,
                       const char ***users);

/**
 * @brief Lists Users
 **/
wbcErr wbcListUsers(const char *domain_name,
                    uint32_t *num_users,
                    const char ***users);

/**
 * @brief Lists Groups
 **/
wbcErr wbcCtxListGroups(struct wbcContext *ctx,
                        const char *domain_name,
                        uint32_t *num_groups,
                        const char ***groups);

/**
 * @brief Lists Groups
 **/
wbcErr wbcListGroups(const char *domain_name,
                     uint32_t *num_groups,
                     const char ***groups);

wbcErr wbcCtxGetDisplayName(struct wbcContext *ctx,
                            const struct wbcDomainSid *sid,
                            char **pdomain,
                            char **pfullname,
                            enum wbcSidType *pname_type);

wbcErr wbcGetDisplayName(const struct wbcDomainSid *sid,
                         char **pdomain,
                         char **pfullname,
                         enum wbcSidType *pname_type);

/**********************************************************
 * SID/uid/gid Mappings
 **********************************************************/

/**
 * @brief Convert a Windows SID to a Unix uid, allocating an uid if needed
 *
 * @param *ctx        wbclient Context
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *puid       Pointer to the resolved uid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxSidToUid(struct wbcContext *ctx,
                      const struct wbcDomainSid *sid,
                      uid_t *puid);

/**
 * @brief Convert a Windows SID to a Unix uid, allocating an uid if needed
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *puid       Pointer to the resolved uid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcSidToUid(const struct wbcDomainSid *sid,
                   uid_t *puid);

/**
 * @brief Convert a Windows SID to a Unix uid if there already is a mapping
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *puid       Pointer to the resolved uid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcQuerySidToUid(const struct wbcDomainSid *sid,
                        uid_t *puid);

/**
 * @brief Convert a Unix uid to a Windows SID, allocating a SID if needed
 *
 * @param *ctx        wbclient Context
 * @param uid         Unix uid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxUidToSid(struct wbcContext *ctx, uid_t uid,
                      struct wbcDomainSid *sid);

/**
 * @brief Convert a Unix uid to a Windows SID, allocating a SID if needed
 *
 * @param uid         Unix uid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcUidToSid(uid_t uid,
                   struct wbcDomainSid *sid);

/**
 * @brief Convert a Unix uid to a Windows SID if there already is a mapping
 *
 * @param uid         Unix uid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcQueryUidToSid(uid_t uid,
                        struct wbcDomainSid *sid);

/**
 * @brief Convert a Windows SID to a Unix gid, allocating a gid if needed
 *
 * @param *ctx        wbclient Context
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxSidToGid(struct wbcContext *ctx,
                      const struct wbcDomainSid *sid,
                      gid_t *pgid);

/**
 * @brief Convert a Windows SID to a Unix gid, allocating a gid if needed
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcSidToGid(const struct wbcDomainSid *sid,
                   gid_t *pgid);

/**
 * @brief Convert a Windows SID to a Unix gid if there already is a mapping
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcQuerySidToGid(const struct wbcDomainSid *sid,
                        gid_t *pgid);

/**
 * @brief Convert a Unix gid to a Windows SID, allocating a SID if needed
 *
 * @param *ctx        wbclient Context
 * @param gid         Unix gid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxGidToSid(struct wbcContext *ctx, gid_t gid,
                   struct wbcDomainSid *sid);

/**
 * @brief Convert a Unix gid to a Windows SID, allocating a SID if needed
 *
 * @param gid         Unix gid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcGidToSid(gid_t gid,
                   struct wbcDomainSid *sid);

/**
 * @brief Convert a Unix gid to a Windows SID if there already is a mapping
 *
 * @param gid         Unix gid to be resolved
 * @param *sid        Pointer to the resolved domain SID
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcQueryGidToSid(gid_t gid,
                        struct wbcDomainSid *sid);

enum wbcIdType {
        WBC_ID_TYPE_NOT_SPECIFIED,
        WBC_ID_TYPE_UID,
        WBC_ID_TYPE_GID,
        WBC_ID_TYPE_BOTH
};

union wbcUnixIdContainer {
        uid_t uid;
        gid_t gid;
};

struct wbcUnixId {
        enum wbcIdType type;
        union wbcUnixIdContainer id;
};

/**
 * @brief Convert a list of sids to unix ids
 *
 * @param *ctx        wbclient Context
 * @param sids        Pointer to an array of SIDs to convert
 * @param num_sids    Number of SIDs
 * @param ids         Preallocated output array for translated IDs
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxSidsToUnixIds(struct wbcContext *ctx,
                           const struct wbcDomainSid *sids, uint32_t num_sids,
                           struct wbcUnixId *ids);

/**
 * @brief Convert a list of sids to unix ids
 *
 * @param sids        Pointer to an array of SIDs to convert
 * @param num_sids    Number of SIDs
 * @param ids         Preallocated output array for translated IDs
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcSidsToUnixIds(const struct wbcDomainSid *sids, uint32_t num_sids,
                        struct wbcUnixId *ids);

/**
 * @brief Convert a list of unix ids to sids
 *
 * @param ctx         wbclient Context
 * @param ids         Pointer to an array of UNIX IDs to convert
 * @param num_ids     Number of UNIX IDs
 * @param sids        Preallocated output array for translated SIDs
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxUnixIdsToSids(struct wbcContext *ctx,
                           const struct wbcUnixId *ids, uint32_t num_ids,
                           struct wbcDomainSid *sids);

/**
 * @brief Convert a list of unix ids to sids
 *
 * @param ids         Pointer to an array of UNIX IDs to convert
 * @param num_ids     Number of UNIX IDs
 * @param sids        Preallocated output array for translated SIDs
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcUnixIdsToSids(const struct wbcUnixId *ids, uint32_t num_ids,
                        struct wbcDomainSid *sids);

/**
 * @brief Obtain a new uid from Winbind
 *
 * @param *ctx        wbclient Context
 * @param *puid       Pointer to the allocated uid
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxAllocateUid(struct wbcContext *ctx, uid_t *puid);

/**
 * @brief Obtain a new uid from Winbind
 *
 * @param *puid       Pointer to the allocated uid
 *
 * @return #wbcErr
 **/
wbcErr wbcAllocateUid(uid_t *puid);

/**
 * @brief Obtain a new gid from Winbind
 *
 * @param *ctx        wbclient Context
 * @param *pgid       Pointer to the allocated gid
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxAllocateGid(struct wbcContext *ctx, gid_t *pgid);

/**
 * @brief Obtain a new gid from Winbind
 *
 * @param *pgid       Pointer to the allocated gid
 *
 * @return #wbcErr
 **/
wbcErr wbcAllocateGid(gid_t *pgid);

/**
 * @brief Set an user id mapping
 *
 * @param uid       Uid of the desired mapping.
 * @param *sid      Pointer to the sid of the desired mapping.
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcSetUidMapping(uid_t uid, const struct wbcDomainSid *sid);

/**
 * @brief Set a group id mapping
 *
 * @param gid       Gid of the desired mapping.
 * @param *sid      Pointer to the sid of the desired mapping.
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcSetGidMapping(gid_t gid, const struct wbcDomainSid *sid);

/**
 * @brief Remove a user id mapping
 *
 * @param uid       Uid of the mapping to remove.
 * @param *sid      Pointer to the sid of the mapping to remove.
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcRemoveUidMapping(uid_t uid, const struct wbcDomainSid *sid);

/**
 * @brief Remove a group id mapping
 *
 * @param gid       Gid of the mapping to remove.
 * @param *sid      Pointer to the sid of the mapping to remove.
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcRemoveGidMapping(gid_t gid, const struct wbcDomainSid *sid);

/**
 * @brief Set the highwater mark for allocated uids.
 *
 * @param uid_hwm      The new uid highwater mark value
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcSetUidHwm(uid_t uid_hwm);

/**
 * @brief Set the highwater mark for allocated gids.
 *
 * @param gid_hwm      The new gid highwater mark value
 *
 * @return #wbcErr
 *
 * @deprecated      This method is not impemented any more and should
 *                  be removed in the next major version change.
 **/
wbcErr wbcSetGidHwm(gid_t gid_hwm);

/**********************************************************
 * NSS Lookup User/Group details
 **********************************************************/

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *ctx      wbclient Context
 * @param *name     Username to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetpwnam(struct wbcContext *ctx,
                      const char *name, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *name     Username to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetpwnam(const char *name, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param *ctx      wbclient Context
 * @param uid       Uid to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetpwuid(struct wbcContext *ctx,
                      uid_t uid, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param uid       Uid to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetpwuid(uid_t uid, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on sid
 *
 * @param *ctx         wbclient Context
 * @param sid       Sid to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetpwsid(struct wbcContext *ctx,
                      struct wbcDomainSid * sid, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on sid
 *
 * @param sid       Sid to lookup
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetpwsid(struct wbcDomainSid * sid, struct passwd **pwd);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *ctx      wbclient Context
 * @param *name     Username to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetgrnam(struct wbcContext *ctx,
                      const char *name, struct group **grp);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on username
 *
 * @param *name     Username to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetgrnam(const char *name, struct group **grp);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param *ctx      wbclient Context
 * @param gid       Uid to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetgrgid(struct wbcContext *ctx,
                      gid_t gid, struct group **grp);

/**
 * @brief Fill in a struct passwd* for a domain user based
 *   on uid
 *
 * @param gid       Uid to lookup
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetgrgid(gid_t gid, struct group **grp);

/**
 * @brief Reset the passwd iterator
 *
 * @param *ctx      wbclient Context
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxSetpwent(struct wbcContext *ctx);

/**
 * @brief Reset the passwd iterator
 *
 * @return #wbcErr
 **/
wbcErr wbcSetpwent(void);

/**
 * @brief Close the passwd iterator
 *
 * @param *ctx      wbclient Context
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxEndpwent(struct wbcContext *ctx);

/**
 * @brief Close the passwd iterator
 *
 * @return #wbcErr
 **/
wbcErr wbcEndpwent(void);

/**
 * @brief Return the next struct passwd* entry from the pwent iterator
 *
 * @param *ctx      wbclient Context
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetpwent(struct wbcContext *ctx, struct passwd **pwd);

/**
 * @brief Return the next struct passwd* entry from the pwent iterator
 *
 * @param **pwd     Pointer to resulting struct passwd* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetpwent(struct passwd **pwd);

/**
 * @brief Reset the group iterator
 *
 * @param *ctx      wbclient Context
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxSetgrent(struct wbcContext *ctx);

/**
 * @brief Reset the group iterator
 *
 * @return #wbcErr
 **/
wbcErr wbcSetgrent(void);

/**
 * @brief Close the group iterator
 *
 * @param *ctx      wbclient Context
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxEndgrent(struct wbcContext *ctx);

/**
 * @brief Close the group iterator
 *
 * @return #wbcErr
 **/
wbcErr wbcEndgrent(void);

/**
 * @brief Return the next struct group* entry from the pwent iterator
 *
 * @param *ctx      wbclient Context
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetgrent(struct wbcContext *ctx, struct group **grp);

/**
 * @brief Return the next struct group* entry from the pwent iterator
 *
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetgrent(struct group **grp);

/**
 * @brief Return the next struct group* entry from the pwent iterator
 *
 * This is similar to #wbcGetgrent, just that the member list is empty
 *
 * @param *ctx      wbclient Context
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetgrlist(struct wbcContext *ctx, struct group **grp);

/**
 * @brief Return the next struct group* entry from the pwent iterator
 *
 * This is similar to #wbcGetgrent, just that the member list is empty
 *
 * @param **grp     Pointer to resulting struct group* from the query.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetgrlist(struct group **grp);

/**
 * @brief Return the unix group array belonging to the given user
 *
 * @param *ctx           wbclient Context
 * @param *account       The given user name
 * @param *num_groups    Number of elements returned in the groups array
 * @param **_groups      Pointer to resulting gid_t array.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxGetGroups(struct wbcContext *ctx,
                       const char *account,
                       uint32_t *num_groups,
                       gid_t **_groups);

/**
 * @brief Return the unix group array belonging to the given user
 *
 * @param *account       The given user name
 * @param *num_groups    Number of elements returned in the groups array
 * @param **_groups      Pointer to resulting gid_t array.
 *
 * @return #wbcErr
 **/
wbcErr wbcGetGroups(const char *account,
                    uint32_t *num_groups,
                    gid_t **_groups);


/**********************************************************
 * Lookup Domain information
 **********************************************************/

/**
 * @brief Lookup the current status of a trusted domain
 *
 * @param *ctx           wbclient Context
 * @param domain         The domain to query
 *
 * @param dinfo          A pointer to store the returned domain_info struct.
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxDomainInfo(struct wbcContext *ctx,
                        const char *domain,
                        struct wbcDomainInfo **dinfo);

/**
 * @brief Lookup the current status of a trusted domain
 *
 * @param domain         The domain to query
 *
 * @param dinfo          A pointer to store the returned domain_info struct.
 *
 * @return #wbcErr
 **/
wbcErr wbcDomainInfo(const char *domain,
                     struct wbcDomainInfo **dinfo);

/**
 * @brief Lookup the currently contacted DCs
 *
 * @param *ctx          wbclient Context
 * @param domain        The domain to query
 *
 * @param num_dcs       Number of DCs currently known
 * @param dc_names      Names of the currently known DCs
 * @param dc_ips        IP addresses of the currently known DCs
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxDcInfo(struct wbcContext *ctx,
                    const char *domain, size_t *num_dcs,
                    const char ***dc_names, const char ***dc_ips);

/**
 * @brief Lookup the currently contacted DCs
 *
 * @param domain        The domain to query
 *
 * @param num_dcs       Number of DCs currently known
 * @param dc_names      Names of the currently known DCs
 * @param dc_ips        IP addresses of the currently known DCs
 *
 * @return #wbcErr
 **/
wbcErr wbcDcInfo(const char *domain, size_t *num_dcs,
                 const char ***dc_names, const char ***dc_ips);

/**
 * @brief Enumerate the domain trusts known by Winbind
 *
 * @param *ctx          wbclient Context
 * @param **domains     Pointer to the allocated domain list array
 * @param *num_domains  Pointer to number of domains returned
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxListTrusts(struct wbcContext *ctx,
                        struct wbcDomainInfo **domains,
                        size_t *num_domains);

/**
 * @brief Enumerate the domain trusts known by Winbind
 *
 * @param **domains     Pointer to the allocated domain list array
 * @param *num_domains  Pointer to number of domains returned
 *
 * @return #wbcErr
 **/
wbcErr wbcListTrusts(struct wbcDomainInfo **domains,
                     size_t *num_domains);

/* Flags for wbcLookupDomainController */

#define WBC_LOOKUP_DC_FORCE_REDISCOVERY        0x00000001
#define WBC_LOOKUP_DC_DS_REQUIRED              0x00000010
#define WBC_LOOKUP_DC_DS_PREFERRED             0x00000020
#define WBC_LOOKUP_DC_GC_SERVER_REQUIRED       0x00000040
#define WBC_LOOKUP_DC_PDC_REQUIRED             0x00000080
#define WBC_LOOKUP_DC_BACKGROUND_ONLY          0x00000100
#define WBC_LOOKUP_DC_IP_REQUIRED              0x00000200
#define WBC_LOOKUP_DC_KDC_REQUIRED             0x00000400
#define WBC_LOOKUP_DC_TIMESERV_REQUIRED        0x00000800
#define WBC_LOOKUP_DC_WRITABLE_REQUIRED        0x00001000
#define WBC_LOOKUP_DC_GOOD_TIMESERV_PREFERRED  0x00002000
#define WBC_LOOKUP_DC_AVOID_SELF               0x00004000
#define WBC_LOOKUP_DC_ONLY_LDAP_NEEDED         0x00008000
#define WBC_LOOKUP_DC_IS_FLAT_NAME             0x00010000
#define WBC_LOOKUP_DC_IS_DNS_NAME              0x00020000
#define WBC_LOOKUP_DC_TRY_NEXTCLOSEST_SITE     0x00040000
#define WBC_LOOKUP_DC_DS_6_REQUIRED            0x00080000
#define WBC_LOOKUP_DC_RETURN_DNS_NAME          0x40000000
#define WBC_LOOKUP_DC_RETURN_FLAT_NAME         0x80000000

/**
 * @brief Enumerate the domain trusts known by Winbind
 *
 * @param *ctx          wbclient Context
 * @param domain        Name of the domain to query for a DC
 * @param flags         Bit flags used to control the domain location query
 * @param *dc_info      Pointer to the returned domain controller information
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLookupDomainController(struct wbcContext *ctx,
                                    const char *domain,
                                    uint32_t flags,
                                    struct wbcDomainControllerInfo **dc_info);

/**
 * @brief Enumerate the domain trusts known by Winbind
 *
 * @param domain        Name of the domain to query for a DC
 * @param flags         Bit flags used to control the domain location query
 * @param *dc_info      Pointer to the returned domain controller information
 *
 * @return #wbcErr
 **/
wbcErr wbcLookupDomainController(const char *domain,
                                 uint32_t flags,
                                 struct wbcDomainControllerInfo **dc_info);

/**
 * @brief Get extended domain controller information
 *
 * @param *ctx          wbclient Context
 * @param domain        Name of the domain to query for a DC
 * @param guid          Guid of the domain to query for a DC
 * @param site          Site of the domain to query for a DC
 * @param flags         Bit flags used to control the domain location query
 * @param *dc_info      Pointer to the returned extended domain controller information
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLookupDomainControllerEx(struct wbcContext *ctx,
                                      const char *domain,
                                      struct wbcGuid *guid,
                                      const char *site,
                                      uint32_t flags,
                                      struct wbcDomainControllerInfoEx **dc_info);

/**
 * @brief Get extended domain controller information
 *
 * @param domain        Name of the domain to query for a DC
 * @param guid          Guid of the domain to query for a DC
 * @param site          Site of the domain to query for a DC
 * @param flags         Bit flags used to control the domain location query
 * @param *dc_info      Pointer to the returned extended domain controller information
 *
 * @return #wbcErr
 **/
wbcErr wbcLookupDomainControllerEx(const char *domain,
                                   struct wbcGuid *guid,
                                   const char *site,
                                   uint32_t flags,
                                   struct wbcDomainControllerInfoEx **dc_info);

/**********************************************************
 * Athenticate functions
 **********************************************************/

/**
 * @brief Authenticate a username/password pair
 *
 * @param *ctx         wbclient Context
 * @param username     Name of user to authenticate
 * @param password     Clear text password os user
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxAuthenticateUser(struct wbcContext *ctx,
                              const char *username,
                              const char *password);

/**
 * @brief Authenticate a username/password pair
 *
 * @param username     Name of user to authenticate
 * @param password     Clear text password os user
 *
 * @return #wbcErr
 **/
wbcErr wbcAuthenticateUser(const char *username,
                           const char *password);

/**
 * @brief Authenticate with more detailed information
 *
 * @param *ctx         wbclient Context
 * @param params       Input parameters, WBC_AUTH_USER_LEVEL_HASH
 *                     is not supported yet
 * @param info         Output details on WBC_ERR_SUCCESS
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxAuthenticateUserEx(struct wbcContext *ctx,
                                const struct wbcAuthUserParams *params,
                                struct wbcAuthUserInfo **info,
                                struct wbcAuthErrorInfo **error);

/**
 * @brief Authenticate with more detailed information
 *
 * @param params       Input parameters, WBC_AUTH_USER_LEVEL_HASH
 *                     is not supported yet
 * @param info         Output details on WBC_ERR_SUCCESS
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcAuthenticateUserEx(const struct wbcAuthUserParams *params,
                             struct wbcAuthUserInfo **info,
                             struct wbcAuthErrorInfo **error);

/**
 * @brief Logon a User
 *
 * @param[in]  *ctx        wbclient Context
 * @param[in]  params      Pointer to a wbcLogonUserParams structure
 * @param[out] info        Pointer to a pointer to a wbcLogonUserInfo structure
 * @param[out] error       Pointer to a pointer to a wbcAuthErrorInfo structure
 * @param[out] policy      Pointer to a pointer to a wbcUserPasswordPolicyInfo structure
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLogonUser(struct wbcContext *ctx,
                       const struct wbcLogonUserParams *params,
                       struct wbcLogonUserInfo **info,
                       struct wbcAuthErrorInfo **error,
                       struct wbcUserPasswordPolicyInfo **policy);

/**
 * @brief Logon a User
 *
 * @param[in]  params      Pointer to a wbcLogonUserParams structure
 * @param[out] info        Pointer to a pointer to a wbcLogonUserInfo structure
 * @param[out] error       Pointer to a pointer to a wbcAuthErrorInfo structure
 * @param[out] policy      Pointer to a pointer to a wbcUserPasswordPolicyInfo structure
 *
 * @return #wbcErr
 **/
wbcErr wbcLogonUser(const struct wbcLogonUserParams *params,
                    struct wbcLogonUserInfo **info,
                    struct wbcAuthErrorInfo **error,
                    struct wbcUserPasswordPolicyInfo **policy);

/**
 * @brief Trigger a logoff notification to Winbind for a specific user
 *
 * @param *ctx        wbclient Context
 * @param username    Name of user to remove from Winbind's list of
 *                    logged on users.
 * @param uid         Uid assigned to the username
 * @param ccfilename  Absolute path to the Krb5 credentials cache to
 *                    be removed
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLogoffUser(struct wbcContext *ctx,
                        const char *username, uid_t uid,
                        const char *ccfilename);

/**
 * @brief Trigger a logoff notification to Winbind for a specific user
 *
 * @param username    Name of user to remove from Winbind's list of
 *                    logged on users.
 * @param uid         Uid assigned to the username
 * @param ccfilename  Absolute path to the Krb5 credentials cache to
 *                    be removed
 *
 * @return #wbcErr
 **/
wbcErr wbcLogoffUser(const char *username,
                     uid_t uid,
                     const char *ccfilename);

/**
 * @brief Trigger an extended logoff notification to Winbind for a specific user
 *
 * @param *ctx        wbclient Context
 * @param params      A wbcLogoffUserParams structure
 * @param error       User output details on error
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxLogoffUserEx(struct wbcContext *ctx,
                          const struct wbcLogoffUserParams *params,
                          struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger an extended logoff notification to Winbind for a specific user
 *
 * @param params      A wbcLogoffUserParams structure
 * @param error       User output details on error
 *
 * @return #wbcErr
 **/
wbcErr wbcLogoffUserEx(const struct wbcLogoffUserParams *params,
                       struct wbcAuthErrorInfo **error);

/**
 * @brief Change a password for a user
 *
 * @param *ctx          wbclient Context
 * @param username      Name of user to authenticate
 * @param old_password  Old clear text password of user
 * @param new_password  New clear text password of user
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxChangeUserPassword(struct wbcContext *ctx,
                                const char *username,
                                const char *old_password,
                                const char *new_password);

/**
 * @brief Change a password for a user
 *
 * @param username      Name of user to authenticate
 * @param old_password  Old clear text password of user
 * @param new_password  New clear text password of user
 *
 * @return #wbcErr
 **/
wbcErr wbcChangeUserPassword(const char *username,
                             const char *old_password,
                             const char *new_password);

/**
 * @brief Change a password for a user with more detailed information upon
 *   failure
 *
 * @param *ctx                  wbclient Context
 * @param params                Input parameters
 * @param error                 User output details on WBC_ERR_PWD_CHANGE_FAILED
 * @param reject_reason         New password reject reason on WBC_ERR_PWD_CHANGE_FAILED
 * @param policy                Password policy output details on WBC_ERR_PWD_CHANGE_FAILED
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxChangeUserPasswordEx(struct wbcContext *ctx,
                                  const struct wbcChangePasswordParams *params,
                                  struct wbcAuthErrorInfo **error,
                                  enum wbcPasswordChangeRejectReason *reject_reason,
                                  struct wbcUserPasswordPolicyInfo **policy);

/**
 * @brief Change a password for a user with more detailed information upon
 *   failure
 *
 * @param params                Input parameters
 * @param error                 User output details on WBC_ERR_PWD_CHANGE_FAILED
 * @param reject_reason         New password reject reason on WBC_ERR_PWD_CHANGE_FAILED
 * @param policy                Password policy output details on WBC_ERR_PWD_CHANGE_FAILED
 *
 * @return #wbcErr
 **/
wbcErr wbcChangeUserPasswordEx(const struct wbcChangePasswordParams *params,
                               struct wbcAuthErrorInfo **error,
                               enum wbcPasswordChangeRejectReason *reject_reason,
                               struct wbcUserPasswordPolicyInfo **policy);

/**
 * @brief Authenticate a user with cached credentials
 *
 * @param *ctx       wbclient Context
 * @param *params    Pointer to a wbcCredentialCacheParams structure
 * @param **info     Pointer to a pointer to a wbcCredentialCacheInfo structure
 * @param **error    Pointer to a pointer to a wbcAuthErrorInfo structure
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxCredentialCache(struct wbcContext *ctx,
                             struct wbcCredentialCacheParams *params,
                             struct wbcCredentialCacheInfo **info,
                             struct wbcAuthErrorInfo **error);

/**
 * @brief Authenticate a user with cached credentials
 *
 * @param *params    Pointer to a wbcCredentialCacheParams structure
 * @param **info     Pointer to a pointer to a wbcCredentialCacheInfo structure
 * @param **error    Pointer to a pointer to a wbcAuthErrorInfo structure
 *
 * @return #wbcErr
 **/
wbcErr wbcCredentialCache(struct wbcCredentialCacheParams *params,
                          struct wbcCredentialCacheInfo **info,
                          struct wbcAuthErrorInfo **error);

/**
 * @brief Save a password with winbind for doing wbcCredentialCache() later
 *
 * @param *ctx       wbclient Context
 * @param *user      Username
 * @param *password  Password
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxCredentialSave(struct wbcContext *ctx,
                            const char *user, const char *password);

/**
 * @brief Save a password with winbind for doing wbcCredentialCache() later
 *
 * @param *user      Username
 * @param *password  Password
 *
 * @return #wbcErr
 **/
wbcErr wbcCredentialSave(const char *user, const char *password);

/**********************************************************
 * Resolve functions
 **********************************************************/

/**
 * @brief Resolve a NetbiosName via WINS
 *
 * @param *ctx         wbclient Context
 * @param name         Name to resolve
 * @param *ip          Pointer to the ip address string
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxResolveWinsByName(struct wbcContext *ctx,
                               const char *name, char **ip);

/**
 * @brief Resolve a NetbiosName via WINS
 *
 * @param name         Name to resolve
 * @param *ip          Pointer to the ip address string
 *
 * @return #wbcErr
 **/
wbcErr wbcResolveWinsByName(const char *name, char **ip);

/**
 * @brief Resolve an IP address via WINS into a NetbiosName
 *
 * @param *ctx         wbclient Context
 * @param ip           The ip address string
 * @param *name        Pointer to the name
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcCtxResolveWinsByIP(struct wbcContext *ctx,
                             const char *ip, char **name);

/**
 * @brief Resolve an IP address via WINS into a NetbiosName
 *
 * @param ip           The ip address string
 * @param *name        Pointer to the name
 *
 * @return #wbcErr
 *
 **/
wbcErr wbcResolveWinsByIP(const char *ip, char **name);

/**********************************************************
 * Trusted domain functions
 **********************************************************/

/**
 * @brief Trigger a verification of the trust credentials of a specific domain
 *
 * @param *ctx         wbclient Context
 * @param *domain      The name of the domain.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxCheckTrustCredentials(struct wbcContext *ctx, const char *domain,
                                   struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a verification of the trust credentials of a specific domain
 *
 * @param *domain      The name of the domain.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcCheckTrustCredentials(const char *domain,
                                struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a change of the trust credentials for a specific domain
 *
 * @param *ctx         wbclient Context
 * @param *domain      The name of the domain.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxChangeTrustCredentials(struct wbcContext *ctx, const char *domain,
                                    struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a change of the trust credentials for a specific domain
 *
 * @param *domain      The name of the domain.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcChangeTrustCredentials(const char *domain,
                                 struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a no-op call through the NETLOGON pipe. Low-cost
 *        version of wbcCheckTrustCredentials
 *
 * @param *ctx         wbclient Context
 * @param *domain      The name of the domain, only NULL for the default domain is
 *                     supported yet. Other values than NULL will result in
 *                     WBC_ERR_NOT_IMPLEMENTED.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxPingDc(struct wbcContext *ctx, const char *domain,
                    struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a no-op call through the NETLOGON pipe. Low-cost
 *        version of wbcCheckTrustCredentials
 *
 * @param *domain      The name of the domain, only NULL for the default domain is
 *                     supported yet. Other values than NULL will result in
 *                     WBC_ERR_NOT_IMPLEMENTED.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 *
 * @return #wbcErr
 **/
wbcErr wbcPingDc(const char *domain, struct wbcAuthErrorInfo **error);

/**
 * @brief Trigger a no-op call through the NETLOGON pipe. Low-cost
 *        version of wbcCheckTrustCredentials
 *
 * @param *ctx         wbclient Context
 * @param *domain      The name of the domain, only NULL for the default domain is
 *                     supported yet. Other values than NULL will result in
 *                     WBC_ERR_NOT_IMPLEMENTED.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 * @param dcname       DC that was attempted to ping
 *
 * @return #wbcErr
 **/
wbcErr wbcCtxPingDc2(struct wbcContext *ctx, const char *domain,
                     struct wbcAuthErrorInfo **error,
                     char **dcname);

/**
 * @brief Trigger a no-op call through the NETLOGON pipe. Low-cost
 *        version of wbcCheckTrustCredentials
 *
 * @param *domain      The name of the domain, only NULL for the default domain is
 *                     supported yet. Other values than NULL will result in
 *                     WBC_ERR_NOT_IMPLEMENTED.
 * @param error        Output details on WBC_ERR_AUTH_ERROR
 * @param dcname       DC that was attempted to ping
 *
 * @return #wbcErr
 **/
wbcErr wbcPingDc2(const char *domain, struct wbcAuthErrorInfo **error,
                  char **dcname);

/**********************************************************
 * Helper functions
 **********************************************************/

/**
 * @brief Initialize a named blob and add to list of blobs
 *
 * @param[in,out] num_blobs     Pointer to the number of blobs
 * @param[in,out] blobs         Pointer to an array of blobs
 * @param[in]     name          Name of the new named blob
 * @param[in]     flags         Flags of the new named blob
 * @param[in]     data          Blob data of new blob
 * @param[in]     length        Blob data length of new blob
 *
 * @return #wbcErr
 **/
wbcErr wbcAddNamedBlob(size_t *num_blobs,
                       struct wbcNamedBlob **blobs,
                       const char *name,
                       uint32_t flags,
                       uint8_t *data,
                       size_t length);

#endif      /* _WBCLIENT_H */
