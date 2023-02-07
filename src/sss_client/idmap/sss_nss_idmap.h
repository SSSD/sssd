/*
    SSSD

    NSS  Responder ID-mapping interface

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

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

#ifndef SSS_NSS_IDMAP_H_
#define SSS_NSS_IDMAP_H_

#include <stdint.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

/**
 * Object types
 */
enum sss_id_type {
    SSS_ID_TYPE_NOT_SPECIFIED = 0,
    SSS_ID_TYPE_UID,
    SSS_ID_TYPE_GID,
    SSS_ID_TYPE_BOTH /* used for user or magic private groups */
};

struct sss_nss_kv {
    char *key;
    char *value;
};

/**
 * @brief Find SID by fully qualified name
 *
 * @param[in] fq_name  Fully qualified name of a user or a group
 * @param[out] sid     String representation of the SID of the requested user
 *                     or group, must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success, sid contains the requested SID
 *  - ENOENT: requested object was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 */
int sss_nss_getsidbyname(const char *fq_name, char **sid,
                         enum sss_id_type *type);

/**
 * @brief Find SID by fully qualified user name
 *
 * @param[in] fq_name  Fully qualified name of a user
 * @param[out] sid     String representation of the SID of the requested user,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getsidbyusername(const char *fq_name,
                             char **sid,
                             enum sss_id_type *type);

/**
 * @brief Find SID by fully qualified group name
 *
 * @param[in] fq_name  Fully qualified name of a group
 * @param[out] sid     String representation of the SID of the requested group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getsidbygroupname(const char *fq_name,
                              char **sid,
                              enum sss_id_type *type);

/**
 * @brief Find SID by a POSIX UID or GID
 *
 * @param[in] id       POSIX UID or GID
 * @param[out] sid     String representation of the SID of the requested user
 *                     or group, must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getsidbyid(uint32_t id, char **sid, enum sss_id_type *type);

/**
 * @brief Find SID by a POSIX UID
 *
 * @param[in] uid      POSIX UID
 * @param[out] sid     String representation of the SID of the requested user,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getsidbyuid(uint32_t uid, char **sid, enum sss_id_type *type);

/**
 * @brief Find SID by a POSIX GID
 *
 * @param[in] gid      POSIX GID
 * @param[out] sid     String representation of the SID of the requested group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getsidbygid(uint32_t id, char **sid, enum sss_id_type *type);

/**
 * @brief Return the fully qualified name for the given SID
 *
 * @param[in] sid      String representation of the SID
 * @param[out] fq_name Fully qualified name of a user or a group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the SID
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getnamebysid(const char *sid, char **fq_name,
                         enum sss_id_type *type);

/**
 * @brief Return the POSIX ID for the given SID
 *
 * @param[in] sid      String representation of the SID
 * @param[out] id      POSIX ID related to the SID
 * @param[out] id_type Type of the object related to the SID
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getidbysid(const char *sid, uint32_t *id,
                       enum sss_id_type *id_type);

/**
 * @brief Find original data by fully qualified name
 *
 * @param[in] fq_name  Fully qualified name of a user or a group
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success, sid contains the requested SID
 *  - ENOENT: requested object was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 */
int sss_nss_getorigbyname(const char *fq_name, struct sss_nss_kv **kv_list,
                          enum sss_id_type *type);

/**
 * @brief Find original data by fully qualified user name
 *
 * @param[in] fq_name  Fully qualified name of a user
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success
 *  - ENOENT: requested user was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 */
int sss_nss_getorigbyusername(const char *fq_name, struct sss_nss_kv **kv_list,
                              enum sss_id_type *type);

/**
 * @brief Find original data by fully qualified group name
 *
 * @param[in] fq_name  Fully qualified name of a group
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success
 *  - ENOENT: requested group was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 */
int sss_nss_getorigbygroupname(const char *fq_name, struct sss_nss_kv **kv_list,
                               enum sss_id_type *type);

/**
 * @brief Return the fully qualified name for the given base64 encoded
 * X.509 certificate in DER format
 *
 * @param[in] cert     base64 encoded certificate
 * @param[out] fq_name Fully qualified name of a user or a group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the cert
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getnamebycert(const char *cert, char **fq_name,
                          enum sss_id_type *type);

/**
 * @brief Return a list of fully qualified names for the given base64 encoded
 * X.509 certificate in DER format
 *
 * @param[in] cert     base64 encoded certificate
 * @param[out] fq_name List of fully qualified name of users or groups,
 *                     must be freed by the caller
 * @param[out] type    List of types of the objects related to the cert
 *
 * @return
 *  - see #sss_nss_getsidbyname
 */
int sss_nss_getlistbycert(const char *cert, char ***fq_name,
                          enum sss_id_type **type);

/**
 * @brief Free key-value list returned by sss_nss_getorigbyXYZ()
 *
 * @param[in] kv_list Key-value list returned by sss_nss_getorigbyname() and
 *                    similar calls.
 */
void sss_nss_free_kv(struct sss_nss_kv *kv_list);

/**
 * Flags to control the behavior and the results for sss_*_ex() calls
 */

#define SSS_NSS_EX_FLAG_NO_FLAGS 0

/** Always request data from the server side, client must be privileged to do
 *  so, see nss_trusted_users option in man sssd.conf for details.
 *  This flag cannot be used together with SSS_NSS_EX_FLAG_INVALIDATE_CACHE */
#define SSS_NSS_EX_FLAG_NO_CACHE (1 << 0)

/** Invalidate the data in the caches, client must be privileged to do
 *  so, see nss_trusted_users option in man sssd.conf for details.
 *  This flag cannot be used together with SSS_NSS_EX_FLAG_NO_CACHE */
#define SSS_NSS_EX_FLAG_INVALIDATE_CACHE (1 << 1)

#ifdef IPA_389DS_PLUGIN_HELPER_CALLS

/**
 * @brief Return user information based on the user name
 *
 * @param[in]  name       same as for getpwnam_r(3)
 * @param[in]  pwd        same as for getpwnam_r(3)
 * @param[in]  buffer     same as for getpwnam_r(3)
 * @param[in]  buflen     same as for getpwnam_r(3)
 * @param[out] result     same as for getpwnam_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no user with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getpwnam_timeout(const char *name, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout);

/**
 * @brief Return user information based on the user uid
 *
 * @param[in]  uid        same as for getpwuid_r(3)
 * @param[in]  pwd        same as for getpwuid_r(3)
 * @param[in]  buffer     same as for getpwuid_r(3)
 * @param[in]  buflen     same as for getpwuid_r(3)
 * @param[out] result     same as for getpwuid_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no user with the given uid found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getpwuid_timeout(uid_t uid, struct passwd *pwd,
                             char *buffer, size_t buflen,
                             struct passwd **result,
                             uint32_t flags, unsigned int timeout);

/**
 * @brief Return group information based on the group name
 *
 * @param[in]  name       same as for getgrnam_r(3)
 * @param[in]  pwd        same as for getgrnam_r(3)
 * @param[in]  buffer     same as for getgrnam_r(3)
 * @param[in]  buflen     same as for getgrnam_r(3)
 * @param[out] result     same as for getgrnam_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no group with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getgrnam_timeout(const char *name, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout);

/**
 * @brief Return group information based on the group gid
 *
 * @param[in]  gid        same as for getgrgid_r(3)
 * @param[in]  pwd        same as for getgrgid_r(3)
 * @param[in]  buffer     same as for getgrgid_r(3)
 * @param[in]  buflen     same as for getgrgid_r(3)
 * @param[out] result     same as for getgrgid_r(3)
 * @param[in]  flags      flags to control the behavior and the results of the
 *                        call
 * @param[in]  timeout    timeout in milliseconds
 *
 * @return
 *  - 0:
 *  - ENOENT:    no group with the given gid found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getgrgid_timeout(gid_t gid, struct group *grp,
                             char *buffer, size_t buflen, struct group **result,
                             uint32_t flags, unsigned int timeout);

/**
 * @brief Return a list of groups to which a user belongs
 *
 * @param[in]      name       name of the user
 * @param[in]      group      same as second argument of getgrouplist(3)
 * @param[in]      groups     array of gid_t of size ngroups, will be filled
 *                            with GIDs of groups the user belongs to
 * @param[in,out]  ngroups    size of the groups array on input. On output it
 *                            will contain the actual number of groups the
 *                            user belongs to. With a return value of 0 the
 *                            groups array was large enough to hold all group.
 *                            With a return valu of ERANGE the array was not
 *                            large enough and ngroups will have the needed
 *                            size.
 * @param[in]  flags          flags to control the behavior and the results of
 *                            the call
 * @param[in]  timeout        timeout in milliseconds
 *
 * @return
 *  - 0:         success
 *  - ENOENT:    no user with the given name found
 *  - ERANGE:    Insufficient buffer space supplied
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getgrouplist_timeout(const char *name, gid_t group,
                                 gid_t *groups, int *ngroups,
                                 uint32_t flags, unsigned int timeout);
/**
 * @brief Find SID by fully qualified name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a user or a group
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested user
 *                     or group, must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success, sid contains the requested SID
 *  - ENOENT: requested object was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getsidbyname_timeout(const char *fq_name, unsigned int timeout,
                                 char **sid, enum sss_id_type *type);

/**
 * @brief Find SID by fully qualified user name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a user
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested user,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getsidbyusername_timeout(const char *fq_name,
                                     unsigned int timeout,
                                     char **sid,
                                     enum sss_id_type *type);

/**
 * @brief Find SID by fully qualified group name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a group
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getsidbygroupname_timeout(const char *fq_name,
                                      unsigned int timeout,
                                      char **sid,
                                      enum sss_id_type *type);

/**
 * @brief Find SID by a POSIX UID or GID with timeout
 *
 * @param[in] id       POSIX UID or GID
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested user
 *                     or group, must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getsidbyid_timeout(uint32_t id, unsigned int timeout,
                               char **sid, enum sss_id_type *type);
/**
 * @brief Find SID by a POSIX UID with timeout
 *
 * @param[in] uid      POSIX UID
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested user,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getsidbyuid_timeout(uint32_t uid, unsigned int timeout,
                                char **sid, enum sss_id_type *type);

/**
 * @brief Find SID by a POSIX GID with timeout
 *
 * @param[in] gid      POSIX GID
 * @param[in] timeout  timeout in milliseconds
 * @param[out] sid     String representation of the SID of the requested group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the given ID
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getsidbygid_timeout(uint32_t gid, unsigned int timeout,
                                char **sid, enum sss_id_type *type);


/**
 * @brief Return the fully qualified name for the given SID with timeout
 *
 * @param[in] sid      String representation of the SID
 * @param[in] timeout  timeout in milliseconds
 * @param[out] fq_name Fully qualified name of a user or a group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the SID
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getnamebysid_timeout(const char *sid, unsigned int timeout,
                                 char **fq_name, enum sss_id_type *type);

/**
 * @brief Return the POSIX ID for the given SID with timeout
 *
 * @param[in] sid      String representation of the SID
 * @param[in] timeout  timeout in milliseconds
 * @param[out] id      POSIX ID related to the SID
 * @param[out] id_type Type of the object related to the SID
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getidbysid_timeout(const char *sid, unsigned int timeout,
                               uint32_t *id, enum sss_id_type *id_type);

/**
 * @brief Find original data by fully qualified name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a user or a group
 * @param[in] timeout  timeout in milliseconds
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success, sid contains the requested SID
 *  - ENOENT: requested object was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getorigbyname_timeout(const char *fq_name, unsigned int timeout,
                                  struct sss_nss_kv **kv_list,
                                  enum sss_id_type *type);

/**
 * @brief Find original data by fully qualified user name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a user
 * @param[in] timeout  timeout in milliseconds
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success
 *  - ENOENT: requested user was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getorigbyusername_timeout(const char *fq_name, unsigned int timeout,
                                      struct sss_nss_kv **kv_list,
                                      enum sss_id_type *type);

/**
 * @brief Find original data by fully qualified group name with timeout
 *
 * @param[in] fq_name  Fully qualified name of a group
 * @param[in] timeout  timeout in milliseconds
 * @param[out] kv_list A NULL terminate list of key-value pairs where the key
 *                     is the attribute name in the cache of SSSD,
 *                     must be freed by the caller with sss_nss_free_kv()
 * @param[out] type    Type of the object related to the given name
 *
 * @return
 *  - 0 (EOK): success
 *  - ENOENT: requested group was not found in the domain extracted from the given name
 *  - ENETUNREACH: SSSD does not know how to handle the domain extracted from the given name
 *  - ENOSYS: this call is not supported by the configured provider
 *  - EINVAL: input cannot be parsed
 *  - EIO: remote servers cannot be reached
 *  - EFAULT: any other error
 *  - ETIME:     request timed out but was send to SSSD
 *  - ETIMEDOUT: request timed out but was not send to SSSD
 */
int sss_nss_getorigbygroupname_timeout(const char *fq_name, unsigned int timeout,
                                       struct sss_nss_kv **kv_list,
                                       enum sss_id_type *type);

/**
 * @brief Return the fully qualified name for the given base64 encoded
 * X.509 certificate in DER format with timeout
 *
 * @param[in] cert     base64 encoded certificate
 * @param[in] timeout  timeout in milliseconds
 * @param[out] fq_name Fully qualified name of a user or a group,
 *                     must be freed by the caller
 * @param[out] type    Type of the object related to the cert
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getnamebycert_timeout(const char *cert, unsigned int timeout,
                                  char **fq_name, enum sss_id_type *type);

/**
 * @brief Return a list of fully qualified names for the given base64 encoded
 * X.509 certificate in DER format with timeout
 *
 * @param[in] cert     base64 encoded certificate
 * @param[in] timeout  timeout in milliseconds
 * @param[out] fq_name List of fully qualified name of users or groups,
 *                     must be freed by the caller
 * @param[out] type    List of types of the objects related to the cert
 *
 * @return
 *  - see #sss_nss_getsidbyname_timeout
 */
int sss_nss_getlistbycert_timeout(const char *cert, unsigned int timeout,
                                  char ***fq_name, enum sss_id_type **type);

#endif /* IPA_389DS_PLUGIN_HELPER_CALLS */
#endif /* SSS_NSS_IDMAP_H_ */
