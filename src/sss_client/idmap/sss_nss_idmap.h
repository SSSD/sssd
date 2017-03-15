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
 * @brief Free key-value list returned by sss_nss_getorigbyname()
 *
 * @param[in] kv_list Key-value list returned by sss_nss_getorigbyname().
 */
void sss_nss_free_kv(struct sss_nss_kv *kv_list);
#endif /* SSS_NSS_IDMAP_H_ */
