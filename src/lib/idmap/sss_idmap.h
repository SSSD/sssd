/*
    SSSD

    ID-mapping library

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#ifndef SSS_IDMAP_H_
#define SSS_IDMAP_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#define DOM_SID_PREFIX "S-1-5-21-"
#define DOM_SID_PREFIX_LEN (sizeof(DOM_SID_PREFIX) - 1)

/**
 * @defgroup sss_idmap Map Unix UIDs and GIDs to SIDs and back
 * Libsss_idmap provides a mechanism to translate a SID to a UNIX UID or GID
 * or the other way round.
 * @{
 */

/**
 * Error codes used by libsss_idmap
 */
enum idmap_error_code {
    /** Success */
    IDMAP_SUCCESS = 0,

    /** Function is not yet implemented */
    IDMAP_NOT_IMPLEMENTED,

    /** General error */
    IDMAP_ERROR,

    /** Ran out of memory during processing */
    IDMAP_OUT_OF_MEMORY,

    /** No domain added */
    IDMAP_NO_DOMAIN,

    /** The provided idmap context is invalid */
    IDMAP_CONTEXT_INVALID,

    /** The provided SID is invalid */
    IDMAP_SID_INVALID,

    /** The provided  SID was not found */
    IDMAP_SID_UNKNOWN,

    /** The provided UID or GID could not be mapped */
    IDMAP_NO_RANGE
};

/**
 * Typedef for memory allocation functions
 */
typedef void *(idmap_alloc_func)(size_t size, void *pvt);
typedef void (idmap_free_func)(void *ptr, void *pvt);

/**
 * Structure for id ranges
 * FIXME: this struct might change when it is clear how ranges are handled on
 * the server side
 */
struct sss_idmap_range {
    uint32_t min;
    uint32_t max;
};

/**
 * Opaque type for SIDs
 */
struct sss_dom_sid;

/**
 * Opaque type for the idmap context
 */
struct sss_idmap_ctx;

/**
 * Placeholder for Samba's struct dom_sid. Consumers of libsss_idmap should
 * include an appropriate Samba header file to define struct dom_sid. We use
 * it here to avoid a hard dependency on Samba devel packages.
 */
struct dom_sid;

/**
 * @brief Initialize idmap context
 *
 * @param[in] alloc_func Function to allocate memory for the context, if
 *                       NULL malloc() id used
 * @param[in] alloc_pvt  Private data for allocation routine
 * @param[in] free_func  Function to free the memory the context, if
 *                       NULL free() id used
 * @param[out] ctx       idmap context
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to create the context
 */
enum idmap_error_code sss_idmap_init(idmap_alloc_func *alloc_func,
                                     void *alloc_pvt,
                                     idmap_free_func *free_func,
                                     struct sss_idmap_ctx **ctx);

/**
 * @brief Add a domain to the idmap context
 *
 * @param[in] ctx         Idmap context
 * @param[in] domain_name Zero-terminated string with the domain name
 * @param[in] domain_sid  Zero-terminated string representation of the domain
 *                        SID (S-1-15-.....)
 * @param[in] range       TBD Some information about the id ranges of this
 *                        domain
 *
 * @return
 *  - #IDMAP_OUT_OF_MEMORY: Insufficient memory to store the data in the idmap
 *                          context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_NO_DOMAIN:     No domain domain name given
 */
enum idmap_error_code sss_idmap_add_domain(struct sss_idmap_ctx *ctx,
                                           const char *domain_name,
                                           const char *domain_sid,
                                           struct sss_idmap_range *range);

/**
 * @brief Translate SID to a unix UID or GID
 *
 * @param[in] ctx Idmap context
 * @param[in] sid Zero-terminated string representation of the SID
 * @param[out] id Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 */
enum idmap_error_code sss_idmap_sid_to_unix(struct sss_idmap_ctx *ctx,
                                            const char *sid,
                                            uint32_t *id);

/**
 * @brief Translate a SID stucture to a unix UID or GID
 *
 * @param[in] ctx     Idmap context
 * @param[in] dom_sid SID structure
 * @param[out] id     Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 */
enum idmap_error_code sss_idmap_dom_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                struct sss_dom_sid *dom_sid,
                                                uint32_t *id);

/**
 * @brief Translate a binary SID to a unix UID or GID
 *
 * @param[in] ctx     Idmap context
 * @param[in] bin_sid Array with the binary SID
 * @param[in] length  Size of the array containing the binary SID
 * @param[out] id     Returned unix UID or GID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN:     No domains are added to the idmap context
 *  - #IDMAP_SID_INVALID:   Invalid SID provided
 *  - #IDMAP_SID_UNKNOWN:   SID cannot be found in the domains added to the
 *                          idmap context
 */
enum idmap_error_code sss_idmap_bin_sid_to_unix(struct sss_idmap_ctx *ctx,
                                                uint8_t *bin_sid,
                                                size_t length,
                                                uint32_t *id);

/**
 * @brief Translate unix UID or GID to a SID
 *
 * @param[in] ctx  Idmap context
 * @param[in] id   unix UID or GID
 * @param[out] sid Zero-terminated string representation of the SID, must be
 *                 freed if not needed anymore
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 */
enum idmap_error_code sss_idmap_unix_to_sid(struct sss_idmap_ctx *ctx,
                                            uint32_t id,
                                            char **sid);

/**
 * @brief Translate unix UID or GID to a SID structure
 *
 * @param[in] ctx      Idmap context
 * @param[in] id       unix UID or GID
 * @param[out] dom_sid SID structure, must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 */
enum idmap_error_code sss_idmap_unix_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                struct sss_dom_sid **dom_sid);

/**
 * @brief Translate unix UID or GID to a binary SID
 *
 * @param[in] ctx      Idmap context
 * @param[in] id       unix UID or GID
 * @param[out] bin_sid Array with the binary SID,
 *                     must be freed if not needed anymore
 * @param[out] length  size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_NO_DOMAIN: No domains are added to the idmap context
 *  - #IDMAP_NO_RANGE:  The provided ID cannot be found in the domains added
 *                      to the idmap context
 */
enum idmap_error_code sss_idmap_unix_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                uint32_t id,
                                                uint8_t **bin_sid,
                                                size_t *length);

/**
 * @brief Free all the allocated memory of the idmap context
 *
 * @param[in] ctx         Idmap context
 *
 * @return
 *  - #IDMAP_CONTEXT_INVALID: Provided context is invalid
 */
enum idmap_error_code sss_idmap_free(struct sss_idmap_ctx *ctx);

/**
 * @brief Translate error code to a string
 *
 * @param[in] err  Idmap error code
 *
 * @return
 *  - Error description as a zero-terminated string
 */
const char *idmap_error_string(enum idmap_error_code err);

/**
 * @brief Check if given string can be used as domain SID
 *
 * @param[in] str   String to check
 *
 * @return
 *  - true: String can be used as domain SID
 *  - false: String can not be used as domain SID
 */
bool is_domain_sid(const char *str);

/**
 * @brief Convert binary SID to SID structure
 *
 * @param[in] ctx      Idmap context
 * @param[in] bin_sid  Array with the binary SID
 * @param[in] length   Size of the array containing the binary SID
 * @param[out] dom_sid SID structure,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct sss_dom_sid **dom_sid);

/**
 * @brief Convert binary SID to SID string
 *
 * @param[in] ctx      Idmap context
 * @param[in] bin_sid  Array with the binary SID
 * @param[in] length   Size of the array containing the binary SID
 * @param[out] sid     Zero-terminated string representation of the SID,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               const uint8_t *bin_sid,
                                               size_t length,
                                               char **sid);

/**
 * @brief Convert SID structure to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] dom_sid   SID structure
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   uint8_t **bin_sid,
                                                   size_t *length);

/**
 * @brief Convert SID string to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               uint8_t **bin_sid,
                                               size_t *length);

/**
 * @brief Convert SID structure to SID string
 *
 * @param[in] ctx      Idmap context
 * @param[in] dom_sid  SID structure
 * @param[out] sid     Zero-terminated string representation of the SID,
 *                     must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct sss_dom_sid *dom_sid,
                                               char **sid);

/**
 * @brief Convert SID string to SID structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] dom_sid  SID structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct sss_dom_sid **dom_sid);

/**
 * @brief Convert SID string to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] sid       Zero-terminated string representation of the SID
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                               const char *sid,
                                               struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to SID string
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] sid      Zero-terminated string representation of the SID,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_sid(struct sss_idmap_ctx *ctx,
                                               struct dom_sid *smb_sid,
                                               char **sid);

/**
 * @brief Convert SID stucture to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] dom_sid   SID structure
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_dom_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   struct sss_dom_sid *dom_sid,
                                                   struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to SID structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] dom_sid  SID structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_dom_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   struct sss_dom_sid **dom_sid);

/**
 * @brief Convert binary SID to Samba dom_sid structure
 *
 * @param[in] ctx       Idmap context
 * @param[in] bin_sid   Array with the binary SID
 * @param[in] length    Size of the array containing the binary SID
 * @param[out] smb_sid  Samba dom_sid structure,
 *                      must be freed if not needed anymore
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_bin_sid_to_smb_sid(struct sss_idmap_ctx *ctx,
                                                   const uint8_t *bin_sid,
                                                   size_t length,
                                                   struct dom_sid **smb_sid);

/**
 * @brief Convert Samba dom_sid structure to binary SID
 *
 * @param[in] ctx       Idmap context
 * @param[in] smb_sid   Samba dom_sid structure
 * @param[out] bin_sid  Array with the binary SID,
 *                      must be freed if not needed anymore
 * @param[out] length   Size of the array containing the binary SID
 *
 * @return
 *  - #IDMAP_SID_INVALID: Given SID is invalid
 *  - #IDMAP_OUT_OF_MEMORY: Failed to allocate memory for the result
 */
enum idmap_error_code sss_idmap_smb_sid_to_bin_sid(struct sss_idmap_ctx *ctx,
                                                   struct dom_sid *smb_sid,
                                                   uint8_t **bin_sid,
                                                   size_t *length);
/**
 * @}
 */
#endif /* SSS_IDMAP_H_ */
