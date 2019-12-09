/*
    SSSD

    Library for rule based certificate to user mapping

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

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

#ifndef _SSS_CERTMAP_H_
#define _SSS_CERTMAP_H_

#include <stdlib.h>
#include <stdint.h>
#include <talloc.h>

/**
 * @defgroup sss_certmap Allow rule-based mapping of certificates to users
 * Libsss_certmap provides a mechanism to map X509 certificate to users based
 * on rules.
 * @{
 */

/**
 * Opaque type for the idmap context
 */
struct sss_certmap_ctx;

/**
 * Lowest priority of a rule
 */
#define SSS_CERTMAP_MIN_PRIO UINT32_MAX

/**
 * Typedef for external debug callback
 */
typedef void (sss_certmap_ext_debug)(void *pvt,
                                     const char *file, long line,
                                     const char *function,
                                     const char *format, ...);
/**
 * @brief Initialize certmap context
 *
 * @param[in] mem_ctx    Talloc memory context, may be NULL
 * @param[in] debug      Callback to handle debug output, may be NULL
 * @param[in] debug_priv Private data for debugging callback, may be NULL
 * @param[out] ctx       New certmap context
 *
 * @return
 *  - 0:      success
 *  - ENOMEM: failed to allocate internal Talloc context
 *  - EINVAL: ctx is NULL
 */
int sss_certmap_init(TALLOC_CTX *mem_ctx,
                     sss_certmap_ext_debug *debug, void *debug_priv,
                     struct sss_certmap_ctx **ctx);

/**
 * @brief Free certmap context
 *
 * @param[in] ctx certmap context previously initialized with
 *            @ref sss_certmap_init, may be NULL
 */
void sss_certmap_free_ctx(struct sss_certmap_ctx *ctx);

/**
 * @brief Add a rule to the certmap context
 *
 * @param[in] ctx        certmap context previously initialized with
 *                       @ref sss_certmap_init
 * @param[in] priority   priority of the rule, 0 is the hightest priority, the
 *                       lowest is SSS_CERTMAP_MIN_PRIO
 * @param[in] match_rule String with the matching rule
 * @param[in] map_rule   String with the mapping rule
 * @param[in] domains    NULL-terminated string array with a list of domains
 *                       the rule should be valid for, i.e. only this domains
 *                       should be searched for matching users
 *
 * @return
 *  - 0:      success
 */
int sss_certmap_add_rule(struct sss_certmap_ctx *ctx,
                         uint32_t priority, const char *match_rule,
                         const char *map_rule, const char **domains);

/**
 * @brief Check if a certificate matches any of the applied rules
 *
 * @param[in] ctx      certmap context previously initialized with
 *                     @ref sss_certmap_init
 * @param[in] der_cert binary blob with the DER encoded certificate
 * @param[in] der_size size of the certificate blob
 *
 * @return
 *  - 0:      certificate matches a rule
 *  - ENOENT: certificate does not match
 *  - EINVAL: internal error
 */
int sss_certmap_match_cert(struct sss_certmap_ctx *ctx,
                           const uint8_t *der_cert, size_t der_size);

/**
 * @brief Get the LDAP filter string for a certificate
 *
 * @param[in] ctx      certmap context previously initialized with
 *                     @ref sss_certmap_init
 * @param[in] der_cert binary blob with the DER encoded certificate
 * @param[in] der_size size of the certificate blob
 * @param[out] filter  LDAP filter string, expanded templates are sanitized,
 *                     caller should free the data by calling
 *                     sss_certmap_free_filter_and_domains
 * @param[out] domains NULL-terminated array of strings with the domains the
 *                     rule applies, caller should free the data by calling
 *                     sss_certmap_free_filter_and_domains
 *
 * @return
 *  - 0:      certificate matches a rule
 *  - ENOENT: certificate does not match
 *  - EINVAL: internal error
 */
int sss_certmap_get_search_filter(struct sss_certmap_ctx *ctx,
                                  const uint8_t *der_cert, size_t der_size,
                                  char **filter, char ***domains);

/**
 * @brief Expand the mapping rule by replacing the templates
 *
 * @param[in] ctx        certmap context previously initialized with
 *                       @ref sss_certmap_init
 * @param[in] der_cert   binary blob with the DER encoded certificate
 * @param[in] der_size   size of the certificate blob
 * @param[out] expanded  expanded mapping rule, templates are filled in
 *                       verbatim in contrast to sss_certmap_get_search_filter,
 *                       caller should free the data by
 *                       calling sss_certmap_free_filter_and_domains
 * @param[out] domains   NULL-terminated array of strings with the domains the
 *                       rule applies, caller should free the data by calling
 *                       sss_certmap_free_filter_and_domains
 *
 * @return
 *  - 0:      certificate matches a rule
 *  - ENOENT: certificate does not match
 *  - EINVAL: internal error
 */
int sss_certmap_expand_mapping_rule(struct sss_certmap_ctx *ctx,
                                    const uint8_t *der_cert, size_t der_size,
                                    char **_expanded, char ***_domains);
/**
 * @brief Free data returned by @ref sss_certmap_get_search_filter
 *        and @ref sss_certmap_expand_mapping_rule
 *
 * @param[in] filter  LDAP filter strings returned by
 *                    sss_certmap_get_search_filter
 * @param[in] domains string array of domains returned by
 *                     sss_certmap_get_search_filter
 */
void sss_certmap_free_filter_and_domains(char *filter, char **domains);

/**
 * @brief Get a string with the content of the certificate used by the library
 *
 * @param[in]  mem_ctx    Talloc memory context, may be NULL
 * @param[in]  der_cert   binary blob with the DER encoded certificate
 * @param[in]  der_size   size of the certificate blob
 * @param[out] desc       Multiline string showing the certificate content
 *                        which is used by libsss_certmap
 *
 * @return
 *  - 0:      success
 *  - EINVAL: certificate cannot be parsed
 *  - ENOMEM: memory allocation failure
 */
int sss_certmap_display_cert_content(TALLOC_CTX *mem_cxt,
                                     const uint8_t *der_cert, size_t der_size,
                                     char **desc);

/**
 * @}
 */
#endif /* _SSS_CERTMAP_H_ */
