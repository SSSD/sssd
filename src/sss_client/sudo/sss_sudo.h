/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#ifndef SSS_SUDO_H_
#define SSS_SUDO_H_

/**
 * @defgroup libsss_sudo A library for communication between SUDO and SSSD
 * libsss_sudo provides a mechanism to for a SUDO plugin
 * to communicate with the sudo responder of SSSD.
 *
 * @{
 */

#include <stdint.h>
#include <sys/types.h>

/** The value returned when the communication with SUDO is successful and
 *  the user was found in one of the domains
 */
#define SSS_SUDO_ERROR_OK   0

/**
 * Component of an sss_rule structure. The component
 * has exactly one name and one or more values.
 *
 */
struct sss_sudo_attr {
    /** The attribute name */
    char *name;
    /** A string array that contains all the attribute values */
    char **values;

    /** The number of values the attribute contains.
     *
     * Attributes are multivalued in general.
     */
    unsigned int num_values;
};

/**
 * One sudo rule. The rule consists of one or more
 * attributes of sss_attr type
 */
struct sss_sudo_rule {
    /** The number of attributes in the rule */
    unsigned int num_attrs;

    /** List of rule attributes */
    struct sss_sudo_attr *attrs;
};

/**
 * A result object returned from SSSD.
 *
 * The result consists of zero or more sss_rule elements.
 */
struct sss_sudo_result {
    /**
     * The number of rules for the user
     *
     * In case the user exists in one of SSSD domains
     * but no rules match for him, the num_rules element
     * is 0.
     */
    unsigned int num_rules;

    /** List of rules found */
    struct sss_sudo_rule *rules;
};

/**
 * @brief Send a request to SSSD to retrieve all SUDO rules for a given
 * user.
 *
 * @param[in] uid         The uid of the user to retrieve the rules for.
 * @param[in] username    The username to retrieve the rules for
 * @param[in] domainname  The domain name the user is a member of.
 * @param[out] _error     The result of the search in SSSD's domains. If the
 *                        user was present in the domain, the _error code is
 *                        SSS_SUDO_ERROR_OK and the _result structure is
 *                        returned even if it was empty (in other words
 *                        _result->num_rules == 0). Other problems are returned
 *                        as errno codes. Most prominently these are ENOENT
 *                        (the user was not found with SSSD), EIO (SSSD
 *                        encountered an internal problem) and EINVAL
 *                        (malformed query).
 * @param[out] _result    Newly allocated structure sss_result that contains
 *                        the rules for the user. If no rules were found but
 *                        the user was valid, this structure is "empty", which
 *                        means that the num_rules member is 0.
 *
 * @return 0 on success and other errno values on failure. The return value
 *         denotes whether communication with SSSD was successful. It does not
 *         tell whether the result contains any rules or whether SSSD knew the
 *         user at all. That information is transferred in the _error parameter.
 */
int sss_sudo_send_recv(uid_t uid,
                       const char *username,
                       const char *domainname,
                       uint32_t *_error,
                       struct sss_sudo_result **_result);

/**
 * @brief Send a request to SSSD to retrieve the default options, commonly
 * stored in the "cn=defaults" record,
 *
 * @param[in] uid          The uid of the user to retrieve the rules for.
 *
 * @param[in] username     The username to retrieve the rules for.
 *
 * @param[out] _error      The result of the search in SSSD's domains. If the
 *                         options were present in the domain, the _error code
 *                         is SSS_SUDO_ERROR_OK and the _result structure is
 *                         returned even if it was empty (in other words
 *                         _result->num_rules == 0). Other problems are returned
 *                         as errno codes.
 *
 * @param[out] _domainname The domain name the user is a member of.
 *
 * @param[out] _result     Newly allocated structure sss_result that contains
 *                         the options. If no options were found this structure
 *                         is "empty", which means that the num_rules member
 *                         is 0.
 *
 * @return 0 on success and other errno values on failure. The return value
 *         denotes whether communication with SSSD was successful. It does not
 *         tell whether the result contains any rules or whether SSSD knew the
 *         user at all. That information is transferred in the _error parameter.
 *
 * @note   The _domainname should be freed using free().
 */
int sss_sudo_send_recv_defaults(uid_t uid,
                                const char *username,
                                uint32_t *_error,
                                char **_domainname,
                                struct sss_sudo_result **_result);

/**
 * @brief Free the sss_result structure returned by sss_sudo_send_recv
 *
 * @param[in] result    The sss_result structure to free. The structure was
 *                      previously returned by sss_sudo_get_values().
 */
void sss_sudo_free_result(struct sss_sudo_result *result);

/**
 * @brief Get all values for a given attribute in an sss_rule
 *
 * @param[in] e           The sss_rule to get values from
 * @param[in] attrname    The name of the attribute to query from the rule
 * @param[out] values     A newly allocated list of values the attribute has in
 *                        rule. On success, this parameter is an array of
 *                        NULL-terminated strings, the last element is a NULL
 *                        pointer. On failure (including when the attribute is
 *                        not found), the pointer address is not changed.
 *
 * @return 0 on success, ENOENT in case the attribute is not found and other
 * errno values on failure.
 *
 * @note the returned values should be freed using sss_sudo_free_values()
 */
int sss_sudo_get_values(struct sss_sudo_rule *e,
                        const char *attrname,
                        char ***values);

/**
 * @brief Free the values returned by sss_sudo_get_values
 *
 * @param[in] values    The list of values to free. The values were previously
 *                      returned by sss_sudo_get_values()
 */
void sss_sudo_free_values(char **values);

/**
 * @}
 */
#endif /* SSS_SUDO_H_ */
