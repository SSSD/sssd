/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2009 Red Hat

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

#ifndef IPA_HBAC_H_
#define IPA_HBAC_H_

/**
 * @defgroup ipa_hbac Host-Based Access Control Resolver
 * Libipa_hbac provides a mechanism to validate FreeIPA
 * HBAC rules as well as evaluate whether they apply to
 * a particular user login attempt.
 *
 * Libipa_hbac is case-insensitive and compatible with
 * UTF-8.
 * @{
 */

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/** Debug levels for HBAC. */
enum hbac_debug_level {
    HBAC_DBG_FATAL,     /** Fatal failure (not used). */
    HBAC_DBG_ERROR,     /** Serious failure (out of memory, for example). */
    HBAC_DBG_WARNING,   /** Warnings (not used). */
    HBAC_DBG_INFO,      /** HBAC allow/disallow info. */
    HBAC_DBG_TRACE      /** Verbose description of rules. */
};

#ifdef HAVE_FUNCTION_ATTRIBUTE_FORMAT
#define HBAC_ATTRIBUTE_PRINTF(a1, a2) __attribute__((format(printf, a1, a2)))
#else
#define HBAC_ATTRIBUTE_PRINTF(a1, a2)
#endif

/**
 * Function pointer to HBAC external debugging function.
 */
typedef void (*hbac_debug_fn_t)(const char *file, int line,
                                const char *function,
                                enum hbac_debug_level, const char *format,
                                ...) HBAC_ATTRIBUTE_PRINTF(5, 6);

/**
 * HBAC uses external_debug_fn for logging messages.
 * @param[in] external_debug_fn Pointer to external logging function.
 */
void hbac_enable_debug(hbac_debug_fn_t external_debug_fn);

/** Result of HBAC evaluation */
enum hbac_eval_result {
    /** An error occurred
     * See the #hbac_info for more details
     */
    HBAC_EVAL_ERROR = -1,

    /** Evaluation grants access */
    HBAC_EVAL_ALLOW,

    /** Evaluation denies access */
    HBAC_EVAL_DENY,

    /** Evaluation failed due to lack of memory
     * #hbac_info is not available
     */
    HBAC_EVAL_OOM
};

/**
 * No service category specified
 */
#define HBAC_CATEGORY_NULL 0x0000

/**
 * Rule should apply to all
 */
#define HBAC_CATEGORY_ALL  0x0001

/**
 * Opaque type contained in hbac_evaluator.c
 */
struct hbac_time_rules;

/**
 * Component of an HBAC rule
 *
 * Components can be one of users, target hosts,
 * source hosts, or services.
 */
struct hbac_rule_element {
    /**
     * Category for this element
     *
     * This value is a bitmask.
     * See #HBAC_CATEGORY_NULL and
     * #HBAC_CATEGORY_ALL
     */
    uint32_t category;

    /**
     * List of explicit members of this rule component
     *
     *  - Users:    usernames
     *  - Hosts:    hostnames
     *  - Services: PAM service names
     */
    const char **names;

    /**
     * List of group members of this rule component
     *
     *  - Users:    user groups (POSIX or non-POSIX)
     *  - Hosts:    hostgroups
     *  - Services: PAM service groups.
     */
    const char **groups;
};

/**
 * HBAC rule object for evaluation
 */
struct hbac_rule {
    const char *name;
    bool enabled;

    /**
     * Services and service groups
     * for which this rule applies
     */
    struct hbac_rule_element *services;

    /**
     * Users and groups for which this
     * rule applies
     */
    struct hbac_rule_element *users;

    /**
     * Target hosts for which this rule apples
     */
    struct hbac_rule_element *targethosts;

    /**
     * Source hosts for which this rule applies
     */
    struct hbac_rule_element *srchosts;

    /**
     * For future use
     */
    struct hbac_time_rules *timerules;
};

/**
 * Component of an HBAC request
 */
struct hbac_request_element {
    /**
     * List of explicit members of this request component
     *
     *  - Users:    usernames
     *  - Hosts:    hostnames
     *  - Services: PAM service names
     */
    const char *name;

    /**
     * List of group members of this request component
     *
     *  - Users:    user groups (POSIX or non-POSIX)
     *  - Hosts:    hostgroups
     *  - Services: PAM service groups.
     */
    const char **groups;
};

/**
 * Request object for an HBAC rule evaluation
 *
 *
 */
struct hbac_eval_req {
    /** This is a list of service DNs to check,
     * it must consist of the actual service
     * requested, as well as all parent groups
     * containing that service.
     */
    struct hbac_request_element *service;

    /** This is a list of user DNs to check,
     * it must consist of the actual user
     * requested, as well as all parent groups
     * containing that user.
     */
    struct hbac_request_element *user;

    /** This is a list of target hosts to check,
     * it must consist of the actual target host
     * requested, as well as all parent groups
     * containing that target host.
     */
    struct hbac_request_element *targethost;

    /** This is a list of source hosts to check,
     * it must consist of the actual source host
     * requested, as well as all parent groups
     * containing that source host.
     */
    struct hbac_request_element *srchost;

    /** For future use */
    time_t request_time;
};

/**
 * Error code returned by the evaluator
 */
enum hbac_error_code {
    /** Unexpected error */
    HBAC_ERROR_UNKNOWN = -1,

    /** Successful evaluation */
    HBAC_SUCCESS,

    /** Function is not yet implemented */
    HBAC_ERROR_NOT_IMPLEMENTED,

    /** Ran out of memory during processing */
    HBAC_ERROR_OUT_OF_MEMORY,

    /** Parse error while evaluating rule */
    HBAC_ERROR_UNPARSEABLE_RULE
};

/** Extended information */
struct hbac_info {
    /**
     * If the hbac_eval_result was HBAC_EVAL_ERROR,
     * this will be an error code.
     * Otherwise it will be HBAC_SUCCESS
     */
    enum hbac_error_code code;

    /**
     * Specify the name of the rule that matched or
     * threw an error
     */
    char *rule_name;
};


/**
 * @brief Evaluate an authorization request against a set of HBAC rules
 *
 * @param[in] rules    A NULL-terminated list of rules to evaluate against
 * @param[in] hbac_req A user authorization request
 * @param[out] info    Extended information (including the name of the
 *                     rule that allowed access (or caused a parse error)
 * @return
 *  - #HBAC_EVAL_ERROR: An error occurred
 *  - #HBAC_EVAL_ALLOW: Access is granted
 *  - #HBAC_EVAL_DENY:  Access is denied
 *  - #HBAC_EVAL_OOM:   Insufficient memory to complete the evaluation
 */
enum hbac_eval_result hbac_evaluate(struct hbac_rule **rules,
                                    struct hbac_eval_req *hbac_req,
                                    struct hbac_info **info);

/**
 * @brief Display result of hbac evaluation in human-readable form
 * @param[in] result Return value of #hbac_evaluate
 * @return English string describing the evaluation result
 */
const char *hbac_result_string(enum hbac_eval_result result);

/**
 * @brief Display error description
 * @param code Error code returned in #hbac_info
 * @return English string describing the error
 */
const char *hbac_error_string(enum hbac_error_code code);

/**
 * @brief Function to safely free #hbac_info returned by #hbac_evaluate
 * @param info #hbac_info returned by #hbac_evaluate
 */
void hbac_free_info(struct hbac_info *info);

/** User element */
#define HBAC_RULE_ELEMENT_USERS       0x01

/** Service element */
#define HBAC_RULE_ELEMENT_SERVICES    0x02

/** Target host element */
#define HBAC_RULE_ELEMENT_TARGETHOSTS 0x04

/** Source host element */
#define HBAC_RULE_ELEMENT_SOURCEHOSTS 0x08

/**
 * @brief Evaluate whether an HBAC rule contains all necessary elements
 *
 * @param[in] rule           An HBAC rule to evaluate
 * @param[out] missing_attrs A list of attributes missing from the rule
 *                           This is a bitmask that may contain one or more
 *                           of #HBAC_RULE_ELEMENT_USERS,
 *                           #HBAC_RULE_ELEMENT_SERVICES,
 *                           #HBAC_RULE_ELEMENT_TARGETHOSTS and
 *                           #HBAC_RULE_ELEMENT_SOURCEHOSTS
 *
 * @return True if the rule contains all mandatory attributes
 *
 * @note This function does not care if the rule is enabled or disabled
 */
bool hbac_rule_is_complete(struct hbac_rule *rule, uint32_t *missing_attrs);

/**
 * @}
 */
#endif /* IPA_HBAC_H_ */
