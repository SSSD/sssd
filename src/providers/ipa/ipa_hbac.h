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

#include <stdint.h>
#include <stdbool.h>

enum hbac_eval_result {
    HBAC_EVAL_ERROR = -1,
    HBAC_EVAL_ALLOW,
    HBAC_EVAL_DENY,
    HBAC_EVAL_OOM
};

#define HBAC_CATEGORY_NULL 0x0000 /* No service category specified */
#define HBAC_CATEGORY_ALL  0x0001 /* Rule should apply to all */

/* Opaque type contained in hbac_evaluator.c */
struct hbac_time_rules;

struct hbac_rule_element {
    uint32_t category;
    const char **names;
    const char **groups;
};

struct hbac_rule {
    const char *name;
    bool enabled;

    /* Services and service groups
     * for which this rule applies
     */
    struct hbac_rule_element *services;

    /* Users and groups for which this
     * rule applies
     */
    struct hbac_rule_element *users;

    /* Target hosts for which this rule apples */
    struct hbac_rule_element *targethosts;

    /* Source hosts for which this rule applies */
    struct hbac_rule_element *srchosts;

    /* For future use */
    struct hbac_time_rules *timerules;
};

struct hbac_request_element {
    const char *name;
    const char **groups;
};

struct hbac_eval_req {
    /* This is a list of service DNs to check,
     * it must consist of the actual service
     * requested, as well as all parent groups
     * containing that service.
     */
    struct hbac_request_element *service;

    /* This is a list of user DNs to check,
     * it must consist of the actual user
     * requested, as well as all parent groups
     * containing that user.
     */
    struct hbac_request_element *user;

    /* This is a list of target hosts to check,
     * it must consist of the actual target host
     * requested, as well as all parent groups
     * containing that target host.
     */
    struct hbac_request_element *targethost;

    /* This is a list of source hosts to check,
     * it must consist of the actual source host
     * requested, as well as all parent groups
     * containing that source host.
     */
    struct hbac_request_element *srchost;

    /* For future use */
    time_t request_time;
};

enum hbac_error_code {
    HBAC_ERROR_UNKNOWN = -1,
    HBAC_SUCCESS,
    HBAC_ERROR_NOT_IMPLEMENTED,
    HBAC_ERROR_OUT_OF_MEMORY,
    HBAC_ERROR_UNPARSEABLE_RULE
};

/* Extended information */
struct hbac_info {
    /* If the hbac_eval_result was HBAC_EVAL_ERROR,
     * this will be an error code.
     * Otherwise it will be HBAC_SUCCESS
     */
    enum hbac_error_code code;

    /* Specify the name of the rule that matched or
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
 */
enum hbac_eval_result hbac_evaluate(struct hbac_rule **rules,
                                    struct hbac_eval_req *hbac_req,
                                    struct hbac_info **info);

const char *hbac_result_string(enum hbac_eval_result result);
const char *hbac_error_string(enum hbac_error_code code);

void hbac_free_info(struct hbac_info *info);


#define HBAC_RULE_ELEMENT_USERS       0x01
#define HBAC_RULE_ELEMENT_SERVICES    0x02
#define HBAC_RULE_ELEMENT_TARGETHOSTS 0x04
#define HBAC_RULE_ELEMENT_SOURCEHOSTS 0x08

/**
 * @brief Evaluate whether an HBAC rule contains all necessary elements
 *
 * @param[in] rule           An HBAC rule to evaluate
 * @param[out] missing_attrs A list of attributes missing from the rule
 *                           This is a bitmask that may contain one or more
 *                           of HBAC_RULE_ELEMENT_USERS,
 *                           HBAC_RULE_ELEMENT_SERVICES,
 *                           HBAC_RULE_ELEMENT_TARGETHOSTS and
 *                           HBAC_RULE_ELEMENT_SOURCEHOSTS
 *
 * @return True if the rule contains all mandatory attributes
 *
 * @note This function does not care if the rule is enabled or disabled
 */
bool hbac_rule_is_complete(struct hbac_rule *rule, uint32_t *missing_attrs);

#endif /* IPA_HBAC_H_ */
