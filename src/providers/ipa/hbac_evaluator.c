/*
    SSSD

    IPA Backend Module -- Access control

    Authors:
        Sumit Bose <sbose@redhat.com>
        Stephen Gallagher <sgallagh@redhat.com>

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "providers/ipa/ipa_hbac.h"
#include "util/sss_utf8.h"

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

#ifndef EOK
#define EOK 0
#endif

/* Placeholder structure for future HBAC time-based
 * evaluation rules
 */
struct hbac_time_rules {
    int not_yet_implemented;
};

enum hbac_eval_result_int {
    HBAC_EVAL_MATCH_ERROR = -1,
    HBAC_EVAL_MATCHED,
    HBAC_EVAL_UNMATCHED
};

static bool hbac_rule_element_is_complete(struct hbac_rule_element *el)
{
    if (el == NULL) return false;
    if (el->category == HBAC_CATEGORY_ALL) return true;

    if (el->names == NULL && el->groups == NULL) return false;

    if ((el->names && el->names[0] != NULL)
            || (el->groups && el->groups[0] != NULL))
        return true;

    /* If other categories are added, handle them here */

    return false;
}

bool hbac_rule_is_complete(struct hbac_rule *rule, uint32_t *missing_attrs)
{
    bool complete = true;

    *missing_attrs = 0;

    if (rule == NULL) {
        /* No rule passed in? */
        return false;
    }

    /* Make sure we have all elements */
    if (!hbac_rule_element_is_complete(rule->users)) {
        complete = false;
        *missing_attrs |= HBAC_RULE_ELEMENT_USERS;
    }

    if (!hbac_rule_element_is_complete(rule->services)) {
        complete = false;
        *missing_attrs |= HBAC_RULE_ELEMENT_SERVICES;
    }

    if (!hbac_rule_element_is_complete(rule->targethosts)) {
        complete = false;
        *missing_attrs |= HBAC_RULE_ELEMENT_TARGETHOSTS;
    }

    if (!hbac_rule_element_is_complete(rule->srchosts)) {
        complete = false;
        *missing_attrs |= HBAC_RULE_ELEMENT_SOURCEHOSTS;
    }

    return complete;
}

enum hbac_eval_result_int hbac_evaluate_rule(struct hbac_rule *rule,
                                             struct hbac_eval_req *hbac_req,
                                             enum hbac_error_code *error);

enum hbac_eval_result hbac_evaluate(struct hbac_rule **rules,
                                    struct hbac_eval_req *hbac_req,
                                    struct hbac_info **info)
{
    enum hbac_error_code ret;
    enum hbac_eval_result result = HBAC_EVAL_DENY;
    enum hbac_eval_result_int intermediate_result;

    if (info) {
        *info = malloc(sizeof(struct hbac_info));
        if (!*info) {
            return HBAC_EVAL_OOM;
        }
        (*info)->code = HBAC_ERROR_UNKNOWN;
        (*info)->rule_name = NULL;
    }
    uint32_t i;

    for (i = 0; rules[i]; i++) {
        intermediate_result = hbac_evaluate_rule(rules[i], hbac_req, &ret);
        if (intermediate_result == HBAC_EVAL_UNMATCHED) {
            /* This rule did not match at all. Skip it */
            continue;
        } else if (intermediate_result == HBAC_EVAL_MATCHED) {
            /* This request matched an ALLOW rule
             * Set the result to ALLOW but continue checking
             * the other rules in case a DENY rule trumps it.
             */
            result = HBAC_EVAL_ALLOW;
            if (info) {
                (*info)->code = HBAC_SUCCESS;
                (*info)->rule_name = strdup(rules[i]->name);
                if (!(*info)->rule_name) {
                    result = HBAC_EVAL_ERROR;
                    (*info)->code = HBAC_ERROR_OUT_OF_MEMORY;
                }
            }
            break;
        } else {
            /* An error occurred processing this rule */
            result = HBAC_EVAL_ERROR;
            (*info)->code = ret;
            (*info)->rule_name = strdup(rules[i]->name);
            /* Explicitly not checking the result of strdup(), since if
             * it's NULL, we can't do anything anyway.
             */
            goto done;
        }
    }

    /* If we've reached the end of the loop, we have either set the
     * result to ALLOW explicitly or we'll stick with the default DENY.
     */
done:

    return result;
}

static errno_t hbac_evaluate_element(struct hbac_rule_element *rule_el,
                                     struct hbac_request_element *req_el,
                                     bool *matched);

enum hbac_eval_result_int hbac_evaluate_rule(struct hbac_rule *rule,
                                             struct hbac_eval_req *hbac_req,
                                             enum hbac_error_code *error)
{
    errno_t ret;
    bool matched;

    if (!rule->enabled) return HBAC_EVAL_UNMATCHED;

    /* Make sure we have all elements */
    if (!rule->users
     || !rule->services
     || !rule->targethosts
     || !rule->srchosts) {
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    }

    /* Check users */
    ret = hbac_evaluate_element(rule->users,
                                hbac_req->user,
                                &matched);
    if (ret != EOK) {
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    } else if (!matched) {
        return HBAC_EVAL_UNMATCHED;
    }

    /* Check services */
    ret = hbac_evaluate_element(rule->services,
                                hbac_req->service,
                                &matched);
    if (ret != EOK) {
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    } else if (!matched) {
        return HBAC_EVAL_UNMATCHED;
    }

    /* Check target hosts */
    ret = hbac_evaluate_element(rule->targethosts,
                                hbac_req->targethost,
                                &matched);
    if (ret != EOK) {
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    } else if (!matched) {
        return HBAC_EVAL_UNMATCHED;
    }

    /* Check source hosts */
    ret = hbac_evaluate_element(rule->srchosts,
                                hbac_req->srchost,
                                &matched);
    if (ret != EOK) {
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    } else if (!matched) {
        return HBAC_EVAL_UNMATCHED;
    }
    return HBAC_EVAL_MATCHED;
}

static errno_t hbac_evaluate_element(struct hbac_rule_element *rule_el,
                                     struct hbac_request_element *req_el,
                                     bool *matched)
{
    size_t i, j;
    const uint8_t *rule_name;
    const uint8_t *req_name;
    int ret;

    if (rule_el->category & HBAC_CATEGORY_ALL) {
        *matched = true;
        return EOK;
    }

    /* First check the name list */
    if (rule_el->names) {
        for (i = 0; rule_el->names[i]; i++) {
            if (req_el->name != NULL) {
                rule_name = (const uint8_t *) rule_el->names[i];
                req_name = (const uint8_t *) req_el->name;

                /* Do a case-insensitive comparison. */
                ret = sss_utf8_case_eq(rule_name, req_name);
                if (ret != EOK && ret != ENOMATCH) {
                    return ret;
                } else if (ret == EOK) {
                    *matched = true;
                    return EOK;
                }
            }
        }
    }

    if (rule_el->groups) {
        /* Not found in the name list
         * Check for group membership
         */
        for (i = 0; rule_el->groups[i]; i++) {
            rule_name = (const uint8_t *) rule_el->groups[i];

            for (j = 0; req_el->groups[j]; j++) {
                req_name = (const uint8_t *) req_el->groups[j];

                /* Do a case-insensitive comparison. */
                ret = sss_utf8_case_eq(rule_name, req_name);
                if (ret != EOK && ret != ENOMATCH) {
                    return ret;
                } else if (ret == EOK) {
                    *matched = true;
                    return EOK;
                }
            }
        }
    }

    /* Not found in groups either */
    *matched = false;
    return EOK;
}

const char *hbac_result_string(enum hbac_eval_result result)
{
    switch(result) {
    case HBAC_EVAL_ALLOW:
        return "HBAC_EVAL_ALLOW";
    case HBAC_EVAL_DENY:
        return "HBAC_EVAL_DENY";
    case HBAC_EVAL_ERROR:
        return "HBAC_EVAL_ERROR";
    case HBAC_EVAL_OOM:
        return "Could not allocate memory for hbac_info object";
    }
    return "HBAC_EVAL_ERROR";
}

void hbac_free_info(struct hbac_info *info)
{
    if (info == NULL) return;

    free(info->rule_name);
    free(info);
    info = NULL;
}

const char *hbac_error_string(enum hbac_error_code code)
{
    switch(code) {
    case HBAC_SUCCESS:
        return "Success";
    case HBAC_ERROR_NOT_IMPLEMENTED:
        return "Function is not yet implemented";
    case HBAC_ERROR_OUT_OF_MEMORY:
        return "Out of memory";
    case HBAC_ERROR_UNPARSEABLE_RULE:
        return "Rule could not be evaluated";
    case HBAC_ERROR_UNKNOWN:
    default:
        return "Unknown error code";
    }
}
