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

#include "config.h" /* for HAVE_FUNCTION_ATTRIBUTE_FORMAT in "ipa_hbac.h" */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "ipa_hbac.h"
#include "sss_utf8.h"

#ifndef HAVE_ERRNO_T
#define HAVE_ERRNO_T
typedef int errno_t;
#endif

#ifndef EOK
#define EOK 0
#endif

/* HBAC logging system */

/* debug macro */
#define HBAC_DEBUG(level, format, ...) do { \
    if (hbac_debug_fn != NULL) { \
        hbac_debug_fn(__FILE__, __LINE__, __FUNCTION__, \
                      level, format, ##__VA_ARGS__); \
    } \
} while (0)

/* static pointer to external logging function */
static hbac_debug_fn_t hbac_debug_fn = NULL;

/* setup function for external logging function */
void hbac_enable_debug(hbac_debug_fn_t external_debug_fn)
{
    hbac_debug_fn = external_debug_fn;
}

/* auxiliary function for hbac_request_element logging */
static void hbac_request_element_debug_print(struct hbac_request_element *el,
                                             const char *label);

/* auxiliary function for hbac_eval_req logging */
static void hbac_req_debug_print(struct hbac_eval_req *req);

/* auxiliary function for hbac_rule_element logging */
static void hbac_rule_element_debug_print(struct hbac_rule_element *el,
                                          const char *label);

/* auxiliary function for hbac_rule logging */
static void hbac_rule_debug_print(struct hbac_rule *rule);


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
    uint32_t i;

    enum hbac_error_code ret;
    enum hbac_eval_result result = HBAC_EVAL_DENY;
    enum hbac_eval_result_int intermediate_result;

    HBAC_DEBUG(HBAC_DBG_INFO, "[< hbac_evaluate()\n");
    hbac_req_debug_print(hbac_req);

    if (info) {
        *info = malloc(sizeof(struct hbac_info));
        if (!*info) {
            HBAC_DEBUG(HBAC_DBG_ERROR, "Out of memory.\n");
            return HBAC_EVAL_OOM;
        }
        (*info)->code = HBAC_ERROR_UNKNOWN;
        (*info)->rule_name = NULL;
    }

    for (i = 0; rules[i]; i++) {
        hbac_rule_debug_print(rules[i]);
        intermediate_result = hbac_evaluate_rule(rules[i], hbac_req, &ret);
        if (intermediate_result == HBAC_EVAL_UNMATCHED) {
            /* This rule did not match at all. Skip it */
            HBAC_DEBUG(HBAC_DBG_INFO, "The rule [%s] did not match.\n",
                       rules[i]->name);
            continue;
        } else if (intermediate_result == HBAC_EVAL_MATCHED) {
            HBAC_DEBUG(HBAC_DBG_INFO, "ALLOWED by rule [%s].\n", rules[i]->name);
            result = HBAC_EVAL_ALLOW;
            if (info) {
                (*info)->code = HBAC_SUCCESS;
                (*info)->rule_name = strdup(rules[i]->name);
                if (!(*info)->rule_name) {
                    HBAC_DEBUG(HBAC_DBG_ERROR, "Out of memory.\n");
                    result = HBAC_EVAL_ERROR;
                    (*info)->code = HBAC_ERROR_OUT_OF_MEMORY;
                }
            }
            break;
        } else {
            /* An error occurred processing this rule */
            HBAC_DEBUG(HBAC_DBG_ERROR,
                       "Error %d occurred during evaluating of rule [%s].\n",
                       ret, rules[i]->name);
            result = HBAC_EVAL_ERROR;
            if (info) {
                (*info)->code = ret;
                (*info)->rule_name = strdup(rules[i]->name);
            }
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

    HBAC_DEBUG(HBAC_DBG_INFO, "hbac_evaluate() >]\n");
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

    if (!rule->enabled) {
        HBAC_DEBUG(HBAC_DBG_INFO, "Rule [%s] is not enabled\n", rule->name);
        return HBAC_EVAL_UNMATCHED;
    }

    /* Make sure we have all elements */
    if (!rule->users
     || !rule->services
     || !rule->targethosts
     || !rule->srchosts) {
        HBAC_DEBUG(HBAC_DBG_INFO,
                   "Rule [%s] cannot be parsed, some elements are empty\n",
                   rule->name);
        *error = HBAC_ERROR_UNPARSEABLE_RULE;
        return HBAC_EVAL_MATCH_ERROR;
    }

    /* Check users */
    ret = hbac_evaluate_element(rule->users,
                                hbac_req->user,
                                &matched);
    if (ret != EOK) {
        HBAC_DEBUG(HBAC_DBG_ERROR,
                   "Cannot parse user elements of rule [%s]\n", rule->name);
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
        HBAC_DEBUG(HBAC_DBG_ERROR,
                   "Cannot parse service elements of rule [%s]\n", rule->name);
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
        HBAC_DEBUG(HBAC_DBG_ERROR,
                   "Cannot parse targethost elements of rule [%s]\n",
                   rule->name);
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
        HBAC_DEBUG(HBAC_DBG_ERROR,
                   "Cannot parse srchost elements of rule [%s]\n",
                   rule->name);
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
    switch (result) {
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
}

const char *hbac_error_string(enum hbac_error_code code)
{
    switch (code) {
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

static void hbac_request_element_debug_print(struct hbac_request_element *el,
                                             const char *label)
{
    int i;

    if (el) {
        if (el->name) {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s [%s]\n", label, el->name);
        }

        if (el->groups) {
            if (el->groups[0]) {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_group:\n", label);
                for (i = 0; el->groups[i]; i++) {
                    HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t\t[%s]\n", el->groups[i]);
                }
            } else {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_group (none)\n", label);
            }
        }
    } else {
        HBAC_DEBUG(HBAC_DBG_TRACE, "\t%s (none)\n", label);
    }
}

static void hbac_req_debug_print(struct hbac_eval_req *req)
{
    HBAC_DEBUG(HBAC_DBG_TRACE, "\tREQUEST:\n");
    if (req) {
        struct tm *local_time = NULL;
        size_t ret;
        const size_t buff_size = 100;
        char time_buff[buff_size];

        hbac_request_element_debug_print(req->service, "service");
        hbac_request_element_debug_print(req->user, "user");
        hbac_request_element_debug_print(req->targethost, "targethost");
        hbac_request_element_debug_print(req->srchost, "srchost");

        local_time = localtime(&req->request_time);
        if (local_time == NULL) {
            return;
        }

        ret = strftime(time_buff, buff_size, "%Y-%m-%d %H:%M:%S", local_time);
        if (ret <= 0) {
            return;
        }

        HBAC_DEBUG(HBAC_DBG_TRACE, "\t\trequest time %s\n", time_buff);
    } else {
        HBAC_DEBUG(HBAC_DBG_TRACE, "\tRequest is EMPTY.\n");
    }
}

static void hbac_rule_element_debug_print(struct hbac_rule_element *el,
                                          const char *label)
{
    int i;

    if (el) {
        HBAC_DEBUG(HBAC_DBG_TRACE, "\t\tcategory [%#x] [%s]\n", el->category,
                   (el->category == HBAC_CATEGORY_ALL) ? "ALL" : "NONE");

        if (el->names) {
            if (el->names[0]) {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_names:\n", label);
                for (i = 0; el->names[i]; i++) {
                    HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t\t[%s]\n", el->names[i]);
                }
            } else {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_names (none)\n", label);
            }
        }

        if (el->groups) {
            if (el->groups[0]) {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_groups:\n", label);
                for (i = 0; el->groups[i]; i++) {
                    HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t\t[%s]\n", el->groups[i]);
                }
            } else {
                HBAC_DEBUG(HBAC_DBG_TRACE, "\t\t%s_groups (none)\n", label);
            }
        }
    }
}

static void hbac_rule_debug_print(struct hbac_rule *rule)
{
    if (rule) {
        HBAC_DEBUG(HBAC_DBG_TRACE, "\tRULE [%s] [%s]:\n",
                   rule->name, (rule->enabled) ? "ENABLED" : "DISABLED");
        if (rule->services) {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tservices:\n");
            hbac_rule_element_debug_print(rule->services, "services");
        } else {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tservices (none)\n");
        }

        if (rule->users) {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tusers:\n");
            hbac_rule_element_debug_print(rule->users, "users");
        } else {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tusers (none)\n");
        }

        if (rule->targethosts) {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\ttargethosts:\n");
            hbac_rule_element_debug_print(rule->targethosts, "targethosts");
        } else {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\ttargethosts (none)\n");
        }

        if (rule->srchosts) {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tsrchosts:\n");
            hbac_rule_element_debug_print(rule->srchosts, "srchosts");
        } else {
            HBAC_DEBUG(HBAC_DBG_TRACE, "\tsrchosts (none)\n");
        }
    }
}
