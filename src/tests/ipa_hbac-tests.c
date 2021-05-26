/*
    SSSD

    Authors:
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
#include <check.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <talloc.h>

#include "tests/common_check.h"
#include "lib/ipa_hbac/ipa_hbac.h"

#define HBAC_TEST_USER "testuser"
#define HBAC_TEST_INVALID_USER "nosuchuser"

#define HBAC_TEST_GROUP1 "testgroup1"
#define HBAC_TEST_GROUP2 "testgroup2"
#define HBAC_TEST_INVALID_GROUP "nosuchgroup"

#define HBAC_TEST_SERVICE "testservice"
#define HBAC_TEST_INVALID_SERVICE "nosuchservice"

#define HBAC_TEST_SERVICEGROUP1 "login_services"
#define HBAC_TEST_SERVICEGROUP2 "all_services"
#define HBAC_TEST_INVALID_SERVICEGROUP "nosuchservicegroup"

#define HBAC_TEST_SRCHOST "client.example.com"
#define HBAC_TEST_INVALID_SRCHOST "nosuchsrchost"

#define HBAC_TEST_SRCHOSTGROUP1 "site_hosts"
#define HBAC_TEST_SRCHOSTGROUP2 "corp_hosts"
#define HBAC_TEST_INVALID_SRCHOSTGROUP "nosuchsrchostgroup"


/* These don't make sense for a user/group/service but they do the job and
 * every one is from a different codepage */
/* Latin Extended A - "Czech" */
const uint8_t user_utf8_lowcase[] = { 0xC4, 0x8D, 'e', 'c', 'h', 0x0 };
const uint8_t user_utf8_upcase[] = { 0xC4, 0x8C, 'e', 'c', 'h', 0x0 };
const uint8_t user_utf8_lowcase_neg[] = { 0xC4, 0x8E, 'e', 'c', 'h', 0x0 };
/* Latin 1 Supplement - "Munchen" */
const uint8_t service_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
const uint8_t service_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
/* Greek - "AlphaBetaGamma" */
const uint8_t srchost_utf8_lowcase[] = { 0xCE, 0xB1, 0xCE, 0xB2, 0xCE, 0xB3, 0x0  };
const uint8_t srchost_utf8_upcase[] = { 0xCE, 0x91, 0xCE, 0x92, 0xCE, 0x93, 0x0 };
/* Turkish "capital I" and "dotless i" */
const uint8_t user_lowcase_tr[] = { 0xC4, 0xB1, 0x0 };
const uint8_t user_upcase_tr[] = { 0x49, 0x0 };

static void get_allow_all_rule(TALLOC_CTX *mem_ctx,
                               struct hbac_rule **allow_rule)
{
    struct hbac_rule *rule;
    /* Create a rule that ALLOWs all services, users and
     * remote hosts.
     */
    rule = talloc_zero(mem_ctx, struct hbac_rule);
    sss_ck_fail_if_msg(rule == NULL, "Failed to allocate memory");

    rule->enabled = true;

    rule->services = talloc_zero(rule, struct hbac_rule_element);
    sss_ck_fail_if_msg(rule->services == NULL, "Failed to allocate memory");
    rule->services->category = HBAC_CATEGORY_ALL;
    rule->services->names = NULL;
    rule->services->groups = NULL;

    rule->users = talloc_zero(rule, struct hbac_rule_element);
    sss_ck_fail_if_msg(rule->users == NULL, "Failed to allocate memory");
    rule->users->category = HBAC_CATEGORY_ALL;
    rule->users->names = NULL;
    rule->users->groups = NULL;

    rule->targethosts = talloc_zero(rule, struct hbac_rule_element);
    sss_ck_fail_if_msg(rule->targethosts == NULL, "Failed to allocate memory");
    rule->targethosts->category = HBAC_CATEGORY_ALL;
    rule->targethosts->names = NULL;
    rule->targethosts->groups = NULL;

    rule->srchosts = talloc_zero(rule, struct hbac_rule_element);
    sss_ck_fail_if_msg(rule->srchosts == NULL, "Failed to allocate memory");
    rule->srchosts->category = HBAC_CATEGORY_ALL;
    rule->srchosts->names = NULL;
    rule->srchosts->groups = NULL;

    *allow_rule = rule;
}

static void get_test_user(TALLOC_CTX *mem_ctx,
                          struct hbac_request_element **user)
{
    struct hbac_request_element *new_user;

    new_user = talloc_zero(mem_ctx, struct hbac_request_element);
    sss_ck_fail_if_msg(new_user == NULL, "Failed to allocate memory");

    new_user->name = talloc_strdup(new_user, HBAC_TEST_USER);
    sss_ck_fail_if_msg(new_user->name == NULL, "Failed to allocate memory");

    new_user->groups = talloc_array(new_user, const char *, 3);
    sss_ck_fail_if_msg(new_user->groups == NULL, "Failed to allocate memory");

    new_user->groups[0] = talloc_strdup(new_user->groups, HBAC_TEST_GROUP1);
    sss_ck_fail_if_msg(new_user->groups[0] == NULL, "Failed to allocate memory");

    new_user->groups[1] = talloc_strdup(new_user->groups, HBAC_TEST_GROUP2);
    sss_ck_fail_if_msg(new_user->groups[1] == NULL, "Failed to allocate memory");

    new_user->groups[2] = NULL;

    *user = new_user;
}

static void get_test_service(TALLOC_CTX *mem_ctx,
                             struct hbac_request_element **service)
{
    struct hbac_request_element *new_service;

    new_service = talloc_zero(mem_ctx, struct hbac_request_element);
    sss_ck_fail_if_msg(new_service == NULL, "Failed to allocate memory");

    new_service->name = talloc_strdup(new_service, HBAC_TEST_SERVICE);
    sss_ck_fail_if_msg(new_service->name == NULL, "Failed to allocate memory");

    new_service->groups = talloc_array(new_service, const char *, 3);
    sss_ck_fail_if_msg(new_service->groups == NULL, "Failed to allocate memory");

    new_service->groups[0] = talloc_strdup(new_service->groups, HBAC_TEST_SERVICEGROUP1);
    sss_ck_fail_if_msg(new_service->groups[0] == NULL, "Failed to allocate memory");

    new_service->groups[1] = talloc_strdup(new_service->groups, HBAC_TEST_SERVICEGROUP2);
    sss_ck_fail_if_msg(new_service->groups[1] == NULL, "Failed to allocate memory");

    new_service->groups[2] = NULL;

    *service = new_service;
}

static void get_test_srchost(TALLOC_CTX *mem_ctx,
                             struct hbac_request_element **srchost)
{
    struct hbac_request_element *new_srchost;

    new_srchost = talloc_zero(mem_ctx, struct hbac_request_element);
    sss_ck_fail_if_msg(new_srchost == NULL, "Failed to allocate memory");

    new_srchost->name = talloc_strdup(new_srchost, HBAC_TEST_SRCHOST);
    sss_ck_fail_if_msg(new_srchost->name == NULL, "Failed to allocate memory");

    new_srchost->groups = talloc_array(new_srchost, const char *, 3);
    sss_ck_fail_if_msg(new_srchost->groups == NULL, "Failed to allocate memory");

    new_srchost->groups[0] = talloc_strdup(new_srchost->groups,
                                           HBAC_TEST_SRCHOSTGROUP1);
    sss_ck_fail_if_msg(new_srchost->groups[0] == NULL, "Failed to allocate memory");

    new_srchost->groups[1] = talloc_strdup(new_srchost->groups,
                                           HBAC_TEST_SRCHOSTGROUP2);
    sss_ck_fail_if_msg(new_srchost->groups[1] == NULL, "Failed to allocate memory");

    new_srchost->groups[2] = NULL;

    *srchost = new_srchost;
}

START_TEST(ipa_hbac_test_allow_all)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);
    rules[0]->name = talloc_strdup(rules[0], "Allow All");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;
    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_user)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific user */
    rules[0]->name = talloc_strdup(rules[0], "Allow user");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    rules[0]->users->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->users->names == NULL, "Failed to allocate memory");

    rules[0]->users->names[0] = HBAC_TEST_USER;
    rules[0]->users->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->users->names[0] = HBAC_TEST_INVALID_USER;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_utf8)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Override the with UTF8 values */
    eval_req->user->name = (const char *) &user_utf8_lowcase;
    eval_req->srchost->name = (const char *) &srchost_utf8_lowcase;
    eval_req->service->name = (const char *) &service_utf8_lowcase;

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    rules[0]->name = talloc_strdup(rules[0], "Allow user");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    /* Modify the rule to allow only a specific user */
    rules[0]->users->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->users->names == NULL, "Failed to allocate memory");

    rules[0]->users->names[0] = (const char *) &user_utf8_upcase;
    rules[0]->users->names[1] = NULL;

    /* Modify the rule to allow only a specific service */
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->services->names == NULL, "Failed to allocate memory");

    rules[0]->services->names[0] = (const char *) &service_utf8_upcase;
    rules[0]->services->names[1] = NULL;

    /* Modify the rule to allow only a specific service */
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->services->names == NULL, "Failed to allocate memory");

    rules[0]->srchosts->names[0] = (const char *) &srchost_utf8_upcase;
    rules[0]->srchosts->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;


    /* Negative test - a different letter */
    rules[0]->users->names[0] = (const char *) &user_utf8_lowcase_neg;

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test - Turkish dotless i. We cannot know that capital I
     * casefolds into dotless i unless we know the language is Turkish */
    eval_req->user->name = (const char *) &user_lowcase_tr;
    rules[0]->users->names[0] = (const char *) &user_upcase_tr;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_group)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow group");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->users->category = HBAC_CATEGORY_NULL;

    rules[0]->users->names = NULL;
    rules[0]->users->groups = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->users->groups == NULL, "Failed to allocate memory");

    rules[0]->users->groups[0] = HBAC_TEST_GROUP1;
    rules[0]->users->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->users->groups[0] = HBAC_TEST_INVALID_GROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_svc)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific service */
    rules[0]->name = talloc_strdup(rules[0], "Allow service");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->services->names == NULL, "Failed to allocate memory");

    rules[0]->services->names[0] = HBAC_TEST_SERVICE;
    rules[0]->services->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->services->names[0] = HBAC_TEST_INVALID_SERVICE;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_svcgroup)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow servicegroup");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->services->category = HBAC_CATEGORY_NULL;

    rules[0]->services->names = NULL;
    rules[0]->services->groups = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->services->groups == NULL, "Failed to allocate memory");

    rules[0]->services->groups[0] = HBAC_TEST_SERVICEGROUP1;
    rules[0]->services->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->services->groups[0] = HBAC_TEST_INVALID_SERVICEGROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_srchost)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a specific service */
    rules[0]->name = talloc_strdup(rules[0], "Allow srchost");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->srchosts->names == NULL, "Failed to allocate memory");

    rules[0]->srchosts->names[0] = HBAC_TEST_SRCHOST;
    rules[0]->srchosts->names[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->srchosts->names[0] = HBAC_TEST_INVALID_SRCHOST;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_allow_srchostgroup)
{
    enum hbac_eval_result result;
    TALLOC_CTX *test_ctx;
    struct hbac_rule **rules;
    struct hbac_eval_req *eval_req;
    struct hbac_info *info = NULL;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    /* Create a request */
    eval_req = talloc_zero(test_ctx, struct hbac_eval_req);
    sss_ck_fail_if_msg(eval_req == NULL, "Failed to allocate memory");

    get_test_user(eval_req, &eval_req->user);
    get_test_service(eval_req, &eval_req->service);
    get_test_srchost(eval_req, &eval_req->srchost);

    /* Create the rules to evaluate against */
    rules = talloc_array(test_ctx, struct hbac_rule *, 2);
    sss_ck_fail_if_msg(rules == NULL, "Failed to allocate memory");

    get_allow_all_rule(rules, &rules[0]);

    /* Modify the rule to allow only a group of users */
    rules[0]->name = talloc_strdup(rules[0], "Allow srchostgroup");
    sss_ck_fail_if_msg(rules[0]->name == NULL, "Failed to allocate memory");
    rules[0]->srchosts->category = HBAC_CATEGORY_NULL;

    rules[0]->srchosts->names = NULL;
    rules[0]->srchosts->groups = talloc_array(rules[0], const char *, 2);
    sss_ck_fail_if_msg(rules[0]->srchosts->groups == NULL, "Failed to allocate memory");

    rules[0]->srchosts->groups[0] = HBAC_TEST_SRCHOSTGROUP1;
    rules[0]->srchosts->groups[1] = NULL;

    rules[1] = NULL;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_ALLOW,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_ALLOW),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    /* Negative test */
    rules[0]->srchosts->groups[0] = HBAC_TEST_INVALID_SRCHOSTGROUP;

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rules[0], &missing_attrs);
    ck_assert_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs == 0,
                "Unexpected missing attributes. Got: %"PRIx32, missing_attrs);

    /* Evaluate the rules */
    result = hbac_evaluate(rules, eval_req, &info);
    ck_assert_msg(result == HBAC_EVAL_DENY,
                "Expected [%s], got [%s]; "
                "Error: [%s]",
                hbac_result_string(HBAC_EVAL_DENY),
                hbac_result_string(result),
                info ? hbac_error_string(info->code):"Unknown");
    hbac_free_info(info);
    info = NULL;

    talloc_free(test_ctx);
}
END_TEST

START_TEST(ipa_hbac_test_incomplete)
{
    TALLOC_CTX *test_ctx;
    struct hbac_rule *rule;
    bool is_valid;
    uint32_t missing_attrs;

    test_ctx = talloc_new(global_talloc_context);

    rule = talloc_zero(test_ctx, struct hbac_rule);

    /* Validate this rule */
    is_valid = hbac_rule_is_complete(rule, &missing_attrs);
    sss_ck_fail_if_msg(is_valid, "hbac_rule_is_complete failed");
    ck_assert_msg(missing_attrs | HBAC_RULE_ELEMENT_USERS,
                "missing_attrs failed for HBAC_RULE_ELEMENT_USERS");
    ck_assert_msg(missing_attrs | HBAC_RULE_ELEMENT_SERVICES,
                "missing_attrs failed for HBAC_RULE_ELEMENT_SERVICES");
    ck_assert_msg(missing_attrs | HBAC_RULE_ELEMENT_TARGETHOSTS,
                "missing_attrs failed for HBAC_RULE_ELEMENT_TARGETHOSTS");
    ck_assert_msg(missing_attrs | HBAC_RULE_ELEMENT_SOURCEHOSTS,
                "missing_attrs failed for HBAC_RULE_ELEMENT_SOURCEHOSTS");

    talloc_free(test_ctx);
}
END_TEST

Suite *hbac_test_suite (void)
{
    Suite *s = suite_create ("HBAC");

    TCase *tc_hbac = tcase_create("HBAC_rules");
    tcase_add_checked_fixture(tc_hbac,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);

    tcase_add_test(tc_hbac, ipa_hbac_test_allow_all);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_user);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_group);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_svc);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_svcgroup);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_srchost);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_srchostgroup);
    tcase_add_test(tc_hbac, ipa_hbac_test_allow_utf8);
    tcase_add_test(tc_hbac, ipa_hbac_test_incomplete);

    suite_add_tcase(s, tc_hbac);
    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = hbac_test_suite();
    SRunner *sr = srunner_create(s);

    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
