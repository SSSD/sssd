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

#ifndef IPA_HBAC_PRIVATE_H_
#define IPA_HBAC_PRIVATE_H_

#include "providers/ipa/ipa_access.h"
#include "lib/ipa_hbac/ipa_hbac.h"

#define IPA_HBAC_RULE "ipaHBACRule"

#define IPA_HBAC_SERVICE "ipaHBACService"
#define IPA_HBAC_SERVICE_GROUP "ipaHBACServiceGroup"

#define IPA_MEMBER "member"
#define HBAC_HOSTS_SUBDIR "hbac_hosts"
#define HBAC_HOSTGROUPS_SUBDIR "hbac_hostgroups"

#define IPA_MEMBEROF "memberOf"
#define IPA_ACCESS_RULE_TYPE "accessRuleType"
#define IPA_HBAC_ALLOW "allow"
#define IPA_SERVICE_NAME "serviceName"
#define IPA_SOURCE_HOST "sourceHost"
#define IPA_SOURCE_HOST_CATEGORY "sourceHostCategory"
#define IPA_MEMBER_SERVICE "memberService"
#define IPA_SERVICE_CATEGORY "serviceCategory"

#define IPA_HBAC_BASE_TMPL "cn=hbac,%s"
#define IPA_SERVICES_BASE_TMPL "cn=hbacservices,cn=accounts,%s"

#define SYSDB_HBAC_BASE_TMPL "cn=hbac,"SYSDB_TMPL_CUSTOM_BASE

#define HBAC_RULES_SUBDIR "hbac_rules"
#define HBAC_SERVICES_SUBDIR "hbac_services"
#define HBAC_SERVICEGROUPS_SUBDIR "hbac_servicegroups"

/* From ipa_hbac_common.c */
errno_t
replace_attribute_name(const char *old_name,
                       const char *new_name, const size_t count,
                       struct sysdb_attrs **list);

errno_t hbac_ctx_to_rules(TALLOC_CTX *mem_ctx,
                          struct hbac_ctx *hbac_ctx,
                          struct hbac_rule ***rules,
                          struct hbac_eval_req **request);

errno_t
hbac_get_category(struct sysdb_attrs *attrs,
                  const char *category_attr,
                  uint32_t *_categories);

errno_t
hbac_thost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         struct hbac_rule_element **thosts);

errno_t
hbac_shost_attrs_to_rule(TALLOC_CTX *mem_ctx,
                         struct sss_domain_info *domain,
                         const char *rule_name,
                         struct sysdb_attrs *rule_attrs,
                         bool support_srchost,
                         struct hbac_rule_element **source_hosts);

const char **
hbac_get_attrs_to_get_cached_rules(TALLOC_CTX *mem_ctx);

/* From ipa_hbac_services.c */
struct tevent_req *
ipa_hbac_service_info_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct sdap_handle *sh,
                           struct sdap_options *opts,
                           struct sdap_search_base **search_bases);

errno_t
ipa_hbac_service_info_recv(struct tevent_req *req,
                           TALLOC_CTX *mem_ctx,
                           size_t *service_count,
                           struct sysdb_attrs ***services,
                           size_t *servicegroup_count,
                           struct sysdb_attrs ***servicegroups);

errno_t
hbac_service_attrs_to_rule(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *domain,
                           const char *rule_name,
                           struct sysdb_attrs *rule_attrs,
                           struct hbac_rule_element **services);
errno_t
get_ipa_servicegroupname(TALLOC_CTX *mem_ctx,
                         struct sysdb_ctx *sysdb,
                         const char *service_dn,
                         char **servicename);

/* From ipa_hbac_users.c */
errno_t
hbac_user_attrs_to_rule(TALLOC_CTX *mem_ctx,
                        struct sss_domain_info *domain,
                        const char *rule_name,
                        struct sysdb_attrs *rule_attrs,
                        struct hbac_rule_element **users);

errno_t
get_ipa_groupname(TALLOC_CTX *mem_ctx,
                  struct sysdb_ctx *sysdb,
                  const char *group_dn,
                  const char **groupname);

#endif /* IPA_HBAC_PRIVATE_H_ */
