"""
Active Directory Provider Multiple Server Tests

All SSSD tests pertaining to topologies that contain more than one AD server, tests require
subdomains, nested subdomains, primary and secondary domain controller and multiple forests.

:requirement: AD:
"""

from __future__ import annotations

import pytest

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

todo
====
* multidomain topology - child, tree domain

bash
====
# ad_forest/ad_access_filter.sh
?:ad_forest/ad_access_filter.sh:Access provider defaults to ad
?:ad_forest/ad_access_filter.sh:Access provider ad without any other options denies expired users
?:ad_forest/ad_access_filter.sh:An expired user even though he matches the filter is denied access
?:ad_forest/ad_access_filter.sh:Access provider ad without any other options allows non expired users
?:ad_forest/ad_access_filter.sh:Allow users from group of domain0 only
?:ad_forest/ad_access_filter.sh:Allow only single user from domain0
?:ad_forest/ad_access_filter.sh:Allow users from group of domain0 with different syntax
?:ad_forest/ad_access_filter.sh:Allow only users of a group from domain2
?:ad_forest/ad_access_filter.sh:sssd be process crashes when ad access filter uses FOREST keyword bz1032982
?:ad_forest/ad_access_filter.sh:Invalid ad access filter bz1033132

# ad_forest/ad_other_dc.sh:
b:Forest DNS service records lookup child domain bz974149 bz1263735
b:ad_forest/ad_other_dc.sh:kdcinfo files are not created for subdomains of a directly joined AD client
b:ad_forest/ad_other_dc.sh:Forest user lookup when joined to child domain bz1077327 bz1090653 bz1097323
b:ad_forest/ad_other_dc.sh:Forest DNS service records lookup second tree domain bz974149
b:ad_forest/ad_other_dc.sh:Forest user lookup when joined to second tree domain bz1077327 bz1090653 bz1097323
b:ad_forest/ad_other_dc.sh:UPN root join test
b:ad_forest/ad_other_dc.sh:UPN second tree join test
b:ad_forest/ad_other_dc.sh:UPN child join test
b:ad_forest/ad_other_dc.sh:Different OU root join test
b:ad_forest/ad_other_dc.sh:Different OU second tree join test
b:ad_forest/ad_other_dc.sh:Different OU child join test

# ad_forest/auth.sh
b:ad_forest/auth.sh:Auth users from all domains
b:ad_forest/auth.sh:Change password for all users from all domains bz1078839
b:ad_forest/auth.sh:Support of enterprise principals bz924403 bz1079783
b:ad_forest/auth.sh:Cached credentials are not working with enterprise UPN logins bz1002590
b:ad_forest/auth.sh:Cannot login to the 0st domain when 2 domain is configured in sssd bz966557
b:ad_forest/auth.sh:Subdomains list is never read if sssd starts offline bz1038636

# ad_forest/lookup.sh
b:ad_forest/lookup.sh:Lookup users and groups bz1002591 bz1001318 bz1033096 bz969882
b:ad_forest/lookup.sh:Group renaming not reflecting correctly
b:ad_forest/lookup.sh:id root user triggers LDAP lookup
b:ad_forest/lookup.sh:User and group memberships from different domains bz1059422 bz1028057 bz1002597
b:ad_forest/lookup.sh:Enumerate users and groups bz1009613 bz1028039
b:ad_forest/lookup.sh:Use flatname in the fully qualified format bz969881
b:ad_forest/lookup.sh:Subdomain do not inherit fallbacks and overrides settings bz1053105
b:ad_forest/lookup.sh:Individual group search returned multiple results in GC lookups bz1030482
b:ad_forest/lookup.sh:Detect if posix attributes have been replicated to the global catalog bz1033080
b:ad_forest/lookup.sh:Not retrieving homedirs of AD users with posix attributes bz1066095
b:ad_forest/lookup.sh:Inconsistent results for id bz1072994
b:ad_forest/lookup.sh:Enumeration reads data from ldap while regular lookups connect to gc bz1028038
b:ad_forest/lookup.sh:sssd nss segfaults if initgroups request is by UPN and does not find anything bz1200092
b:ad_forest/lookup.sh:Ignore group members does not work for subdomains bz1227862
b:ad_forest/lookup.sh:Use TCP for kerberos by default
b:ad_forest/lookup.sh:removing subdomain from ad_enabled_domains does not disable old subdomain bz1708322
b:ad_forest/lookup.sh:sssd can be marked offline if a trusted domain is not reachable bz1301739


# ad_gpo_hbac_multidomain
b:child.sh:child domain gpo is disabled
b:child.sh:child domain gpo is enforcing
b:child.sh:child domain gpo is enforcing with no gpo applied
b:child.sh:child domain gpo is permissive
b:child.sh:child domain testing domain and ou inheritance
b:child.sh:child domain testing gpo mapping
b:child.sh:#child domain testing offline mode
b:child.sh:child domain gpo child fails when log is enabled in smb bz1177139
b:child.sh:child domain sssd crashes intermittently in GPO code bz1206091 bz1204203
b:child.sh:child domain invalid/empty values in GptTmpl.inf bz1316163
b:child.sh:child domain gpos code ignores ad_site option
b:child.sh:child domain changed default behavior from allow any to deny any
b:child.sh:child domain sssd doesn't follow the link order of AD Group Policy Management
b:tree.sh:tree domain gpo is disabled
b:tree.sh:tree domain gpo is enforcing
b:tree.sh:tree domain gpo is enforcing with no gpo applied
b:tree.sh:tree domain gpo is permissive
b:tree.sh:tree domain testing domain and ou inheritance
b:tree.sh:tree domain testing gpo mapping
b:tree.sh:#tree domain testing offline mode
b:tree.sh:tree domain gpo tree fails when log is enabled in smb bz1177139
b:tree.sh:tree domain sssd crashes intermittently in GPO code bz1206091 bz1204203
b:tree.sh:tree domain invalid/empty values in GptTmpl.inf bz1316163
b:tree.sh:tree domain gpos code ignores ad_site option
b:tree.sh:tree domain changed default behavior from allow any to deny any
b:tree.sh:tree domain sssd doesn't follow the link order of AD Group Policy Management
b:tree.sh:tree domain skip GPOs that have groupPolicyContainers unreadable by sssd


# ad_forest/multidomain_legacy.sh
b:crash when looking up the Domain Users group on second domain bz1148572

# ad_forest/simple_access_control.sh
b:Allowing access for only user0 from domain1 with simple allow users
b:Simple access provider support subdomain users and groups bz991054
b:Access denied for users from gc domain when using format DOMAIN backward slash username bz1048101
b:Blocking access of users from another domain and child domain specifically
b:Allowing access to the group from domain0 and domain2 and child domain with single syntax
b:Simple allow groups does not find group from other AD domains bz1125186
b:With realm permit command groups option does not work bz982618
b:Permit All Users
b:Deny All Users

# dns_sites/ad_sites.sh
?:ad site unset and Default First Site Name is default
?:ad site equal to LocalSite but AD has Default First Site Name as default bz1161564

# dns_sites/runtest
?:ad enable dns sites option set to false
?:Only default site Default First Site Name exists
?:Empty LocalSite for the client subnet
?:PDC exists in the LocalSite
?:Both Servers are in LocalSite
?:Secondary DC has higher priority SRV Record
?:Only secondary DC is in LocalSite

# test_multidomain.py
?:test_0000_bz2013297
?:test_0001_bz2018432
?:test_0002_bz2167728
?:test_0003_bz1913284_keytab_as_nonroot

# test_adsites.py
?:test_001_ad_startup_discovery
?:test_002_ad_startup_discovery_one_server_unreachable
?:test_003_ad_startup_discovery_two_different_sites
?:test_004_ad_startup_discovery_one_server_unreachable
"""


@pytest.mark.parametrize("domain", ["child", "tree"])
def test_ad_forest__trusted_user_can_authenticate_to_parent_domain(domain: str):
    """
    :title: User from a child or tree domain can login to the parent domain
    TODO: create a new topology and topology_controller to join the client to the trusted domain
    """
    pass


@pytest.mark.parametrize("domain", ["child", "tree"])
def test_ad_forest__lookup_trusted_users_when_they_are_members_of_parent_domain_group(domain: str):
    """
    :title: Users in a trusted domain are a part of a global or enterprise group are resolved
    """
    pass

#
