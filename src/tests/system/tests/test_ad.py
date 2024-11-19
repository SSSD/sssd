"""
Active Directory Provider SSSD Tests

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
# ad_large_dataset/ad_large_dataset.sh
?:'Users in large group non posix id mapping'
?:'Users in large group posix id mapping bz1226119 bz1201840'
?:'User in large number of groups non posix id mapping'
?:'User in large number of groups posix id mapping'



# ldap_krb5/ldap_krb5.sh
?:#Enumerate AD User user01 over LDAP without SSL
?:Enumerate and Authenticate user01 over STARTTLS bz748833
?:AD user authentication with GSSAPI only
?:Enumerate and Authenticate user01 over LDAPS
?:Authenticate lkuser01 over KRB5
?:Lookup valid LDAP Groups
?:Enumerate user belonging to multiple groups
?:Enumerate user belonging to nested groups
?:Enumerate user without UNIX attributes belonging to nested groups and intermediate groups bz748822
?:Enumerate non existing user
?:Enumerate non existing group
?:Enumerate valid user and group with id less than min id bz692455
?:Enumerate valid user and group with id more than max id bz692455
?:Check with ldap access filter
?:Check with ldap access filter and global character
?:Check when ldap sasl mech set to GSSAPI
?:Check login for disabled AD user account
?:Check Active Directory Account Lockout for expired user
?:Check GECOS Fallback to cn
?:Users lacking posix attribute breaks group lookup bz791208
?:Lookup users and groups with backslash and comma bz683158
?:Allow SSSD to notify user of denial due to AD account lockout bz1264705

# range_retrieval/runtest -> test_identity_client.py
?:ldap provider lookup group with large number of users
?:ad provider search base with filter bz848031
?:ad provider lookup user belonging to large number of groups
?:ad provider ldap user search base with filter
?:Setting up ldap disable range retrieval to true bz928807 bz916997
?:setting up ldap disable range retrieval to false bz928807 bz916997

# shortnames/shortnames.sh
b:Parent domain get users
b:Parent domain get child users
b:Parent domain get tree users
b:Parent domain get groups
b:Parent domain get child groups
b:Parent domain get tree groups
b:Child domain get parent users
b:Child domain get child users
b:Child domain get tree users
b:Child domain get parent groups
b:Child domain get child groups
b:Child domain get tree groups
b:Tree domain get parent users
b:Tree domain get child users
b:Tree domain get tree users
b:Tree domain get parent groups
b:Tree domain get child groups
b:Tree domain get tree groups



# cifs/smbd_client/smbd_client.sh
?:Check alternatives link
?:Create files on share1 with mount cifs
?:Read files on share1 with mount cifs
?:Update files on share1 with mount cifs
?:Delete files on share1 with mount cifs

# cifs/smbd_server/smbd_server.sh
?:Check alternatives link
?:Check cifs share1 created files
?:Check cifs share1 updated files
?:check cifs share1 deleted files
?:sssd libwbclient causes crash in wbinfo bz1175705

multihost
=========


# test_ad_misc.py
?:test_0001_provider_config_cross_interference
?:test_0002_improved_use_negative_sid_for_sid_lookup
?:test_0003_gssapi_ssh
?:test_0004_bz2110091
?:test_0005_get_sid_by_username

# test_adparameters_ported.py
?:test_0001_ad_parameters_domain
?:test_0002_ad_parameters_junk_domain
?:test_0003_ad_parameters_junk_domain_invalid_keytab
?:test_0004_ad_parameters_valid_domain_shorthost
?:test_0005_ad_parameters_blank_domain
?:test_0006_ad_parameters_homedir_override_nss
?:test_0007_ad_parameters_homedir_override_domain
?:test_0008_ad_parameters_homedir_override_both
?:test_0009_ad_parameters_ldap_sasl_full
?:test_0010_ad_parameters_ldap_sasl_short
?:test_0011_ad_parameters_server_resolvable
?:test_0012_ad_parameters_server_unresolvable
?:test_0013_ad_parameters_server_srv_record
?:test_0014_ad_parameters_server_blank
?:test_0015_ad_parameters_ad_hostname_machine
?:test_0016_ad_parameters_ad_hostname_valid
?:test_0017_ad_parameters_krb5_keytab_nonexistent
?:test_0018_ad_parameters_krb5_keytab_elsewhere
?:test_0019_ad_parameters_ldap_id_mapping_false
?:test_0020_ad_parameters_ssh_change_password
?:test_0021_ad_parameters_ssh_change_password_logon
?:test_0022_ad_parameters_account_disabled
?:test_0023_ad_parameters_account_expired
?:test_0024_ad_parameters_getgrgid_nested
?:test_0025_ad_parameters_empty_group
?:test_0026_ad_parameters_dns_failover
?:test_0027_ad_parameters_group_membership_empty
?:test_0028_ad_parameters_nested_in_nonposix_group
?:test_0029_ad_parameters_tokengroups_with_ldap
?:test_0030_ad_parameters_tokengroups_searchbase
?:test_0031_ad_parameters_custom_re
?:test_0032_ad_parameters_group_name_attribute
?:test_0033_ad_parameters_group_cleanup_sanitize
?:test_0034_ad_parameters_group_work_intermittently
?:test_0035_ad_parameters_delete_cache
?:test_0036_ad_parameters_renewal_leaks_descriptors
?:test_0037_ad_parameters_extra_attrs_mail
?:test_0038_ad_parameters_authentication_failure_invalid_keytab
?:test_0039_ad_parameters_auth_krb5
?:test_0040_ad_parameters_newline_ssh_key
?:test_0041_ad_parameters_sss_ssh_knownhostsproxy
?:test_0042_ad_parameters_nonroot_user_sssd
?:test_0043_sssd_not_using_given_krb_port
?:test_0044_ad_parameters_homedir_override_lowercase
?:test_0045_ad_parameters_upn_mismatch_check
?:test_0046_ad_parameters_upn_empty_skip_check
?:test_0047_ad_parameters_filter_group

# test_adparameters.py
?:test_0001_bz1296618
?:test_0002_bz1287209
?:test_0003_bz1421622
?:test_00015_authselect_cannot_validate_its_own_files
?:test_0005_BZ1527149_BZ1549675
?:test_0006_bz1592964
?:test_0007_bz1361597
?:test_0008_bz1431858
?:test_0009_bz1565761
?:test_0010_bz1527662
?:test_0011_bz1571526
?:test_0012_bz1738532
?:test_0013_bz1794016
?:test_0014_user_filtering
?:test_0016_forceLDAPS
?:test_0017_gssspnego_adjoin

# test_adschema.py
?:test_0001_ad_schema_idmapping_true_user
?:test_0002_ad_schema_idmapping_true_group
?:test_0003_ad_schema_idmapping_false_user
?:test_0004_ad_schema_idmapping_false_group

# test_hostkeytabrotation.py
?:test_001_rotation
?:test_002_updatedkeytab
?:test_003_delentry
?:test_004_multiplespn
?:test_005_deletespn

# test__id_mapping.py
?:test_001_findrid
?:test_002_rangelessthansid
?:test_003_disablerange
?:test_004_rangeequalsid
?:test_005_disablerange
?:test_006_rangevalues
?:test_007_disablerangevalues

# test_idmap.py
?:test_001_idmap_disable

# test_memcache_sid.py
?:test_0001_memcache_sid

# test_samba_data.py
?:test_0001_rotation

# test_multiforest.py
?:test_0001_multiforest
"""


def test_ad__authentication_using_ldap_and_krb_providers():
    """
    :title: Users can login when SSSD is configured to connect to AD using ldap provider to connect
    """
    pass
