"""

Tests pertaining to the client configuration rather than the setup of the provider or contents, like object classes,
attributes, or the DIT structure.

:requirement: identity
"""

import pytest

"""
?:needs review
p:pushed
+:approved
-:drop
b:blocked
-> move

bash
====
# multiple_namingcontext
+:ldap search base is not specified
+:ldap search base and ldap user search base is specified
+:ldap search base is specified
+:ldap search base is not specified and ldap user search base is specified bz784870

?:Enumerate user belonging to multiple groups
?:Enumerate user belonging to nested groups
?:Enumerate user without UNIX attributes belonging to nested groups and intermediate groups bz748822
?:Enumerate non existing user
?:Enumerate non existing group
?:Enumerate valid user and group with id less than min id bz692455
?:Enumerate valid user and group with id more than max id bz692455
Identity Client Configuration Tests

multihost
=========
# test_range_retrieval.py
?:test_0001_grouplookup_large_members
?:test_0002_ad_provider_search_base_with_filter
?:test_0003_ad_provider_userlookup_large_numberof_groups
?:test_0004_ad_provider_ldap_user_searchbase_with_filter
?:test_0005_setting_up_ldap_disable_range_retrieval_to_true
?:test_0006_setting_up_ldap_disable_range_retrieval_to_false
"""


@pytest.mark.parametrize("ldap_searchbase", [None, "basedn", "userdn", "both"])
def test_identity_client__ldap_search_base(ldap_searchbase: str):
    """
    :title: Configure the client with explicitly defining ldap_search_base and ldap_user_searchbase
    """
    pass


def test_identity__lookup_username_with_enumeration_enabled():
    """
    :title: Resolve user by name with enumeration is enabled
    """


def test_identity__lookup_group_with_enumeration_enabled():
    """
    :title: Resolve group by name with enumeration is enabled
    """


