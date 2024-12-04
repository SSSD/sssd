"""
SSSD Access Control Tests

Tests pertaining to user, group and host access control providers and or filters. Some of the providers will be
in their own python file.

* Simple access-control provider
* LDAP and AD access filter
* Kerberos access provider (k5login): test_kerberos.py
* Group Policy Objects (GPO) access control: test_gpo.py

:requirement: access control
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

intg
====

multihost
=========
# test_ns_account_lock.py
?:test_user_inactivated_locked
?:test_inactive_managed_roles
?:test_inactivated_filtered_roles
?:test_nested_role_inactivated

# test_access_control.py
test_001_simple_allow_user_to_user1 -> test_access_control.py
?:test_002_too_much_logging_from_sssd_be -> test_access_controlpy
?:test_003_simple_allow_user_to_dollar_symbol
?:test_simple_allow_user_to_invalid_user
?:test_simple_deny_user_to_user1
?:test_simple_deny_user_to_invalid_user
?:test_simple_allow_groups_top_nested
?:test_simple_deny_groups_top_nested
?:test_simple_allow_groups_invalid_group
?:test_simple_deny_groups_invalid_grp
?:test_permit_all_users
?:test_deny_all_users
?:test_dont_fail_auth_with_allow_rules

notes
=====
* parametrize the search attributes, allowing ad and ldap filters be one test
* parametrize fully qualified names 
"""


def test_access_control__disabled_user_cannot_login():
    """
    :title: Disabled user account is denied access
    TODO: sssd_framework, add enable/disable user account functionality to all role user classes
    """
    pass


@pytest.mark.parametrize("name", ["name", "fully_qualified_name"])
def test_access_control__simple_filter_users(name: str):
    """
    :title: User access is managed by the simple access filter parameter
    """
    pass


@pytest.mark.parametrize("name", ["name", "fully_qualified_name"])
def test_access_control__simple_filter_groups(name: str):
    """
    :title: User is a member of a group that is managed by the simple access filter
    """
    pass


@pytest.mark.parametrize("name", ["name", "fully_qualified_name"])
def test_access_control__simple_filter_nested_groups(name: str):
    """
    :title: User is a member of a nested group that is managed by the simple access filter
    """
    pass


@pytest.mark.sanity
@pytest.mark.parametrize("users", [("user1 user2", False), ("user1, user2", True)])
def test_access_control__simple_filter_valid_strings_in_users_field_work(users: str):
    """
    :title: Check possible valid or invalid permutations when users are in the value
    """
    pass


@pytest.mark.sanity
@pytest.mark.parametrize("groups", [("group1 group2", False), ("group1, group2", True)])
def test_access_control__simple_filter_valid_strings_in_group_field_work(groups: str):
    """
    :title: Check possible valid or invalid permutations when groups are in the value
    """
    pass


def test_access_control__simple_filter_implicitly_deny_users_and_groups():
    """
    :title: Users and groups with no access are implicitly denied
    """
    pass


@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_searches_a_single_user_attribute(attr: tuple):
    """
    :title: Access control filter uses one attribute
    """
    pass


@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_searches_group_members(attr: tuple):
    """
    :title: Access control filter searches by group membership
    """
    pass


@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_query_contains_conditions_and_or(attr: tuple):
    """
    :title: Access control filters contains conditionals
    """
    pass


@pytest.mark.parametrize("attr", [("samAccountName", "ad"), ("cn", "ldap"), ("dn", "")])
def test_access_control__ldap_filter_query_contains_arithmetic_operators(attr: tuple):
    """
    :title: Access control filters contain arithmetic operators
    """
    pass
