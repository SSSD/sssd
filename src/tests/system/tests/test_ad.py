"""
SSSD AD Provider Test Cases

:requirement: ad
"""

from __future__ import annotations

import pytest
from sssd_test_framework.roles.ad import AD
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericADProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.topology(KnownTopologyGroup.AnyAD)
@pytest.mark.ticket(jira="RHEL-65848", gh=7690)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.importance("high")
def test_ad__user_authentication_when_provider_is_set_to_ldap_with_gss_spnego(
    client: Client, provider: GenericADProvider, method: str
):
    """
    :title: Login to AD when id_provider is set to ldap
    :setup:
        1. Add AD user
        2. Update sssd.conf with 'id_provider = ldap', 'ldap_schema = ad',
        'ldap_id_use_start_tls = false', 'auth_provider = ad' and
        'ldap_sasl_mech = gssspengo' and Start SSSD
    :steps:
        1. Check authentication of the user
        2. Check log message in krb5_child.log, UPN [user1@null] should not be logged
    :expectedresults:
        1. Authentication is successful
        2. Get required UPN [user1@<domain_name>] from krb5_child.log
    :customerscenario: False
    """
    provider.user("user1").add()

    client.sssd.config.remove_option("domain/test", "id_provider")

    configurations = {
        "id_provider": "ldap",
        "ldap_schema": "ad",
        "ldap_id_use_start_tls": "False",
        "auth_provider": "ad",
        "ldap_referrals": "False",
        "ldap_sasl_mech": "GSS-SPNEGO",
        "ldap_id_mapping": "True",
    }

    for key, value in configurations.items():
        client.sssd.domain[key] = value

    # id_provider = ldap will not add them automatically if they are not
    # defined on the server side.
    client.sssd.nss["default_shell"] = "/bin/bash"
    client.sssd.nss["override_homedir"] = "/home/%u"

    # `provider.host.domain` is ignored because it is dynamically added
    p_domain = f"{provider.host.domain}"  # type: ignore[attr-defined]

    client.sssd.domain["krb5_realm"] = f"{p_domain.upper()}"
    client.sssd.domain["dns_discovery_domain"] = f"{p_domain}"

    client.sssd.start()

    assert client.auth.parametrize(method).password("user1", "Secret123"), "User user1 failed login!"

    log_str = client.fs.read("/var/log/sssd/krb5_child.log")
    assert f"UPN [user1@{p_domain}]" in log_str, f"'UPN [user1@{p_domain}]' not in logs!"  # type: ignore


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(gh=7174)
@pytest.mark.parametrize("method", ["su", "ssh"])
@pytest.mark.parametrize("sssd_service_user", ("root", "sssd"))
@pytest.mark.importance("critical")
@pytest.mark.require(
    lambda client, sssd_service_user: ((sssd_service_user == "root") or client.features["non-privileged"]),
    "SSSD was built without support for running under non-root",
)
def test_authentication__using_the_users_email_address(client: Client, ad: AD, method: str, sssd_service_user: str):
    """
    :title: Login using the user's email address
    :description:
        Testing the feature to login using an email address instead of the userid. The username used,
        must match one of the user's LDAP attribute values, "EmailAddress". The login should be
        case-insensitive and permit special characters.
    :setup:
        1. Add AD users with different email addresses
        2. Start SSSD
    :steps:
        1. Authenticate users using their email address and in different cases
    :expectedresults:
        1. Authentication is successful using the email address and is case-insensitive
    :customerscenario: False
    """
    ad.user("user-1").add(password="Secret123", email=f"user-1@{ad.host.domain}")
    ad.user("user-2").add(password="Secret123", email="user-2@alias-domain.com")
    ad.user("user_3").add(password="Secret123", email="user_3@alias-domain.com")

    client.sssd.start(service_user=sssd_service_user)

    assert client.auth.parametrize(method).password(
        f"user-1@{ad.host.domain}", "Secret123"
    ), f"User user-1@{ad.host.domain} failed login!"
    assert client.auth.parametrize(method).password(
        "user-2@alias-domain.com", "Secret123"
    ), "User user-2@alias-domain.com failed login!"
    assert client.auth.parametrize(method).password(
        "uSEr_3@alias-dOMain.com", "Secret123"
    ), "User uSEr_3@alias-dOMain.com failed login!"


@pytest.mark.topology(KnownTopology.AD)
@pytest.mark.ticket(jira="RHEL-75484")
@pytest.mark.importance("high")
def test_range_retrieval__group_membership(client: Client, ad: AD):
    """
    :title: Users with with more groups than MaxValRange can be retrieved
    :description:
        Testing the feature to retrieve users with more groups than MaxValRange.
    :setup:
        1. Set MaxValRange in lDAPAdminLimits on AD.
        2. Create an ad user with number of groups > MaxValRange
        3. Clear caches and restart sssd
    :steps:
        1. Retrieve the user running id -u user and check cached content
    :expectedresults:
        1. No groups are missing from the cache
    :customerscenario: True
    """
    size = 152
    # The lDAPAdminLimits list contains mutiple items in key=value format.
    # We retrieve the current lDAPAdminLimits, remove MaxValRange from it.
    # Then we append new MaxValRange and write it back.
    ad.host.conn.run(
        rf"""
            $basedn = '{ad.naming_context}'
            $policyDN = "CN=Default Query Policy,CN=Query-Policies,CN=Directory"+
            " Service,CN=Windows NT,CN=Services,CN=Configuration,$basedn"
            $currentLimits = (Get-ADObject -Identity $policyDN `
            -Properties lDAPAdminLimits).lDAPAdminLimits
            Write-Output "Current limits: $currentLimits"
            $regexPattern = "MaxValRange=.*"
            $newLimits = @()
            $newLimits += $currentLimits -notmatch $regexPattern
            $newLimits += "MaxValRange={size - 2}"
            Write-Output "New limits: $newLimits"
            Set-ADObject -Identity $policyDN -Replace @{{lDAPAdminLimits = $newLimits}}
            """
    )
    client.sssd.domain["ldap_id_mapping"] = "false"
    client.sssd.domain["use_fully_qualified_names"] = "True"
    client.sssd.start()
    # Provisioning groups one by one using the framework functions
    # each in its own ssh call takes too long.
    ad.host.conn.run(
        rf"""
            Import-Module ActiveDirectory
            $basedn = '{ad.naming_context}'
            New-ADUser -Name "big-user" -AccountPassword (ConvertTo-SecureString `
            "Secret123" -AsPlainText -force) -OtherAttributes @{{"uid"="big-user"`
            ;"uidNumber"=10001;"gidNumber"=20001;"gecos"="big-user";"loginShell"=`
            "/bin/bash"}} -Enabled $True -Path "cn=users,$basedn" -EmailAddress `
            big-user@$basedn -GivenName dummyfirstname -Surname dummylastname `
            -UserPrincipalName big-user@$basedn
            $count = 0
            while ($count -lt {size}) {{
                $gidNumber = 30000 + $count
                New-ADGroup -Name "group-$count" -GroupScope 'Global' -GroupCategory `
                'Security' -OtherAttributes @{{"gidNumber"="$gidNumber"}} -Path "cn=users,$basedn"
                Add-ADGroupMember -Identity "cn=group-$count,cn=users,$basedn" `
                -Members "cn=big-user,cn=users,$basedn"
                $count++
            }}
            """
    )
    client.sssctl.cache_expire(everything=True)
    client.host.conn.run(f"id -u big-user@{client.sssd.default_domain}")
    grps = client.host.conn.run(
        f"ldbsearch -H /var/lib/sss/db/cache_{client.sssd.default_domain}.ldb"
        f" '(name=big-user@{client.sssd.default_domain})' | grep -Pio "
        f"'originalMemberOf: CN=\\K([a-zA-Z0-9-]+)'"
    ).stdout.splitlines()
    assert len(grps) != 0, "User is not a member of any group!"
    assert len(grps) == size, "User's membership is not complete!"
