from __future__ import annotations

import pytest
from sssd_test_framework.roles.client import Client
from sssd_test_framework.roles.generic import GenericProvider
from sssd_test_framework.topology import KnownTopology, KnownTopologyGroup


@pytest.mark.ticket(bz=1654018)
@pytest.mark.topology(KnownTopology.Client)
def test_authselect__select_minimal_profile_with_local_user_auth(client: Client):
    """
    :title: Authselect minimal profile is functionally tested
    :setup:
        1. Create local user "user-1"
    :steps:
        1. Select the authselect minimal profile
        2. Configure SSSD for local proxy provider
        3. Start SSSD
        4. Authenticate as "user-1"
    :expectedresults:
        1. Minimal profile is selected
        2. SSSD is configured for local authentication
        3. SSSD starts successfully
        4. Authentication is successful for "user-1"
    :customerscenario: False
    :requirement: authselect does not have a "local" profile
    """
    client.local.user("user-1").add()

    client.authselect.select("minimal")
    client.sssd.common.local()
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")


@pytest.mark.skip
@pytest.mark.rhel
@pytest.mark.ticket(bz=1654018)
@pytest.mark.topology(KnownTopology.Client)
def test_authselect__minimal_profile_works_with_no_additional_packages(client: Client):
    """
    TODO: Needs testing.
    The Fedora container was unable to roll back the changes, repository does not contain the versions that are
    installed on the container.

    :title: Minimal profile only requires the necessary packages to run.

            sssd-client, sssd-common and sssd-nfs-idmap
    :setup:
        1. Create local user "user-1"
        2. Remove all sssd-* packages except the following; sssd-client, sssd-common and sssd-nfs-idmap
    :steps:
        1. Select the authselect minimal profile
        2. Start SSSD
        3. Authenticate as "user-1"
    :expectedresults:
        1. Minimal profile is selected
        2. SSSD started successfully
        3. Authentication is successful for "user-1"
    :customerscenario: False
    :requirement:i authselect remove all unnecessary SSSD packages
    """
    client.local.user("user-1").add()

    client.tools.dnf(["remove", "sssd-ldap", "sssd-ad", "sssd-kcm", "sssd-ipa"])

    client.authselect.select("minimal")
    client.sssd.common.local()
    client.sssd.start()


@pytest.mark.skip
@pytest.mark.rhel
@pytest.mark.ticket(bz=1892761)
@pytest.mark.topology(KnownTopology.Client)
def test_authselect__when_removed_the_uninstall_is_clean(client: Client):
    """
    TODO: Need to test against RHEL.
    Unable to uninstall Authselect in Fedora because sudo depends on authselect

    :title: Uninstalling authselect will roll back all configuration changes.

            Authselect makes several critical changes to the authentication stack, this tests to ensures the system
            is fully reverted and is not broken.
    :setup:
        1. Create local user "user-1"
    :steps:
        1. Uninstall authselect
        2. Check authselect configuration files
        3. Check PAM and NSS configuration files
        4. Authenticate as "user-1"
    :expectedresults:
        1. Authselect is uninstalled
        2. Authselect configuration directory has been deleted
        3. PAM and NSS configurations are no longer symbolically linked to authselect files
        4. Authentication is successful for "user-1"
    :customerscenario: False
    :requirement: authselect Remove All
    """
    client.local.user("user-1").add()

    client.authselect.select("sssd")
    client.sssd.common.local()
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authselect__select_sssd_profile_with_user_auth(client: Client, provider: GenericProvider):
    """
    :title: Authselect sssd profile is selected and functionally tested
    :setup:
        1. Create POSIX user "user-1"
    :steps:
        1. Select SSSD profile
        2. Start SSSD
        3. Authenticate as "user-1"
        4. Select another profile
        5. Authenticate as "user-1"
    :expectedresults:
        1. SSSD profile is selected
        2. SSSD is started
        3. Authentication is successful for "user-1"
        4. Minimal profile is selected
        5. Authentication is unsuccessful for "user-1"
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile manual Client configuration
    """
    provider.user("user-1").add()

    client.authselect.select("sssd")
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")

    client.authselect.select("minimal")

    assert not client.auth.ssh.password("user-1", "Secret123")


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authselect__sssd_profile_enable_and_disable_mkhomedir(client: Client, provider: GenericProvider):
    """
    :title: Authselect sssd profile with-mkhomedir is functionally tested

            This test pam_mkhomedir and oddjobd, which creates user's home directories upon login if they don't exist.
    :setup:
        1. Create POSIX user "user-1"
    :steps:
        1. Select SSSD profile with with-mkhomedir
        2. Start SSSD
        3. Authenticate as "user-1" and check home directory
        4. Delete "user-1" home directory
        5. Disable mkhomedir feature
        6. Authenticate as "user-1" and check home directory
    :expectedresults:
        1. SSSD profile is selected
        2. SSSD is started
        3. Authentication is successful for "user-1" and home directory exists
        4. Home directory is deleted
        5. Feature is disabled
        6. Authentication is successful for "user-1" and no home directory exists
    :customerscenario: False
    :requirement: True
    """
    provider.user("user-1").add(home="/home/user-1")

    client.authselect.select("sssd", ["with-mkhomedir"])
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")
    assert client.fs.exists("/home/user-1")

    client.tools.host.ssh.run("rm -rf /home/user-1")
    client.authselect.disable_feature(["with-mkhomedir"])

    assert client.auth.ssh.password("user-1", "Secret123")
    assert not client.fs.exists("/home/user-1")


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authselect__sssd_profile_enable_and_disable_faillock(client: Client, provider: GenericProvider):
    """
    :title: Authselect sssd profile with-faillock is functionally tested

            PAM Faillock is a module that manages login policies on the host, such as login attempts, lockout time.
            Configuration is /etc/security/faillock.conf , and set to 3 attempts. To reset the lockout, the faillock
            command is used.
    :setup:
        1. Create POSIX user "user-1"
    :steps:
        1. Select the authselect SSSD profile with-faillock
        2. Configure pam-faillock and set login attempts to 3
        3. Start SSSD
        4. Authenticate as "user-1"
        5. Authenticate as "user-1" 3 times with an invalid password
        6. Reset faillock for "user-1"
        7. Authenticate as "user-1"
        8. Disable feature pam-faillock
        9. Authenticate as "user-1" 3 times with an invalid password
        10. Authenticate as "user-1"
    :expectedresults:
        1. Authselect SSSD profile is selected with-faillock
        2. pam-faillock is configured
        3. SSSD is started
        4. Authentication is successful for "user-1"
        5. Authentication attempts are unsuccessful for "user-1"
        6. Faillock is reset for "user-1"
        7. Authentication is successful for "user-1"
        8. Feature pam-faillock is disabled
        9. Authentication attempts are unsuccessful for "user-1"
        10. Authentication is successful for "user-1"
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable faillock
    """
    provider.user("user-1").add()
    client.pam.faillock().config()

    client.sssd.common.pam(["with-faillock"])
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")

    for i in range(3):
        client.auth.ssh.password("user-1", "BadSecret123")

    assert not client.auth.ssh.password("user-1", "Secret123")
    client.pam.faillock("user-1").reset()
    assert client.auth.ssh.password("user-1", "Secret123")

    client.authselect.disable_feature(["with-faillock"])

    for i in range(3):
        client.auth.ssh.password("user-1", "BadSecret123")
    assert client.auth.ssh.password("user-1", "Secret123")


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authselect__sssd_profile_enable_and_disable_pam_sudo(client: Client, provider: GenericProvider):
    """
    :title: Authselect sssd profile with-sudo is functionally tested

            This test functionally tests authselect enabling and disabling with-sudo.
    :setup:
        1. Create POSIX user "user-1"
    :steps:
        1. Select the authselect SSSD profile with-sudo
        2. Setup sudo rules for "user-1"
        3. Start SSSD
        4. List and run sudo commands as "user-1"
        5. Disable with-sudo feature
        6. List and run sudo command as "user-1"
    :expectedresults:
        1. Authselect SSSD profile is selected with-sudo
        2. Rules are added
        3. SSSD is started
        4. Sudo rule are listed and sudo command is successful
        5. Feature with-sudo is disabled
        6. Sudo rule are not listed and sudo command is unsuccessful
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM sudo
    """
    provider.user("user-1").add()
    provider.sudorule("test").add(user="user-1", host="ALL", command="/bin/ls")

    client.sssd.common.sudo()
    client.sssd.start()

    assert client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    assert client.auth.sudo.run("user-1", "Secret123", command="/bin/ls /root")

    client.authselect.disable_feature(["with-sudo"])

    assert not client.auth.sudo.list("user-1", "Secret123", expected=["(root) /bin/ls"])
    assert not client.auth.sudo.run("user-1", "Secret123", command="/bin/ls /root")


@pytest.mark.topology(KnownTopologyGroup.AnyProvider)
def test_authselect__sssd_profile_enable_and_disable_pam_access(client: Client, provider: GenericProvider):
    """
    :title: Authselect sssd profile with-pamaccess is functionally tested

            PAM Access manages host based access control locally and is configured in /etc/security/access.conf
            When configured a user can be restricted from what host/session they are connection from.
    :setup:
        1. Create local users "user-1" and "user-2"
    :steps:
        1. Select the authselect SSSD profile with-pamaccess
        2. Setup pam access
        3. Start SSSD
        4. Authenticate as "user-1"
        5. Authenticate as "user-2"
        6. Disable authselect feature with-pamaccess
        7. Authenticate as "user-1"
        8. Authenticate as "user-2"
    :expectedresults:
        1. Authselect SSSD profile is selected with-pamaccess
        2. Rules are added
        3. SSSD is started
        4. Authentication is successful for "user-1"
        5. Authentication is unsuccessful for "user-2"
        6. Feature with-pamaccess is disabled
        7. Authentication is successful for "user-1"
        8. Authentication is successful for "user-2"
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM access
    """
    provider.user("user-1").add()
    provider.user("user-2").add()
    client.pam.access().add(["+:user-1:ALL", "-:user-2:ALL"])

    client.sssd.common.pam(["with-pamaccess"])
    client.sssd.domain["use_fully_qualified_names"] = "False"
    client.sssd.start()

    assert client.auth.ssh.password("user-1", "Secret123")
    assert not client.auth.ssh.password("user-2", "Secret123")

    client.authselect.disable_feature(["with-pamaccess"])

    assert client.auth.ssh.password("user-1", "Secret123")
    assert client.auth.ssh.password("user-2", "Secret123")


@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_smartcard(client: Client):
    """
    :title: Authselect sssd profile with-smartcard, sanity only
    :steps:
        1. Select the authselect SSSD profile with-smartcard
        2. Configure and started SSSD for smartcards
        3. Check pam configuration
        4. Disable authselect feature
        5. Check pam configuration
    :expectedresults:
        1. SSSD profile is selected with-smartcard
        2. SSSD is configured and started for smartcards
        3. PAM Configuration contains try_cert_auth
        4. Feature is disabled
        5. PAM Configuration does not contain try_cert_auth
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM smartcard
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-smartcard"])
    client.sssd.pam["pam_cert_auth"] = "True"

    client.sssd.start()

    assert "try_cert_auth" in client.fs.read("/etc/pam.d/system-auth")

    client.authselect.disable_feature(["with-smartcard"])

    assert "try_cert_auth" not in client.fs.read("/etc/pam.d/system-auth")


@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_smartcard_lock_on_removal(client: Client):
    """
    :title: SAuthselect sssd profile with-smartcard-lock-on-removal, sanity only
    :steps:
        1. Select the authselect SSSD profile with-smartcard-lock-on-removal
        2. Configure and start SSSD for smartcards
        3. Check pam configuration
        4. Disable authselect feature
        5. Check pam configuration
    :expectedresults:
        1. SSSD profile is selected with-smartcard-lock-on-removal
        2. SSSD is configured for smartcards and started
        3. PAM Configuration contains try_cert_auth
        4. Feature is disabled
        5. PAM Configuration does not contain try_cert_auth
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM smartcard lock on removal
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-smartcard", "with-smartcard-lock-on-removal"])
    client.sssd.pam["pam_cert_auth"] = "True"

    client.sssd.start()

    assert "removal-action" in client.fs.read("/etc/dconf/db/distro.d/locks/20-authselect")

    client.authselect.disable_feature(["with-smartcard-lock-on-removal"])

    assert "removal-action" not in client.fs.read("/etc/dconf/db/distro.d/locks/20-authselect")


@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_fingerprint(client: Client):
    """
    :title: Authselect sssd profile with-fingerprint, sanity only
    :steps:
        1. Select the authselect SSSD profile with-fingerprint
        2. Configure and start SSSD
        3. Check pam configuration
        4. Disable authselect feature
        5. Check pam configuration
    :expectedresults:
        1. SSSD profile is selected with-fingerprint
        2. SSSD is configured for fingerprint and started
        3. PAM Configuration contains pam_fprintd.so
        4. Feature is disabled
        5. PAM Configuration does not contain pam_fprintd.so
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM fingerprint
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-fingerprint"])

    client.sssd.start()

    assert "pam_fprintd.so" in client.fs.read("/etc/pam.d/system-auth")

    client.authselect.disable_feature(["with-fingerprint"])

    assert "pam_fprintd.so" not in client.fs.read("/etc/pam.d/system-auth")


@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_silent_lastlog(client: Client):
    """
    :title: Authselect sssd profile with-silent-lastlog, sanity only
    :steps:
        1. Select the authselect SSSD profile with-silent-lastlog
        2. Configure and start SSSD
        3. Check pam configuration
        4. Disable authselect feature
        5. Check pam configuration
    :expectedresults:
        1. SSSD profile is selected with-silent-lastlog
        2. SSSD is configured for silent-lastlog and started
        3. PAM Configuration contains pam_lastlog.so
        4. Feature is disabled
        5. PAM configuration does not contain pam_lastlog.so
    :customerscenario: False
    :requirement: IDM-SSSD-TC: authselect: Authselect SSSD profile enable and disable PAM silent lastlog
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-silent-lastlog"])

    client.sssd.start()

    assert "pam_lastlog.so nowtmp silent" in client.fs.read("/etc/pam.d/postlogin")

    client.authselect.disable_feature(["with-silent-lastlog"])

    assert "pam_lastlog.so nowtmp showfailed" in client.fs.read("/etc/pam.d/postlogin")


@pytest.mark.ticket(bz=2077893)
@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_with_gssapi(client: Client):
    """
    :title: Authselect sssd profile with-gssapi, sanity only
    :steps:
        1. Select the authselect SSSD profile with-gssapi
        2. Configure and start SSSD
        3. Check pam configuration
        4. Disable authselect feature
        5. Check pam configuration
    :expectedresults:
        1. SSSD profile is selected with-gssapi
        2. SSSD is configured for gssapi and started
        3. PAM Configuration contains pam_sss_gss.so
        4. Feature is disabled
        5. PAM Configuration does not contain pam_sss_gss.so
    :customerscenario: False
    :requirement: IDM-SSSD-TC: sssd: bz2077893 add with-gssapi (pam_sss_gss.so)
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-gssapi"])

    client.sssd.start()

    assert "pam_sss_gss.so" in client.fs.read("/etc/pam.d/system-auth")

    client.authselect.disable_feature(["with-gssapi"])

    assert "pam_sss_gss.so" not in client.fs.read("/etc/pam.d/system-auth")


@pytest.mark.ticket(bz=2075192)
@pytest.mark.topology(KnownTopology.Client)
def test_authselect__sssd_profile_enable_and_disable_with_subid(client: Client):
    """
    :title: Authselect sssd profile with-subid, sanity only
    :steps:
        1. Select the authselect SSSD profile with-subid
        2. Configure and start SSSD
        3. Check nsswitch configuration
        4. Disable authselect feature
        5. Check nsswitch configuration
    :expectedresults:
        1. SSSD profile is selected with-subid
        2. SSSD is configured for subid and started
        3. NSSSwitch contains subid
        4. Feature is disabled
        5. NSSSwitch does not contain subid
    :customerscenario: False
    :requirement:
    """
    client.sssd.common.local()
    client.authselect.select("sssd", ["with-subid"])

    client.sssd.start()

    assert "subid" in client.fs.read("/etc/nsswitch.conf")

    client.authselect.disable_feature(["with-subid"])

    assert "subid" not in client.fs.read("/etc/nsswitch.conf")
