""" AD-Provider AD Schema tests ported from bash

:requirement: ad_schema
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
:caseautomation: Automated
:testtype: functional
"""

import random
import pytest


from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import ADOperations

# Constants for id mapping
RANGE_MIN = 200000
RANGE_SIZE = 400000
RANGE_MAX = 2000200000


@pytest.fixture(scope="function", name="prepare_users")
def fixture_prepare_users(session_multihost, request):
    """Prepare users and groups"""
    uid = random.randint(9999, 99999)
    ad_op = ADOperations(session_multihost.ad[0])

    # Setup non-posix user 1
    ad_user_1 = 'testuser1%d' % uid
    ad_group_1 = 'testgroup1%d' % uid
    ad_op.create_ad_nonposix_user(ad_user_1)
    ad_op.create_ad_nonposix_group(ad_group_1)
    ad_op.add_user_member_of_group(ad_group_1, ad_user_1)

    # Add gecos to user 1
    usr = f"powershell.exe -inputformat none -noprofile 'Set-ADUser " \
        f"-Identity \"{ad_user_1}\" -Add @{{" \
        f"gecos = \"{ad_user_1}\";}}'"
    session_multihost.ad[0].run_command(usr, raiseonerr=False)

    # Set user primary group
    upg = f"powershell.exe -inputformat none -noprofile " \
        f"'Set-ADUserPrimaryGroup {ad_user_1} \'{ad_group_1}\''"
    res = session_multihost.ad[0].run_command(upg, raiseonerr=False)
    # Windows 2012R2 does not know Set-ADUserPrimaryGroup
    # This is a crude re-implementation
    if "'Set-ADUserPrimaryGroup' is not recognized" in res.stderr_text:
        info_cmd = f"powershell.exe -inputformat none -noprofile '" \
            f"write-host $(Get-ADGroup -Identity {ad_group_1}).SID'"
        cmd = session_multihost.ad[0].run_command(info_cmd, raiseonerr=False)
        group_id = cmd.stdout_text.strip().split('-')[-1]
        pgp_cmd = f"powershell.exe -inputformat none -noprofile Set-ADUser " \
            f"-Identity {ad_user_1} -Replace @{{'primaryGroupID' = '{group_id}'}}"
        session_multihost.ad[0].run_command(pgp_cmd, raiseonerr=False)

    # Setup posix user 2
    ad_user_2 = 'testuser2%d' % uid
    ad_group_2 = 'testgroup2%d' % uid
    ad_op.create_ad_unix_user_group(ad_user_2, ad_group_2)

    # Add gecos to user 2
    usr = f"powershell.exe -inputformat none -noprofile 'Set-ADUser " \
        f"-Identity \"{ad_user_2}\" -Add @{{gecos = \"{ad_user_2}\";}}'"
    session_multihost.ad[0].run_command(usr, raiseonerr=False)

    def remove_ad_user_groups():
        """ Remove windows AD users and groups"""
        ad_op.delete_ad_user_group(ad_user_1)
        ad_op.delete_ad_user_group(ad_group_1)
        ad_op.delete_ad_user_group(ad_user_2)
        ad_op.delete_ad_user_group(ad_group_2)

    request.addfinalizer(remove_ad_user_groups)
    return ad_user_1, ad_group_1, ad_user_2, ad_group_2


@pytest.mark.adschema
@pytest.mark.usefixtures("joinad")
class TestADSchema:
    """Automated Test Cases for AD Schema ported from bash"""

    @staticmethod
    @pytest.mark.tier1_3
    def test_0001_ad_schema_idmapping_true_user(multihost, prepare_users):
        """test_0001_ad_schema_idmapping_true_user

        :title: IDM-SSSD-TC: ad_provider: ad_schema: Compare with sysdb when
         idmapping is set to True for an user
        :id: fb75a597-7567-48c2-a786-74c6b4eeab37
        :setup:
          1. Configure ldap_idmap_range_size, ldap_id_mapping=True clear
         cache and restart sssd.
        :steps:
          1. Gather user information using getent passwd and run id command.
          2. Gather user information directly from AD (powershell).
          3. Gather user information from cache ldb.
          4. Compute user uid, gid.
          5. Compare gathered data and make sure that it is consistent.
        :expectedresults:
          1. User is found.
          2. Data is collected.
          3. Data is collected.
          4. Computed user uid, gid are matching the ones from getent.
          5. The content of data is consistent across the sources.
        :customerscenario: False
        """
        ad_realm = multihost.ad[0].domainname.upper()

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_idmap_range_size': RANGE_SIZE,
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Get the non-posix user name from the fixture
        ad_user, _, _, _ = prepare_users

        # Gather the info about user from getent passwd
        getent_info = client.get_getent_passwd(f"{ad_user}@{ad_realm}")

        multihost.client[0].run_command(
            f'id {ad_user}@{ad_realm}', raiseonerr=False)

        ldb_info = client.dump_ldb(ad_user, ad_realm.lower())

        ad_op = ADOperations(multihost.ad[0])
        ad_info = ad_op.get_user_info(ad_user)

        uid, gid = ADOperations.compute_id_mapping(
            ad_info['objectSid'], int(ad_info['primaryGroupID']),
            range_min=RANGE_MIN, range_size=RANGE_SIZE, range_max=RANGE_MAX)

        ad_info['uidnumber_'], ad_info['gidnumber_'] = str(uid), str(gid)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert ad_info['Name'] in getent_info['name']
        assert getent_info['uid'] == ad_info['uidnumber_']
        assert getent_info['gid'] == ad_info['gidnumber_']
        assert getent_info['gecos'] == ad_info['gecos']

        assert ad_info['Name'] == ldb_info['fullName']
        assert ad_info['SamAccountName'] in ldb_info['name']
        assert ad_info['uidnumber_'] == ldb_info['uidNumber']
        assert ad_info['gidnumber_'] == ldb_info['gidNumber']
        assert ad_info['gecos'] == ldb_info['gecos']
        assert ldb_info['originalMemberOf'].replace(" ", "") \
            in ad_info['MemberOf'].replace(" ", "")
        assert ad_info['userAccountControl'] == \
            ldb_info['adUserAccountControl']
        assert ad_info['objectSid'] == ldb_info['objectSIDString']

    @staticmethod
    @pytest.mark.tier1_3
    def test_0002_ad_schema_idmapping_true_group(multihost, prepare_users):
        """test_0002_ad_schema_idmapping_true_group

        :title: IDM-SSSD-TC: ad_provider: ad_schema: Compare with sysdb when
         idmapping is set to True for a group
        :id: 777bb5e3-6da5-495f-9098-754e483fa010
        :setup:
          1. Configure ldap_idmap_range_size, ldap_id_mapping=True clear
         cache and restart sssd.
        :steps:
          1. Gather group information using getent group.
          2. Gather group information directly from AD (powershell).
          3. Gather group information from cache ldb.
          4. Compute the gid for the group and compare with getent output.
          5. Compare gathered data and make sure that it is consistent.
        :expectedresults:
          1. Group is found.
          2. Data is collected.
          3. Data is collected.
          4. Computed gid is matching with the one from getent.
          5. The content of data is consistent across the sources.
        :customerscenario: False
        """
        ad_realm = multihost.ad[0].domainname.upper()

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'True',
            'debug_level': '9',
            'id_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_idmap_range_size': RANGE_SIZE,
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Get the non-posix group name from the fixture
        _, ad_group, _, _ = prepare_users

        # Get info from getent
        getent_groupinfo = client.get_getent_group(f"{ad_group}@{ad_realm}")

        # Get group info from AD
        ad_op = ADOperations(multihost.ad[0])
        group_info = ad_op.get_group_info(ad_group)

        # Get group info from local cache ldb
        group_ldb_info = client.dump_ldb(ad_group, ad_realm.lower())

        # Compute group gid
        g_gid, _ = ADOperations.compute_id_mapping(
            group_info['objectSid'], 0,
            range_min=RANGE_MIN, range_size=RANGE_SIZE, range_max=RANGE_MAX)
        group_info['gidnumber_'] = str(g_gid)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert group_info['Name'] in getent_groupinfo['name']
        assert group_info['gidnumber_'] == getent_groupinfo['gid']
        assert group_info['Name'] in group_ldb_info['name']
        assert group_info['gidnumber_'] == group_ldb_info['gidNumber']
        assert group_info['objectSid'] == group_ldb_info['objectSIDString']

        # Windows 2012 has a different format is different
        if 'member' in group_info:
            assert getent_groupinfo['users'].split("@")[0] in \
                   group_info['member']
            assert group_ldb_info['orig_member'] in group_info['member']
        elif 'members' in group_info:
            assert getent_groupinfo['users'].split("@")[0] in \
                   group_info['members']
            assert group_ldb_info['orig_member'] in group_info['members']

    @staticmethod
    @pytest.mark.tier1_3
    def test_0003_ad_schema_idmapping_false_user(multihost, prepare_users):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_schema: Compare with sysdb when
         idmapping is set to False an user
        :id: bef6b2d1-656c-48f9-b6ff-2153d10c3556
        :setup:
          1. Configure ldap_idmap_range_size, ldap_id_mapping=False clear
          cache and restart sssd.
        :steps:
          1. Gather user information using getent passwd and run id command.
          2. Gather user information directly from AD (powershell).
          3. Gather user information from cache ldb.
          4. Compare gathered data and make sure that it is consistent.
        :expectedresults:
          1. User is found.
          2. Data is collected.
          3. Data is collected.
          4. The content of data is consistent across the sources.
        :customerscenario: False
        """
        ad_realm = multihost.ad[0].domainname.upper()
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Backup the config because with broken config we can't leave ad
        client.backup_sssd_conf()

        # Configure sssd to ad_domain = junk
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'debug_level': '9',
            'id_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_idmap_range_size': RANGE_SIZE,
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Get the posix user name from the fixture
        _, _, ad_user, _ = prepare_users

        # Gather the info about user from getent passwd
        getent_info = client.get_getent_passwd(f"{ad_user}@{ad_realm}")

        multihost.client[0].run_command(
            f'id {ad_user}@{ad_realm}', raiseonerr=False)

        ldb_info = client.dump_ldb(ad_user, ad_realm.lower())

        ad_op = ADOperations(multihost.ad[0])
        ad_info = ad_op.get_user_info(ad_user)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert ad_info['Name'] in getent_info['name']
        assert getent_info['uid'] == ad_info['uidNumber']
        assert getent_info['gid'] == ad_info['gidNumber']
        assert getent_info['gecos'] == ad_info['gecos']
        assert getent_info['home'] == ad_info['unixHomeDirectory']
        assert getent_info['shell'] == ad_info['loginShell']

        assert ad_info['Name'] == ldb_info['fullName']
        assert ad_info['SamAccountName'] in ldb_info['name']
        assert ad_info['uidNumber'] == ldb_info['uidNumber']
        assert ad_info['gidNumber'] == ldb_info['gidNumber']
        assert ad_info['loginShell'] == ldb_info['loginShell']
        assert ad_info['uSNChanged'] == ldb_info['entryUSN']
        assert ad_info['gecos'] == ldb_info['gecos']
        assert ad_info['unixHomeDirectory'] == ldb_info['homeDirectory']
        assert ad_info['accountExpires'] == ldb_info['adAccountExpires']
        assert ldb_info['originalMemberOf'].replace(" ", "") in \
            ad_info['MemberOf'].replace(" ", "")
        assert ad_info['userAccountControl'] == \
            ldb_info['adUserAccountControl']
        assert ad_info['objectSid'] == ldb_info['objectSIDString']

    @staticmethod
    @pytest.mark.tier1_3
    def test_0004_ad_schema_idmapping_false_group(multihost, prepare_users):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_schema: Compare with sysdb when
         idmapping is set to False for a group
        :id: b1856f79-cbf8-4dd5-a1bd-a3761c1a4432
        :setup:
          1. Configure ldap_idmap_range_size, ldap_id_mapping=False clear
          cache and restart sssd.
        :steps:
          1. Gather group information using getent group.
          2. Gather group information directly from AD (powershell).
          3. Gather group information from cache ldb.
          4. Compare gathered data and make sure that it is consistent.
        :expectedresults:
          1. Group is found.
          2. Data is collected.
          3. Data is collected.
          4. The content of data is consistent across the sources.
        :customerscenario: False
        """
        ad_realm = multihost.ad[0].domainname.upper()
        client = sssdTools(multihost.client[0], multihost.ad[0])

        # Backup the config because with broken config we can't leave ad
        client.backup_sssd_conf()

        # Configure sssd to ad_domain = junk
        multihost.client[0].service_sssd('stop')
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ldap_id_mapping': 'False',
            'debug_level': '9',
            'id_provider': 'ad',
            'ad_domain': multihost.ad[0].domainname.lower(),
            'ad_server': multihost.ad[0].hostname,
            'ldap_idmap_range_size': RANGE_SIZE,
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Get the posix group name from the fixture
        _, _, _, ad_group = prepare_users

        # Get info from getent
        getent_groupinfo = client.get_getent_group(f"{ad_group}@{ad_realm}")

        # Get group info from AD
        ad_op = ADOperations(multihost.ad[0])
        group_info = ad_op.get_group_info(ad_group)

        # Get group info from local cache ldb
        group_ldb_info = client.dump_ldb(ad_group, ad_realm.lower())

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert group_info['Name'] in getent_groupinfo['name']
        assert group_info['gidNumber'] == getent_groupinfo['gid']
        assert group_info['Name'] in group_ldb_info['name']
        assert group_info['gidNumber'] == group_ldb_info['gidNumber']
        assert group_info['objectSid'] == group_ldb_info['objectSIDString']
        assert group_info['uSNChanged'] == group_ldb_info['entryUSN']
        # Windows 2012 has a different format is different
        if 'member' in group_info:
            assert getent_groupinfo['users'].split("@")[0] in \
                   group_info['member']
            assert group_ldb_info['orig_member'] in group_info['member']
        elif 'members' in group_info:
            assert getent_groupinfo['users'].split("@")[0] in \
                   group_info['members']
            assert group_ldb_info['orig_member'] in group_info['members']
