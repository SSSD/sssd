""" AD-Provider range retrieval

:requirement: range_retrieval
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import re
import time
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('fetch_ca_cert')
@pytest.mark.usefixtures('range_retr_mods', 'create_small_grp_usr', 'create_range_aduser_group')
@pytest.mark.tier1_4
@pytest.mark.rangeretrieval
class TestADRangeRetrieval:
    """ Test Cases for AD default output range modified ported from bash
    :setup:
     1. Fetch the certificates from AD on client and Configure client to use them
     2. On AD-server, from default query policy, in lDAPAdminLimits, set value of MaxValRange to 50
     3. Create a group 'smallgrp' with 50 users members on AD-server
     4. On AD-server, create 200 ADusers and 200 ADgroups
     5. On AD-server, create a ADuser and add it to 200 ADgroups as member
     6. On AD-server, create a ADgroup and add 200 ADusers members to it.
    """
    @staticmethod
    def test_0001_grouplookup_large_members(multihost, adjoin):
        """
        :title: with ldap provider lookup group with large number of users
        :id: 74ecb720-e2d3-4c72-b43a-12cf5e6166d6
        :setup:
         1. Configure sssd.conf to use id_provider = ldap, 'ldap_schema = ad' and it's related option
         2. Set ldap_id_mapping to True in domain section of sssd.conf
         3. Restart SSSD service with cleaned cache and logs
        :steps:
          1. Fetch information of rangegroup and assert groupmembers beyond 100 and 200 are fetched)
          2. Assert 'Base attribute of [member]' in sssd_domain.log
          3. Assert 'Parsed range values: [member][50]' in sssd_domain.log
          4. Log in with a AD-user from a group with large number of members
        :expectedresults:
          1. Fetched group information shows members beyond 100 and 200 range
          2. Expected Log is present in domain log
          3. Expected Log is present in domain log
          4. Successful user log in
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        binddn = f'cn=Administrator,cn=users,{multihost.ad[0].domain_basedn_entry}'
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ldap',
            'use_fully_qualified_names': 'false',
            'ldap_uri': f'ldaps://{multihost.ad[0].sys_hostname}',
            'ldap_id_mapping': 'True',
            'ldap_schema': 'ad',
            'ldap_default_bind_dn': binddn,
            'ldap_default_authtok': f'{multihost.ad[0].ssh_password}',
            'ldap_referrals': 'false',
            'ldap_tls_cacert': '/etc/openldap/certs/ad_cert.pem'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        time.sleep(5)
        cmd1 = multihost.client[0].run_command('getent group rangegroup', raiseonerr=False)
        time.sleep(3)
        log = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        patt = re.compile(r'Base.+attribute.+of.+member.*range.0-49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.+range.*values.*member.*50', re.IGNORECASE)
        login = client.auth_from_client(f'rangeuser010@{domain_name}', 'Secret123') == 3, 'user log in failed'
        client.restore_sssd_conf()
        assert 'rangeuser0100' in cmd1.stdout_text, 'group information missing rangeuser0100'
        assert 'rangeuser0200' in cmd1.stdout_text, 'group information missing rangeuser0200'
        assert patt.search(log), 'Base atribute of [member] log is missing'
        assert patt1.search(log), 'Parsed range values: member] log is missing'
        assert login, 'user log in failed'

    @staticmethod
    def test_0002_ad_provider_search_base_with_filter(multihost, adjoin):
        """
        :title: ad provider search base with filter bz848031
        :id: 928b2f4e-dd1e-416d-abdd-4345be386f5d
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=848031
        :setup:
          1. Configure sssd with 'id_provider = ad' and it's related options
          2. Configure ldap_group-search_base to 'AD_BASEDN??(rangegroup)' in domain_section
        :steps:
          1. Fetch rangegroup membership and assert groupmembers beyond 100 are not fetched
          2. Assert 'Base attribute of [member]' in sssd_domain.log
          4. Assert 'Parsed range values: [member][50]' in sssd_domain.log
          5. Log in with AD-user from a group with large number of members
        :expectedresults:
          1. Fetched group information does not shows members beyond 100
          2. Log is present
          3. Log is present
          4. User Log in successful
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        multihost.client[0].service_sssd('stop')
        basedn = multihost.ad[0].domain_basedn_entry
        sssd_params = {
            'debug_level': '0xFFF0',
            'use_fully_qualified_names': 'false',
            'id_provider': 'ad',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ad_domain': domain_name,
            'ldap_group_search_base': f'{basedn}??(cn=rangegroup)'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        patt = re.compile(r'Base.attribute.of.*member.*range.*0.49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.range.values.*member.*50', re.IGNORECASE)
        cmd1 = multihost.client[0].run_command('getent group rangegroup', raiseonerr=False)
        time.sleep(2)
        log_str = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        login = client.auth_from_client(f'rangeuser0150@{domain_name}', 'Secret123') == 3
        client.restore_sssd_conf()
        assert 'rangeuser050' in cmd1.stdout_text, 'group missing rangeuser050 as member'
        assert 'rangeuser0100' not in cmd1.stdout_text, 'rangegroup showing rangeuser0100 as member'
        assert 'rangeuser0200' not in cmd1.stdout_text, 'rangegroup showing rangeuser0200 as member'
        assert patt.search(log_str), 'Base atribute of [member] log is missing'
        assert patt1.search(log_str), 'Parsed range values: member] log is missing'
        assert login, 'user login failed'

    @staticmethod
    def test_0003_ad_provider_userlookup_large_numberof_groups(multihost, adjoin):
        """
        :title: ad provider lookup user belonging to large number of groups
        :id: 87843cff-cf70-4537-adb7-d05bd3d0b3c4
        :setup:
         1. Configure id_provider = ad in the domain section
        :steps:
          1. Run 'id rangeuser'
          2. SSSD domain logs should have logs related to "Base attribute of [memberOf;range=0-49]
             is [memberOf]"
          3. SSSD domain logs should have logs for 'Parsed range values: [memberOf][50]'
          4. User 'rangeuser' log in ssh
        :expectedresults:
          1. The 'id Rangeuser' should show the group membership upto 200 groups
          2. Logs is present
          3. Logs is present
          4. Successful authentication
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        multihost.client[0].service_sssd('stop')
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'false',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ad_domain': f'{domain_name}'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        time.sleep(3)
        cmd1 = multihost.client[0].run_command('getent group rangegroup', raiseonerr=False)
        patt = re.compile(r'Base.attribute.of.*member.*range.*0.49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.range.values.*member.*50', re.IGNORECASE)
        log_str = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        login = client.auth_from_client(f'rangeuser010@{domain_name}', 'Secret123') == 3, 'user log in failed'
        assert 'rangeuser0100' in cmd1.stdout_text, 'rangegroup group is not fetching rangeuser0100'
        assert 'rangeuser0200' in cmd1.stdout_text, 'rangegroup group is not fetching rangeuser0200'
        assert login, 'User log in failed'
        assert patt.search(log_str), 'Base atribute of [member] log is missing'
        assert patt1.search(log_str), 'Parsed range values: member] log is missing'

    @staticmethod
    def test_0004_ad_provider_ldap_user_searchbase_with_filter(multihost, adjoin):
        """
        :title: ad provider ldap user search base with filter
        :id: 27100011-c8c6-46ee-b135-8df50537c0fc
        :setup:
          1. Configure ldap_group-search_base to 'AD_BASEDN??(rangegroup)' in domain_section
        :steps:
          1. Fetch information of rangegroup and assert groupmembers beyond 100 and 200 are fetched)
          2. Assert a log related to "Base attribute of [memberOf;range=0-49]" is in domain log
          3. Assert 'Parsed range values: [member][50]' in sssd_domain.log
          4. Log in with AD-user from a group with large number of members
        :expectedresults:
          1. Fetched group information shows members beyond 100 and 200 range
          2. Log is asserted
          3. Log is asserted
          4. Log in successful
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        basedn = multihost.ad[0].domain_basedn_entry
        multihost.client[0].service_sssd('stop')
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'false',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ldap_user_search_base': f'{basedn}??(cn=rangeuser)',
            'ad_domain': domain_name
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        cmd1 = multihost.client[0].run_command('id rangeuser', raiseonerr=False)
        patt = re.compile(r'Base.attribute.of.*member.*range.*0.49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.range.values.*member.*50', re.IGNORECASE)
        log_str = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        login = client.auth_from_client(f'rangeuser010@{domain_name}', 'Secret123') == 3, 'user log in failed'
        assert 'rangegroup0100' in cmd1.stdout_text, 'rangegroup group is not fetching rangeuser0100'
        assert 'rangegroup0200' in cmd1.stdout_text, 'rangegroup group is not fetching rangeuser0200'
        assert patt.search(log_str), 'Base atribute of [member] log is missing'
        assert patt1.search(log_str), 'Parsed range values: member] log is missing'
        assert login, 'user login failed'

    @staticmethod
    def test_0005_setting_up_ldap_disable_range_retrieval_to_true(multihost, adjoin):
        """
        :title: Setting up ldap disable range retrieval to true bz928807 bz916997
        :id: 8b5d762f-f198-4a27-b811-df9b3f9f4306
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=928807
          https://bugzilla.redhat.com/show_bug.cgi?id=916997
        :setup:
          1. Set ldap_disable_range_retrieval = true in domain section of sssd.conf
        :steps:
          1. Fetch information of rangegroup and assert user 'rangeuser' is not in it
          2. Fetch group information of smallgrp and confirm it has 50 members
        :expectedresults:
          1. The rangegroup membership does not return rangeuser as it's member
          2. The smallgrp group has 50 members
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        multihost.client[0].service_sssd('stop')
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'false',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ad_domain': f'{domain_name}',
            'ldap_disable_range_retrieval': 'True'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        cmd1 = multihost.client[0].run_command('getent -s sss group rangegroup', raiseonerr=False)
        cmd2 = multihost.client[0].run_command('getent -s sss group smallgrp', raiseonerr=False)
        assert 'rangeuser' not in cmd1.stdout_text, 'rangegroup is having rangeuser as member'
        assert cmd2.stdout_text.count('ad_user') == 50, 'smallgrp group does not contain 50 members'

    @staticmethod
    def test_0006_setting_up_ldap_disable_range_retrieval_to_false(multihost, adjoin):
        """
        :title: Setting up ldap disable range retrieval to false
        :id: 43d9637c-b2ab-47e3-acc7-22abe0fb85ec
        :bugzilla:
          https://bugzilla.redhat.com/show_bug.cgi?id=928807
          https://bugzilla.redhat.com/show_bug.cgi?id=916997
        :setup:
          1. Set ldap_disable_range_retrieval = false in domain section of sssd.conf
          2. Enable ldap_id_mapping in domain section
        :steps:
          1. fetch information of rangegroup and assert user 'rangeuser' is not in it
          2. fetch group information of smallgrp and confirm it has 50 members
        :expectedresults:
          1. The rangegroup membership returns rangeuser as it's member
          2. The smallgrp group has 50 members
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        multihost.client[0].service_sssd('stop')
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'false',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ad_domain': f'{domain_name}',
            'ldap_id_mapping': 'True',
            'ldap_disable_range_retrieval': 'false'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache()
        cmd1 = multihost.client[0].run_command('getent -s sss group rangegroup', raiseonerr=False)
        cmd2 = multihost.client[0].run_command('getent -s sss group smallgrp', raiseonerr=False)
        assert 'rangeuser' in cmd1.stdout_text, 'rangeuser is not the member of rangegroup group'
        assert cmd2.stdout_text.count('ad_user') == 50, 'smallgrp group doesnot contain 50 members'
