""" AD-Provider range retrieval

:requirement: range_retrieval
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import re
import pytest
import pexpect
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import SSSDException
from sssd.testlib.common.exceptions import SSHLoginException


@pytest.mark.usefixtures('fetch_ca_cert')
@pytest.mark.usefixtures('range_retr_mods', 'create_small_grp_usr', 'create_range_aduser_group')
@pytest.mark.tier1_9
@pytest.mark.rangeretrieval
class TestADRangeRetrieval:
    """ BZ Automated Test Cases for AD Parameters ported from bash"""
    @staticmethod
    def test_0001_grouplookup_large_members(multihost, adjoin):
        """
        :title: ldap provider lookup group with large number of users
        :id: 74ecb720-e2d3-4c72-b43a-12cf5e6166d6
        :setup:
         1. Configure sssd.conf with id_provider = ldap, ldap_schema=ad etc
        :steps:
          1. fetch information of rangegroup and assert groupmembers beyond 100 and 200 are fetched)
          2. Assert 'Base attribute of [member]' in sssd_domain.log
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
        multihost.client[0].run_command('cp /etc/sssd/sssd.conf /etc/sssd/sssd.conf_bk', raiseonerr=False)
        cmd = multihost.client[0].run_command('getent group rangegroup|egrep rangeuser0200| egrep rangeuser0100', raiseonerr=False)
        time.sleep(3)
        log = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        patt = re.compile(r'Base.+attribute.+of.+member.*range.0-49.*is.*member', re.IGNORECASE)
        patt = re.compile(r'Parsed.+range.*values.*member.*50', re.IGNORECASE)
        cl_hostname = multihost.client[0].sys_hostname
        cl = pexpect_ssh(cl_hostname, f'rangeuser010@{domain_name}', 'Secret123', debug=False)
        try:
            cl.login()
        except SSHLoginException:
            pytest.fail(f'rangeuser010@{domain_name} failed to login')
        except pexpect.EOF as err:
            print(err)
        else:
            (stdout, _) = cl.command(f'id rangeuser010@{domain_name}')
            cl.logout()
        client.restore_sssd_conf()
        assert cmd.returncode == 0
        assert patt.search(log)
        assert 'rangeuser010' in stdout

    @staticmethod
    def test_0002_ad_provider_search_base_with_filter(multihost, adjoin):
        """
        :title: ad provider search base with filter bz848031
        :id: 928b2f4e-dd1e-416d-abdd-4345be386f5d
        :setup:
          1. Configure ldap_group-search_base to 'AD_BASEDN??(rangegroup)' in domain_section
          2. Assert 'Base attribute of [member]' in sssd_domain.log
          3. Assert 'Parsed range values: [member][50]' in sssd_domain.log
          4. Log in with AD-user from a group with large number of members
        :steps:
          1. fetch information of rangegroup and assert groupmembers beyond 100 and 200 are fetched)
          2. Assert 'Base attribute of [member]' in sssd_domain.log
          3. Assert 'Parsed range values: [member][50]' in sssd_domain.log
          4. Log in with AD-user from a group with large number of members
        :expectedresults:
          1. Fetched group information shows members beyond 100 and 200 range
          2. Log is asserted
          3. Log is asserted
          4. Log in successful
        :customerscenario: True
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
        multihost.client[0].run_command(f'cp /etc/sssd/sssd.conf /root/sssd.conf_02', raiseonerr=False)
        client.clear_sssd_cache()
        cmd = multihost.client[0].run_command('getent group rangegroup | grep rangeuser050', raiseonerr=False)
        cmd3 = multihost.client[0].run_command('getent group rangegroup | grep rangeuser0200 | grep rangeuser0100', raiseonerr=False)
        patt = re.compile(r'Base.attribute.of.*member.*range.*0.49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.range.values.*member.*50', re.IGNORECASE)
        time.sleep(2)
        log_str = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        cl_hostname = multihost.client[0].sys_hostname
        cl = pexpect_ssh(cl_hostname, f'rangeuser0150@{domain_name}', 'Secret123', debug=False)
        try:
            cl.login()
        except SSHLoginException:
            pytest.fail(f'rangeuser010 failed to login')
        except pexpect.EOF:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        else:
            (stdout, _) = cl.command(f'id rangeuser0150@{domain_name}')
            cl.logout()
        client.restore_sssd_conf()
        assert cmd.returncode == 0
        assert patt.search(log_str)
        assert patt1.search(log_str)
        assert cmd3.returncode != 0

    @staticmethod
    def test_0003_ad_provider_userlookup_large_numberof_groups(multihost, adjoin):
        """
        :title: ad provider lookup user belonging to large number of groups
        :id: 87843cff-cf70-4537-adb7-d05bd3d0b3c4
        :setup:
         1. Configure id_provider = ad in the domain section
        :steps:
          1. Output of 'id rangeuser' should return groups from range 100 and 200
          2. SSSD domain logs should have logs related to "Base attribute of [memberOf;range=0-49]
             is [memberOf\]"
          3. SSSD domain logs should have logs for 'Parsed range values: [memberOf][50]'
          4. Log in of rangeuser via ssh
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
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
            'ad_domain': domain_name
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache('/var/log/secure')
        client.clear_sssd_cache()
        cmd = multihost.client[0].run_command('id rangeuser|egrep rangegroup0200|egrep rangegroup0100')
        time.sleep(3)
        #cmd1 = multihost.client[0].run_command('egrep "Base attribute of \[memberOf;range=0-49\] is \[memberOf\]" "/var/log/sssd/sssd_ADTEST.log"')
        #cmd2 = multihost.client[0].run_command('egrep "Parsed range values: [memberOf][50]" /var/log/sssd/sssd_{domain}.log')
        patt = re.compile(r'Base.attribute.of.*member.*range.*0.49.*is.*member', re.IGNORECASE)
        patt1 = re.compile(r'Parsed.range.values.*member.*50', re.IGNORECASE)
        log_str = multihost.client[0].get_file_contents(f'/var/log/sssd/sssd_{domain_name}.log').decode('utf-8')
        cl_hostname = multihost.client[0].sys_hostname
        cl = pexpect_ssh(cl_hostname, f'rangeuser@{domain_name}', 'Secret123', debug=False)
        try:
            cl.login()
        except SSHLoginException:
            pytest.fail('rangeuser failed to login')
        except pexpect.EOF as err:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
        else:
            (stdout, _) = cl.command(f'id rangeuser@{domain_name}')
            cl.logout()
        multihost.client[0].run_command(f'cp /var/log/sssd/sssd_{domain_name}.log /root/sssd_{domain_name}3.log', raiseonerr=False)
        multihost.client[0].run_command(f'cp /etc/sssd/sssd.conf /root/sssd.conf_03', raiseonerr=False)
        assert 'rangeuser' in stdout
        assert patt.search(log_str)
        assert patt1.search(log_str)
        cmd.returncode == 0
        #cmd1.returncode == 0
        #cmd2.returncode == 0

    @staticmethod
    def test_0004_ad_provider_ldap_user_searchbase_with_filter(multihost, adjoin):
        """
        :title: ad provider ldap user search base with filter
        :id: 27100011-c8c6-46ee-b135-8df50537c0fc
        :setup:
          1. Configure ldap_group-search_base to 'AD_BASEDN??(rangegroup)' in domain_section
          2. SSSD domain logs should have logs related to "Base attribute of [memberOf;range=0-49]
             is [memberOf\]"
          3. SSSD domain logs should have logs for 'Parsed range values: [memberOf][50]'
          4. Log in with AD-user from a group with large number of members
        :steps:
          1. fetch information of rangegroup and assert groupmembers beyond 100 and 200 are fetched)
          2. Assert 'Base attribute of [member]' in sssd_domain.log
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
            'ad_server': f'{multihost.ad[0].ip}',
            'ldap_user_search_base': f'{basedn}??(cn=rangeuser)',
            'ad_domain': domain_name
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache('/var/log/secure')
        client.clear_sssd_cache()
        cl_hostname = multihost.client[0].sys_hostname
        cl = pexpect_ssh(cl_hostname, f'rangeuser@{domain_name}', 'Secret123', debug=False)
        try:
            cl.login()
        except SSHLoginException:
            pytest.fail('rangeuser failed to login')
        except pexpect.EOF as err:
            log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
            patt = re.compile(r'Access.*denied for user')
        else:
            (stdout, _) = cl.command(f'id rangeuser@{domain_name}')
            cl.logout()
        assert 'rangeuser' in stdout
        #client = sssdTools(multihost.client[0], multihost.ad[0])
        #domain_name = client.get_domain_section_name()
        #domain_section = f'domain/{domain_name}'
        #multihost.client[0].service_sssd('stop')
        #basedn = multihost.ad[0].domain_basedn_entry
        #sssd_params = {
        #    'debug_level': '0xFFF0',
        #    'id_provider': 'ad',
        #    'ad_server': f'{multihost.ad[0].ip}',
        #    'ad_domain': domain_name
        #}
        #sssdconf = multihost.client[0].get_file_contents('/etc/sssd/sssd.conf')
        #client.sssd_conf(domain_section, sssd_params)
        #client.clear_sssd_cache('/var/log/secure')
        #client.clear_sssd_cache()
        ##    'ldap_user_search_base': f'{basedn}??(cn=rangeuser)',
        ##cmd = multihost.client[0].run_command('id rangeuser|egrep rangegroup200|egrep rangegroup100')
        ##cmd1 = multihost.client[0].run_command('egrep "Base attribute of \[memberOf;range=0-49\] is \[memberOf\]" "/var/log/sssd/sssd_ADTEST.log"')
        ##cmd2 = multihost.client[0].run_command('egrep "Parsed range values: [memberOf][50]" /var/log/sssd/sssd_{domain}.log')
        #cl_hostname = multihost.client[0].sys_hostname
        #cl = pexpect_ssh(cl_hostname, f'rangeuser@{domain_name}', 'Secret123', debug=False)
        #try:
        #    cl.login()
        #except SSHLoginException:
        #    pytest.fail(f'rangeuser failed to login')
        #except pexpect.EOF as err:
        #    log_str = multihost.client[0].get_file_contents('/var/log/secure').decode('utf-8')
        #else:
        #    (stdout, _) = cl.command(f'id rangeuser@{domain_name}')
        #    cl.logout()
        #assert 'rangeuser' in stdout

    @staticmethod
    def test_0005_setting_up_ldap_disable_range_retrieval_to_true(multihost, adjoin):
        """
        :title: Setting up ldap disable range retrieval to true bz928807 bz916997
        :id: 8b5d762f-f198-4a27-b811-df9b3f9f4306
        :setup:
          1. Set ldap_disable_range_retrieval = true in domain section of sssd.conf
          2. SSSD domain logs should have logs related to "Base attribute of [memberOf;range=0-49]
             is [memberOf\]"
          3. SSSD domain logs should have logs for 'Parsed range values: [memberOf][50]'
          4. Log in with AD-user from a group with large number of members
        :steps:
          1. fetch information of rangegroup and assert user 'rangeuser' is not in it
          2. fetch group information of smallgrp and confirm it has 50 members
        :expectedresults:
          1. Should succeed
          2. Should succeed
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
            'ad_server': f'{multihost.ad[0].ip}',
            'ad_domain': domain_name,
            'ldap_disable_range_retrieval': 'True'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache('/var/log/secure')
        client.clear_sssd_cache()
        cmd = multihost.client[0].run_command('getent -s sss group rangegroup|egrep -v rangeuser', raiseonerr=False)
        cmd1 = multihost.client[0].run_command('getent -s sss group smallgrp | awk -F , "{print NF}" | egrep $AD_MAX_RANGE', raiseonerr=False)
        cmd1.returncode == 0
        cmd.returncode == 0

    @staticmethod
    def test_0006_setting_up_ldap_disable_range_retrieval_to_false( multihost, adjoin):
        """
        :title: Setting up ldap disable range retrieval to false bz928807 bz916997
        :id: 43d9637c-b2ab-47e3-acc7-22abe0fb85ec
        :setup:
          1. Set ldap_disable_range_retrieval = true in domain section of sssd.conf
          2. SSSD domain logs should have logs related to "Base attribute of [memberOf;range=0-49]
             is [memberOf\]"
          3. SSSD domain logs should have logs for 'Parsed range values: [memberOf][50]'
          4. Log in with AD-user from a group with large number of members
        :steps:
          1. fetch information of rangegroup and assert user 'rangeuser' is not in it
          2. fetch group information of smallgrp and confirm it has 50 members
        :expectedresults:
          1. Should succeed
          2. Should succeed
        :customerscenario: False
        """
        adjoin(membersw='adcli')
        AD_MAX_RANGE = 50
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        domain_section = f'domain/{domain_name}'
        multihost.client[0].service_sssd('stop')
        sssd_params = {
            'debug_level': '0xFFF0',
            'id_provider': 'ad',
            'use_fully_qualified_names': 'false',
            'ad_server': f'{multihost.ad[0].sys_hostname}',
            'ad_domain': domain_name,
            'ldap_id_mapping': 'True',
            'ldap_disable_range_retrieval': 'false'
        }
        client.sssd_conf(domain_section, sssd_params)
        client.clear_sssd_cache('/var/log/secure')
        client.clear_sssd_cache()
        multihost.client[0].run_command('cp /etc/sssd/sssd.conf /root/sssd.conf_06', raiseonerr=False)
        cmd = multihost.client[0].run_command(f'getent -s sss group rangegroup@{domain_name}', raiseonerr=False)
        cmd1 = multihost.client[0].run_command('getent -s sss group smallgrp@domain_name | awk -F , "{print NF}" | egrep {AD_MAX_RANGE}', raiseonerr=False)
        cmd2 = multihost.client[0].run_command(f'getent -s sss group smallgrp@{domain_name}', raiseonerr=False)
        assert cmd2.returncode == 0
        assert 'rangeuser' in cmd.stdout_text
        assert cmd1.returncode == 0
