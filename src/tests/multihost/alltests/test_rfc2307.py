""" Automation of proxy provider suite

:requirement: IDM-SSSD-REQ : Proxy Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
from __future__ import print_function
import time
import os
import re
import pytest
from sssd.testlib.common.utils import sssdTools, LdapOperations
from constants import ds_suffix, ds_instance_name


def check_sorted(test_list):
    """
    Will check if list is in ascending order
    """
    flag = 0
    i = 1
    while i < len(test_list):
        if test_list[i] < test_list[i - 1]:
            flag = 1
        i += 1

    if not flag:
        return True


def execute_cmd(multihost, command):
    """ Execute command on client """
    cmd = multihost.client[0].run_command(command)
    return cmd


@pytest.fixture(scope='class')
def ldap_objects_sssd_client(multihost, request):
    """
        Create required users for this test script
        Configure /etc/pam_ldap.conf
        Restore
    """
    execute_cmd(multihost, "> /etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'base {ds_suffix}' "
                           "> /etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'pam_password md5' "
                           ">> /etc/pam_ldap.conf")
    execute_cmd(multihost, f"echo 'host {multihost.master[0].ip}' "
                           f">> /etc/pam_ldap.conf")
    execute_cmd(multihost, "echo 'tls_cacertfile "
                           "/etc/openldap/certs/cacert.asc'"
                           " >> /etc/pam_ldap.conf")

    execute_cmd(multihost, 'systemctl restart nslcd')

    def restoresssdconf():
        """ Restore sssd.conf """
        execute_cmd(multihost, "rm -vf /etc/pam_ldap.conf")

    request.addfinalizer(restoresssdconf)


@pytest.mark.usefixtures('setupds',
                         'default_sssd',
                         'sssdproxyldap',
                         'install_nslcd',
                         'ldap_objects_sssd_client')
@pytest.mark.tier1_3
class TestProxyMisc(object):
    """
    This is test case class for proxy provider suite
    """
    def test_lookup_user_group_netgroup(self, multihost, backupsssdconf):
        """
        :title: avoid interlocking among threads that use
          `libsss_nss_idmap` API (or other sss_client libs)
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1978119
        :id: 836759ee-fc19-11ec-b57d-845cf3eff344
        :customerscenario: true
        :steps:
            1. Configure sssd with proxy
            2. Create multiple tread from single process
            3. Check that requests are not being handled serially
        :expectedresults:
            1. Should succeed
            2. Should succeed
            3. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'domains': ds_instance_name}
        tools.sssd_conf('sssd', sssd_params)
        domain_name = tools.get_domain_section_name()
        domain_params = {'debug_level': '9',
                         'id_provider': 'proxy',
                         'proxy_lib_name': 'ldap',
                         'proxy_pam_target': 'sssdproxyldap',
                         'case_sensitive': 'true',
                         'use_fully_qualified_names': 'False' }
        tools.sssd_conf('domain/' + domain_name, domain_params)
        services = {'debug_level': '9'}
        tools.sssd_conf('nss', services)
        tools.clear_sssd_cache()
        client = multihost.client[0]
        client.run_command("yum install -y gcc")
        file_location = '/script/thread.c'
        client.transport.put_file(os.path.dirname(os.path.abspath(__file__))
                                  + file_location,
                                  '/tmp/thread.c')
        execute_cmd(multihost, "gcc /tmp/thread.c -o /tmp/thread")
        execute_cmd(multihost, ">/var/log/sssd/sssd_nss.log")
        execute_cmd(multihost, "cd /tmp/; ./thread")
        time.sleep(2)
        cmd = execute_cmd(multihost, "grep 'Looking up' "
                                     "/var/log/sssd/sssd_nss.log").stdout_text
        crs = [int(i.split('#')[1]) for i in re.findall('CR #[0-9]+', cmd)]
        assert not check_sorted(crs)
