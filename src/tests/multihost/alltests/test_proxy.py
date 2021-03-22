""" test cases for sssd proxy

:requirement: IDM-SSSD-REQ : Proxy Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""

import time
import re
import pytest
import ldap
from constants import ds_instance_name, ds_suffix, krb_realm
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import sssdTools, LdapOperations
from sssd.testlib.common.exceptions import SSHLoginException
from sssd.testlib.common.libkrb5 import krb5srv
from constants import ds_instance_name


@pytest.mark.usefixtures('setup_sssd_krb', 'create_host_keytab',
                         'create_posix_usersgroups')
@pytest.mark.proxy
class TestsssdProxy(object):
    """ Testing sssd-proxy  """
    @pytest.mark.tier1
    def test_0001_1724717(self, multihost):
        """
        :title: proxy: sssd-proxy crashes resolving groups with no members
        :id: 28b64673-8f1b-46c1-b0dd-6eaba9f80b2c
        """
        # backup sssd.conf
        backup = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.backup'
        restore = 'cp -f /etc/sssd/sssd.conf.backup /etc/sssd/sssd.conf'
        multihost.client[0].run_command(backup)
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        user = 'foo1@%s' % domain_name
        # user add
        add_user = 'useradd foo1'
        # delete user
        del_user = 'userdel -r foo1'
        multihost.client[0].run_command(add_user)
        domain_params = {'id_provider': 'proxy',
                         'proxy_lib_name': 'files',
                         'ignore_group_members': 'False',
                         'cache_credentials': 'True',
                         'krb5_validate': 'True'}
        tools.sssd_conf('domain/%s' % domain_name, domain_params)
        del_domain_params = {'ldap_uri': 'ldaps:%s' %
                             (multihost.master[0].run_command),
                             'ldap_tls_cacert':
                             '/etc/openldap/cacerts/cacert.pem',
                             'ldap_search_base': ds_suffix,
                             'use_fully_qualified_names': 'True'}
        tools.sssd_conf('domain/%s' % domain_name,
                        del_domain_params, action='delete')
        cat = 'cat /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cat)
        multihost.client[0].service_sssd('start')
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(del_user)
            multihost.client[0].run_command(restore)
            pytest.fail("%s failed to login" % user)
        else:
            id_cmd = 'id %s' % user
            (_, ret) = client.command(id_cmd)
            assert ret == '0'
            client.logout()
        # On fedora after user logs out it takes time
        # for systemd process running as user to get stopped, hence
        # adding sleep
        time.sleep(20)
        multihost.client[0].run_command(del_user)
        multihost.client[0].run_command(restore)
