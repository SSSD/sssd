""" Tests related to Caching of ssh keys """

import pytest
import time
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.exceptions import SSHLoginException


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_ssh_schema', 'setup_sshd_authorized_keys',
                         'enable_ssh_responder')
@pytest.mark.ssh
class TestSSHkeys(object):
    """ Test ssh responder """

    @pytest.mark.tier1
    @pytest.mark.fips
    def test_0001_bz1137013(self, multihost, create_ssh_keys):
        """ @Title: ssh_authorizedkeys: OpenSSH LPK support 
        by default bz1137013 """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            pytest.fail("%s failed to login" % user)
        else:
            client.logout()
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = 'Adding sshPublicKey'
        find = re.compile(r'%s' % msg)
        assert find.search(log)
