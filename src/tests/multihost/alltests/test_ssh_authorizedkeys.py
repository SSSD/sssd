""" Tests related to Caching of ssh keys

:requirement: ssh_authorizedkeys
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import pytest
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.ssh2_python import check_login_client


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups',
                         'enable_ssh_schema', 'setup_sshd_authorized_keys',
                         'enable_ssh_responder')
@pytest.mark.ssh
class TestSSHkeys(object):
    """ Test ssh responder """

    @pytest.mark.tier1
    @pytest.mark.fips
    def test_0001_bz1137013(self, multihost, create_ssh_keys):
        """
        :title: ssh_authorizedkeys: OpenSSH LPK support
         by default bz1137013
        :id: 82c962b4-e740-4774-a3d1-b6e93a00bf26
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        user = 'foo1@%s' % domain_name
        check_login_client(multihost, user, 'Secret123')
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = 'Adding sshPublicKey'
        find = re.compile(r'%s' % msg)
        assert find.search(log)
