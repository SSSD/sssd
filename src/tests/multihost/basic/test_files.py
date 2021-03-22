"""Files test provider cases

:requirement: IDM-SSSD-REQ :: SSSD is default for local resolution
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import pytest
from sssd.testlib.common.utils import SSHClient


def get_sss_entry(multihost, db, ent_name):
    cmd = multihost.master[0].run_command(
                                    'getent %s -s sss %s' % (db, ent_name),
                                    raiseonerr=False)
    return cmd.returncode, cmd.stdout_text


def get_sss_user(multihost, username):
    return get_sss_entry(multihost, 'passwd', username)


@pytest.mark.usefixtures('enable_files_domain', 'files_domain_users_class')
class TestImplicitFilesProvider(object):
    """
    Test the files provider. This test runs the implicit files provider
    together with another domain to stick close to what users use in Fedora
    """
    def test_files_does_not_handle_root(self, multihost):
        """
        :title: files: files provider does not handle root
        :id: 5aa5165d-379f-4fc6-b4ed-b32b66406d4f
        """
        exit_status, _ = get_sss_user(multihost, 'root')
        assert exit_status == 2

    def test_files_sanity(self, multihost):
        """
        :title: files: Test that the files provider can resolve a user
        :id: 242cd094-b04d-4857-981a-8624573dde84
        """
        exit_status, _ = get_sss_user(multihost, 'lcl1')
        assert exit_status == 0

    def test_files_enumeration(self, multihost):
        """
        :title: files: Verify files provider do not enumerate
        :id: e6d922bf-3af2-4cea-8570-6dd9233da624
        :description: Since nss_files enumerates and libc would
         concatenate the results, the files provider of SSSD should
         not enumerate
        """
        cmd = multihost.master[0].run_command('getent passwd -s sss')
        assert len(cmd.stdout_text) == 0

    def test_no_homedir_no_slash(self, multihost):
        """
        :title: files: Test that sssd returns an empty value with no homedir
        :id: 58010941-f1d6-453f-86f7-ade11dc81bb5
        """
        exit_status, output = get_sss_user(multihost, 'no_home_user')
        assert exit_status == 0
        assert ":/:" not in output
