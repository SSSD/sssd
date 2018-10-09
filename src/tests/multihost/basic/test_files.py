"""
Files test provider cases
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
        """ The files provider does not handle root """
        exit_status, _ = get_sss_user(multihost, 'root')
        assert exit_status == 2

    def test_files_sanity(self, multihost):
        """ Test that the files provider can resolve a user """
        exit_status, _ = get_sss_user(multihost, 'lcl1')
        assert exit_status == 0

    def test_files_enumeration(self, multihost):
        """
        Since nss_files enumerates and libc would concatenate the results,
        the files provider of SSSD should not enumerate
        """
        cmd = multihost.master[0].run_command('getent passwd -s sss')
        assert len(cmd.stdout_text) == 0
