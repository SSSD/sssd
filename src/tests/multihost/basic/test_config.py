""" SSSD Configuration-related Test Cases """
import configparser as ConfigParser
import pytest
from utils_config import set_param, remove_section


class TestSSSDConfig(object):
    """
    Test cases around SSSD config management
    """
    def _assert_config_value(self, multihost, section, key, value):
        # This would really be much, much nicer to implement using python-ldb
        # but at the moment, the multihost tests rely on a virtual environment
        # where everything is pip-installed..and python-ldb is not present in
        # pip
        confdb_dn = 'cn=%s,cn=config' % (section)
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/config.ldb -b %s' % (confdb_dn)
        cmd = multihost.master[0].run_command(ldb_cmd)
        check_str = '%s: %s' % (key, value)
        assert check_str in cmd.stdout_text

    def test_sssd_genconf_sssd_running(self, multihost):
        """
        Test that sssd --genconf is able to re-generate the configuration
        even while SSSD is running.
        """
        multihost.master[0].service_sssd('restart')

        self._assert_config_value(multihost, 'pam', 'debug_level', '9')

        set_param(multihost, 'pam', 'debug_level', '1')
        multihost.master[0].run_command('/usr/sbin/sssd --genconf')
        self._assert_config_value(multihost, 'pam', 'debug_level', '1')

        set_param(multihost, 'pam', 'debug_level', '9')

    def test_sssd_genconf_section_only(self, multihost):
        """
        Test that --genconf-section only refreshes those sections given
        on the command line
        """
        multihost.master[0].service_sssd('restart')

        self._assert_config_value(multihost, 'pam', 'debug_level', '9')
        self._assert_config_value(multihost, 'nss', 'debug_level', '9')

        set_param(multihost, 'pam', 'debug_level', '1')
        set_param(multihost, 'nss', 'debug_level', '1')
        multihost.master[0].run_command(
                '/usr/sbin/sssd --genconf-section=pam')

        # We only told genconf to touch the pam section..
        self._assert_config_value(multihost, 'pam', 'debug_level', '1')
        # ..so the NSS section shouldn't be updated at all
        self._assert_config_value(multihost, 'nss', 'debug_level', '9')

        set_param(multihost, 'nss', 'debug_level', '9')
        set_param(multihost, 'pam', 'debug_level', '9')

    def test_sssd_genconf_add_remove_section(self, multihost):
        """
        Test that --genconf-section can not only modify existing
        configuration sections, but also add a new section
        """
        # Establish a baseline
        multihost.master[0].service_sssd('restart')
        self._assert_config_value(multihost, 'pam', 'debug_level', '9')
        self._assert_config_value(multihost, 'nss', 'debug_level', '9')

        set_param(multihost, 'foo', 'bar', 'baz')

        multihost.master[0].run_command(
                '/usr/sbin/sssd --genconf-section=foo')

        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/config.ldb -b cn=foo,cn=config'
        cmd = multihost.master[0].run_command(ldb_cmd)
        assert 'bar: baz' in cmd.stdout_text

        remove_section(multihost, 'foo')
        multihost.master[0].run_command(
                '/usr/sbin/sssd --genconf-section=foo')

        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/config.ldb -b cn=foo,cn=config'
        cmd = multihost.master[0].run_command(ldb_cmd)
        assert 'foo' not in cmd.stdout_text
        # Also make sure the existing sections were intact
        self._assert_config_value(multihost, 'pam', 'debug_level', '9')
        self._assert_config_value(multihost, 'nss', 'debug_level', '9')

    def test_sssd_genconf_no_such_section(self, multihost):
        """
        Referencing a non-existant section must not fail, because
        we want to call this command from the systemd unit files
        and by default the sections don't have to be present
        """
        multihost.master[0].service_sssd('restart')
        multihost.master[0].run_command(
                '/usr/sbin/sssd --genconf-section=xyz')
