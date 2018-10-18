"""sssctl config-check Test Cases"""

import pytest
import re


class TestSssctlConfigCheck(object):
    def test_verify_typo_option_name(self, multihost):
        """ Verify typos in option name (not value) of configuration file """
        cfgget = '/etc/sssd/sssd.conf'
        cfgput = '/tmp/sssd.conf.backup'
        multihost.master[0].run_command(['/bin/cp',
                                         '-a', cfgget, cfgput],
                                        raiseonerr=False)
        sssdcfg = multihost.master[0].get_file_contents(cfgget)

        # replacing ldap_search_base option with search_base
        sssdcfg = re.sub(b"ldap_search_base",
                         b"search_base", sssdcfg)
        multihost.master[0].put_file_contents(cfgget, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.master[0].run_command(sssctl_cmd, raiseonerr=False)
        if cmd.returncode == 1:
            log = re.compile(r'Attribute\s.search.base.\sis\snot\sallowed.*')
            if log.search(cmd.stdout_text):
                assert True
            else:
                assert False
        else:
            assert False
        multihost.master[0].run_command(['/bin/cp', '-a', cfgput, cfgget],
                                        raiseonerr=False)

    def test_verify_typo_domain_name(self, multihost):
        """ Verify typos in domain name of configuration file """
        cfgget = '/etc/sssd/sssd.conf'
        cfgput = '/tmp/sssd.conf.backup'
        multihost.master[0].run_command(['/bin/cp',
                                         '-a', cfgget, cfgput],
                                        raiseonerr=False)
        sssdcfg = multihost.master[0].get_file_contents(cfgget)

        # replacing the domain name with typo
        sssdcfg = re.sub(b"domain/EXAMPLE.TEST",
                         b"domain/", sssdcfg)
        multihost.master[0].put_file_contents(cfgget, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.master[0].run_command(sssctl_cmd, raiseonerr=False)
        if cmd.returncode == 1:
            log = re.compile(r'Section\s\[domain\/\]\sis\snot\sallowed.*')
            if log.search(cmd.stdout_text):
                assert True
            else:
                assert False
        else:
            assert False
        multihost.master[0].run_command(['/bin/cp', '-a', cfgput, cfgget],
                                        raiseonerr=False)

    def test_misplaced_option(self, multihost):
        """ Verify misplace options in default configuration file """
        cfgget = '/etc/sssd/sssd.conf'
        cfgput = '/tmp/sssd.conf.backup'
        sssdcfg = multihost.master[0].get_file_contents(cfgget)

        # adding services option under domain section
        sssdcfg = re.sub(b"services = nss, pam, sudo, ifp",
                         b"#services = nss, pam, sudo, ifp", sssdcfg)
        sssdcfg = re.sub(b".domain/EXAMPLE.TEST.",
                         b"[domain/EXAMPLE.TEST]" +
                         b"\nservices = nss, pam, sudo, ifp", sssdcfg)
        multihost.master[0].put_file_contents(cfgget, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.master[0].run_command(sssctl_cmd,
                                              raiseonerr=False)
        if cmd.returncode == 1:
            log = re.compile(
                r'.Attribute\s.services.\sis\snot\sallowed\sin\ssection\s.*')
            if log.search(cmd.stdout_text):
                assert True
            else:
                assert False
        else:
            assert False
        multihost.master[0].run_command(['/bin/cp', '-a', cfgput, cfgget],
                                        raiseonerr=False)
