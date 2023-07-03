"""sssctl config-check Test Cases

:requirement: IDM-SSSD-REQ: Status utility
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

import re

import pytest


class TestSssctlConfigCheck(object):
    @pytest.mark.converted('test_sssctl_config_check.py', 'test_sssctl_config_check__typo_option_name')
    def test_verify_typo_option_name(self, multihost):
        """
        :title: sssctl: Verify typos in option name (not value)
         of configuration file
        :id: 4089f5d6-cdeb-4bcb-9028-cabd97d43045
        """
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

    @pytest.mark.converted('test_sssctl_config_check.py', 'test_sssctl_config_check__typo_domain_name')
    def test_verify_typo_domain_name(self, multihost):
        """
        :title: sssctl: Verify typos in domain name of configuration file
        :id: a5d3a3a5-f832-4fc6-a628-9165dab69dd2
        """
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

    @pytest.mark.converted('test_sssctl_config_check.py', 'test_sssctl_config_check__misplaced_option')
    def test_misplaced_option(self, multihost):
        """
        :title: sssctl: Verify misplace options in default configuration file
        :id: ed814158-dea5-4f62-8500-fe62087332f9
        """
        cfgget = '/etc/sssd/sssd.conf'
        cfgput = '/tmp/sssd.conf.backup'
        sssdcfg = multihost.master[0].get_file_contents(cfgget)

        # adding services option under domain section
        sssdcfg = re.sub(b"services = nss, pam, sudo, ifp",
                         b"#services = nss, pam, sudo, ifp", sssdcfg)
        sssdcfg = re.sub(b".domain/EXAMPLE.TEST.",
                         b"[domain/EXAMPLE.TEST]"
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
