""" Automation of configuration merging"""
from __future__ import print_function
import re
from random import choice
from string import ascii_uppercase
from constants import ds_instance_name
from sssd.testlib.common.utils import sssdTools
import pytest
import time


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.configmerge
class TestConfigMerge(object):
    """
    This is test case class for ldap configuration merging suite
    """
    @pytest.mark.tier1
    def test_0001_verifypermission(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify the permission of
        snippet files
       """
        multihost.client[0].service_sssd('stop')
        section = "domain/%s" % ds_instance_name
        content = "[%s]\nuse_fully_quailified_name = False" % section
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, content)
        returncode = multihost.client[0].service_sssd('start')
        if returncode == 0:
            config_check = 'sssctl config-check'
            cmd = multihost.client[0].run_command(config_check,
                                                  raiseonerr=False)
            log_1 = re.compile(r'.*did\snot\spass\saccess\scheck.*')
            if log_1.search(cmd.stdout_text):
                user = 'foo1@%s' % ds_instance_name
                cmd = 'getent passwd %s' % user
                lookup = multihost.client[0].run_command(cmd, raiseonerr=False)
                assert lookup.returncode == 0
                user = 'foo1'
                cmd = 'getent passwd %s' % user
                lookup = multihost.client[0].run_command(cmd, raiseonerr=False)
                assert lookup.returncode == 2
        cmd = 'rm -f %s' % snippet_file
        multihost.client[0].run_command(cmd, raiseonerr=False)

    @pytest.mark.tier1
    def test_0002_hiddenfiles(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: SSSD reads all *.conf
        files, that are not starting with a . (hidden files)
        """
        multihost.client[0].service_sssd('stop')
        dom_section = "domain/%s" % ds_instance_name
        file_content = "[%s]\nuse_fully_quailified_name = False" % dom_section
        snippet_file = "/etc/sssd/conf.d/._01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        start = multihost.client[0].service_sssd('start')
        sssctl_cmd = 'sssctl config-check'
        if start == 0:
            cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
            assert cmd.returncode == 0
        remove_snippet = 'rm -f /etc/sssd/conf.d/._01_snippet.conf'
        multihost.client[0].run_command(remove_snippet, raiseonerr=False)

    @pytest.mark.tier1
    def test_0003_lastreadparameter(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: SSSD will use the last
        read parameter if the same option appears multiple times.
        """
        multihost.client[0].service_sssd('stop')
        dom_section = "domain/%s" % ds_instance_name
        for idx in ['True', 'False']:
            content = "[%s]\nuse_fully_qualified_names = %s" % (dom_section,
                                                                idx)
            snippet_file = "/etc/sssd/conf.d/%s_snippet.conf" % idx
            multihost.client[0].put_file_contents(snippet_file, content)
            chmod = 'chmod 600 %s' % snippet_file
            multihost.client[0].run_command(chmod)
        start = multihost.client[0].service_sssd('start')
        cmd = multihost.client[0].run_command(['sssctl', 'config-check'])
        if cmd.returncode == 0 and start == 0:
            for user in ['foo1@%s' % ds_instance_name, 'foo1']:
                getent = 'getent passwd %s' % user
                cmd = multihost.client[0].run_command(getent, raiseonerr=False)
                if '@' not in getent:
                    assert cmd.returncode != 0
                else:
                    assert cmd.returncode == 0
        for str1 in ['True', 'False']:
            cmd = 'rm -f /etc/sssd/conf.d/%s_snippet.conf' % str1
            multihost.client[0].run_command(cmd, raiseonerr=False)

    @pytest.mark.tier1
    def test_0004_formatsnippetfile(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify the format of
        snippet files
        """
        multihost.client[0].service_sssd('stop')
        dom_section = "domain/%s" % ds_instance_name
        file_content = "[%s]\nuse_fully_qualified_names = False" % dom_section
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf.disable"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        cmd_chmod = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(cmd_chmod, raiseonerr=False)
        start = multihost.client[0].service_sssd('start')
        if start == 0:
            config_check = 'sssctl config-check'
            cmd = multihost.client[0].run_command(config_check,
                                                  raiseonerr=False)
            assert cmd.returncode == 0
        else:
            assert False
        remove_snippet = 'rm -f %s' % snippet_file
        multihost.client[0].run_command(remove_snippet, raiseonerr=False)

    @pytest.mark.tier1
    def test_0005_ownershisnippetfile(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify the ownership of
        snippet files
        """
        multihost.client[0].service_sssd('stop')
        gen = sssdTools(multihost.client[0])
        gen.remove_sss_cache('/var/lib/sss/db')
        dom_section = "domain/%s" % ds_instance_name
        file_content = "[%s]\nuse_fully_qualified_names = False" % dom_section
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        user = (''.join(choice(ascii_uppercase) for _ in range(10)))
        group = (''.join(choice(ascii_uppercase) for _ in range(10)))
        user_group = '{}:{}'.format(user, group)
        multihost.client[0].put_file_contents(snippet_file, file_content)
        cmd_chmod = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(cmd_chmod, raiseonerr=False)
        useradd = 'useradd %s' % user
        groupadd = 'groupadd %s' % group
        cmd_chown = 'chown %s %s' % (user_group, snippet_file)
        multihost.client[0].run_command(useradd, raiseonerr=False)
        multihost.client[0].run_command(groupadd, raiseonerr=False)
        multihost.client[0].run_command(cmd_chown, raiseonerr=False)
        start = multihost.client[0].service_sssd('start')
        if start == 0:
            config_check = 'sssctl config-check'
            cmd = multihost.client[0].run_command(config_check,
                                                  raiseonerr=False)
            log_1 = re.compile(r'.*did\snot\spass\saccess\scheck.*')
            if log_1.search(cmd.stdout_text):
                user = 'foo1@%s' % ds_instance_name
                getent1 = 'getent passwd %s' % user
                lookup1 = multihost.client[0].run_command(getent1,
                                                          raiseonerr=False)
                assert lookup1.returncode == 0
                user = 'foo1'
                getent2 = 'getent passwd %s' % user
                lookup2 = multihost.client[0].run_command(getent2,
                                                          raiseonerr=False)
                assert lookup2.returncode == 2
        remove_snippet = 'rm -f %s' % snippet_file
        multihost.client[0].run_command(remove_snippet, raiseonerr=False)
        userdel = 'userdel %s' % user
        groupdel = 'groupdel %s' % group
        multihost.client[0].run_command(userdel, raiseonerr=False)
        multihost.client[0].run_command(groupdel, raiseonerr=False)

    @pytest.mark.tier1
    def test_0006_bz1372258(self, multihost):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Add path to files when
        pattern matching fails
        """
        multihost.client[0].service_sssd('stop')
        section = "domain/%s" % ds_instance_name
        for idx in ['True', 'False']:
            content = "[%s]\nuse_fully_qualified_names = %s" % (idx, section)
            snippet_file = "/etc/sssd/conf.d/%s_snippet.conf" % idx
            multihost.client[0].put_file_contents(snippet_file, content)
        sssctl_cmd = "sssctl config-check"
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        assert '/etc/sssd/conf.d/False_snippet.conf' in result
        for idx in ['True', 'False']:
            snippet_file = "/etc/sssd/conf.d/%s_snippet.conf" % idx
            cmd = "rm -f %s" % snippet_file
            multihost.client[0].run_command(cmd, raiseonerr=False)

    @pytest.mark.tier1
    def test_0007_bz1466503(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify scenario when no
        sssd.conf and the snippets should be working
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        # Delete the sssd.conf and add under /etc/sssd/conf.d/ directory
        cp_cmd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/conf.d/01.conf'
        rm_cmd = 'rm -f /etc/sssd/sssd.conf'
        chmod_cmd = 'chmod 600 /etc/sssd/conf.d/01.conf'
        for cmd in [cp_cmd, rm_cmd, chmod_cmd]:
            multihost.client[0].run_command(cmd, raiseonerr=False)
        tools.clear_sssd_cache()
        cmd_start = multihost.client[0].service_sssd('start')
        assert cmd_start == 0
        user = 'foo1@%s' % ds_instance_name
        getent1 = 'getent passwd %s' % user
        lookup1 = multihost.client[0].run_command(getent1,
                                                  raiseonerr=False)
        assert lookup1.returncode == 0
        cmd = "rm -f /etc/sssd/conf.d/01.conf"
        multihost.client[0].run_command(cmd, raiseonerr=False)

    @pytest.mark.tier1
    def test_0008_bz1466503(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify scenario when no
        sssd.conf and wrong snippets should not be working
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        rm_cmd = 'rm -f /etc/sssd/sssd.conf'
        file_content = "[sssd]\ndomains = foo\n\n[domain/foo]\n" \
                       "id_provider = foo"
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        cmd_chmod = 'chmod 600 %s' % snippet_file
        for cmd in [rm_cmd, cmd_chmod]:
            multihost.client[0].run_command(cmd, raiseonerr=False)
        tools.remove_sss_cache('/var/lib/sss/db')
        tools.remove_sss_cache('/var/log/sssd')
        start_sssd = 'systemctl start sssd'
        start = multihost.client[0].run_command(start_sssd, raiseonerr=False)
        assert start.returncode is not 0
        cmd_rm = 'rm -f /etc/sssd/conf.d/01_snippet.conf'
        multihost.client[0].run_command(cmd_rm, raiseonerr=False)

    @pytest.mark.tier1
    def test_0009_bz1666307(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Configuration merging: sssctl config-check
        giving the wrong error message when there are only snippet files
        and no sssd. conf
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        # Delete the sssd.conf and add under /etc/sssd/conf.d/ directory
        cp_cmd = 'cp -f /etc/sssd/sssd.conf /etc/sssd/conf.d/01.conf'
        rm_cmd = 'rm -f /etc/sssd/sssd.conf'
        chmod_cmd = 'chmod 600 /etc/sssd/conf.d/01.conf'
        for cmd in [cp_cmd, rm_cmd, chmod_cmd]:
            multihost.client[0].run_command(cmd, raiseonerr=False)
        tools.clear_sssd_cache()
        cmd_start = multihost.client[0].service_sssd('start')
        assert cmd_start == 0
        sssctl_cmd = "sssctl config-check"
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        assert '/etc/sssd/conf.d/01.conf' in result and \
               sssctl_check.returncode == 0
        user = 'foo1@%s' % ds_instance_name
        getent1 = 'getent passwd %s' % user
        lookup1 = multihost.client[0].run_command(getent1,
                                                  raiseonerr=False)
        assert lookup1.returncode == 0
        cmd = "rm -f /etc/sssd/conf.d/01.conf"
        multihost.client[0].run_command(cmd, raiseonerr=False)

    @pytest.mark.tier1
    def test_0010_bz1723273(self, multihost, backupsssdconf):
        """
        @Title: IDM-SSSD-TC: Configuration merging: Verify error in snippet
        file created under /etc/sssd/conf.d and /tmp/test/conf.d/
        """
        multihost.client[0].service_sssd('stop')
        cp_cmd = "mkdir -p /tmp/test/conf.d; cp /etc/sssd/sssd.conf /tmp/test/"
        chmod_cmd = "chmod 600 /tmp/test/sssd.conf"
        file_content = "[domain/example1]\n_fully_quailified_name = False\n"
        for snip in ['/etc/sssd/conf.d/', '/tmp/test/conf.d/']:
            for cmd in [cp_cmd, chmod_cmd]:
                multihost.client[0].run_command(cmd, raiseonerr=False)
            snippet_file = snip + '01_snippet.conf'
            multihost.client[0].put_file_contents(snippet_file, file_content)
            cmd_chmod = 'chmod 600 %s' % snippet_file
            multihost.client[0].run_command(cmd_chmod, raiseonerr=False)
            multihost.client[0].service_sssd('start')
            sssctl_cmd = "sssctl config-check -c /tmp/test/sssd.conf -s %s" \
                         % snip
            sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                           raiseonerr=False)
            result = sssctl_check.stdout_text.strip()
            cmd_rm = 'rm -f %s' % snippet_file
            multihost.client[0].run_command(cmd_rm, raiseonerr=False)
            rm_dir = 'rm -rf /tmp/test'
            multihost.client[0].run_command(rm_dir, raiseonerr=False)
            assert "Attribute '_fully_quailified_name' is not allowed" \
                   in result and sssctl_check.returncode == 1
