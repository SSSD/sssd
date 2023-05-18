""" Automation of configuration validation

:requirement: IDM-SSSD-REQ: Configuration validation
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""

from __future__ import print_function
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF
from constants import ds_instance_name
from random import choice
from string import ascii_uppercase


@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.configvalidation
class TestConfigValidation(object):
    """ SSSD Config Validation """
    @pytest.mark.tier1
    def test_0001_searchbase(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos in option
         name (not value) of configuration file
        :id: e15fcc7f-1a5d-49f2-b995-3963d0e8d1e5
        """
        section = "domain/%s" % ds_instance_name
        domain_params = {'ldap_search_base': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf(section, domain_params, action='delete')
        incorrect_domain_params = {'search_base': ''}
        tools.sssd_conf(section, incorrect_domain_params)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Attribute\s.search.base.\sis\snot\sallowed.*')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0002_domainname(self, multihost, backupsssdconf):
        """
        :title:  IDM-SSSD-TC: Configuration validation: Verify typos in domain
         name of configuration file
        :id: 9188aa83-012d-4358-8387-e09cec1aa25d
        """
        sssdcfg = multihost.client[0].get_file_contents('/etc/sssd/sssd.conf')
        sssdcfg = re.sub(b'domain/%s' % ds_instance_name.encode('utf-8'),
                         b'domain/', sssdcfg)
        multihost.client[0].put_file_contents('/etc/sssd/sssd.conf', sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[domain\/\]\sis\snot\sallowed.*')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0003_snippetfile(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos in option
         name (not value) of snippet files
        :id: 7e3f57f6-aa7c-4c30-841b-d81ba98d2e29
        """
        section = "domain/%s" % ds_instance_name
        content = "[%s]\nfully_quailified_name = False" % section
        snippet_file = "/etc/sssd/conf.d/01_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, content)
        chmod_cmd = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(chmod_cmd, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'Attribute\s.fully.quailified.name.\sis\snot\sall.*')
        assert log.search(cmd.stdout_text)
        rm_snippet_file = 'rm -rf %s' % snippet_file
        multihost.client[0].run_command(rm_snippet_file, raiseonerr=False)

    @pytest.mark.tier1
    def test_0004_snippetfile(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos in domain
         name of snippet files
        :id: 0f3a8809-594f-41d0-a52a-2d7365e23b09
        """
        file_content = "[dmain/%s]\nfully_quailified_name = False" \
                       % ds_instance_name
        snippet_file = "/etc/sssd/conf.d/02_snippet.conf"
        multihost.client[0].put_file_contents(snippet_file, file_content)
        chmod_cmd = 'chmod 600 %s' % snippet_file
        multihost.client[0].run_command(chmod_cmd, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'Section\s\[dmain\/example1\]\sis\snot\sallowed.*')
        assert log.search(cmd.stdout_text)
        rm_snippet_file = 'rm -rf %s' % snippet_file
        multihost.client[0].run_command(rm_snippet_file, raiseonerr=False)

    @pytest.mark.tier1
    def test_0005_misplaced(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify misplaced
         options
        :id: ba3278f1-d80c-429f-ac00-f96a9f0f0f0f
        """
        section = "domain/%s" % ds_instance_name
        sssd_params = {'services': ''}
        tools = sssdTools(multihost.client[0])
        tools.sssd_conf('sssd', sssd_params, action='delete')
        domain_params = {'services': 'nss, pam'}
        tools.sssd_conf(section, domain_params)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r".Attribute\s.services.\sis\snot\sallowed\sin\sse.*")
        assert log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0006_sameerrors(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify same error when
         sssd is started
        :id: ab843b71-6f23-45f5-899e-6c66aabee936
        """
        for status in ['start', 'stop']:
            multihost.client[0].service_sssd(status)
            section = "domain/%s" % ds_instance_name
            domain_params = {'ldap_search_base': ''}
            tools = sssdTools(multihost.client[0])
            tools.sssd_conf(section, domain_params, action='delete')
            incorrect_domain_params = {'search_base': ''}
            tools.sssd_conf(section, incorrect_domain_params)
            sssctl_cmd = 'sssctl config-check'
            cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
            assert cmd.returncode == 1
            log_1 = re.compile(r'Attribute\s.search.base.\sis\snot\sallowed.*')
            assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0007_equalsign(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: No equal sign between
         option name and value
        :id: 17fddf2e-07fe-4b1a-b6e2-7028b12c7ef8
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        sssdcfg = re.sub(b'id_provider = ldap',
                         b'id_provider ldap ', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'.Equal\ssign\sis\smissing.')
        print(log.search(cmd.stderr_text))

    @pytest.mark.tier1
    def test_0008_specialcharacter(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Option name contains
         special character
        :id: c4d9c29b-d3a6-4a44-ba88-317d46930916
        """
        section = "domain/%s" % ds_instance_name
        tools = sssdTools(multihost.client[0])
        incorrect_domain_params = {'id_@provider': 'ldap'}
        tools.sssd_conf(section, incorrect_domain_params)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Attribute\s.id.\@provider.\sis\snot\sallowed\sin'
                           r'\ssection')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0009_sectionname(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos in
         section name
        :id: 8c03a1a1-2833-4216-86b3-1c97bf5276ca
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b'[dmain/%s]' % instance_name, sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[dmain\/%s\]\sis\snot\sallowed.*'
                           % ds_instance_name)
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0010_splcharacters(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos
         (special character) in section name
        :id: de98c544-2f4a-4540-a180-34352b063db2
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b'[d$main/%s]' % instance_name, sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[d\$main\/%s\]\sis\snot\sallowed.*'
                           % ds_instance_name)
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0011_splcharacters(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos (special
         character) in domain name
        :id: b2a70e9a-2bab-489a-a93d-7508aceb5cd8
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b'[domain/example@1]', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[domain\/example\@1\]\sis\snot\s'
                           r'allowed')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0012_forwardslash(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Forward slash is not
         present between domain name and section name
        :id: d7a73c48-3e92-46aa-864d-40ddeeebdcfb
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b'[domainexample@1]', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[domainexample\@1\]\sis\snot\sallowed')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0013_sectiontypos(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation:
         Typo in sssd section name
        :id: 1d049368-3088-4fd9-9c12-9c379cf7639b
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        sssdcfg = re.sub(b'.sssd.',
                         b'[ssd]', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'Section\s\[ssd]\sis\snot\sallowed')
        assert log_1.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0014_pamsection(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Typos in pam section
         name
        :id: 1d9ac54d-278c-441f-8ad8-5e127e137039
        """
        tools = sssdTools(multihost.client[0])
        pam_params = {'debug_level': '9'}
        tools.sssd_conf('[pa]', pam_params)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'.\sSection\s\[\[pa\]\]\sis\snot\sallowed.*')
        assert log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0015_nsssection(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Typos in nss section
         name
        :id: 0506e544-5d96-43c9-bc61-407c991a565f
        """
        tools = sssdTools(multihost.client[0])
        pam_params = {'debug_level': '9'}
        tools.sssd_conf('[ns]', pam_params)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'.\sSection\s\[\[ns\]\]\sis\snot\sallowed.*')
        assert log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0016_verifypermission(self, multihost):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify the permission
         of default configuration file
        :id: e395db40-f61f-4a74-992c-a52f58c58d25
        """
        cfgget = '/etc/sssd/sssd.conf'
        chmod = 'chmod 0777 %s' % cfgget
        multihost.client[0].run_command(chmod, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'File\sownership\sand\spermissions\scheck\sfailed.*')
        assert log.search(cmd.stdout_text)
        restore_mod = 'chmod 0600 %s' % cfgget
        multihost.client[0].run_command(restore_mod, raiseonerr=False)

    @pytest.mark.tier1
    def test_0017_verifyownership(self, multihost):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify the ownership
         of default configuration file
        :id: d2737dfc-ece2-42ad-9af4-410c58d91766
        """
        cfgget = '/etc/sssd/sssd.conf'
        user = (''.join(choice(ascii_uppercase) for _ in range(10)))
        group = (''.join(choice(ascii_uppercase) for _ in range(10)))
        multihost.client[0].run_command(['useradd', user], raiseonerr=False)
        multihost.client[0].run_command(['groupadd', group], raiseonerr=False)
        user_group = '{}:{}'.format(user, group)
        chown = 'chown %s %s' % (user_group, cfgget)
        multihost.client[0].run_command(chown, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'File\sownership\sand\spermissions\scheck\sfailed.*')
        assert log.search(cmd.stdout_text)
        userdel = 'userdel %s' % user
        grpdel = 'groupdel %s' % group
        multihost.client[0].run_command(userdel, raiseonerr=False)
        multihost.client[0].run_command(grpdel, raiseonerr=False)
        restore_chown = 'chown root:root %s' % cfgget
        multihost.client[0].run_command(restore_chown, raiseonerr=False)

    @pytest.mark.tier1
    def test_0018_closingbrackets(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify the closing
         bracket for sssd section
        :id: ab53035f-9662-447e-8645-abb0d520de87
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        sssdcfg = re.sub(b'.sssd.',
                         b'[sssd', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'No\sclosing\sbracket.*')
        assert log_1.search(cmd.stderr_text)

    @pytest.mark.tier1
    def test_0019_openingbracket(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Check starting square
         bracket in domain section
        :id: 665a2792-f1ca-4e6a-b0fd-378b10328537
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b'domain/%s]' % instance_name, sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log_1 = re.compile(r'.Equal\ssign\sis\smissing.*')
        assert log_1.search(cmd.stderr_text)

    @pytest.mark.tier1
    def test_0020_fatalerror(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: No sssctl commands can
         be run if the configuration has fatal errors
        :id: b483e14b-b263-4e4b-a6f7-539badc76aa4
        """
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        instance_name = ds_instance_name.encode('utf-8')
        sssdcfg = re.sub(b'.domain/%s.' % instance_name,
                         b' ', sssdcfg)
        sssdcfg1 = re.sub(b'id_provider',
                          b'sd_provider', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg1)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'ldap_search_base.\sis\snot allowed\sin\ssection\s'
                         r'.sssd.*')
        assert log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0021_twodomain(self, multihost, multidomain_sssd):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typo in option
         name with multiple domains in default configuration file
        :id: c240e28a-996f-482b-bac7-9a68c737192c
        """
        multidomain_sssd(domains='ldap_ldap')
        sssdcfg = multihost.client[0].get_file_contents(SSSD_DEFAULT_CONF)
        sssdcfg = re.sub(b'ldap_uri',
                         b'ldap_ri', sssdcfg)
        multihost.client[0].put_file_contents(SSSD_DEFAULT_CONF, sssdcfg)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r'Attribute..ldap_ri..is.not.allowed.in.section'
                         r'..doma.*')
        assert log.search(cmd.stdout_text)
        restore = 'cp -f /etc/sssd/sssd.conf.orig %s' % SSSD_DEFAULT_CONF
        multihost.client[0].run_command(restore)

    @pytest.mark.tier1
    def test_0022_fatalerror(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: No sssctl commands can
         be run if the configuration has fatal errors (2)
        :id: 9c7d169e-0999-4544-8df6-685f0e33023a
        """
        rm_cmd = 'rm -f %s' % SSSD_DEFAULT_CONF
        multihost.client[0].run_command(rm_cmd, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        log = re.compile(r'sssd.conf\sdoes\snot\sexist')
        assert cmd.returncode == 1 and log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0023_checkldaphostobjectdomain(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Check
         ldap_host_object_class option in domain section
        :id: d072b8e7-4981-431f-949d-34d8c12a2d6c
        """
        section = "domain/%s" % ds_instance_name
        tools = sssdTools(multihost.client[0])
        domain_params = {'ldap_host_object_class': 'ipService'}
        tools.sssd_conf(section, domain_params)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier1
    def test_0024_checkldaphostobjectsssd(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Check
         ldap_host_object_class option in sssd section
        :id: d25f61ca-f75f-4a66-a43d-495bc0325fef
        """
        section = "sssd"
        tools = sssdTools(multihost.client[0])
        sssd_params = {'ldap_host_object_class': 'ipService'}
        tools.sssd_conf(section, sssd_params)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 1
        log = re.compile(r".Attribute\s.ldap_host_object_class.\sis\snot\s"
                         r"allowed\sin\ssection\s.sssd.*")
        assert log.search(cmd.stdout_text)

    @pytest.mark.tier1
    def test_0025_check2FA(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Check false
         warnings are logged in sssd.log file after enabling 2FA prompting
         settings in sssd.conf
        :id: 3a1060db-0120-4270-b669-aae8923613a0
        :customerscenario: True
        """
        # Automation of BZ1856861
        tools = sssdTools(multihost.client[0])
        section1 = "prompting/2fa/sshd"
        domain_params1 = {'first_prompt': 'Enter OTP Token Value:',
                          'single_prompt': 'single_prompt'}
        section2 = "prompting/2fa"
        domain_params2 = {'single_prompt': 'True',
                          'first_prompt': 'Prompt1',
                          'second_prompt': 'Prompt2'}
        tools.sssd_conf(section1, domain_params1)
        tools.sssd_conf(section2, domain_params2)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier1
    def test_0026_checkchilddomain(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: sssctl config-check
         reports errors when auto_private_groups is disabled or enabled in
         child domains
        :id: 40722365-9c34-4230-9a7a-9d958acf078d
        :customerscenario: True
        """
        # Automation of BZ1791892
        tools = sssdTools(multihost.client[0])
        section1 = "domain/td5f4f77.com/two5f4f77.td5f4f77.com"
        section2 = "domain/td5f4f77.com/one5f4f77.td5f4f77.com"
        param = {'auto_private_groups': 'True'}
        tools.sssd_conf(section1, param)
        tools.sssd_conf(section2, param)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = 'sssctl config-check'
        cmd = multihost.client[0].run_command(sssctl_cmd, raiseonerr=False)
        assert cmd.returncode == 0

    @pytest.mark.tier1
    def test_0027_bz1723273(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration merging: sssctl config-check
         complains about non-existing snippet dirctory
        :id: 8ed183c4-5102-492a-ada1-a6876978be1f
        :customerscenario: True
        """
        cp_cmd = "mkdir /tmp/test; cp /etc/sssd/sssd.conf /tmp/test/"
        multihost.client[0].run_command(cp_cmd, raiseonerr=False)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = "sssctl config-check -c /tmp/test/sssd.conf"
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        rm_dir = 'rm -rf /tmp/test'
        multihost.client[0].run_command(rm_dir, raiseonerr=False)
        assert 'Directory /tmp/test/conf.d does not exist' in result and \
               sssctl_check.returncode == 1

    @pytest.mark.tier1
    def test_0028_bz1723273(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration merging: sssctl config-check
         gives error message when copied conf file does not have proper
         ownership and permission
        :id: 6453d102-167c-44a2-9332-80379bcd6f46
        """
        cp_cmd = "mkdir /tmp/test; cp /etc/sssd/sssd.conf /tmp/test/"
        chmod_cmd = "chmod 777 /tmp/test/sssd.conf"
        for cmd in [cp_cmd, chmod_cmd]:
            multihost.client[0].run_command(cmd, raiseonerr=False)
        multihost.client[0].service_sssd('restart')
        sssctl_cmd = "sssctl config-check -c /tmp/test/sssd.conf"
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        rm_dir = 'rm -rf /tmp/test'
        multihost.client[0].run_command(rm_dir, raiseonerr=False)
        assert 'File ownership and permissions check failed. Expected ' \
               'root:root and 0600' in result and \
               sssctl_check.returncode == 1

    @pytest.mark.tier1
    def test_0029_bz1723273(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Verify typos in option
         name of copied configuration file
        :id: bf6663f3-eed1-4a0b-97d5-f2e68eec0dbf
        """
        tools = sssdTools(multihost.client[0])
        section = "domain/%s" % ds_instance_name
        domain_params = {'ldap_search_base': ''}
        tools.sssd_conf(section, domain_params, action='delete')
        incorrect_domain_params = {'search_base': ''}
        tools.sssd_conf(section, incorrect_domain_params)
        cp_cmd = "mkdir -p /tmp/test/conf.d; cp /etc/sssd/sssd.conf " \
                 "/tmp/test"
        multihost.client[0].run_command(cp_cmd, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check -c /tmp/test/sssd.conf'
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        rm_dir = 'rm -rf /tmp/test'
        multihost.client[0].run_command(rm_dir, raiseonerr=False)
        assert "Attribute 'search_base' is not allowed in section " \
               "'domain/example1'. Check for typos." in result \
               and sssctl_check.returncode == 1

    @pytest.mark.tier1
    def test_0030_bz1723273(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: Does not complain
         about snippet directory after adding with proper permissions
        :id: 7a1946ca-f32a-4749-bf49-dbc643c120a5
        """
        tools = sssdTools(multihost.client[0])
        section = "domain/%s" % ds_instance_name
        domain_params = {'ldap_search_base': ''}
        tools.sssd_conf(section, domain_params, action='delete')
        incorrect_domain_params = {'search_base': ''}
        tools.sssd_conf(section, incorrect_domain_params)
        cp_cmd = "mkdir -p /tmp/test/conf.d; cp /etc/sssd/sssd.conf " \
                 "/tmp/test; chmod 700 /tmp/test/conf.d"
        multihost.client[0].run_command(cp_cmd, raiseonerr=False)
        sssctl_cmd = 'sssctl config-check -c /tmp/test/sssd.conf'
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        rm_dir = 'rm -rf /tmp/test'
        multihost.client[0].run_command(rm_dir, raiseonerr=False)
        assert "Directory /tmp/test/conf.d does not exist" not in result \
               and sssctl_check.returncode == 1

    @pytest.mark.tier1
    def test_0031_bz1723273(self, multihost, backupsssdconf):
        """
        :title: IDM-SSSD-TC: Configuration validation: complains about non
         existing snippet directory
        :id: 3d30164f-b80b-4594-883d-1783d9337031
        """
        sssctl_cmd = 'sssctl config-check -s /tmp/does/not/exists'
        sssctl_check = multihost.client[0].run_command(sssctl_cmd,
                                                       raiseonerr=False)
        result = sssctl_check.stdout_text.strip()
        assert "Directory /tmp/does/not/exists does not exist" in result \
               and sssctl_check.returncode == 1
