""" Automation of ldap_extra_attr suite"""
from __future__ import print_function
import re
import pytest
from sssd.testlib.common.utils import sssdTools
from constants import ds_instance_name
import time

@pytest.mark.usefixtures('setup_sssd', 'create_posix_usersgroups')
@pytest.mark.ldapextraattrs
class TestLdapExtraAttrs(object):
    """
    This is test case class for ldap ldap_extra_attr suite
    """
    @pytest.mark.tier1
    def test_0001_bz1362023(self, multihost):
        """
        :Title: IDM-SSSD-TC: ldap_extra_attrs: Verify the bz1362023, SSSD
        fails to start when ldap_user_extra_attrs contains mail
        """
        services = "nss, pam, ifp"
        ldap_extra_attr = {'ldap_user_extra_attrs':
                           'mail, firstname:givenname, lastname:sn'}
        # stop sssd service
        multihost.client[0].service_sssd('stop')
        tools = sssdTools(multihost.client[0])
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        sssd_param = {'services': services}
        tools.sssd_conf('sssd', sssd_param)
        domain_params = {'ldap_user_extra_attrs': ldap_extra_attr}
        tools.sssd_conf('domain/%s' % (ds_instance_name), domain_params)
        start = multihost.client[0].service_sssd('start')
        assert start == 0

    @pytest.mark.tier1
    def test_0002_givenmail(self, multihost):
        """
        :Title: IDM-SSSD-TC: ldap_extra_attrs: Verify the entry of option
        value given_email:mail in cache data
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        section = "sssd"
        sssd_params = {'services': 'nss, pam'}
        tools.sssd_conf(section, sssd_params, action='update')
        ldap_extra_attr = 'given_email:mail'
        domain_params = {'ldap_user_extra_attrs': ldap_extra_attr}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, domain_params, action='update')
        start = multihost.client[0].service_sssd('start')
        lkup = 'getent passwd foo1@%s' % ds_instance_name
        lkup_cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        assert start == 0 and lkup_cmd.returncode == 0
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb -b cn=users,' \
                  'cn=%s,cn=sysdb' % (ds_instance_name, ds_instance_name)
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        find = re.compile(r'given_email\:\sfoo1\@example\.test')
        result = find.search(cmd.stdout_text)
        assert result is not None

    @pytest.mark.tier1
    def test_0003_checkldb(self, multihost):
        """
        :Title: IDM-SSSD-TC: ldap_extra_attrs: Verify recently added
        attribute should be in cache db along with their value
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        sssd_section = "sssd"
        sssd_params = {'services': 'nss, pam'}
        tools.sssd_conf(sssd_section, sssd_params, action='update')
        ldap_extra_attr = 'ldap_user_extra_attrs = firstname:cn, ' \
                          'lastname:sn, description:gecos, ' \
                          'user`s_home_directoy:homeDirectory, user_id:uid'
        domain_params = {'ldap_user_extra_attrs': ldap_extra_attr}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, domain_params, action='update')
        start = multihost.client[0].service_sssd('start')
        lkup = 'getent passwd foo1@%s' % ds_instance_name
        lkup_cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        assert start == 0 and lkup_cmd.returncode == 0
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb -b cn=users,' \
                  'cn=%s,cn=sysdb' % (ds_instance_name, ds_instance_name)
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        checks = ['firstname: foo1', 'lastname: foo1',
                  'description: foo1 User',
                  'user`s_home_directoy: /home/foo1', 'user_id: foo1']
        for str1 in checks:
            find = re.compile(r'%s' % str1)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1
    def test_0004_negativecache(self, multihost):
        """
        :Title: IDM-SSSD-TC: ldap_extra_attrs: Check whether, not added
        parameter of user is displaying in cache or not
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        sssd_section = "sssd"
        sssd_params = {'services': 'nss, pam'}
        tools.sssd_conf(sssd_section, sssd_params, action='update')
        ldap_extra_attr = 'number:telephonenumber'
        domain_params = {'ldap_user_extra_attrs': ldap_extra_attr}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, domain_params, action='update')
        start = multihost.client[0].service_sssd('start')
        lkup = 'getent passwd foo1@%s' % ds_instance_name
        lkup_cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        assert start == 0 and lkup_cmd.returncode == 0
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb -b cn=users,' \
                  'cn=%s,cn=sysdb' % (ds_instance_name, ds_instance_name)
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        find = re.compile(r'number\:telephonenumber')
        result = find.search(cmd.stdout_text)
        assert result is None

    @pytest.mark.tier1
    def test_0005_ldapextraattrs(self, multihost):
        """
        :Title: IDM-SSSD-TC: ldap_extra_attrs: Check sssd should start with
        options ldap_user_email and ldap_user_extra_attrs and check entries in
        cache
        """
        tools = sssdTools(multihost.client[0])
        multihost.client[0].service_sssd('stop')
        # remove sssd cache
        tools.remove_sss_cache('/var/lib/sss/db')
        sssd_section = "sssd"
        sssd_params = {'services': 'nss, pam, ifp'}
        tools.sssd_conf(sssd_section, sssd_params, action='update')
        ldap_extra_attr = 'email:mail, firstname:cn, lastname:sn'
        domain_params = {'ldap_user_extra_attrs': ldap_extra_attr}
        domain_section = 'domain/%s' % ds_instance_name
        tools.sssd_conf(domain_section, domain_params, action='update')
        domain_params2 = {'ldap_user_email': 'mail'}
        tools.sssd_conf('domain/%s' % (ds_instance_name), domain_params2)
        start = multihost.client[0].service_sssd('start')
        lkup = 'getent passwd foo1@%s' % ds_instance_name
        lkup_cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        assert start == 0 and lkup_cmd.returncode == 0
        ldb_cmd = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb -b cn=users,' \
                  'cn=%s,cn=sysdb' % (ds_instance_name, ds_instance_name)
        cmd = multihost.client[0].run_command(ldb_cmd, raiseonerr=False)
        checks = ['mail: foo1@example.test',
                  'email: foo1@example.test',
                  'firstname: foo1',
                  'lastname: foo1']
        for str1 in checks:
            find = re.compile(r'%s' % str1)
            result = find.search(cmd.stdout_text)
            assert result is not None

    @pytest.mark.tier1
    def test_0006_bz1667252(self, multihost):
        """
        @Title: ifp: crash when requesting extra attributes

        BZ:1667252 crash when requesting extra attributes
        """
        tools = sssdTools(multihost.client[0])
        sssd_params = {'services': 'nss, pam, ifp'}
        tools.sssd_conf('sssd', sssd_params, action='update')
        ifp_params = {'user_attributes': '+test'}
        tools.sssd_conf('ifp', ifp_params)
        domain_section = 'domain/%s' % ds_instance_name
        domain_params = {'ldap_user_extra_attrs': 'test:homeDirectory'}
        tools.sssd_conf(domain_section, domain_params)
        start = multihost.client[0].service_sssd('start')
        assert start == 0
        sssctl_cmd = 'sssctl user-checks foo1@%s' % (ds_instance_name)
        cmd = multihost.client[0].run_command(sssctl_cmd)
        ret = multihost.client[0].service_sssd('status')
        assert ret == 0
