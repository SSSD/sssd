""" IPA AD Trust Sanity tests """

import pytest
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException


@pytest.mark.usefixtures('setup_ipa_client')
@pytest.mark.trust
class TestADTrust(object):
    """ IPA AD Trust tests """
    def test_basic_sssctl_list(self, multihost):
        """ @Title: Verify sssctl lists trusted domain  """
        domain_list = 'sssctl domain-list'
        ad_domain_name = multihost.ad[0].domainname
        cmd = multihost.master[0].run_command(domain_list, raiseonerr=False)
        mylist = cmd.stdout_text.split()
        assert ad_domain_name in mylist

    def test_ipaserver_sss_cache_user(self, multihost):
        """ @Title: Verify AD user is cached on IPA server
        when ipa client queries AD User
        """
        ipaserver = sssdTools(multihost.master[0])
        domain_name = ipaserver.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain_name)
        cache_path = '/var/lib/sss/db/cache_%s.ldb' % domain_name
        ad_domain_name = multihost.ad[0].domainname
        user_name = 'Administrator@%s' % (ad_domain_name)
        id_cmd = 'id %s' % user_name
        multihost.master[0].run_command(id_cmd, raiseonerr=False)
        multihost.client[0].run_command(id_cmd, raiseonerr=False)
        dn = 'name=Administrator@%s,cn=users,cn=%s,cn=sysdb' % (ad_domain_name,
                                                                ad_domain_name)
        ldb_cmd = 'ldbsearch -H %s -b "%s"' % (cache_path, dn)
        multihost.master[0].run_command(ldb_cmd, raiseonerr=False)

    def test_enforce_gid(self, multihost):
        """
        @Title: Verify whether the new gid is enforceable when
        gid of AD Group Domain Users is overridden

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1817219
        """
        create_view = 'ipa idview-add  foo_bar'
        multihost.master[0].run_command(create_view)
        ad_domain_name = multihost.ad[0].domainname
        ad_grp = 'Domain Users@%s' % ad_domain_name
        cmd = 'ipa idoverridegroup-add foo_bar "%s" --gid=40000000' % (ad_grp)
        multihost.master[0].run_command(cmd, raiseonerr=False)
        # apply the view on client
        client_hostname = multihost.client[0].sys_hostname
        apply_view = "ipa idview-apply foo_bar --hosts=%s" % client_hostname
        multihost.master[0].run_command(apply_view)
        client = sssdTools(multihost.client[0])
        client.clear_sssd_cache()
        time.sleep(5)
        user_name = 'Administrator@%s' % (ad_domain_name)
        id_cmd = 'id %s' % user_name
        cmd = multihost.client[0].run_command(id_cmd, raiseonerr=False)
        group = "40000000(domain users@%s)" % ad_domain_name
        delete_id_view = 'ipa idview-del foo_bar'
        multihost.master[0].run_command(delete_id_view)
        client.clear_sssd_cache()
        assert group in cmd.stdout_text

    def test_honour_idoverride(self, multihost, create_aduser_group):
        """
        @Title: Verify sssd honours the customized ID View

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1826720
        """
        (aduser, adgroup) = create_aduser_group
        domain = multihost.ad[0].domainname
        ipa_client = sssdTools(multihost.client[0])
        ipa_client.clear_sssd_cache()
        ad_user_fqdn = '%s@%s' % (aduser, domain)
        id_cmd = 'id -g %s' % (ad_user_fqdn)
        cmd = multihost.master[0].run_command(id_cmd, raiseonerr=False)
        current_gid = cmd.stdout_text.strip()
        create_view = 'ipa idview-add madrid_trust_view'
        multihost.master[0].run_command(create_view)
        cmd = 'ipa idoverrideuser-add madrid_trust_view '\
              '%s --uid=50001 --gidnumber=50000 '\
              '--home=/home/%s' % (ad_user_fqdn, aduser)
        multihost.master[0].run_command(cmd, raiseonerr=False)
        # apply the view on client
        apply_view = "ipa idview-apply madrid_trust_view "\
                     "--hosts=%s" % multihost.client[0].sys_hostname
        multihost.master[0].run_command(apply_view)
        ipa_client.clear_sssd_cache()
        time.sleep(5)
        id_cmd = 'id %s' % ad_user_fqdn
        count = 0
        for i in range(50):
            cmd = multihost.client[0].run_command(id_cmd, raiseonerr=False)
            gid = cmd.stdout_text.strip()
            if gid == current_gid:
                count += 1
        delete_id_view = 'ipa idview-del madrid_trust_view'
        multihost.master[0].run_command(delete_id_view)
        ipa_client.clear_sssd_cache()
        assert count == 0


    def test_sudo_kerberos_ticket(self, multihost, create_aduser_group):
        """
        :title: Verify pam_sss_gss.so can handle large kerberos ticket
                for sudo
        :id: 456ea53b-6702-4b8e-beb1-eee841b85fed
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1948657
        :steps:
         1. Add sudo rule in IPA-server for AD-users
         2. Modify /etc/krb5.conf.d/kcm_default_ccache to specify location
            of storing a TGT
         3. Enable pam_sss_gss.so for auth in /etc/pam.d/{sudo,sudo-i} files
         4. Add a sudo rule for AD-user
         5. Log in on ipa-client as AD-user
         6. Run kinit and fetch tgt
         7. Run sudo command
         8. Remove sudo cache
         9. Run sudo command again
         :expectedresults:
         1. Should succeed
         2. Should succeed
         3. Should succeed
         4. Should succeed
         5. Should succeed
         6. Should succeed
         7. Should not ask password, and should succeed
         8. Should succeed
         9. Should not ask password, and should succeed

        """
        (aduser, adgroup) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        ipaserver = sssdTools(multihost.master[0])
        cmd = 'dnf install -y sssd sssd-kcm'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        domain_name = ipaserver.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain_name)
        params = {'pam_gssapi_services': 'sudo, sudo-i'}
        client.sssd_conf(domain_section, params)
        krbkcm = '/etc/krb5.conf.d/kcm_default_ccache'
        bk_krbkcm = '/tmp/kcm_default_ccache'
        src = 'KCM:'
        dest = 'FILE:/tmp/krb5cc_%{uid}'
        multihost.client[0].run_command(f'cp {krbkcm} {bk_krbkcm}')
        cmd = "echo -e  '[libdefaults]\n' \
              '    default_ccache_name  = FILE:/tmp/krb5cc_%{uid}:'"
        multihost.client[0].run_command(cmd, raiseonerr=False)
        multihost.client[0].service_sssd('restart')
        pam_sss_gss = "auth       sufficient   pam_sss_gss.so debug"
        for pam_file in "/etc/pam.d/sudo-i", "/etc/pam.d/sudo":
            cmd = f'sed -i "1 i\{pam_sss_gss}" {pam_file}'
            multihost.client[0].run_command(cmd, raiseonerr=False)
        cmd = f'echo "{aduser} ALL=(ALL) ALL" >> /etc/sudoers'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        try:
            ssh = SSHClient(multihost.client[0].sys_hostname,
                            username=aduser, password='Secret123')

        except paramiko.ssh_exception.AuthenticationException:
            pytest.fail(f'{aduser} failed to login')
        else:
            (_, _, exit_status) = ssh.execute_cmd(f'kinit {aduser}',
                                                  stdin='Secret123')
            assert exit_status == 0
            (stdout, _, exit_status) = ssh.execute_cmd('sudo id')
            assert 'uid=0(root)' in stdout.readlines()
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -k')
            (stdout, _, exit_status) = ssh.execute_cmd('sudo -l')
            assert '(ALL) ALL' in stdout.readlines()
        client.sssd_conf(domain_section, params, action='delete')
        for pam_file in "/etc/pam.d/sudo-i", "/etc/pam.d/sudo":
            cmd = f'sed -i "1d" {pam_file}'
            multihost.client[0].run_command(cmd, raiseonerr=False)
        cmd = f'sed -i "$ d" /etc/sudoers'
        multihost.client[0].run_command(cmd, raiseonerr=False)
        cmd = f'mv {bk_krbkcm} {krbkcm}'
        multihost.client[0].run_command(cmd, raiseonerr=False)
