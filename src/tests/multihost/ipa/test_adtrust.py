""" IPA AD Trust Sanity tests

:requirement: IDM-SSSD-REQ: Testing SSSD in IPA Provider
:casecomponent: sssd
:subsystemteam: sst_identity_management
:upstream: yes
"""

import pytest
import time
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSSDException


@pytest.mark.usefixtures('setup_ipa_client')
@pytest.mark.trust
class TestADTrust(object):
    """ IPA AD Trust tests """
    def test_basic_sssctl_list(self, multihost):
        """
        :title: Verify sssctl lists trusted domain
        :id: 8da8919d-524c-4498-8dc8-608eb5e139b0
        """
        domain_list = 'sssctl domain-list'
        ad_domain_name = multihost.ad[0].domainname
        cmd = multihost.master[0].run_command(domain_list, raiseonerr=False)
        mylist = cmd.stdout_text.split()
        assert ad_domain_name in mylist

    def test_ipaserver_sss_cache_user(self, multihost):
        """
        :title: Verify AD user is cached on IPA server
         when ipa client queries AD User
        :id: 4a48ee7a-62d1-4eea-9f33-7df3fccc908e
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
        :title: Verify whether the new gid is enforceable when
         gid of AD Group Domain Users is overridden
        :id: 3581c7c0-d598-4e34-bb9b-9d791b93ec65
        :bugzilla:
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
        :title: Verify sssd honours the customized ID View
        :id: 0c0dcfbb-6099-4c61-81c9-3bd3a003ff58
        :bugzilla:
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
