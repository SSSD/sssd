from __future__ import print_function
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.adsites
class Testadsites(object):
    """
    @Title: IDM-SSSD-TC: ad_provider: adsites:
    Improve AD site discovery process
    Test cases for BZ: 1819012

    @Steps:
    1. Join client to AD
    2. Start SSSD and enable debug
    3. Create secondary site, move second domain controller to second site
    """
    @pytest.mark.adsites
    def test_001_ad_startup_discovery(self, multihost, adjoin):
        """
        @Title: IDM-SSSD-TC: ad_startup_discovery
        * grep sssd domain logs for cldap ping
        * grep sssd logs for cldap ping parallel batch
        * grep sssd logs for cldap ping domain discovery
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'debug_level': '0xFFF0'}
        client.sssd_conf(domain_section, sssd_params)

        ad1 = multihost.ad[0].hostname
        ad2 = multihost.ad[1].hostname
        multihost.client[0].service_sssd('start')

        cmd_id = 'id Administrator@%s' % domain
        multihost.client[0].run_command(cmd_id)

        cmd_check_ping = 'grep -ire ad_cldap_ping_send ' \
                         '/var/log/sssd/sssd_%s.log | ' \
                         'grep -ire \"Found 2 domain controllers in domain ' \
                         'Default-First-Site-Name._sites.%s\"'\
                         % (domain, domain)
        check_ping = multihost.client[0].run_command(cmd_check_ping,
                                                     raiseonerr=False)
        assert check_ping.returncode == 0
        cmd_check_batch1 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad1)
        check_batch1 = multihost.client[0].run_command(cmd_check_batch1,
                                                       raiseonerr=False)
        cmd_check_batch2 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad2)
        check_batch2 = multihost.client[0].run_command(cmd_check_batch2,
                                                       raiseonerr=False)
        if check_batch1.returncode == 0 or check_batch2.returncode == 0:
            assert True
        else:
            assert False
        cmd_check_discovery = 'grep -ire ad_cldap_ping_domain_discovery_done' \
                              ' /var/log/sssd/sssd_%s.log | ' \
                              'grep -ire \"Found 2 domain controllers in' \
                              ' domain Default-First-Site-Name._sites.%s\"'\
                              % (domain, domain)
        check_discovery = multihost.client[0].run_command(cmd_check_discovery,
                                                          raiseonerr=False)
        assert check_discovery.returncode == 0

    @pytest.mark.adsites
    def test_002_ad_startup_discovery_one_server_unreachable(self, multihost,
                                                             adjoin):
        """
        @Title: IDM-SSSD-TC: ad_startup_discovery_one_server_unreachable
        * grep sssd domain logs for cldap ping
        * grep sssd logs for cldap ping parallel batch
        * grep sssd logs for cldap ping domain discovery
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'debug_level': '0xFFF0'}
        client.sssd_conf(domain_section, sssd_params)

        ad1 = multihost.ad[0].hostname
        ad2 = multihost.ad[1].hostname
        ad2ip = multihost.ad[1].ip

        cmd_dnf_firewalld = 'dnf install -y firewalld'
        multihost.client[0].run_command(cmd_dnf_firewalld)
        cmd_start_firewalld = 'systemctl start firewalld'
        multihost.client[0].run_command(cmd_start_firewalld)
        fw_add = 'firewall-cmd --permanent --direct --add-rule ipv4 ' \
                 'filter OUTPUT 0 -d %s -j DROP' % ad2ip
        fw_reload = 'firewall-cmd --reload'
        multihost.client[0].run_command(fw_add, raiseonerr=True)
        multihost.client[0].run_command(fw_reload, raiseonerr=True)
        multihost.client[0].service_sssd('start')

        cmd_check_ping = 'grep -ire ad_cldap_ping_send ' \
                         '/var/log/sssd/sssd_%s.log | ' \
                         'grep -ire \"Found 2 domain controllers in domain ' \
                         'Default-First-Site-Name._sites.%s\"'\
                         % (domain, domain)
        check_ping = multihost.client[0].run_command(cmd_check_ping,
                                                     raiseonerr=False)
        assert check_ping.returncode == 0
        cmd_check_batch1 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad1)
        check_batch1 = multihost.client[0].run_command(cmd_check_batch1,
                                                       raiseonerr=False)
        cmd_check_batch2 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad2)
        check_batch2 = multihost.client[0].run_command(cmd_check_batch2,
                                                       raiseonerr=False)
        if check_batch1.returncode == 1 and check_batch2.returncode == 0:
            assert True
        else:
            assert False
        cmd_check_discovery = 'grep -ire ad_cldap_ping_domain_discovery_done' \
                              ' /var/log/sssd/sssd_%s.log | ' \
                              'grep -ire \"Found 2 domain' \
                              ' controllers in domain ' \
                              'Default-First-Site-Name._sites.%s\"'\
                              % (domain, domain)
        check_discovery = multihost.client[0].run_command(cmd_check_discovery,
                                                          raiseonerr=False)
        assert check_discovery.returncode == 0

        fw_stop = 'systemctl stop firewalld'
        multihost.client[0].run_command(fw_stop, raiseonerr=True)
        fw_remove = 'dnf remove -y firewalld'
        multihost.client[0].run_command(fw_remove, raiseonerr=True)

    @pytest.mark.adsites
    def test_003_ad_startup_discovery_two_different_sites(self, multihost,
                                                          adjoin, create_site):
        """
         @Title: IDM-SSSD-TC: ad_startup_discovery_two_different_sites
        * grep sssd domain logs for cldap ping
        * grep sssd logs for cldap ping parallel batch
        * grep sssd logs for cldap ping domain discovery
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'debug_level': '0xFFF0'}
        client.sssd_conf(domain_section, sssd_params)

        ad1 = multihost.ad[0].hostname
        ad2 = multihost.ad[1].hostname
        multihost.client[0].service_sssd('start')

        cmd_check_ping = 'grep -ire ad_cldap_ping_send' \
                         ' /var/log/sssd/sssd_%s.log | ' \
                         'grep -ire \"Found 2 domain controllers in domain ' \
                         'Default-First-Site-Name._sites.%s\"'\
                         % (domain, domain)
        check_ping = multihost.client[0].run_command(cmd_check_ping,
                                                     raiseonerr=False)
        assert check_ping.returncode == 0
        cmd_check_batch1 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad1)
        check_batch1 = multihost.client[0].run_command(cmd_check_batch1,
                                                       raiseonerr=False)
        cmd_check_batch2 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad2)
        check_batch2 = multihost.client[0].run_command(cmd_check_batch2,
                                                       raiseonerr=False)
        if check_batch1.returncode == 0 or check_batch2.returncode == 0:
            assert True
        else:
            assert False
        cmd_check_discovery = 'grep -ire ad_cldap_ping_domain_discovery_done' \
                              ' /var/log/sssd/sssd_%s.log | ' \
                              'grep -ire \"Found 2 domain' \
                              ' controllers in domain ' \
                              'Default-First-Site-Name._sites.%s\"'\
                              % (domain, domain)
        check_discovery = multihost.client[0].run_command(cmd_check_discovery,
                                                          raiseonerr=False)
        assert check_discovery.returncode == 0

    @pytest.mark.adsites
    def test_004_ad_startup_discovery_one_server_unreachable(self,
                                                             multihost,
                                                             adjoin,
                                                             create_site):
        """
        @Title: IDM-SSSD-TC:
        ad_startup_discovery_two_different_sites_one_server_unreachable
        * grep sssd domain logs for cldap ping
        * grep sssd logs for cldap ping parallel batch
        * grep sssd logs for cldap ping domain discovery
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'debug_level': '0xFFF0'}
        client.sssd_conf(domain_section, sssd_params)

        ad1 = multihost.ad[0].hostname
        ad2 = multihost.ad[1].hostname
        ad2ip = multihost.ad[1].ip

        cmd_dnf_firewalld = 'dnf install -y firewalld'
        multihost.client[0].run_command(cmd_dnf_firewalld)
        cmd_start_firewalld = 'systemctl start firewalld'
        multihost.client[0].run_command(cmd_start_firewalld)
        fw_add = 'firewall-cmd --permanent --direct --add-rule ipv4 ' \
                 'filter OUTPUT 0 -d %s -j DROP' % ad2ip
        fw_reload = 'firewall-cmd --reload'
        multihost.client[0].run_command(fw_add, raiseonerr=True)
        multihost.client[0].run_command(fw_reload, raiseonerr=True)

        multihost.client[0].service_sssd('start')

        cmd_check_ping = 'grep -ire ad_cldap_ping_send' \
                         ' /var/log/sssd/sssd_%s.log | ' \
                         'grep -ire \"Found 2 domain controllers in domain ' \
                         'Default-First-Site-Name._sites.%s\"'\
                         % (domain, domain)
        check_ping = multihost.client[0].run_command(cmd_check_ping,
                                                     raiseonerr=False)
        assert check_ping.returncode == 0
        cmd_check_batch1 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad1)
        check_batch1 = multihost.client[0].run_command(cmd_check_batch1,
                                                       raiseonerr=False)
        cmd_check_batch2 = 'grep -ire ad_cldap_ping_parallel_batch' \
                           ' /var/log/sssd/sssd_%s.log | ' \
                           'grep -ire \" %s\"' % (domain, ad2)
        check_batch2 = multihost.client[0].run_command(cmd_check_batch2,
                                                       raiseonerr=False)
        if check_batch1.returncode == 1 and check_batch2.returncode == 0:
            assert True
        else:
            assert False
        cmd_check_discovery = 'grep -ire ad_cldap_ping_domain_discovery_done' \
                              ' /var/log/sssd/sssd_%s.log | ' \
                              'grep -ire \"Found 2 domain' \
                              ' controllers in domain ' \
                              'Default-First-Site-Name._sites.%s\"'\
                              % (domain, domain)
        check_discovery = multihost.client[0].run_command(cmd_check_discovery,
                                                          raiseonerr=False)
        assert check_discovery.returncode == 0

        fw_stop = 'systemctl stop firewalld'
        multihost.client[0].run_command(fw_stop, raiseonerr=True)
        fw_remove = 'dnf remove -y firewalld'
        multihost.client[0].run_command(fw_remove, raiseonerr=True)
