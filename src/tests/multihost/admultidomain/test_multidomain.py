import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.tier1
@pytest.mark.admultidomain
class TestADMultiDomain(object):

    def test_0001_bz2013297(multihost, newhostname, adchildjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests: disabled root ad domain
        causes subdomains to be marked offline
        :id:
        :setup:
          1. Configure parent and child domain
          2. Join client to child domain
          3. ad_enabled_domains is not configured
          4. ad_enabled_domains to contain only the child domain
        :steps:
          1. Lookup user from child domain
          2. Lookup user from parent domain
          3. Change  ad_enabled_domains parameter
          4. Lookup user from child domain
          5. Lookup user from parent domain
        :expectedresults:
          1. Parent user is found
          2. Child user is found
          3. Parent user is not found
          4. Child user is found
        :customerscenario: True
        """
        adchildjoin(membersw='adcli')
        ad_domain = multihost.ad[0].domainname
        child_domain = multihost.ad[1].domainname
        ad_server = multihost.ad[1].hostname

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[1])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': child_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'ad_server': ad_server,
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user in root domain
        getent_root_user1 = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}',
            raiseonerr=False
        )
        # Search for the user in child domain
        getent_child_user1 = multihost.client[0].run_command(
            f'getent passwd child_user1@{child_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert getent_root_user1.returncode == 0
        assert getent_child_user1.returncode == 0

        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': child_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ad_server': ad_server,
            'ad_enabled_domains': child_domain
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user in root domain
        getent_root_user2 = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}',
            raiseonerr=False
        )
        # Search for the user in child domain
        getent_child_user2 = multihost.client[0].run_command(
            f'getent passwd child_user1@{child_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert getent_root_user2.returncode == 2
        assert getent_child_user2.returncode == 0

    def test_0002_bz2018432(multihost, newhostname, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests:  based SSSD adds more AD
        domains than it should be based on the configuration file
        :id:
        :setup:
          1. Configure several domains, this suite contains 4 trusted domains
          2. Join client to parent domain
        :steps:
          1. Perform sssctl domain-list
        :expectedresults:
          1. Only trusted domains listed
        :customerscenario: True
        """
        adjoin(membersw='adcli')
        ad_domain = multihost.ad[0].domainname
        ad_server = multihost.ad[0].hostname

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': ad_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'ad_server': ad_server,
            'cache_credentials': 'True'
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # List domains
        # The lists have to be manipulated, the DC in the other forest
        # needs to be removed as well as implicit_files from the output
        domain_list_cmd = multihost.client[0].run_command(
            'sssctl domain-list', raiseonerr=False)
        domain_list = domain_list_cmd.stdout_text.split('\n')
        if "" in domain_list:
            domain_list.remove("")
        if "implicit_files" in domain_list:
            domain_list.remove("implicit_files")
        multihost_list = []
        for x in multihost.ad:
            multihost_list.append(x.domainname)
        # This is necessary because the AD server in the second forest needs to
        # be removed from the list.
        multihost_list.pop()

        domain_list.sort()
        multihost_list.sort()

        assert domain_list == multihost_list
