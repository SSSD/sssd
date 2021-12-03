""" AD-Provider AD Parameters tests ported from bash

:requirement: ad_parameters
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
"""
import tempfile
import pytest

from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSSDException
from sssd.testlib.common.utils import ADOperations


@pytest.fixture(scope="class")
def change_client_hostname(session_multihost, request):
    """ Change client hostname to a truncated version in the AD domain"""
    cmd = session_multihost.client[0].run_command(
        'hostname', raiseonerr=False)
    old_hostname = cmd.stdout_text.rstrip()
    ad_domain = session_multihost.ad[0].domainname
    session_multihost.client[0].run_command(
        f'hostname client.{ad_domain}', raiseonerr=False)

    def restore():
        """ Restore hostname """
        session_multihost.client[0].run_command(
            f'hostname {old_hostname}',
            raiseonerr=False
        )
    request.addfinalizer(restore)


@pytest.mark.tier1
@pytest.mark.admultidomain
@pytest.mark.usefixtures("change_client_hostname")
class TestADMultiDomain(object):

    @staticmethod
    def test_0001_bz2013297(multihost, adchildjoin):
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
        ad_child_domain = multihost.ad[1].domainname

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[1])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': ad_child_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user in root domain
        parent_cmd = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}',
            raiseonerr=False
        )
        # Search for the user in child domain
        child_cmd = multihost.client[0].run_command(
            f'getent passwd child_user1@{ad_child_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert parent_cmd.returncode == 0
        assert child_cmd.returncode == 0

        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': ad_child_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'ad_enabled_domains': ad_child_domain
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()

        # Search for the user in root domain
        parent_cmd = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}',
            raiseonerr=False
        )
        # Search for the user in child domain
        child_cmd = multihost.client[0].run_command(
            f'getent passwd child_user1@{ad_child_domain}',
            raiseonerr=False
        )

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert parent_cmd.returncode == 2
        assert child_cmd.returncode == 0

    @staticmethod
    def test_0002_bz2018432(multihost, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests:  based SSSD adds more AD
        domains than it should based on the configuration file
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
        ad_child_domain = multihost.ad[1].domainname
        ad_child1_domain = multihost.ad[2].domainname
        ad_tree_domain = multihost.ad[3].domainname

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        dom_section = f'domain/{client.get_domain_section_name()}'
        sssd_params = {
            'ad_domain': ad_domain,
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True'
        }
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        # List domains
        domain_list_cmd = multihost.client[0].run_command(
            'sssctl domain-list', raiseonerr=False)
        ad_count = len(multihost.ad)

        assert str(ad_domain) \
               and str(ad_child_domain) \
               and str(ad_child1_domain) \
               and str(ad_tree_domain) \
               in domain_list_cmd.stdout_text

        assert (len(domain_list_cmd.stdout_text.split('\n'))-1) == ad_count
