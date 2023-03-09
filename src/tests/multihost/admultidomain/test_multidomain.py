import re
import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.tier1
@pytest.mark.admultidomain
class TestADMultiDomain(object):

    @staticmethod
    def test_0001_bz2013297(multihost, newhostname, adchildjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests: disabled root domain causes subdomains to be marked offline
        :id: 3055d093-8449-4146-a6e1-b221dee35395
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
        client.sssd_conf(dom_section, sssd_params, action='update')
        client.clear_sssd_cache()
        multihost.client[0].service_sssd('start')

        getent_root_user1 = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}', raiseonerr=False)
        getent_child_user1 = multihost.client[0].run_command(
            f'getent passwd child_user1@{child_domain}', raiseonerr=False)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

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
        client.sssd_conf(dom_section, sssd_params, action='update')
        client.clear_sssd_cache()
        multihost.client[0].service_sssd('start')

        getent_root_user2 = multihost.client[0].run_command(
            f'getent passwd user1@{ad_domain}', raiseonerr=False)
        getent_child_user2 = multihost.client[0].run_command(
            f'getent passwd child_user1@{child_domain}', raiseonerr=False)

        client.restore_sssd_conf()
        client.clear_sssd_cache()

        assert getent_root_user2.returncode == 2
        assert getent_child_user2.returncode == 0

    @staticmethod
    def test_0002_bz2018432(multihost, newhostname, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests: sssctl domain_list shows more domains than it should
        :id: b2c9efc8-b3a6-4216-99d6-7ae1d868c43f
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
        client.sssd_conf(dom_section, sssd_params, action='update')
        client.clear_sssd_cache()
        multihost.client[0].service_sssd('start')
        # The output needs to be pruned of servers that are not apart of the forest and 'implicit files'
        domain_list_cmd = multihost.client[0].run_command('sssctl domain-list', raiseonerr=False)
        domain_list = domain_list_cmd.stdout_text.split('\n')
        if "" in domain_list:
            domain_list.remove("")
        if "implicit_files" in domain_list:
            domain_list.remove("implicit_files")
        multihost_list = []
        for x in multihost.ad:
            multihost_list.append(x.domainname)
        multihost_list.pop()

        domain_list.sort()
        multihost_list.sort()

        assert domain_list == multihost_list

    @staticmethod
    def test_0003_bz2167728(multihost, newhostname, adchildjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests: bz2167728 Auth fails if client cannot speak to forest root domain
        :id: e9ba9423-0a42-4379-a900-637c79ff0e5c
        :setup:
          1. Clear out the contents of [domain_realm] in /etc/krb5.conf
          2. Join client to child domain
        :steps:
          1. Lookup root, child and tree domain users
        :expectedresults:
          1. All lookups should work
        :customerscenario: True
        """
        client = sssdTools(multihost.client[0], multihost.ad[1])
        krb5 = multihost.client[0].get_file_contents('/etc/krb5.conf', encoding='utf-8')
        resolv = multihost.client[0].get_file_contents('/etc/resolv.conf', encoding='utf-8')
        domain = multihost.ad[0].domainname
        ip = multihost.ad[0].ip
        child_domain = multihost.ad[1].domainname
        child_ip = multihost.ad[1].ip
        tree_domain = multihost.ad[2].domainname
        tree_ip = multihost.ad[2].ip

        # To verify this bug the contents of /etc/krb5.conf needs to have no [realm] entries
        for x in multihost.ad:
            _domain = x.domainname
            _domain_upper = _domain.capitalize()
            _krb5 = multihost.client[0].get_file_contents('/etc/krb5.conf', encoding='utf-8')
            _krb5_1 = re.sub(f"^.{_domain} = {_domain_upper}", "", re.sub(f"^{_domain} = {_domain_upper}", "", _krb5))
            multihost.client[0].put_file_contents('/etc/krb5.conf', _krb5_1)
        adchildjoin(membersw='adcli')

        multihost.client[0].service_sssd('stop')
        client.backup_sssd_conf()
        sssd_domain = f'domain/{client.get_domain_section_name()}'
        sssd_params = {'debug_level': '9'}
        client.sssd_conf(sssd_domain, sssd_params, action='update')

        client.update_resolv_conf(child_ip)
        client.update_resolv_conf(ip)
        client.update_resolv_conf(tree_ip)

        multihost.client[0].service_sssd('start')

        getent1 = multihost.client[0].run_command(f'getent passwd user1@{domain}', raiseonerr=False)
        getent2 = multihost.client[0].run_command(f'getent passwd child_user1@{child_domain}', raiseonerr=False)
        getent3 = multihost.client[0].run_command(f'getent passwd tree_user1@{tree_domain}', raiseonerr=False)

        multihost.client[0].put_file_contents('/etc/krb5.conf', krb5)
        multihost.client[0].run_command('chattr -i /etc/resolv.conf', raiseonerr=False)
        multihost.client[0].put_file_contents('/etc/resolv.conf', resolv)
        multihost.client[0].run_command('chattr +i /etc/resolv.conf', raiseonerr=False)
        client.restore_sssd_conf()

        assert getent1.returncode == 0, f'Could not find user1@{domain}!'
        assert getent2.returncode == 0, f'Could not find child_user1@{child_domain}!'
        assert getent3.returncode == 0, f'Could not find tree_user1@{tree_domain}!'

    @pytest.mark.ticket(bz=1913284, jira=["SSSD-3092", "RHEL-4974"])
    @staticmethod
    def test_0004_bz1913284_keytab_as_nonroot(multihost, newhostname, adchildjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: forests: krb5_kt_start_seq_get failed:
          Permission denied when running as unprivileged user sssd
        :id: 53a6871e-95a6-4865-9e61-1e12815ec35b
        :setup:
          1. Configure parent and child domain
          2. Join client to child domain
        :steps:
          1. Lookup user from child domain
          2. Lookup user from parent domain
          3. Check log for a keytab error
        :expectedresults:
          1. Parent user is found
          2. Child user is found
          3. The permission denied error is not present in log.
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1913284
        """
        adchildjoin(membersw='adcli')
        ad_domain = multihost.ad[0].domainname
        child_domain = multihost.ad[1].domainname
        ad_server = multihost.ad[1].hostname

        # Configure sssd
        client = sssdTools(multihost.client[0], multihost.ad[1])
        if client.sssd_user != "sssd":
            pytest.skip("The test is not applicable without non-root fetaure (sssd 2.10+)!")
        multihost.client[0].service_sssd('stop')
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
        # Download sssd log
        log_str = multihost.client[0].get_file_contents(
            f"/var/log/sssd/sssd_{multihost.ad[1].domainname.lower()}.log"). \
            decode('utf-8')
        client.restore_sssd_conf()
        client.clear_sssd_cache()

        # Evaluate test results
        assert getent_root_user1.returncode == 0
        assert getent_child_user1.returncode == 0
        assert "krb5_kt_start_seq_get failed: Permission denied" not in log_str
        assert "Failed to read keytab [FILE:/etc/krb5.keytab]: No " \
               "suitable principal found in keytab" not in log_str
