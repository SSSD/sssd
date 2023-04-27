import subprocess
import time

import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.tier1
@pytest.mark.admultiforest
class TestADMultiForest(object):

    def test_0001_multiforest(multihost, newhostname, adjoin):
        """
        :title: IDM-SSSD-TC: ad_provider: admultiforest : Authentication against two forests
        :id: 900f2467-1aca-430c-bbaa-b22d30a829ad
        :setup:
          1. Configure two domain controllers in different forests
          2. Join client to the first domain
          3. Update sssd.conf for second domain
          4. Update krb5.conf for second domain
          5. Create krb principal and keytab for second domain in the second forest and update sssd.conf
        :steps:
          1. Lookup user in the root domain of the first forest
          2. Lookup user in the  root domain fo the second forest
        :expectedresults:
          1. User is found in the root domain in the first forest
          2. User is found in the root domain in the second forest
        :customerscenario: True
        """
        adjoin(membersw='adcli')
        ad_domain = multihost.ad[0].domainname
        ad_server = multihost.ad[0].hostname
        # The second forest domain must be the last entry in the metadata file
        ad1_ip = multihost.ad[len(multihost.ad)-1].ip
        ad1_domain = multihost.ad[len(multihost.ad)-1].domainname
        ad1_domain_upper = str.upper(ad1_domain)
        ad1_server = multihost.ad[len(multihost.ad)-1].hostname
        ad1_password = multihost.ad[len(multihost.ad)-1].ssh_password

        hosts = multihost.client[0].get_file_contents('/etc/hosts', encoding='utf-8')
        hosts_new = hosts + f'{ad1_ip}    {ad1_server}'
        multihost.client[0].put_file_contents('/etc/hosts.bak', hosts)
        multihost.client[0].put_file_contents('/etc/hosts', hosts_new)

        get_keytab = f'adcli join -v -K /etc/krb5-domain1.keytab -D {ad1_domain} -S {ad1_server} --stdin-password'
        change_context = 'chcon -t krb5_keytab_t /etc/krb5-domain1.keytab'
        cleanup_krb5 = 'rm -rf /etc/krb5-domain1.keytab'
        krb5 = multihost.client[0].get_file_contents('/etc/krb5.conf', encoding='utf-8')
        substr = 'domain_realm]\n'
        new_lines = f"{ad1_domain} = {ad1_domain_upper}\n.{ad1_domain} = {ad1_domain_upper}\n"
        krb5_new = krb5.replace(substr, substr + new_lines)
        try:
            multihost.client[0].run_command(get_keytab, stdin_text=ad1_password)
        except subprocess.CalledProcessError:
            pytest.fail("adcli join failed")
        multihost.client[0].put_file_contents('/etc/krb5.conf', krb5_new)
        multihost.client[0].run_command(change_context)

        # Configure sssd
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        client.backup_sssd_conf()
        client.sssd_conf("sssd", {'domains': f'{ad_domain}, {ad1_domain}'}, action='update')
        domain_params = {
            'ad_domain': f'{ad_domain}',
            'dns_discovery_domain': f'{ad_domain}',
            'ad_server': f'{ad_server}',
            'debug_level': '9',
            'use_fully_qualified_names': 'True',
            'cache_credentials': 'True',
            'dyndns_update': 'True'}
        client.sssd_conf(f'domain/{ad_domain}', domain_params, action='update')
        domain1_params = {
            'ad_domain': f'{ad1_domain}',
            'ad_server': f'{ad1_server}',
            'krb5_realm': f'{ad1_domain_upper}',
            'debug_level': '9',
            'use_fully_qualified_names': 'False',
            'cache_credentials': 'True',
            'realmd_tags': 'manages-system joined-with-samba',
            'dyndns_update': 'False',
            'krb5_keytab': '/etc/krb5-domain1.keytab',
            'ldap_krb5_keytab': '/etc/krb5-domain1.keytab',
            'id_provider': 'ad',
            'access_provider': 'ad',
            'timeout': '3600',
            'krb5_store_password_if_offline': 'True',
            'default_shell': '/bin/bash',
            'ldap_id_mapping': 'True'}
        client.sssd_conf(f'domain/{ad1_domain}', domain1_params, action='update')
        client.clear_sssd_cache()
        multihost.client[0].service_sssd('start')
        # Search for the user in same forest and domain
        getent_domain_user1 = multihost.client[0].run_command(f'getent passwd user1@{ad_domain}', raiseonerr=False)
        getent_domain_user2 = multihost.client[0].run_command(f'getent passwd user2@{ad_domain}', raiseonerr=False)
        id_domain_user1 = multihost.client[0].run_command(f'id user1@{ad_domain}', raiseonerr=False)
        id_domain_user2 = multihost.client[0].run_command(f'id user2@{ad_domain}', raiseonerr=False)
        # Search for the user in a different forest and domain
        getent_domain1_user1 = multihost.client[0].run_command(f'getent passwd user1@{ad1_domain}', raiseonerr=False)
        getent_domain1_user2 = multihost.client[0].run_command(f'getent passwd user2@{ad1_domain}', raiseonerr=False)
        id_domain1_user1 = multihost.client[0].run_command(f'id user1@{ad1_domain}', raiseonerr=False)
        id_domain1_user2 = multihost.client[0].run_command(f'id user2@{ad1_domain}', raiseonerr=False)

        multihost.client[0].put_file_contents('/etc/hosts', hosts)
        multihost.client[0].put_file_contents('/etc/krb5.conf', krb5)
        multihost.client[0].run_command(cleanup_krb5)
        client.restore_sssd_conf()

        assert getent_domain_user1.returncode == 0, f"Could not find user1 {getent_domain_user1}!"
        assert getent_domain_user2.returncode == 0, f"Could not find user1 {getent_domain_user2}!"
        assert id_domain_user1.returncode == 0, f"Could not find user1 {id_domain1_user1}!"
        assert id_domain_user2.returncode == 0, f"Could not find user2 {id_domain_user2}!"
        assert getent_domain1_user1.returncode == 0, f"Could not find user1 {getent_domain1_user1}!"
        assert getent_domain1_user2.returncode == 0, f"Could not find user2 {getent_domain1_user2}!"
        assert id_domain1_user1.returncode == 0, f"Could not find user1 {id_domain1_user1}!"
        assert id_domain1_user2.returncode == 0, f"Could not find user2 {id_domain1_user2}!"
