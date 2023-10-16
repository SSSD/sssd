""" AD-Provider BZ Automations

:requirement: ad_parameters
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
from __future__ import print_function
import time
import random
import re
import pytest

from sssd.testlib.common.utils import sssdTools


@pytest.mark.adparameters
class TestBugzillaAutomation(object):
    """ BZ Automated Test Cases """

    @pytest.mark.tier1
    def test_0001_bz1296618(self, multihost, adjoin,
                            create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Properly remove
         OriginalMemberOf attribute from SSSD cache if user has no secondary
         groups anymore
        :id: af7fd9fd-e044-461c-ad51-c91c0b371018
        :steps:
          1. Run id <ad user>
          2. Run ldbsearch -H <Domain-cache> name=AD user
          3. Remove AD users membership of Group
          4. Stop, clear cache and start sssd
          5. Run ldbsearch -H <Domain-cache> name=AD user
        :expectedresults:
          1. AD Users cache Entry should not have OriginalMember of
             attribute having Windows AD Group DN
        """
        adjoin(membersw='adcli')
        (aduser, adgroup) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        basedn_entry = multihost.ad[0].domain_basedn_entry
        users_dn_entry = '{},{}'.format('CN=Users', basedn_entry)
        ad_group_dn = 'CN={},{}'.format(adgroup, users_dn_entry)
        domain = multihost.ad[0].domainname
        client.clear_sssd_cache()
        user_id = 'id %s@%s' % (aduser, domain)
        multihost.client[0].run_command(user_id)
        user_cache_entry = 'name=%s@%s,cn=users'\
                           ',cn=%s,cn=sysdb' % (aduser, domain.lower(), domain)
        ldb_search = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb  -b ' \
                     '%s originalMemberOf' % (domain_name, user_cache_entry)
        cmd = multihost.client[0].run_command(ldb_search)
        results = cmd.stdout_text.split()
        # Remove user from group and clear sssd cache
        if ad_group_dn in results:
            client.remove_ad_user_group(aduser)
            client.remove_ad_user_group(adgroup)
            client.clear_sssd_cache()
            id_lookup = 'id %s@%s' % (aduser, domain)
            multihost.client[0].run_command(id_lookup, raiseonerr=False)
            cmd = multihost.client[0].run_command(ldb_search, raiseonerr=False)
            results = cmd.stdout_text.split()
            assert ad_group_dn not in results
        else:
            pytest.fail("%s cmd failed" % ldb_search)

    @pytest.mark.tier1
    def test_0002_bz1287209(self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Allow short usernames
         in trust setups
        :id: 651a0fb6-7199-40af-aafb-5edff3e17d39
        :customerscenario: True
        :steps:
          1. Modify sssd.conf and set "full_name_format=%1$s" in  Domain
             section
          2. Run command "su -ADUser@Domain -c whoami"
        :expectedresults:
          1. Should succeed
          2. Output of whoami command should display only the User part without
             Domain part ,Ex: "ADUser"
        """
        adjoin(membersw='adcli')
        (ad_user, _) = create_aduser_group
        client_ad = sssdTools(multihost.client[0], multihost.ad[0])
        bkup = 'cp -af /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
        multihost.client[0].run_command(bkup)
        domainname = multihost.ad[0].domainname
        domain_section = 'domain/{}'.format(domainname)
        sssd_params = {'full_name_format': '%1$s'}
        client_ad.sssd_conf(domain_section, sssd_params)
        multihost.client[0].service_sssd('restart')
        time.sleep(10)
        domain = multihost.ad[0].domainname
        su_cmd = 'su - %s@%s -c  whoami' % (ad_user, domain)
        cmd = multihost.client[0].run_command(su_cmd, raiseonerr=False)
        assert ad_user == cmd.stdout_text.strip()
        restore = 'cp -af /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        multihost.client[0].run_command(restore)

    @pytest.mark.tier1
    def test_0003_bz1421622(self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Users or Groups are
         cached as mixed-case resulting in users unable to sign in
        :id: 164201c2-61f4-4bbc-b936-fd0050d2fa08
        :steps:
          1. Run command "#getent group <group_name>"
          2. Run command "#sssctl group-show <group_name>"
        :expectedresults:
          1. Group look up should successful.
          2. Get successful information about cached group.
        """
        logger_cmd = 'logger test_0003_bz1421622'
        multihost.client[0].run_command(logger_cmd, raiseonerr=False)
        adjoin(membersw='adcli')
        (_, _) = create_aduser_group
        domain = multihost.ad[0].domainname.strip().upper()
        userlist = ['users', 'Users', 'USERS', 'uSERS', 'UsErS', 'uSeRs',
                    'users']
        domainlist = ['domain', 'Domain', 'DOMAIN', 'dOMAIN', 'DoMaIn',
                      'dOmAiN', 'DOMAIN']
        for i in zip(userlist, domainlist):
            grp = (i[1] + ' ' + i[0] + "@" + domain)
            cmd1 = multihost.client[0].run_command(['getent', 'group', grp],
                                                   raiseonerr=False)
            cmd2 = multihost.client[0].run_command(['sssctl', 'group-show',
                                                    grp], raiseonerr=False)
            if cmd1.returncode == 0 and cmd2.returncode == 0:
                assert True
            else:
                assert False

    @pytest.mark.tier1
    def test_00015_authselect_cannot_validate_its_own_files(self, multihost, adjoin):
        """
        :title: authselect: authselect cannot validate its own files
        :id: 67bec814-d67b-4469-9662-58354889d549
        :requirement: IDM-SSSD-REQ :: Authselect replaced authconfig
        :casecomponent: authselect
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1734302
        """
        adjoin(membersw='adcli')
        multihost.client[0].run_command("service sssd restart")
        multihost.client[0].run_command("yum install -y gdb")
        multihost.client[0].run_command("gdb -quiet authselect -ex "
                                        "'set breakpoint pending on' -ex "
                                        "'b src/lib/files/system.c:428' -ex "
                                        "'run select sssd --force' -ex "
                                        "'shell sleep 1' -ex 'detach' -ex "
                                        "'quit'")
        cmd_check = multihost.client[0].run_command("authselect check")
        assert "Current configuration is valid." in cmd_check.stdout_text

    @pytest.mark.tier1
    def test_0005_BZ1527149_BZ1549675(self, multihost, adjoin, create_adgrp):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: AD BUILTIN groups are
         cached with gidNumber equal to 0
        :id: d31bffa6-4313-44af-b103-9ea4bc715e72
        :customerscenario: True
        :steps:
          1. Create AD group with scope as "Global" and type "Security"
          2. Update the properties newly created group and update under
             "Member of" tab and add Users BUILTIN group.
          3. Check the group lookup for BUILTIN group.
          4. Check the cache entry, for built in group.
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Group lookup should give empty output.
          4. Should not list the entry for built in group
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        domain = multihost.ad[0].domainname.strip()
        user = 'Administrator@%s' % domain
        ldbcache = '/var/lib/sss/db/cache_%s.ldb' % domain_name
        user_cache_entry = 'name=%s,cn=group,cn=%s,cn=sysdb' % (user, domain)
        # just to check sssd status checking following user lookup
        getent_pwd_cmd = "getent passwd %s" % user
        cmd = multihost.client[0].run_command(getent_pwd_cmd, raiseonerr=False)
        if cmd.returncode == 0:
            getent_cmd = "getent group %s" % user
            cmd = multihost.client[0].run_command(getent_cmd, raiseonerr=False)
            if cmd.returncode != 0:
                ldbcmd = "ldbsearch -H %s -b %s" % (ldbcache, user_cache_entry)
                cmd = multihost.client[0].run_command(ldbcmd, raiseonerr=False)
                if cmd.returncode == 0:
                    ldb_search_entry = cmd.stdout_text.strip().split('\n')[0]
                    assert '# returned 0 records' in ldb_search_entry
            else:
                pytest.fail("Expected to get empty output for group lookup")

    @pytest.mark.tier1
    def test_0006_bz1592964(self, multihost, adjoin,
                            create_aduser_group,
                            create_domain_local_group,
                            add_user_in_domain_local_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Groups go missing
         with PAC enabled in sssd
        :id: 505be110-0b3c-46ea-8be8-15c9ee2291f4
        :customerscenario: True
        :steps:
          1. Update sssd with pac.
          2. Remove the sssd cache.
          3. Check user lookup and check entry for all groups in output.
          4. Check ldbsearch and check entry for all groups for that user
        :expectedResults
          1. Successfully update PAC enabled service in sssd.
          2. Successfully remove the sssd cache.
          3. User and group lookup should be successfull
          4. Get successful information about domain local group in ldbsearch.
        """
        adjoin(membersw='adcli')
        (ad_user, _) = create_aduser_group
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        cfgget = '/etc/sssd/sssd.conf'
        bkup_cmd = 'cp -f %s %s.backup' % (cfgget, cfgget)
        multihost.client[0].run_command(bkup_cmd)
        sssdcfg = multihost.client[0].get_file_contents(cfgget)
        sssdcfg = sssdcfg.replace(b'services = nss, pam',
                                  b'services = nss, pam, pac')
        multihost.client[0].put_file_contents(cfgget, sssdcfg)
        multihost.client[0].run_command('sss_cache -E')
        multihost.client[0].service_sssd('restart')
        time.sleep(20)
        domain = multihost.ad[0].domainname.strip().lower()
        id_lookup = 'id %s@%s' % (ad_user, domain)
        cmd1 = multihost.client[0].run_command(id_lookup, raiseonerr=False)
        user_cache_entry = 'name=%s@%s,cn=users,cn=%s,cn=sysdb' % (ad_user,
                                                                   domain,
                                                                   domain)
        ldb_search = 'ldbsearch -H /var/lib/sss/db/cache_%s.ldb -b %s ' \
                     'name=%s* memberof' % (domain_name, user_cache_entry,
                                            ad_user)

        cmd2 = multihost.client[0].run_command(ldb_search, raiseonerr=False)
        grouplist = ['ltestgroup1', 'ltestgroup2', 'ltestgroup3',
                     'ltestgroup4', 'ltestgroup5']
        for _, group in enumerate(grouplist):
            assert group in cmd1.stdout_text and cmd2.stdout_text
        cp = '/bin/cp -a /etc/sssd/sssd.conf.backup /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cp)

    @pytest.mark.tier2
    def test_0007_bz1361597(self, multihost, adjoin, create_aduser_group):
        """
        :title: IDM-SSSD-TC: ad_provider: ad_parameters: Test if we can lookup
         the AD group with one member
        :id: 03cde0b0-27ae-43bd-84ff-96bceb0a15db
        :steps:
          1. Lookup the group.
          2. Add only one user to the group as the member.
          3. Lookup the group.
          4. Delete the member.
          5. Lookup the group.
        :expectedresults:
          1. Look must be successful.
          2. User must be added to the group as a member successfully.
          3. Look must be successful.
          4. Member should be deleted successfully.
          5. Lookup must be successful.
        """
        adjoin(membersw='adcli')
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'entry_cache_timeout': '30'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        digit = random.randint(1000, 10000)
        group = "testgrp_%s" % digit
        user = "testusr_%s" % digit
        ad_realm = multihost.ad[0].domainname
        password = multihost.ad[0].ssh_password
        adcli_cg = f"adcli create-group {group} --domain={ad_realm}"\
            f" --login-user=Administrator --stdin-password -v"
        multihost.client[0].run_command(adcli_cg, stdin_text=password)

        adcli_cu = f"adcli create-user {user} --domain={ad_realm}"\
            f" --login-user=Administrator --stdin-password -v"
        multihost.client[0].run_command(adcli_cu, stdin_text=password)
        time.sleep(30)
        getent = "date; SSS_NSS_USE_MEMCACHE=NO "\
                 "getent group %s@%s" % (group, ad_realm)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        assert lookup.returncode == 0
        adcli_am = f"adcli add-member {group} {user} --domain={ad_realm} "\
            f"--login-user=Administrator  --stdin-password -v"
        multihost.client[0].run_command(adcli_am, stdin_text=password)
        time.sleep(30)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        print(lookup.stdout_text)
        adcli_rm = f"adcli remove-member {group} {user} --domain={ad_realm} "\
            f"--login-user=Administrator  --stdin-password -v"
        multihost.client[0].run_command(adcli_rm, stdin_text=password)
        time.sleep(30)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        print(lookup.stdout_text)
        search = "%s@%s" % (user, ad_realm)
        assert lookup.stdout_text.find(search) == -1
        print("Delete user and group")
        adcli_dg = f"adcli delete-group {group} --domain={ad_realm}"\
            f" --login-user=Administrator  --stdin-password -v"
        multihost.client[0].run_command(adcli_dg, stdin_text=password)
        adcli_du = f"adcli delete-user {user} --domain={ad_realm}"\
            f" --login-user=Administrator  --stdin-password -v"
        multihost.client[0].run_command(adcli_du, stdin_text=password)
        print("Group {} and User {} deleted".format(group, user))
        assert lookup.returncode == 0

    @pytest.mark.tier3
    def test_0008_bz1431858(self, multihost, adjoin):
        """
        :title : IDM-SSSD-TC: ad_provider: ad_parameters: Wrong principal is
         found with ad provider having long hostname
        :id: 8ce3e54b-6b4d-4a35-b751-47020db1ac97
        :steps:
          1. Provision windows hostname longer than 15 chracters
          2. Provision RHEL machine and install SSSD
          3. Add a user to AD.
          4. Lookup user
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Lookup should be successful
        """
        adjoin(membersw='adcli')
        user = "Administrator"
        ad_realm = multihost.ad[0].domainname
        cmd = "id %s@%s" % (user, ad_realm)
        multihost.client[0].run_command(cmd, raiseonerr=False)
        output = multihost.client[0].run_command('klist -kt').stdout_text
        search = "host/{}".format(multihost.client[0].external_hostname)
        assert output.find(search) != -1

    @pytest.mark.tier1
    def test_0009_bz1565761(self, multihost, adjoin):
        """
        :title : IDM-SSSD-TC: ad_provider: ad_parameters: SSSD reports minor
         failures trying to resolve well-known SIDs
        :id: 65cc1f42-92b0-4e3e-8752-5ed9bac2fd6d
        :customerscenario: True
        :steps:
          1. Lookup user
          2. Grep "Domain not found"
        :expectedresults:
          1. Lookup should be successful.
          2. Empty output
        """
        adjoin(membersw='adcli')
        user = "Administrator"
        ad_relam = multihost.ad[0].domainname
        cmd = "sss_cache -E ; id %s@%s" % (user, ad_relam)
        multihost.client[0].run_command(cmd, raiseonerr=False)
        grep = 'grep -ire "Domain not found" /var/log/sssd/'
        cmd = multihost.client[0].run_command(grep, raiseonerr=False)
        output = cmd.stdout_text
        assert not output  # output should be empty

    @pytest.mark.tier1
    def test_0010_bz1527662(self, multihost, adjoin):
        """
        :title: ad_parameters: Handle conflicting e-mail addresses
         more gracefully
        :id: 21b13b8f-0fc5-44e0-9ce0-e59f74826db0
        :customerscenario: True
        :steps:
          1. create ad user akhomic1 having mail akhomic1b@<domain>
          2. create ad user akhomic1b
          3. login as akhomic1 user
        :expectedresults:
          1. akhomic1 and akhomic1b should  successfully login
        """
        adjoin(membersw='adcli')
        user_list = ['akhomic1', 'akhomic1b']
        ad_realm = multihost.ad[0].domainname
        user_mail = 'akhomic1b@%s' % ad_realm
        client = sssdTools(multihost.client[0], multihost.ad[0])
        for user in user_list:
            group = '%s_group' % (user)
            client.create_ad_user(user, group, user_mail)
        multihost.client[0].service_sssd('restart')
        result = True
        for user in user_list:
            ad_user = '%s@%s' % (user, ad_realm)
            res = client.auth_from_client(ad_user, 'Secret123')
            result = result and (res == 3)

        for user in user_list:
            group = '%s_group' % (user)
            client.remove_ad_user_group(group)
            client.remove_ad_user_group(user)
        assert result, "One ore more users failed to login!"

    @pytest.mark.tier1
    def test_0011_bz1571526(self, multihost, adjoin):
        """
        :title: ad_parameters: sssd should give warning
         when changing ldap schema from AD to others
        :id: ae2fc714-e698-492f-8d80-4d180e049cc3
        :customerscenario: True
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'ldap_schema': 'rfc2307', 'debug_level': '9'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = 'The AD provider only supports the AD LDAP schema. '\
              'SSSD will ignore the ldap_schema option value and '\
              'proceed with ldap_schema=ad'
        find = re.compile(r'%s' % msg)
        assert find.search(log)

    @pytest.mark.tier1
    def test_0012_bz1738532(self, multihost, adjoin, create_aduser_group):
        """
        :title: ad_parameters: lookup identity does not work in some cases
        :id: b8382774-e568-4e5b-b787-bdd4db380c28
        :steps:
          1. Add user and set its UPN different from the username,
             Ex: TestUserUPN@ad.vm
          2. Run command "dbus-send --print-reply --system
             --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/
             infopipe org.freedesktop.sssd.infopipe.GetUserAttr string:
             TestUserUPN@ad.vm array:string:name"
        :expectedresults:
          1. Should succeed
          2. Output of above command should not give any error message
             suppose to get username in output.
        """
        adjoin(membersw='adcli')
        (ad_user, _) = create_aduser_group
        client = sssdTools(multihost.client[0])
        domain = multihost.ad[0].domainname.strip().lower()
        user = '%s@%s' % (ad_user, domain)
        client.clear_sssd_cache()
        set_UPN = 'powershell.exe -inputformat none -noprofile Set-ADUser ' \
                  '-UserPrincipalName TestUserUPN@ad.vm -Identity %s' % ad_user
        cmd = multihost.ad[0].run_command(set_UPN, raiseonerr=False)
        if cmd.returncode != 0:
            print('Failed to set UPN of user')
            status = 'FAIL'
            test_cmd = 'dbus-send --print-reply --system --dest=org.' \
                       'freedesktop.sssd.infopipe /org/freedesktop/sssd/' \
                       'infopipe org.freedesktop.sssd.infopipe.' \
                       'GetUserAttrstring:TestUserUPN@ad.vm array:string:name'
            check = multihost.client[0].run_command(test_cmd, raiseonerr=False)
            if check.returncode == 0:
                status = 'PASS'
                find = re.compile(r'%s' % user)
                result = find.search(check.stdout_text)
                if result is None:
                    status = 'FAIL'
            assert status != 'FAIL'

    @pytest.mark.tier1
    def test_0013_bz1794016(self, multihost, adjoin):
        """
        :title: sssd_be frequently crashes when refresh_expired_interval
         is set and files provider is also enabled
        :id: ac5e99cc-2d81-48f7-82ff-622f1c6b3684
        """
        adjoin(membersw='adcli')
        backup = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
        restore = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        multihost.client[0].run_command(backup)
        client = sssdTools(multihost.client[0])
        domain_sec_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_sec_name
        sssd_params = {'domains': 'files, %s' % domain_sec_name}
        client.sssd_conf('sssd', sssd_params)
        domain_params = {'entry_cache_timeout': '5400',
                         'refresh_expired_interval': '4000'}
        client.sssd_conf(dom_section, domain_params)
        file_section = 'domain/files'
        file_params = {'id_provider': 'files'}
        client.sssd_conf(file_section, file_params)
        client.clear_sssd_cache()
        journalctl = 'journalctl -x -n 150 --no-pager'
        multihost.client[0].service_sssd('restart')
        journal_output = multihost.client[0].run_command(journalctl)
        coredump = re.compile(r'%s' % '(sssd_be) of user 0 dumped core.')
        result = coredump.search(journal_output.stdout_text)
        multihost.client[0].run_command(restore)
        remove_backup_file = 'rm -f /etc/sssd/sssd.conf.orig'
        multihost.client[0].run_command(remove_backup_file)
        assert result is None

    @pytest.mark.tier1
    def test_0014_user_filtering(self, multihost,
                                 adjoin, create_aduser_group):
        """
        :title: SSSD user filtering is failing
         after files provider rebuilds cache
        :id: a85acb65-a8af-4397-b4e0-fa9e093b86d7
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1824323
        :steps:
          1. Join RHEL to the AD-server
          2. Create two ADusers on AD
          3. Add one ADuser in filter_users in nss section
          4. Enable files domain in sssd.conf
          5. Restart sssd with cleared cache
          6. Make sure that filtered user is not returned by SSSD
          7. Add a local user and fetch that user information
          8. Again Make sure that filtered user is not returned by SSSD
        :expectedresults:
          1. Should Succeed
          2. Should Succeed
          3. Should Succeed
          4. Should Succeed
          5. Should Succeed
          6. filtered user should not be returned
          7. filtered user should not be returned after localuser addition
          8. Other AD-users should be returned correctly
        """
        adjoin(membersw='adcli')
        (aduser1, _) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domainname = multihost.ad[0].domainname
        params1 = {'enable_files_domain': 'true'}
        client.sssd_conf('sssd', params1)
        client.clear_sssd_cache()
        aduser2 = f'administrator@{domainname}'
        lkup1 = f'getent passwd -s sss {aduser1}@{domainname}'
        multihost.client[0].run_command(lkup1, raiseonerr=True)
        lkup2 = f'getent passwd -s sss {aduser2}'
        multihost.client[0].run_command(lkup2, raiseonerr=True)
        multihost.client[0].service_sssd('stop')
        userlist = f'root, {aduser2}'
        params2 = {'filter_users': userlist,
                   'filter_groups': 'root'}
        client.sssd_conf('nss', params2)
        client.remove_sss_cache('/var/lib/sss/db')
        client.remove_sss_cache('/var/lib/sss/mc')
        client.remove_sss_cache('/var/log/sssd')
        multihost.client[0].service_sssd('start')
        multihost.client[0].run_command(lkup1, raiseonerr=True)
        cmd = multihost.client[0].run_command(lkup2, raiseonerr=False)
        assert cmd.returncode == 2
        usradd = '/usr/sbin/useradd localuser-test'
        multihost.client[0].run_command(usradd, raiseonerr=True)
        lkup3 = 'getent passwd localuser-test'
        multihost.client[0].run_command(lkup3, raiseonerr=True)
        multihost.client[0].run_command(lkup1, raiseonerr=True)
        cmd = multihost.client[0].run_command(lkup2, raiseonerr=False)
        usrdel = '/usr/sbin/userdel -rf localuser-test'
        multihost.client[0].run_command(usrdel, raiseonerr=True)
        multihost.client[0].service_sssd('stop')
        client.sssd_conf('sssd', params1, action='delete')
        client.sssd_conf('nss', params2, action='delete')
        multihost.client[0].service_sssd('start')
        assert cmd.returncode == 2

    @pytest.mark.tier1
    def test_0016_forceLDAPS(self, multihost,
                             adjoin, fetch_ca_cert,
                             create_aduser_group):
        """
        :title: Force LDAPS over 636 with AD Access Provider
        :id: 12d0c340-9c50-4583-97c1-23f9f583522c
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1762415
        :steps:
          1. Join RHEL to the AD-server
          2. Block 389 port on client with iptable
          3. Enable 'ad_use_ldaps' option sssd.conf
          4. Add channel bindings /etc/openldap/ldap.conf
          4. Restart sssd
          5. Run id <Username>
          6. Parse sssd log file for port used to contact AD
        :expectedresults:
          1. User information should be returned correctly
          2. Logs should show that port 636 was used to contact AD
        """
        winver = multihost.ad[0].run_command(
            "systeminfo", raiseonerr=False).stdout_text
        if "Microsoft Windows Server 2012" in winver:
            pytest.skip("Test not valid on windows 2012R2.")
        adjoin(membersw='adcli')
        (aduser, adgroup) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        cert_bkup = 'cp /etc/openldap/ldap.conf /etc/openldap.conf_bk'
        cmd = multihost.client[0].run_command(cert_bkup, raiseonerr=False)
        cert_conf = 'echo -e "SASL_CBINDING tls-endpoint\n"\
                    "TLS_CACERT /etc/openldap/certs/cacert.pem\n"\
                    "SASL_NOCANON	on" > /etc/openldap/ldap.conf'
        cmd = multihost.client[0].run_command(cert_conf, raiseonerr=False)
        cat = 'cat /etc/openldap/ldap.conf'
        cmd = multihost.client[0].run_command(cat, raiseonerr=False)
        domainname = multihost.ad[0].domainname
        lkup = 'getent passwd %s@%s' % (aduser, domainname)
        cmd4 = multihost.client[0].run_command(lkup, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        cmd = 'dnf install -y firewalld'
        multihost.client[0].run_command(cmd, raiseonerr=True)
        cmd = 'systemctl start firewalld'
        multihost.client[0].run_command(cmd, raiseonerr=True)
        fw_add1 = 'firewall-cmd --permanent --direct --add-rule ipv4 '\
                  'filter OUTPUT 0 -p tcp -m tcp --dport=389 -j DROP'
        fw_add2 = 'firewall-cmd --permanent --direct --add-rule ipv4 '\
                  'filter OUTPUT 1 -j ACCEPT'
        multihost.client[0].run_command(fw_add1, raiseonerr=True)
        multihost.client[0].run_command(fw_add2, raiseonerr=True)
        fw_rld = 'firewall-cmd --reload'
        multihost.client[0].run_command(fw_rld, raiseonerr=True)
        domain_section = 'domain/{}'.format(domainname)
        sssd_params = {'ad_use_ldaps': 'True',
                       'ldap_id_mapping': 'True',
                       'debug_level': '9'}
        client.sssd_conf(domain_section, sssd_params)
        client.remove_sss_cache('/var/lib/sss/db')
        client.remove_sss_cache('/var/log/sssd')
        multihost.client[0].service_sssd('start')
        time.sleep(3)
        lkup = 'getent passwd %s@%s' % (aduser, domainname)
        cmd4 = multihost.client[0].run_command(lkup, raiseonerr=False)
        fw_r1 = 'firewall-cmd --permanent --direct --remove-rule ipv4 '\
                'filter OUTPUT 0 -p tcp -m tcp --dport=389 -j DROP'
        fw_r2 = 'firewall-cmd --permanent --direct --remove-rule ipv4 '\
                'filter OUTPUT 1 -j ACCEPT'
        multihost.client[0].run_command(fw_r1, raiseonerr=True)
        multihost.client[0].run_command(fw_r2, raiseonerr=True)
        multihost.client[0].run_command(fw_rld, raiseonerr=True)
        cmd = 'systemctl stop firewalld'
        multihost.client[0].run_command(cmd, raiseonerr=True)
        cmd = 'dnf remove -y firewalld'
        multihost.client[0].run_command(cmd, raiseonerr=True)
        cert_restr = 'mv /etc/openldap.conf_bk /etc/openldap/ldap.conf'
        cmd = multihost.client[0].run_command(cert_restr, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        client.sssd_conf(domain_section, sssd_params, action='delete')
        multihost.client[0].service_sssd('start')
        assert cmd4.returncode == 0

    @pytest.mark.tier2
    def test_0017_gssspnego_adjoin(self, multihost):
        """
        :title: Verify sssd uses GSS-SPNEGO when communicating to AD
        :id: 9d8b68a0-1208-446c-9dbd-93ee1f934903
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1707963
        """
        ad_hostname = multihost.ad[0].sys_hostname
        status = ''
        pcapfile = '/tmp/spnego.pcap'
        tcpdump_cmd = 'tcpdump -s0 host %s -w %s' % (ad_hostname, pcapfile)
        ad_domain = multihost.ad[0].domainname
        realm_join_cmd = 'realm join %s --client-software=sssd '\
                         '--server-software=active-directory '\
                         '--membership-software=adcli -v' % (ad_domain)
        multihost.client[0].run_command(tcpdump_cmd, bg=True)
        pkill = 'pkill tcpdump'
        cmd = multihost.client[0].run_command(realm_join_cmd,
                                              stdin_text='Secret123',
                                              raiseonerr='False')
        if cmd.returncode != 0:
            status = 'FAIL'
            print("Joining to %s failed" % ad_domain)
        multihost.client[0].run_command(pkill, raiseonerr=False)
        tshark_cmd = "tshark -r %s -V -2 -R " \
                     "'ldap.mechanism == GSS-SPNEGO'" % pcapfile
        valid_etypes = 'etype: eTYPE-AES256-CTS-HMAC-SHA1-96'
        check_str = re.compile(r'%s' % valid_etypes)
        cmd = multihost.client[0].run_command(tshark_cmd, raiseonerr=False)
        if cmd.returncode != 0:
            status = 'FAIL'
            print("%s failed " % tshark_cmd)
        else:
            if not check_str.search(cmd.stdout_text):
                status = 'FAIL'
        bindResponse = "tshark -r %s -V -2 -R "\
                       "'spnego.krb5.tok_id == 0x0002'" % pcapfile
        cmd = multihost.client[0].run_command(bindResponse, raiseonerr=False)
        if not check_str.search(cmd.stdout_text):
            status = 'FAIL'
        else:
            status = 'PASS'
        realm_leave = "realm leave -v %s" % (ad_domain)
        multihost.client[0].run_command(realm_leave)
        remove_pcap = 'rm -f %s' % pcapfile
        multihost.client[0].run_command(remove_pcap)
        assert status == 'PASS'

    @staticmethod
    @pytest.mark.tier1
    def test_0018_bz1734040(multihost, adjoin, create_aduser_group):
        """
        :title: ad_parameters: sssd crash in ad_get_account_domain_search
        :id: dcca509e-b316-4010-a173-20f541dafd52
        :customerscenario: True
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1734040
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0])
        client.backup_sssd_conf()
        client.remove_sss_cache('/var/log/sssd')
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        client.sssd_conf(dom_section, {'debug_level': '9'})
        client.sssd_conf('sssd', {'debug_level': '9'})

        # Configure local files domain
        local_params = {'id_provider': 'files', 'debug_level': '9'}
        client.sssd_conf('domain/local', local_params)

        # Make SSSD AD offline
        multihost.client[0].run_command(
            'which iptables || yum install -y iptables',
            raiseonerr=False
        )
        multihost.client[0].run_command(
            f'iptables -F; iptables -A INPUT -s {multihost.ad[0].ip} -j DROP;'
            f'iptables -A OUTPUT -d {multihost.ad[0].ip} -j DROP',
            raiseonerr=False
        )

        client.clear_sssd_cache()
        (aduser, _) = create_aduser_group

        # This one should fail as AD is offline and caches are cleaned up
        multihost.client[0].run_command(
            f'getent passwd {aduser}@{multihost.ad[0].domainname}',
            raiseonerr=False)

        time.sleep(15)
        domain_log = '/var/log/sssd/sssd_%s.log' % domain_name
        log = multihost.client[0].get_file_contents(domain_log).decode('utf-8')
        msg = r'Account.*Flags\s.0x0001.'
        find = re.compile(r'%s' % msg)

        # Teardown
        multihost.client[0].run_command('iptables -F', raiseonerr=False)
        client.restore_sssd_conf()

        assert find.search(log), "Expected log record is missing."
