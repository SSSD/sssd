""" AD-Provider BZ Automations """
from __future__ import print_function
import time
import random
import pytest
import paramiko
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient


@pytest.mark.adparameters
class TestBugzillaAutomation(object):
    """ BZ Automated Test Cases """

    @pytest.mark.tier1
    def test_0001_bz1296618(self, multihost, adjoin,
                            create_aduser_group):
        """
        @Title: IDM-SSSD-TC: ad_provider: ad_parameters: Properly remove
        OriginalMemberOf attribute from SSSD cache if user has no secondary
        groups anymore

        @steps:

        1. Run id <ad user>
        2. Run ldbsearch -H <Domain-cache> name=AD user
        3. Remove AD users membership of Group
        4. Stop, clear cache and start sssd
        5. Run ldbsearch -H <Domain-cache> name=AD user

        @Expectedresults:
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
        :Title: IDM-SSSD-TC: ad_provider: ad_parameters: Allow short usernames
        in trust setups

        @setup
        1. Modify sssd.conf and set "full_name_format=%1$s" in  Domain section

        @steps:
        1. Run command "su -ADUser@Domain -c whoami"

        @Expectedresults:
        1.Output of whoami command should display only the User part without
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
        :Title: IDM-SSSD-TC: ad_provider: ad_parameters: Users or Groups are
        cached as mixed-case resulting in users unable to sign in

        @Steps:
        1. Run command "#getent group <group_name>"
        2. Run command "#sssctl group-show <group_name>"

        @Expectedresults:
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

    @pytest.mark.tier2
    def test_0004_bz1407960(self, multihost, create_aduser_group, smbconfig):
        """
        :Title: IDM-SSSD-TC: ad_provider: ad_parameters: wbcLookupSid() fails
        in pdomain is NULL

        @steps:
        1. Leave the already join AD system
        2. Joined to AD using net ads command
        3. Obtain cache Kerberos ticket-granting ticket by Administrator
        4. Check the user info.
        5. Leave the system from AD Domain, using net ads
        6. Join system to AD using realmd

        :Expectedresults:
        1. Successfully leave the already join AD system
        2. Successfully joined to AD using net ads command
        3. Obtained cache Kerberos ticket-granting ticket by Administartor
        4. Successfully check the user info without any segfault
        5. Successfully leave the system from AD Domain, using net ads
        6. Successfully join system to AD using realmd
        """
        (ad_user, _) = create_aduser_group
        password = multihost.ad[0].ssh_password
        username = multihost.ad[0].ssh_username
        client = sssdTools(multihost.client[0])
        domainname = multihost.ad[0].domainname.strip().upper()
        net_join = 'net ads join -U %s %s' % (username, domainname)
        cmd = multihost.client[0].run_command(net_join, stdin_text=password)
        time.sleep(5)
        if cmd.returncode == 0:
            user = '{}@{}'.format(username, multihost.ad[0].domainname.upper())
            ad_ip = multihost.ad[0].ip
            dest_file = '/var/lib/sss/pubconf/kdcinfo.%s' % domainname
            multihost.client[0].put_file_contents(dest_file, ad_ip)
            kinit = 'kinit %s' % user
            cmd = multihost.client[0].run_command(kinit, stdin_text=password)
            if cmd.returncode == 0:
                net_ads_info = 'net ads info'
                aduser_info = multihost.client[0].run_command(net_ads_info,
                                                              raiseonerr=False)
                output = client.get_ad_user_info(ad_user, multihost.ad[0])
                if not (aduser_info.returncode == 0) and output:
                    pytest.fail("Unable to user %s info" % ad_user)
        net_leave = 'net ads leave -U %s %s' % (username, domainname)
        # authselect_cmd = 'authselect disable-feature winbind'
        cmd = multihost.client[0].run_command(net_leave, stdin_text=password)
        # multihost.client[0].run_command(authselect_cmd)
        if cmd.returncode == 0:
            realm_join = 'realm join -U %s %s' % (username, domainname)
            multihost.client[0].run_command(realm_join, raiseonerr=False)
            client.realm_leave(domainname)
            client.realm_join(domainname, password)
            client.realm_leave(domainname)
        else:
            raise Exception("Unable to remove system %s from AD server"
                            % multihost.client[0].external_hostname)
        kdestroy_cmd = 'kdestroy -A'
        multihost.client[0].run_command(kdestroy_cmd)

    @pytest.mark.tier1
    def test_00015_authselect_cannot_validate_its_own_files(self, multihost):
        """
        :Title: authselect: authselect cannot validate its own files
        @bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1734302
        """
        password = multihost.ad[0].ssh_password
        client = sssdTools(multihost.client[0])
        domainname = multihost.ad[0].domainname.strip().upper()
        client.realm_join(domainname, password)
        multihost.client[0].run_command("service sssd restart")
        multihost.client[0].run_command("yum install -y gdb")
        multihost.client[0].run_command("gdb -quiet authselect -ex 'set breakpoint pending on'"
                                        " -ex 'b src/lib/files/system.c:428' -ex 'run select "
                                        "sssd --force' -ex 'shell sleep 1' -ex 'detach' -ex 'quit'")
        cmd_check = multihost.client[0].run_command("authselect check")
        client.realm_leave(domainname)
        if "Current configuration is valid." in cmd_check.stdout_text:
            result = "PASS"
        else:
            result = "FAIL"
        assert result == "PASS"

    @pytest.mark.tier1
    def test_0005_BZ1527149_BZ1549675(self, multihost, adjoin, create_adgrp):
        """
        :Title: IDM-SSSD-TC: ad_provider: ad_parameters: AD BUILTIN groups are
        cached with gidNumber equal to 0

        @Setup:
        1. Create AD group with scope as "Global" and type "Security"
        2. Update the properties newly created group and update under
           "Member of" tab and add Users BUILTIN group.

        @Steps:
        1. Check the group lookup for BUILTIN group.
        2. Check the cache entry, for built in group.

        @Expectedresults:
        1. Group lookup should give empty output.
        2. Should not list the entry for built in group
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
        @Title: IDM-SSSD-TC: ad_provider: ad_parameters: Groups go missing
        with PAC enabled in sssd

        @Steps:
        1. Update sssd with pac.
        2. Remove the sssd cache.
        3. Check user lookup and check entry for all groups in output.
        4. Check ldbsearch and check entry for all groups for that user

        @expectedResults
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
        @Title: IDM-SSSD-TC: ad_provider: ad_parameters: Test if we can lookup
        the AD group with one member

        @Steps:
        1. Lookup the group.
        2. Add only one user to the group as the member.
        3. Lookup the group.
        4. Delete the member.
        5. Lookup the group.

        @Expectedresults:
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
        adcli_cg = "adcli create-group %s --domain=%s"\
            " --login-user=Administrator" % (group, ad_realm)
        multihost.client[0].run_command(adcli_cg, stdin_text=password)

        adcli_cu = "adcli create-user %s --domain=%s"\
            " --login-user=Administrator" % (user, ad_realm)
        multihost.client[0].run_command(adcli_cu, stdin_text=password)
        time.sleep(30)
        getent = "date; SSS_NSS_USE_MEMCACHE=NO "\
                 "getent group %s@%s" % (group, ad_realm)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        assert lookup.returncode == 0
        adcli_am = "adcli add-member %s %s --domain=%s "\
            "--login-user=Administrator" % (group, user, ad_realm)
        multihost.client[0].run_command(adcli_am, stdin_text=password)
        time.sleep(30)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        print(lookup.stdout_text)
        adcli_rm = "adcli remove-member %s %s --domain=%s "\
            "--login-user=Administrator" % (group, user, ad_realm)
        multihost.client[0].run_command(adcli_rm, stdin_text=password)
        time.sleep(30)
        lookup = multihost.client[0].run_command(getent, raiseonerr=False)
        print(lookup.stdout_text)
        search = "%s@%s" % (user, ad_realm)
        assert lookup.stdout_text.find(search) == -1
        print("Delete user and group")
        adcli_dg = "adcli delete-group %s --domain=%s"\
            " --login-user=Administrator" % (group, ad_realm)
        multihost.client[0].run_command(adcli_dg, stdin_text=password)
        adcli_du = "adcli delete-user %s --domain=%s"\
            " --login-user=Administrator" % (user, ad_realm)
        multihost.client[0].run_command(adcli_du, stdin_text=password)
        print("Group {} and User {} deleted".format(group, user))
        assert lookup.returncode == 0

    @pytest.mark.tier3
    def test_0008_bz1431858(self, multihost, adjoin):
        """
        @Title : IDM-SSSD-TC: ad_provider: ad_parameters: Wrong principal is
        found with ad provider having long hostname

        @Setup:
        1. Provision windows hostname longer than 15 chracters
        2. Provision RHEL machine and install SSSD
        3. Add a user to AD.

        @Steps:
        1. Lookup user

        @Expectedresults:
        1. Lookup should be successful.
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
        @Title : IDM-SSSD-TC: ad_provider: ad_parameters: SSSD reports minor
        failures trying to resolve well-known SIDs

        @Steps:
        1. Lookup user
        2. Grep "Domain not found"

        @Expected Results:
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
        @Title: ad_parameters: Handle conflicting e-mail addresses
        more gracefully
        @steps:
        1. create ad user akhomic1 having mail akhomic1b@<domain>
        2. create ad user akhomic1b
        3. login as akhomic1 user

        @expected Results:
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
        for user in user_list:
            ad_user = '%s@%s' % (user, ad_realm)
            try:
                ssh = SSHClient(multihost.client[0].sys_hostname,
                                username=ad_user, password='Secret123')
            except paramiko.ssh_exception.AuthenticationException:
                pytest.fail('%s failed to login' % user)
            else:
                ssh.close()
        for user in user_list:
            group = '%s_group' % (user)
            client.remove_ad_user_group(group)
            client.remove_ad_user_group(user)

    @pytest.mark.tier1
    def test_0011_bz1571526(self, multihost, adjoin):
        """
        @Title: ad_parameters: sssd should give warning
        when changing ldap schema from AD to others
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
        :Title: ad_parameters: lookup identity does not work in some cases

        @setup
        1. Add user and set its UPN different from the username,
        Ex: TestUserUPN@ad.vm

        @steps:
        1. Run command "dbus-send --print-reply --system
        --dest=org.freedesktop.sssd.infopipe /org/freedesktop/sssd/
        infopipe org.freedesktop.sssd.infopipe.GetUserAttr string:
        TestUserUPN@ad.vm array:string:name"

        @Expectedresults:
        1.Output of above command should not give any error message
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
        @Title: sssd_be frequently crashes when refresh_expired_interval
        is set and files provider is also enabled
        """
        adjoin(membersw='adcli')
        realm = multihost.ad[0].domainname.strip().upper()
        backup = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig'
        restore = 'cp -f /etc/sssd/sssd.conf.orig /etc/sssd/sssd.conf'
        multihost.client[0].run_command(backup)
        client = sssdTools(multihost.client[0])
        domain_sec_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_sec_name
        sssd_params = {'domains': 'files, %s' % domain_sec_name}
        client.sssd_conf('sssd', sssd_params)
        domain_params = {'entry_cache_timeout':'5400',
                         'refresh_expired_interval': '4000'}
        client.sssd_conf(dom_section, domain_params)
        file_section = 'domain/files'
        file_params = {'id_provider':'files'}
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
        assert result == None

    @pytest.mark.tier1
    def test_0014_user_filtering(self, multihost,
                            adjoin,
                            create_aduser_group):
        """
        @Title: SSSD user filtering is failing
        after files provider rebuilds cache
        Bz: 1824323

        @Steps:
        1. Join RHEL to the AD-server
        2. Create two ADusers on AD
        3. Add one ADuser in filter_users in nss section
        4. Restart sssd
        5. Make sure that filtered user is not returned by SSSD
        6. Add a local user and fetch that user information
        7. Again Make sure that filtered user is not returned by SSSD

        @Expected Results:
        1. filtered user should not be returned after localuser addition
        2. Other AD-users should be returned correctly

        """
        adjoin(membersw='adcli')
        (aduser, _) = create_aduser_group
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domainname = multihost.ad[0].domainname
        aduser1 = 'administrator@%s' % domainname
        lkup = 'getent passwd -s sss %s@%s' % (aduser, domainname)
        cmd = multihost.client[0].run_command(lkup, raiseonerr=True)
        lkup1 = 'getent passwd -s sss %s@%s' % (aduser1, domainname)
        cmd1 = multihost.client[0].run_command(lkup, raiseonerr=True)
        multihost.client[0].service_sssd('stop')
        domain_section = 'domain/{}'.format(domainname)
        userlist = 'root, aduser1'
        params = {'filter_users': 'root, %s' % aduser1,
                 'filter_groups': 'root'}
        client.sssd_conf('nss', params)
        client.remove_sss_cache('/var/lib/sss/db')
        client.remove_sss_cache('/var/log/sssd')
        multihost.client[0].service_sssd('start')
        cmd = multihost.client[0].run_command(lkup, raiseonerr=False)
        cmd1 = multihost.client[0].run_command(lkup1, raiseonerr=False)
        usradd = '/usr/sbin/useradd localuser-test'
        cmd = multihost.client[0].run_command(usradd, raiseonerr=True)
        lkup2 = 'getent passwd localuser-test'
        cmd = multihost.client[0].run_command(lkup, raiseonerr=True)
        cmd1 = multihost.client[0].run_command(lkup1, raiseonerr=False)
        cmd2 = multihost.client[0].run_command(lkup2, raiseonerr=False)
        usrdel = '/usr/sbin/userdel -rf localuser-test'
        cmd = multihost.client[0].run_command(usrdel, raiseonerr=True)
        multihost.client[0].service_sssd('stop')
        client.sssd_conf('nss', params, action='delete')
        multihost.client[0].service_sssd('start')
        assert cmd1.returncode == 2 and cmd.returncode == 0

    @pytest.mark.tier1
    def test_0016_forceLDAPS(self, multihost,
                            adjoin,
                            fetch_ca_cert,
                            create_aduser_group):
        """
        @Title: Force LDAPS over 636 with AD Access Provider
        Bz: 1762415

        @Steps:
        1. Join RHEL to the AD-server
        2. Block 389 port on client with iptable
        3. Enable 'ad_use_ldaps' option sssd.conf
        4. Add channel bindings /etc/openldap/ldap.conf
        4. Restart sssd
        5. Run id <Username>
        6. Parse sssd log file for port used to contact AD

        @Expected Results:
        1. User information should be returned correctly
        2. Logs should show that port 636 was used to contact AD

        """
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
        cert_restr = 'mv /etc/openldap/ldap.conf_bk /etc/openldap.conf'
        cmd = multihost.client[0].run_command(cert_restr, raiseonerr=False)
        multihost.client[0].service_sssd('stop')
        client.sssd_conf(domain_section, sssd_params, action='delete')
        multihost.client[0].service_sssd('start')
        assert cmd4.returncode == 0


    @pytest.mark.tier2
    def test_0017_gssspnego_adjoin(self, multihost):
        """
        @Title: Verify sssd uses GSS-SPNEGO when communicating to AD

        @Bugzilla:
        https://bugzilla.redhat.com/show_bug.cgi?id=1707963
        """
        tools = sssdTools(multihost.client[0])
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
        bindRequest = "tshark -r %s -V -2 -R 'ldap.mechanism == GSS-SPNEGO'" % pcapfile
        valid_etypes = 'etype: eTYPE-AES256-CTS-HMAC-SHA1-96'
        check_str = re.compile(r'%s' % valid_etypes)
        cmd = multihost.client[0].run_command(bindRequest, raiseonerr=False)
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
