""" test cases for sssd proxy

:requirement: IDM-SSSD-REQ : Proxy Provider
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""


import textwrap
import time
from string import Template
import pytest

from constants import ds_suffix
from sssd.testlib.common.expect import pexpect_ssh
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.exceptions import SSHLoginException


@pytest.mark.usefixtures('setup_sssd_krb', 'create_host_keytab',
                         'create_posix_usersgroups')
@pytest.mark.proxy
class TestsssdProxy(object):
    """ Testing sssd-proxy  """
    @pytest.mark.tier1
    def test_0001_1724717(self, multihost):
        """
        :title: proxy: sssd-proxy crashes resolving groups with no members
        :id: 28b64673-8f1b-46c1-b0dd-6eaba9f80b2c
        """
        # backup sssd.conf
        backup = 'cp -f /etc/sssd/sssd.conf /etc/sssd/sssd.conf.backup'
        restore = 'cp -f /etc/sssd/sssd.conf.backup /etc/sssd/sssd.conf'
        multihost.client[0].run_command(backup)
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        multihost.client[0].service_sssd('stop')
        tools.remove_sss_cache('/var/lib/sss/db')
        user = 'foo1@%s' % domain_name
        # user add
        add_user = 'useradd foo1'
        # delete user
        del_user = 'userdel -r foo1'
        multihost.client[0].run_command(add_user)
        domain_params = {'id_provider': 'proxy',
                         'proxy_lib_name': 'files',
                         'ignore_group_members': 'False',
                         'cache_credentials': 'True',
                         'krb5_validate': 'True'}
        tools.sssd_conf('domain/%s' % domain_name, domain_params)
        del_domain_params = {'ldap_uri': 'ldaps:%s' %
                             (multihost.master[0].run_command),
                             'ldap_tls_cacert':
                             '/etc/openldap/cacerts/cacert.pem',
                             'ldap_search_base': ds_suffix,
                             'use_fully_qualified_names': 'True'}
        tools.sssd_conf('domain/%s' % domain_name,
                        del_domain_params, action='delete')
        cat = 'cat /etc/sssd/sssd.conf'
        multihost.client[0].run_command(cat)
        multihost.client[0].service_sssd('start')
        client = pexpect_ssh(multihost.client[0].sys_hostname, user,
                             'Secret123', debug=False)
        try:
            client.login()
        except SSHLoginException:
            multihost.client[0].run_command(del_user)
            multihost.client[0].run_command(restore)
            pytest.fail("%s failed to login" % user)
        else:
            id_cmd = 'id %s' % user
            (ret1, ret) = client.command(id_cmd)
            assert "no such user" not in ret1
            client.logout()
        # On fedora after user logs out it takes time
        # for systemd process running as user to get stopped, hence
        # adding sleep
        time.sleep(20)
        multihost.client[0].run_command(del_user)
        multihost.client[0].run_command(restore)

    def test_0003_update_removed_grp_membership(self, multihost,
                                                backupsssdconf):
        """
        :title: proxy: secondary group is shown in sssd cache after
         group is removed
        :id: 7cfb9aa9-6e68-4914-afb8-ecfae132aa84
        :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1917970
        :customerscenario: true
        :steps:
          1. Edit sssd.conf and configure proxy provider with
             entry_cache_timeout = 1
          2. Restart SSSD with cleared cache
          3. Create a localuser and localgroup
          4. Add that localuser to the localgroup
          5. Assert localgroup is shown in localuser's group list
          6. Remove localuser from localgroup
          7. Assert that after entry_cache_timeout, localuser's groups
             are not listing localgroup
        :expectedresults:
          1. Should succeed
          2. Should succeed
          3. Should succeed
          4. Should succeed
          5. Should succeed
          6. Should succeed
          7. Should succeed
        """
        tools = sssdTools(multihost.client[0])
        domain_name = tools.get_domain_section_name()
        l_usr, l_grp = 'testuser', 'testgroup'
        multihost.client[0].run_command(f'useradd {l_usr}')
        multihost.client[0].run_command(f'groupadd {l_grp}')
        multihost.client[0].run_command(f'usermod -aG {l_grp} {l_usr}')
        domain_params = {'id_provider': 'proxy',
                         'proxy_lib_name': 'files',
                         'auth_provider': 'krb5',
                         'ignore_group_members': 'False',
                         'cache_credentials': 'True',
                         'entry_cache_timeout': '1',
                         'krb5_validate': 'True'}
        tools.sssd_conf('domain/%s' % domain_name, domain_params)
        del_domain_params = {'ldap_uri': 'ldaps:%s' %
                             (multihost.master[0].run_command),
                             'ldap_tls_cacert':
                             '/etc/openldap/cacerts/cacert.pem',
                             'ldap_search_base': ds_suffix,
                             'use_fully_qualified_names': 'True'}
        tools.sssd_conf('domain/%s' % domain_name,
                        del_domain_params, action='delete')
        tools.clear_sssd_cache()
        cmd = multihost.client[0].run_command(f'groups {l_usr}')
        assert 'testgroup' in cmd.stdout_text
        multihost.client[0].run_command(f'gpasswd -d {l_usr} {l_grp}')
        time.sleep(1)
        cmd = multihost.client[0].run_command(f'groups {l_usr}')
        multihost.client[0].run_command(f'userdel -rf {l_usr}')
        multihost.client[0].run_command(f'groupdel -f {l_grp}')
        assert 'testgroup' not in cmd.stdout_text

    def test_innetgr_threads(self, multihost, backupsssdconf):
        """
        :title: Verify sssd is thread-safe in innetgr
        :id: d38a8279-312d-4f52-808c-17226e7168d3
        :customerscenario: True
        :description:
         SSSD was not thread safe in innetgr call when using nested netgroups
         resulting in nfs-ganesha not working correctly
        :setup:
          1. Configure client to use sssd proxy files
          2. Create /etc/netgroup file with two groups containing 1000+
             members.
          3. Add the group/host info to the c sources
          4. Compile the sources using gcc
        :steps:
          1. Restart sssd on client and clear caches
          2. Run first binary to verify that the setup is correct.
          3. Run second binary to verify that the bug is fixed.
        :expectedresults:
          1. SSSD restarted successfully
          2. Test binary returns 0 return code.
          3. Test binary returns 0 return code.
        :teardown:
          1. Remove the net groups
          2. Remove the sources and binaries.
        :bugzilla:
         https://bugzilla.redhat.com/show_bug.cgi?id=1703436
        """
        # SETUP
        # Configure proxy provider
        sssd_client = sssdTools(multihost.client[0])
        domain_params = {'id_provider': 'proxy',
                         'proxy_lib_name': 'files',
                         'auth_provider': 'none'
                         }
        sssd_client.sssd_conf(
            'domain/%s' % sssd_client.get_domain_section_name(),
            domain_params
        )

        # Create the net groups in file
        client_shortname = multihost.client[0].shortname
        net_group1_name = "ngr"
        net_group1 = f"{net_group1_name} "
        net_group2 = f"{net_group1_name}2 "

        # We need long enough member searching so the issue appears.
        # This number of members reproduced failure in 2+ threads reliably.
        for i in range(1, 4096):
            net_group1 += "(host1%04d, user1%04d, domain1) " % (i, i)
            net_group2 += "(host2%04d, user2%04d, domain2) " % (i, i)
        net_group1 += f"({client_shortname}, myuser, domain6)"

        multihost.client[0].transport.put_file_contents(
            '/etc/netgroup',
            net_group1 + "\n" + net_group2 + "\n"
        )

        # Prepare c code
        pre = "pthread_mutex_lock(&netg_lock);"
        post = "pthread_mutex_unlock(&netg_lock);"
        code_template_str = textwrap.dedent("""\
            #include <stdio.h>
            #include <stdlib.h>
            #include <netdb.h>
            #include <pthread.h>
            #define NTHREADS 256
            #define NUM_CALLS 1000
            static char *groups[] = {"$group"};
            static char *hosts[] = {"$host"};
            #define NHOSTS (sizeof(hosts)/sizeof(hosts[0]))
            #define NGROUPS (sizeof(groups)/sizeof(groups[0]))
            static int pass_count;
            static int fail_count;
            static int bogus_count;
            static pthread_mutex_t netg_lock = PTHREAD_MUTEX_INITIALIZER;
            static void *thread_main(void *arg)
            {
                unsigned long i;
                char *host;
                char *group;
                int rc;
                for (i = 0; i < NUM_CALLS; i++) {
                    host = hosts[rand() % NHOSTS];
                    group = groups[rand() % NGROUPS];
                    $pre
                    rc = innetgr(group, host, NULL, NULL);
                    $post
                    /* Ideally, atomic increments should be used, but
                     * rough numbers are OK for now
                     */
                    if (rc == 0)
                        fail_count++;
                    else if (rc == 1)
                        pass_count++;
                    else
                        bogus_count++;
                }
            }
            int main()
            {
                pthread_t threads[NTHREADS];
                int i;
                for (i = 0; i < NTHREADS; i++)
                    pthread_create(&threads[i], NULL, thread_main, (void *)0);
                for (i = 0; i < NTHREADS; i++)
                    pthread_join(threads[i], NULL);
                printf("pass:%d, fail:%d, bogus:%d\\n",
                        pass_count, fail_count, bogus_count);
                if ( fail_count > 0 )
                    exit(2);
            }""")
        code_template = Template(code_template_str)

        # Substitute c code and upload
        code = code_template.substitute(
            group=net_group1_name,
            host=client_shortname,
            pre=pre,
            post=post
        )
        multihost.client[0].transport.put_file_contents('/root/netg-lock.c',
                                                        code)
        code = code_template.substitute(
            group=net_group1_name,
            host=client_shortname,
            pre='',
            post=''
        )
        multihost.client[0].transport.put_file_contents('/root/netg-lock2.c',
                                                        code)

        # Install packages including gcc
        sssdTools(multihost.client[0]).client_install_pkgs()

        # Compile c code
        compile_cmd = 'gcc -lpthread -o /root/netg-lock /root/netg-lock.c ' \
                      '&& gcc -lpthread -o /root/netg-lock2 /root/netg-lock2.c'
        gcc = multihost.client[0].run_command(compile_cmd, raiseonerr=False)
        chmod_cmd = 'chmod +x /root/netg-lock*'
        multihost.client[0].run_command(chmod_cmd, raiseonerr=False)

        # TEST EXECUTION
        sssd_client.clear_sssd_cache()
        cmd1 = multihost.client[0].run_command('/root/netg-lock',
                                               raiseonerr=False)
        cmd2 = multihost.client[0].run_command('/root/netg-lock2',
                                               raiseonerr=False)

        # TEARDOWN
        multihost.client[0].run_command(
            'rm -f /root/netg-lock*; rm -f /etc/netgroup',
            raiseonerr=False
        )

        # TEST EVALUATION
        assert gcc.returncode == 0, 'Compiling of binaries failed!'
        assert cmd1.returncode == 0, 'First binary failed, incorrect setup!'
        assert cmd2.returncode == 0, 'Second binary failed, test failed!'
