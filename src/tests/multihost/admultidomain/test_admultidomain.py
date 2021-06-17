from __future__ import print_function
import pytest
import re
from sssd.testlib.common.utils import sssdTools
from sssd.testlib.common.utils import SSHClient


@pytest.mark.admultidomain
class Testadmultidomain(object):
    """
    @Title: IDM-SSSD-TC: ad_provider: admultidomain filter domain groups

    @Steps:
    """
    @pytest.mark.admultidomain
    def test_001_filter_remote_trusted_local_domain_groups(self, multihost,
                                                           adjoin):
        """
        @Title: IDM-SSSD-TC: RFE for the following parameter,
        ad_allow_remote_domain_local_groups bz1883488 bz1756240

        By default, local domain groups are filtered, with a default
        configuration check for the following;

        * domain_group@domain.com
        * child_domain_group@child.domain.com
        * tree_domain_group@treedomain.com
        * domain_group@child.domain.com
        * domain_group@treedomain.com
        * user1@domain.com
        * child_user1@child.domain.com
        * tree_user1@treedomain.com

        And ensure that the child and tree domain groups are not found.
        Enabling the feature, with the extra
        parameters; ldap_use_tokengroups to false and ad_enable_gc to false.
        The groups should be found.

        :param multihost:
        :param adjoin:
        :return:
        """
        adjoin(membersw='adcli')
        client = sssdTools(multihost.client[0])
        domain = client.get_domain_section_name()
        domain_section = 'domain/{}'.format(domain)
        sssd_params = {'ad_allow_remote_domain_local_groups': 'true',
                       'ldap_use_tokengroups': 'false',
                       'ad_enable_gc': 'false'}
        multihost.client[0].service_sssd('start')

        child_domain = multihost.ad[1].domainname
        tree_domain = multihost.ad[2].domainname

        cmd_id_user = 'id user1@%s' % domain
        cmd_get_group = 'getent group domain_group@%s' % domain
        get_group = multihost.client[0].run_command(cmd_get_group,
                                                    raiseonerr=False)
        assert get_group.returncode == 0
        id_user = multihost.client[0].run_command(cmd_id_user,
                                                  raiseonerr=False)
        if id_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'domain_group@%s' % domain)
            get_group_result = find.search(id_user.stdout_text)
            if get_group_result is None:
                status = 'FAIL'
            assert status != 'FAIL'

        cmd_id_child_user = 'id child_user1@%s' % child_domain
        cmd_get_child_group = 'getent group child_domain_group@%s'\
                              % child_domain
        get_child_group = multihost.client[0].run_command(cmd_get_child_group,
                                                          raiseonerr=False)
        assert get_child_group.returncode == 2
        id_child_user = multihost.client[0].run_command(cmd_id_child_user,
                                                        raiseonerr=False)
        if id_child_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'child_domain_group@%s' % child_domain)
            get_child_group_result = find.search(id_child_user.stdout_text)
            if get_child_group_result is True:
                status = 'FAIL'
            assert status != 'FAIL'

            cmd_id_tree_user = 'id tree_user1@%s' % tree_domain
            cmd_get_tree_group = 'getent group tree_domain_group@%s' \
                                 % tree_domain
            get_tree_group = multihost.client[0].run_command(
                cmd_get_tree_group, raiseonerr=False)
            assert get_tree_group.returncode == 2
            id_tree_user = multihost.client[0].run_command(
                cmd_id_tree_user, raiseonerr=False)
            if id_tree_user.returncode == 0:
                status = 'PASS'
                find = re.compile(r'tree_domain_group@%s' % tree_domain)
                get_tree_group_result = find.search(id_tree_user.stdout_text)
                if get_tree_group_result is True:
                    status = 'FAIL'
                assert status != 'FAIL'

        multihost.client[0].service_sssd('stop')
        client.sssd_conf(domain_section, sssd_params)
        client.remove_sss_cache('/var/lib/sss/db')
        client.remove_sss_cache('/var/log/sssd')
        multihost.client[0].service_sssd('restart')

        cmd_id_user = 'id user1@%s' % domain
        cmd_get_group = 'getent group domain_group@%s' % domain
        get_group = multihost.client[0].run_command(cmd_get_group,
                                                    raiseonerr=False)
        assert get_group.returncode == 0
        id_user = multihost.client[0].run_command(cmd_id_user,
                                                  raiseonerr=False)
        if id_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'domain_group@%s' % domain)
            get_group_result = find.search(id_user.stdout_text)
            if get_group_result is None:
                status = 'FAIL'
            assert status != 'FAIL'

        cmd_id_child_user = 'id child_user1@%s' % child_domain
        cmd_get_child_group = 'getent group child_domain_group@%s'\
                              % child_domain
        get_child_group = multihost.client[0].run_command(cmd_get_child_group,
                                                          raiseonerr=False)
        assert get_child_group.returncode == 0
        id_child_user = multihost.client[0].run_command(cmd_id_child_user,
                                                        raiseonerr=False)
        if id_child_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'child_domain_group@%s' % child_domain)
            get_child_group_result = find.search(id_child_user.stdout_text)
            if get_child_group_result is None:
                status = 'FAIL'
            assert status != 'FAIL'

        cmd_id_child_conflict_user = 'id child_user1@%s' % child_domain
        cmd_get_child_conflict_group = 'getent group domain_group@%s'\
                                       % child_domain
        get_child_conflict_group = multihost.client[0].run_command(
            cmd_get_child_conflict_group, raiseonerr=False)
        assert get_child_conflict_group.returncode == 0
        id_child_conflict_user = multihost.client[0].run_command(
            cmd_id_child_conflict_user, raiseonerr=False)
        if id_child_conflict_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'domain_group@%s' % child_domain)
            get_child_conflict_group_result = find.search(
                id_child_conflict_user.stdout_text)
            if get_child_conflict_group_result is True:
                status = 'FAIL'
                assert status != 'FAIL'

        cmd_id_tree_user = 'id tree_user1@%s' % tree_domain
        cmd_get_tree_group = 'getent group tree_domain_group@%s' % tree_domain
        get_tree_group = multihost.client[0].run_command(cmd_get_tree_group,
                                                         raiseonerr=False)
        assert get_tree_group.returncode == 0
        id_tree_user = multihost.client[0].run_command(cmd_id_tree_user,
                                                       raiseonerr=False)
        if id_tree_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'tree_domain_group@%s' % tree_domain)
            get_tree_group_result = find.search(id_tree_user.stdout_text)
            if get_tree_group_result is True:
                status = 'FAIL'
                assert status != 'FAIL'

        cmd_id_tree_conflict_user = 'id tree_user1@%s' % tree_domain
        cmd_get_tree_conflict_group = 'getent group domain_group@%s' \
                                      % tree_domain
        get_tree_conflict_group = multihost.client[0].run_command(
            cmd_get_tree_conflict_group, raiseonerr=False)
        assert get_tree_conflict_group.returncode == 0
        id_tree_conflict_user = multihost.client[0].run_command(
            cmd_id_tree_conflict_user, raiseonerr=False)
        if id_tree_conflict_user.returncode == 0:
            status = 'PASS'
            find = re.compile(r'domain_group@%s' % tree_domain)
            get_tree_conflict_group_result = find.search(
                id_tree_conflict_user.stdout_text)
            if get_tree_conflict_group_result is True:
                status = 'FAIL'
                assert status != 'FAIL'
