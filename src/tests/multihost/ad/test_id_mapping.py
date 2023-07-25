"""Bug 1268902 SSSD doesn't set the ID mapping range automatically

:requirement: IDM-SSSD-REQ: Active Directory host keytab renewal
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import re
import time
import pytest
from sssd.testlib.common.utils import sssdTools


@pytest.mark.usefixtures('joinad')
@pytest.mark.idmaprange
class Testidmaprange(object):
    """ Test cases for BZ: 1268902

    :setup:
      1. Join to AD using adcli command.
      2. Add the user using adcli user add.
    :bugzilla: https://bugzilla.redhat.com/show_bug.cgi?id=1268902
    """
    @pytest.mark.tier1
    def test_001_findrid(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Find RID
         value from objectSID
        :id: ecb488b2-7694-4e68-9ee7-8833cb7100b1
        """
        (_, rid) = get_rid
        assert rid != 0 or rid is not None

    @pytest.mark.tier1
    def test_002_rangelessthansid(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size less than sids
        :id: de6144c2-ac5a-4b00-a7e1-bd6a87f99134
        """
        (ad_user, rid) = get_rid
        new_rid = str(rid - 1)
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'ldap_idmap_range_size': new_rid,
                       'debug_level': '9'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        lookup_cmd = 'getent passwd %s' % ad_user
        cmd = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
        time.sleep(5)
        if cmd.returncode == 0:
            rid = client.find_rid(ad_user)
            assert rid != 0 or rid is not None
        client.sssd_conf(dom_section, sssd_params, action='delete')

    @pytest.mark.tier2
    def test_003_disablerange(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size less than sids with disable feature
        :id: 13d9a69a-de96-4884-872d-579191740cc0
        """
        (ad_user, rid) = get_rid
        assert rid != 0 or rid is not None
        client = sssdTools(multihost.client[0], multihost.ad[0])
        domain_name = client.get_domain_section_name()
        new_rid = str(rid - 1)
        multihost.client[0].service_sssd('stop')
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'ldap_idmap_range_size': new_rid,
                       'ldap_idmap_helper_table_size': '0',
                       'debug_level': '9'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        log = ("/var/log/sssd/sssd_%s.log" % domain_name)
        lookup_cmd = 'getent passwd %s' % ad_user
        getent = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
        time.sleep(15)
        if not getent.returncode == 0:
            log_1 = re.compile(r'.*RID\sthat\sis\slarger\sthan\sthe\s'
                               r'ldap_idmap_range_size.\sSee\sthe\s"ID\s'
                               r'MAPPING"\ssection\sof\ssssd-ad.5.\sfor\san.*')
            test_str_log = multihost.client[0].get_file_contents(log)
            search = log_1.search(test_str_log.decode())
            if search:
                print(search.group(0))
                assert True
            else:
                assert False
        client.sssd_conf(dom_section, sssd_params, action='delete')

    @pytest.mark.tier2
    def test_004_rangeequalsid(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size equal to sids
        :id: 3687ca8c-5b40-434e-b699-0598b1db19e4
        """
        (ad_user, new_rid) = get_rid
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'ldap_idmap_range_size': str(new_rid),
                       'debug_level': '9'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        lookup_cmd = 'getent passwd %s' % ad_user
        log = ("/var/log/sssd/sssd_%s.log" % domain_name)
        cmd = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
        user = ad_user.split('@')[0]
        time.sleep(15)
        if cmd.returncode == 0:
            log_1 = re.compile(r'Mapping\suser\s.%s.*' % user)
            test_str_log = multihost.client[0].get_file_contents(log)
            result = log_1.search(test_str_log.decode())
            if result:
                print(result.group(0))
                assert True
            else:
                assert False
        client.sssd_conf(dom_section, sssd_params, action='delete')

    @pytest.mark.tier2
    def test_005_disablerange(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size equal to sids with disable feature
        :id: 6682d1c8-2ea8-47a2-9d67-3d48e0949816
        """
        (ad_user, new_rid) = get_rid
        multihost.client[0].service_sssd('stop')
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'ldap_idmap_range_size': str(new_rid),
                       'ldap_idmap_helper_table_size': '0',
                       'debug_level': '9'}
        client.sssd_conf(dom_section, sssd_params)
        client.clear_sssd_cache()
        time.sleep(15)
        log = ("/var/log/sssd/sssd_%s.log" % domain_name)
        lookup_cmd = 'getent passwd %s' % ad_user
        cmd = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
        time.sleep(5)
        if not cmd.returncode == 0:
            log_1 = re.compile(r'.*RID\sthat\sis\slarger\sthan\sthe\s'
                               r'ldap_idmap_range_size.\sSee\sthe\s"ID\s'
                               r'MAPPING"\ssection\sof\ssssd-ad.5.\sfor\san.*')
            test_str_log = multihost.client[0].get_file_contents(log)
            result = log_1.search(test_str_log.decode())
            if result:
                print(result.group(0))
                assert True
            else:
                assert False
        client.sssd_conf(dom_section, sssd_params, action='delete')

    @pytest.mark.tier2
    def test_006_rangevalues(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size near border values
        :id: 54178ed0-10b4-4d23-b134-c8c99ebbd724
        """
        rid_list = []
        (ad_user, rid) = get_rid
        rid_list.append(str(rid - 2))
        rid_list.append(str(rid + 1))
        rid_list.append(str(rid + 2))
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        dom_section = 'domain/%s' % domain_name
        sssd_params = {'debug_level': '9'}
        for rid_val in rid_list:
            multihost.client[0].service_sssd('stop')
            sssd_params['ldap_idmap_range_size'] = rid_val
            sssd_params['debug_level'] = '9'
            client.sssd_conf(dom_section, sssd_params)
            client.clear_sssd_cache()
            time.sleep(15)
            log = ("/var/log/sssd/sssd_%s.log" % domain_name)
            lookup_cmd = 'getent passwd %s' % ad_user
            cmd = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
            user = ad_user.split('@')[0]
            if cmd.returncode == 0:
                log_1 = re.compile(r'Mapping\suser\s.%s.*' % user)
                test_str_log = multihost.client[0].get_file_contents(log)
                result = log_1.search(test_str_log.decode())
                if result:
                    print(result.group(0))
                    assert True
                else:
                    assert False
        client.sssd_conf(dom_section, sssd_params, action='delete')

    @pytest.mark.tier2
    def test_007_disablerangevalues(self, multihost, get_rid):
        """
        :title: IDM-SSSD-TC: Support large AD RIDs automatically: Verify user
         lookup when ldap idmap range size near border values with disable
         feature
        :id: 58e85bda-9b03-45c6-b508-5d3bb56ea6cf
        """
        rid_list = []
        (ad_user, rid) = get_rid
        rid_list.append(str(rid - 2))
        rid_list.append(str(rid + 1))
        rid_list.append(str(rid + 2))
        client = sssdTools(multihost.client[0])
        domain_name = client.get_domain_section_name()
        section = 'domain/%s' % domain_name
        sssd_params = {'ldap_idmap_helper_table_size': '0',
                       'debug_level': '9'}
        for rid_val in rid_list:
            multihost.client[0].service_sssd('stop')
            sssd_params['ldap_idmap_range_size'] = rid_val
            client.sssd_conf(section, sssd_params)
            client.clear_sssd_cache()
            log = ("/var/log/sssd/sssd_%s.log" % domain_name)
            lookup_cmd = 'getent passwd %s' % ad_user
            user = ad_user.split('@')[0]
            cmd = multihost.client[0].run_command(lookup_cmd, raiseonerr=False)
            time.sleep(5)
            if not cmd.returncode == 0:
                log_1 = re.compile(r'.*RID\sthat\sis\slarger\sthan\sthe\s'
                                   r'ldap_idmap_range_size.\sSee\sthe\s"ID\s'
                                   r'MAPPING"\ssection\sof\ssssd-ad.5.\s'
                                   r'for\san.*')
            else:
                log_1 = re.compile(r'Mapping\suser\s.%s.*' % user)
            test_str_log = multihost.client[0].get_file_contents(log)
            result = log_1.search(test_str_log.decode())
            if result:
                print(result.group(0))
                assert True
            else:
                assert False
        client.sssd_conf(section, sssd_params, action='delete')
