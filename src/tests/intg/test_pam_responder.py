#
# Test for the PAM responder
#
# Copyright (c) 2018 Red Hat, Inc.
# Author: Sumit Bose <sbose@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

"""
Tests for the PAM responder
"""
import os
import stat
import signal
import errno
import subprocess
import time

import config
import intg.ds_openldap
import kdc

import pytest

from intg.util import unindent

LDAP_BASE_DN = "dc=example,dc=com"

def provider_list():
     if os.environ['FILES_PROVIDER'] == "enabled":
         return ('files', 'proxy')
     else:
         # The comma is required to indicate a list with the string 'proxy' as
         # only item, without it the string 'proxy' will be interpreted as list
         # with five letters.
         return ('proxy',)


class provider_switch:
    def __init__(self, p):
        if p == 'files':
            self.p = "id_provider = files\nfallback_to_nss = False\nlocal_auth_policy = enable:smartcard\n"
        elif p == 'proxy':
            self.p = "id_provider = proxy\nlocal_auth_policy = only\nproxy_lib_name = call\n"
        elif p == 'proxy_password':
            self.p = "id_provider = proxy\nproxy_lib_name = call\nproxy_pam_target = sssd-shadowutils\n"
        elif p == 'proxy_password_with_sc':
            self.p = "id_provider = proxy\nlocal_auth_policy = enable:smartcard\nproxy_lib_name = call\nproxy_pam_target = sssd-shadowutils\n"
        else:
            self.p = none


@pytest.fixture(scope="module")
def ad_inst(request):
    """Fake AD server instance fixture"""
    instance = intg.ds_openldap.FakeAD(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        instance.setup()
    except Exception:
        instance.teardown()
        raise
    request.addfinalizer(instance.teardown)
    return instance


@pytest.fixture(scope="module")
def ldap_conn(request, ad_inst):
    """LDAP server connection fixture"""
    ldap_conn = ad_inst.bind()
    ldap_conn.ad_inst = ad_inst
    request.addfinalizer(ldap_conn.unbind_s)
    return ldap_conn


def format_basic_conf(ldap_conn):
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        domains = FakeAD
        services = pam, nss

        [nss]

        [pam]
        debug_level = 10

        [domain/FakeAD]
        debug_level = 10
        ldap_search_base = {ldap_conn.ad_inst.base_dn}
        ldap_referrals = false

        id_provider = ldap
        auth_provider = ldap
        chpass_provider = ldap
        access_provider = ldap

        ldap_uri = {ldap_conn.ad_inst.ldap_url}
        ldap_default_bind_dn = {ldap_conn.ad_inst.admin_dn}
        ldap_default_authtok_type = password
        ldap_default_authtok = {ldap_conn.ad_inst.admin_pw}

        ldap_schema = ad
        ldap_id_mapping = true
        ldap_idmap_default_domain_sid = S-1-5-21-1305200397-2901131868-73388776
        case_sensitive = False

        [prompting/password]
        password_prompt = My global prompt

        [prompting/password/pam_sss_alt_service]
        password_prompt = My alt service prompt
    """).format(**locals())


USER1 = dict(name='user1', passwd='x', uid=10001, gid=20001,
             gecos='User for tests',
             dir='/home/user1',
             shell='/bin/bash')

USER2 = dict(name='user2', passwd='x', uid=10002, gid=20002,
             gecos='User with no Smartcard mapping',
             dir='/home/user2',
             shell='/bin/bash')


def format_pam_cert_auth_conf(config, provider):
    """Format a basic SSSD configuration"""
    return unindent("""\
        [sssd]
        debug_level = 10
        domains = auth_only
        services = pam, nss

        [nss]
        debug_level = 10

        [pam]
        pam_cert_auth = True
        pam_p11_allowed_services = +pam_sss_service, +pam_sss_sc_required, \
                                   +pam_sss_try_sc, +pam_sss_allow_missing_name
        pam_cert_db_path = {config.PAM_CERT_DB_PATH}
        p11_uri = pkcs11:manufacturer=SoftHSM%20project; \
                  token=SSSD%20Test%20Token
        p11_child_timeout = 5
        p11_wait_for_card_timeout = 5
        debug_level = 10

        [domain/auth_only]
        debug_level = 10
        {provider.p}

        [certmap/auth_only/user1]
        matchrule = <SUBJECT>.*CN=SSSD test cert 0001.*
    """).format(**locals())


def format_pam_cert_auth_conf_name_format(config, provider):
    """Format SSSD configuration with full_name_format"""
    return unindent("""\
        [sssd]
        debug_level = 10
        domains = auth_only
        services = pam, nss

        [nss]
        debug_level = 10

        [pam]
        pam_cert_auth = True
        pam_p11_allowed_services = +pam_sss_service, +pam_sss_sc_required, \
                                   +pam_sss_try_sc, +pam_sss_allow_missing_name
        pam_cert_db_path = {config.PAM_CERT_DB_PATH}
        p11_uri = pkcs11:manufacturer=SoftHSM%20project; \
                  token=SSSD%20Test%20Token
        p11_child_timeout = 5
        p11_wait_for_card_timeout = 5
        debug_level = 10

        [domain/auth_only]
        use_fully_qualified_names = True
        full_name_format = %2$s\\%1$s
        debug_level = 10
        {provider.p}

        [certmap/auth_only/user1]
        matchrule = <SUBJECT>.*CN=SSSD test cert 0001.*
    """).format(**locals())


def format_pam_krb5_auth(config, kdc_instance):
    """Format SSSD configuration for krb5 authentication"""
    return unindent("""\
        [sssd]
        debug_level = 10
        domains = krb5_auth
        services = pam, nss

        [nss]
        debug_level = 10

        [pam]
        debug_level = 10

        [domain/krb5_auth]
        debug_level = 10
        id_provider = proxy
        proxy_lib_name = call
        auth_provider = krb5

        krb5_realm = PAMKRB5TEST
        krb5_server = localhost:{kdc_instance.kdc_port}
    """).format(**locals())


def format_pam_krb5_auth_domains(config, kdc_instance):
    """Format SSSD configuration for krb5 authentication"""
    return unindent("""\
        [sssd]
        debug_level = 10
        domains = wrong.dom1, wrong.dom2, krb5_auth, wrong.dom3
        services = pam, nss

        [nss]
        debug_level = 10

        [pam]
        debug_level = 10

        [domain/wrong.dom1]
        debug_level = 10
        id_provider = proxy
        proxy_lib_name = call
        auth_provider = krb5

        krb5_realm = WRONG1REALM
        krb5_server = localhost:{kdc_instance.kdc_port}

        [domain/wrong.dom2]
        debug_level = 10
        id_provider = proxy
        proxy_lib_name = call
        auth_provider = krb5

        krb5_realm = WRONG2REALM
        krb5_server = localhost:{kdc_instance.kdc_port}

        [domain/wrong.dom3]
        debug_level = 10
        id_provider = proxy
        proxy_lib_name = call
        auth_provider = krb5

        krb5_realm = WRONG3REALM
        krb5_server = localhost:{kdc_instance.kdc_port}

        [domain/krb5_auth]
        debug_level = 10
        id_provider = proxy
        proxy_lib_name = call
        auth_provider = krb5

        krb5_realm = PAMKRB5TEST
        krb5_server = localhost:{kdc_instance.kdc_port}
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)

    def cleanup_conf_file():
        """Remove sssd.conf, if it exists"""
        if os.path.lexists(config.CONF_PATH):
            os.unlink(config.CONF_PATH)

    request.addfinalizer(cleanup_conf_file)


def create_sssd_process(krb5_conf_path=None):
    """Start the SSSD process"""
    my_env = os.environ.copy()
    my_env["SSS_FILES_PASSWD"] = os.environ["NSS_WRAPPER_PASSWD"]
    my_env["SSS_FILES_GROUP"] = os.environ["NSS_WRAPPER_GROUP"]
    if krb5_conf_path is not None:
        my_env['KRB5_CONFIG'] = krb5_conf_path
    if subprocess.call(["sssd", "-D", "--logger=files"], env=my_env) != 0:
        raise Exception("sssd start failed")


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        with open(config.PIDFILE_PATH, "r") as pid_file:
            pid = int(pid_file.read())
        os.kill(pid, signal.SIGTERM)
        while True:
            try:
                os.kill(pid, signal.SIGCONT)
            except OSError:
                break
            time.sleep(1)
    except OSError:
        pass
    for path in os.listdir(config.DB_PATH):
        os.unlink(config.DB_PATH + "/" + path)
    for path in os.listdir(config.MCACHE_PATH):
        os.unlink(config.MCACHE_PATH + "/" + path)

    # make sure that the indicator file is removed during shutdown
    try:
        assert not os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    except OSError as ex:
        if ex.errno != errno.ENOENT:
            raise ex


def create_sssd_fixture(request, krb5_conf_path=None):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process(krb5_conf_path)
    request.addfinalizer(cleanup_sssd_process)


@pytest.fixture
def simple_pam_cert_auth(request, passwd_ops_setup):
    """Setup SSSD with pam_cert_auth=True"""
    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']
    conf = format_pam_cert_auth_conf(config, provider_switch(request.param))
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    passwd_ops_setup.useradd(**USER1)
    passwd_ops_setup.useradd(**USER2)
    return None


@pytest.fixture
def simple_pam_cert_auth_no_cert(request, passwd_ops_setup):
    """Setup SSSD with pam_cert_auth=True"""
    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']

    old_softhsm2_conf = os.environ['SOFTHSM2_CONF']
    del os.environ['SOFTHSM2_CONF']

    conf = format_pam_cert_auth_conf(config, provider_switch(request.param))
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)

    os.environ['SOFTHSM2_CONF'] = old_softhsm2_conf

    passwd_ops_setup.useradd(**USER1)
    passwd_ops_setup.useradd(**USER2)

    return None


@pytest.fixture
def simple_pam_cert_auth_name_format(request, passwd_ops_setup):
    """Setup SSSD with pam_cert_auth=True and full_name_format"""
    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']
    conf = format_pam_cert_auth_conf_name_format(config, provider_switch(request.param))
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    passwd_ops_setup.useradd(**USER1)
    passwd_ops_setup.useradd(**USER2)
    return None

@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_preauth_indicator(simple_pam_cert_auth):
    """Check if preauth indicator file is created"""
    statinfo = os.stat(config.PUBCONF_PATH + "/pam_preauth_available")
    assert stat.S_ISREG(statinfo.st_mode)


@pytest.fixture
def pam_prompting_config(request, ldap_conn):
    """Setup SSSD with PAM prompting config"""
    conf = format_basic_conf(ldap_conn)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_password_prompting_config_global(ldap_conn, pam_prompting_config,
                                          env_for_sssctl):
    """Check global change of the password prompt"""

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1_dom1-19661",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("My global prompt") != -1


def test_password_prompting_config_srv(ldap_conn, pam_prompting_config,
                                       env_for_sssctl):
    """Check change of the password prompt for dedicated service"""

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1_dom1-19661",
                               "--action=auth",
                               "--service=pam_sss_alt_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("My alt service prompt") != -1


@pytest.fixture
def env_for_sssctl(request):
    pwrap_runtimedir = os.getenv("PAM_WRAPPER_SERVICE_DIR")
    if pwrap_runtimedir is None:
        raise ValueError("The PAM_WRAPPER_SERVICE_DIR variable is unset\n")

    env_for_sssctl = os.environ.copy()
    env_for_sssctl['PAM_WRAPPER'] = "1"
    env_for_sssctl['SSSD_INTG_PEER_UID'] = "0"
    env_for_sssctl['SSSD_INTG_PEER_GID'] = "0"
    env_for_sssctl['LD_PRELOAD'] += ':' + os.environ['PAM_WRAPPER_PATH']

    return env_for_sssctl


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_sc_auth_wrong_pin(simple_pam_cert_auth, env_for_sssctl):

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="111")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: "
                    "Authentication failure") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_sc_auth(simple_pam_cert_auth, env_for_sssctl):

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', ['proxy_password'], indirect=True)
def test_sc_proxy_password_fallback(simple_pam_cert_auth, env_for_sssctl):
    """
    Check that there will be a password prompt if another proxy auth module is
    configured and Smartcard authentication is not allowed but a Smartcard is
    present.
    """

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    assert err.find("Password:") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', ['proxy_password_with_sc'],
                         indirect=True)
def test_sc_proxy_no_password_fallback(simple_pam_cert_auth, env_for_sssctl):
    """
    Use the same environ as for test_sc_proxy_password_fallback but now allow
    local Smartcard authentication. Here we expect that there will be a prompt
    for the Smartcard PIN and that Smartcard authentication is successful.
    """

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth", "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_require_sc_auth(simple_pam_cert_auth, env_for_sssctl):

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth",
                               "--service=pam_sss_sc_required"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth_no_cert', provider_list(), indirect=True)
def test_require_sc_auth_no_cert(simple_pam_cert_auth_no_cert, env_for_sssctl):

    # We have to wait about 20s before the command returns because there will
    # be 2 run since retry=1 in the PAM configuration and both
    # p11_child_timeout and p11_wait_for_card_timeout are 5s in sssd.conf,
    # so 2*(5+5)=20. */
    start_time = time.time()
    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth",
                               "--service=pam_sss_sc_required"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    end_time = time.time()
    assert end_time > start_time and \
        (end_time - start_time) >= 20 and \
        (end_time - start_time) < 40
    assert out.find("Please insert smart card\nPlease insert smart card") != -1
    assert err.find("pam_authenticate for user [user1]: Authentication "
                    "service cannot retrieve authentication info") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_try_sc_auth_no_map(simple_pam_cert_auth, env_for_sssctl):

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user2",
                               "--action=auth",
                               "--service=pam_sss_try_sc"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user2]: Authentication "
                    "service cannot retrieve authentication info") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_try_sc_auth(simple_pam_cert_auth, env_for_sssctl):

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth",
                               "--service=pam_sss_try_sc"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_try_sc_auth_root(simple_pam_cert_auth, env_for_sssctl):
    """
    Make sure pam_sss returns PAM_AUTHINFO_UNAVAIL even for root if
    try_cert_auth is set.
    """
    sssctl = subprocess.Popen(["sssctl", "user-checks", "root",
                               "--action=auth",
                               "--service=pam_sss_try_sc"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [root]: Authentication "
                    "service cannot retrieve authentication info") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_sc_auth_missing_name(simple_pam_cert_auth, env_for_sssctl):
    """
    Test pam_sss allow_missing_name feature.
    """

    sssctl = subprocess.Popen(["sssctl", "user-checks", "",
                               "--action=auth",
                               "--service=pam_sss_allow_missing_name"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth', provider_list(), indirect=True)
def test_sc_auth_missing_name_whitespace(simple_pam_cert_auth, env_for_sssctl):
    """
    Test pam_sss allow_missing_name feature.
    """

    sssctl = subprocess.Popen(["sssctl", "user-checks", " ",
                               "--action=auth",
                               "--service=pam_sss_allow_missing_name"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find("pam_authenticate for user [user1]: Success") != -1


@pytest.mark.parametrize('simple_pam_cert_auth_name_format', provider_list(), indirect=True)
def test_sc_auth_name_format(simple_pam_cert_auth_name_format, env_for_sssctl):
    """
    Test that full_name_format is respected with pam_sss allow_missing_name
    option.
    """

    sssctl = subprocess.Popen(["sssctl", "user-checks", "",
                               "--action=auth",
                               "--service=pam_sss_allow_missing_name"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="123456")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find(r"pam_authenticate for user [auth_only\user1]: "
                    "Success") != -1


@pytest.fixture
def kdc_instance(request):
    """Kerberos server instance fixture"""
    kdc_instance = kdc.KDC(config.PREFIX, "PAMKRB5TEST")
    try:
        kdc_instance.set_up()
        kdc_instance.start_kdc()
    except Exception:
        kdc_instance.teardown()
        raise
    request.addfinalizer(kdc_instance.teardown)
    return kdc_instance


@pytest.fixture
def setup_krb5(request, kdc_instance, passwd_ops_setup):
    """
    Setup SSSD for Kerberos authentication with 2 users with different
    passwords
    """
    conf = format_pam_krb5_auth(config, kdc_instance)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request, kdc_instance.krb5_conf_path)

    passwd_ops_setup.useradd(**USER1)
    passwd_ops_setup.useradd(**USER2)
    kdc_instance.add_principal("user1", "Secret123User1")
    kdc_instance.add_principal("user2", "Secret123User2")
    time.sleep(2)   # Give KDC time to initialize
    return None


def test_krb5_auth(setup_krb5, env_for_sssctl):
    """
    Test basic Kerberos authentication, check for authentication failure when
    a wrong password is used
    """
    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth",
                               "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="Secret123User1")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find(r"pam_authenticate for user [user1]: Success") != -1

    sssctl = subprocess.Popen(["sssctl", "user-checks", "user2",
                               "--action=auth",
                               "--service=pam_sss_service"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="Secret123User1")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find(r"pam_authenticate for user [user2]: "
                    "Authentication failure") != -1


@pytest.fixture
def setup_krb5_domains(request, kdc_instance, passwd_ops_setup):
    """
    Setup SSSD for Kerberos authentication with 2 users with different
    passwords and multiple domains configured in sssd.conf
    """
    conf = format_pam_krb5_auth_domains(config, kdc_instance)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request, kdc_instance.krb5_conf_path)

    passwd_ops_setup.useradd(**USER1)
    passwd_ops_setup.useradd(**USER2)
    kdc_instance.add_principal("user1", "Secret123User1")
    kdc_instance.add_principal("user2", "Secret123User2")
    return None


def test_krb5_auth_domains(setup_krb5_domains, env_for_sssctl):
    """
    Test basic Kerberos authentication with pam_sss 'domains' option, make
    sure not-matching domains are skipped even if the user exists in that
    domain
    """
    sssctl = subprocess.Popen(["sssctl", "user-checks", "user1",
                               "--action=auth",
                               "--service=pam_sss_domains"],
                              universal_newlines=True,
                              env=env_for_sssctl, stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        out, err = sssctl.communicate(input="Secret123User1")
    except Exception:
        sssctl.kill()
        out, err = sssctl.communicate()

    sssctl.stdin.close()
    sssctl.stdout.close()

    if sssctl.wait() != 0:
        raise Exception("sssctl failed")

    assert err.find(r"pam_authenticate for user [user1]: Success") != -1
