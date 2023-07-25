#
# ssh public key integration test
#
# Copyright (c) 2018 Red Hat, Inc.
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

import os
import stat
import signal
import subprocess
import time
import string
import random
import pytest

import ds_openldap
import ldap_ent
import ldap
import ldap.modlist
import config

from util import unindent, get_call_output

LDAP_BASE_DN = "dc=example,dc=com"

USER1_PUBKEY1 = "ssh-dss AAAAB3NzaC1kc3MAAACBAPMkvcU53RVhBtjwiC3IqeRIWR9Qwdv8\
DmZzEsDD3Csd6jYxMsPZoXcPrHqwYcEj1s5MVqhdSFS0Cjz13e7gO6OMLInO3xMBSSFHjfp9RE1H\
pgc4WisazzyJaW9EMkQo/DqvkFkKh31oqAmxcSbLAFJRg4TTIqm18qu8IRKS6m/RAAAAFQC97TA5\
JSsMsaX1bRszC7y4PhMBvQAAAIEAt9Yo9v/h9W4nDbzUdkGwNRszlPEK+T12bJv0O9Fk6subD3Do\
6A4Qru/Nr6voXoq8b018Wb7iFWvKOoz5uT/plWBKLXL2NN7ovTR+dUJIzvwurQZroukmU1EghNey\
lkSHmDlxSoMK6Nh21uGu6l+b6x5pXNaZHMpsywG4kY8SoC0AAACAAWLHneEGvqkYA8La4Eob+Hjj\
mAKilx8byxm3Kfb1XO+ZrR6XxadofZOaUYRMpPKgFjKAKPxJftPLiDjWM7lSe6h8df0dUMLVXt6m\
eA83kE0uK5JOOGJfJDqmRed2YnfxUDNNFQGT4xFWGrNtYNbGyw9BWKbkooAsLqaO04zP3Rs= \
user1@LDAP"

USER1_PUBKEY2 = "ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAwHUUF3HPH+DkU6j8k7Q1wHG\
RJY9NeLqSav3h95mTSCQYPSC7I9RTJ4OORgqCbEzrP/DYrrn4TtQ9dhRJar3ZY+F36SH5yFIXORb\
lAIbFU+/anahBuFS9vHi1MqFPckGmwJ4QCpjQhdYxo1ro0e1RuGSaQNp/w9N6S/fDz4Cj4I99xDz\
SeQeGHxYv0e60plQ8dUajmnaGmYRJHF9a6Ban7IWySActCja7eQP2zIRXEZMpuhl1E0U4y+gHTFI\
gD3zQai3QrXm8RUrQURIJ0u6BlGS910OPbHqLpLTFWG08L8sNUcYzC+DY6yoCSO0n/Df3pVRS4C9\
5Krf3FqppMTjdfQ== user1@LDAP"


@pytest.fixture(scope="module")
def ds_inst(request):
    """LDAP server instance fixture"""
    ds_inst = ds_openldap.DSOpenLDAP(
        config.PREFIX, 10389, LDAP_BASE_DN,
        "cn=admin", "Secret123"
    )

    try:
        ds_inst.setup()
    except Exception:
        ds_inst.teardown()
        raise
    request.addfinalizer(ds_inst.teardown)
    return ds_inst


@pytest.fixture(scope="module")
def ldap_conn(request, ds_inst):
    """LDAP server connection fixture"""
    ldap_conn = ds_inst.bind()
    ldap_conn.ds_inst = ds_inst
    request.addfinalizer(ldap_conn.unbind_s)
    return ldap_conn


def create_ldap_entries(ldap_conn, ent_list=None):
    """Add LDAP entries from ent_list"""
    if ent_list is not None:
        for entry in ent_list:
            ldap_conn.add_s(entry[0], entry[1])


def cleanup_ldap_entries(ldap_conn, ent_list=None):
    """Remove LDAP entries added by create_ldap_entries"""
    if ent_list is None:
        for ou in ("Users", "Groups", "Netgroups", "Services", "Policies"):
            for entry in ldap_conn.search_s(f"ou={ou},"
                                            f"{ldap_conn.ds_inst.base_dn}",
                                            ldap.SCOPE_ONELEVEL,
                                            attrlist=[]):
                ldap_conn.delete_s(entry[0])
    else:
        for entry in ent_list:
            ldap_conn.delete_s(entry[0])


def create_ldap_cleanup(request, ldap_conn, ent_list=None):
    """Add teardown for removing all user/group LDAP entries"""
    request.addfinalizer(lambda: cleanup_ldap_entries(ldap_conn, ent_list))


def create_ldap_fixture(request, ldap_conn, ent_list=None):
    """Add LDAP entries and add teardown for removing them"""
    create_ldap_entries(ldap_conn, ent_list)
    create_ldap_cleanup(request, ldap_conn, ent_list)


SCHEMA_RFC2307_BIS = "rfc2307bis"


def format_basic_conf(ldap_conn, schema, config):
    """Format a basic SSSD configuration"""
    schema_conf = "ldap_schema         = " + schema + "\n"
    schema_conf += "ldap_group_object_class = groupOfNames\n"
    return unindent("""\
        [sssd]
        domains             = LDAP
        services            = nss, ssh

        [nss]

        [ssh]
        debug_level=10
        ca_db               = {config.PAM_CERT_DB_PATH}

        [pam]
        pam_cert_auth = True

        [domain/LDAP]
        {schema_conf}
        id_provider         = ldap
        auth_provider       = ldap
        ldap_uri            = {ldap_conn.ds_inst.ldap_url}
        ldap_search_base    = {ldap_conn.ds_inst.base_dn}
        ldap_sudo_use_host_filter = false
        debug_level=10
        ldap_user_certificate = userCertificate;binary
    """).format(**locals())


def create_conf_file(contents):
    """Create sssd.conf with specified contents"""
    conf = open(config.CONF_PATH, "w")
    conf.write(contents)
    conf.close()
    os.chmod(config.CONF_PATH, stat.S_IRUSR | stat.S_IWUSR)


def cleanup_conf_file():
    """Remove sssd.conf, if it exists"""
    if os.path.lexists(config.CONF_PATH):
        os.unlink(config.CONF_PATH)


def create_conf_cleanup(request):
    """Add teardown for removing sssd.conf"""
    request.addfinalizer(cleanup_conf_file)


def create_conf_fixture(request, contents):
    """
    Create sssd.conf with specified contents and add teardown for removing it
    """
    create_conf_file(contents)
    create_conf_cleanup(request)


def create_sssd_process():
    """Start the SSSD process"""
    if subprocess.call(["sssd", "-D", "--logger=files"]) != 0:
        raise Exception("sssd start failed")


def get_sssd_pid():
    pid_file = open(config.PIDFILE_PATH, "r")
    pid = int(pid_file.read())
    return pid


def cleanup_sssd_process():
    """Stop the SSSD process and remove its state"""
    try:
        pid = get_sssd_pid()
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


def create_sssd_fixture(request):
    """Start SSSD and add teardown for stopping it and removing its state"""
    create_sssd_process()
    create_sssd_cleanup(request)


def create_sssd_cleanup(request):
    """Add teardown for stopping SSSD and removing its state"""
    request.addfinalizer(cleanup_sssd_process)


@pytest.fixture
def add_user_with_ssh_key(request, ldap_conn):
    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001,
                      sshPubKey=(USER1_PUBKEY1, USER1_PUBKEY2))
    ent_list.add_user("user2", 1002, 2001)
    create_ldap_fixture(request, ldap_conn, ent_list)

    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS, config)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


def test_ssh_pubkey_retrieve(add_user_with_ssh_key):
    """
    Test that we can retrieve an SSH public key for a user who has one
    and can't retrieve a key for a user who does not have one.
    """
    sshpubkey = get_call_output(["sss_ssh_authorizedkeys", "user1"])
    assert sshpubkey == USER1_PUBKEY1 + '\n' + USER1_PUBKEY2 + '\n'

    sshpubkey = get_call_output(["sss_ssh_authorizedkeys", "user2"])
    assert len(sshpubkey) == 0


def test_ssh_pubkey_retrieve_cert(add_user_with_ssh_cert):
    """
    Test that we can retrieve an SSH public key derived from a cert in ldap.
    Compare with the sshpubkey derived via ssh-keygen, they should match.
    """
    for u in [1, 7]:
        pubsshkey_path = os.path.dirname(config.PAM_CERT_DB_PATH)
        pubsshkey_path += "/SSSD_test_cert_pubsshkey_000%s.pub" % u
        with open(pubsshkey_path, 'r') as f:
            pubsshkey = f.read()
        sshpubkey = get_call_output(["sss_ssh_authorizedkeys", "user%s" % u])
        print(sshpubkey)
        print(pubsshkey)
        assert sshpubkey == pubsshkey


@pytest.fixture()
def sighup_client(request):
    test_ssh_cli_path = os.path.join(config.ABS_BUILDDIR,
                                     "..", "..", "..", "test_ssh_client")
    assert os.access(test_ssh_cli_path, os.X_OK)
    return test_ssh_cli_path


@pytest.fixture
def add_user_with_many_keys(request, ldap_conn):
    # Generate a large list of unique ssh pubkeys
    pubkey_list = []
    while len(pubkey_list) < 50:
        new_pubkey = list(USER1_PUBKEY1)
        new_pubkey[10] = random.choice(string.ascii_uppercase)
        new_pubkey[11] = random.choice(string.ascii_uppercase)
        new_pubkey[12] = random.choice(string.ascii_uppercase)
        str_new_pubkey = ''.join(c for c in new_pubkey)
        if str_new_pubkey in pubkey_list:
            continue
        pubkey_list.append(str_new_pubkey)

    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001, sshPubKey=pubkey_list)
    create_ldap_fixture(request, ldap_conn, ent_list)

    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']
    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS, config)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)
    return None


@pytest.fixture
def add_user_with_ssh_cert(request, ldap_conn):
    # Add a certificate to ldap, to manually test a cert from a smartcard.
    config.PAM_CERT_DB_PATH = os.environ['PAM_CERT_DB_PATH']

    ent_list = ldap_ent.List(ldap_conn.ds_inst.base_dn)
    ent_list.add_user("user1", 1001, 2001)
    ent_list.add_user("user7", 1007, 2001)
    create_ldap_fixture(request, ldap_conn, ent_list)

    for u in [1, 7]:
        der_path = os.path.dirname(config.PAM_CERT_DB_PATH)
        der_path += "/SSSD_test_cert_x509_000%s.der" % u
        with open(der_path, 'rb') as f:
            val = f.read()

        dn = "uid=user%s,ou=Users," % u + LDAP_BASE_DN
        ldap_conn.modify_s(dn, [(ldap.MOD_ADD, 'usercertificate;binary', val)])

    conf = format_basic_conf(ldap_conn, SCHEMA_RFC2307_BIS, config)
    create_conf_fixture(request, conf)
    create_sssd_fixture(request)

    return None


def test_ssh_sighup(add_user_with_many_keys, sighup_client):
    """
    A regression test for https://github.com/SSSD/sssd/issues/4754

    OpenSSH can close its end of the pipe towards sss_ssh_authorizedkeys
    before all of the output is read. In that case, older versions
    of sss_ssh_authorizedkeys were receiving a SIGPIPE
    """
    cli_path = sighup_client

    # python actually does the sensible, but unexpected (for a C programmer)
    # thing and handles SIGPIPE. In order to reproduce the bug, we need
    # to unset the SIGPIPE handler
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    process = subprocess.Popen([cli_path, "user1"],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    _, _ = process.communicate()
    # If the test tool detects that sss_ssh_authorizedkeys was killed with a
    # signal, it would have returned 1
    assert process.returncode == 0
