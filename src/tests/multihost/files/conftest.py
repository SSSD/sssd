"""conftest.py for all tests"""

from __future__ import print_function
import subprocess
import os
import time
import posixpath
import pytest
from sssd.testlib.common.utils import sssdTools
from subprocess import CalledProcessError
from pytest_multihost import make_multihost_fixture
from sssd.testlib.common.paths import SSSD_DEFAULT_CONF, NSSWITCH_DEFAULT_CONF
from sssd.testlib.common.qe_class import session_multihost
from sssd.testlib.common.qe_class import create_testdir
from datetime import datetime, timedelta


def pytest_configure():
    """ Namespace hook to add below dict in the pytest namespace """
    pytest.num_masters = 0
    pytest.num_ad = 0
    pytest.num_atomic = 0
    pytest.num_replicas = 0
    pytest.num_clients = 1
    pytest.num_others = 0



@pytest.fixture(scope="function")
def useradd(session_multihost, request):
    tool = sssdTools(session_multihost.client[0])
    users = ['test1', 'user1']
    groups = ['localgrp', 'l_grp1', 'l_grp2', 'l_grp3']
    for user in users:
        cmd = f'useradd {user}'
        session_multihost.client[0].run_command(cmd)
    for grp in groups:
        cmd = f'groupadd {grp}'
        session_multihost.client[0].run_command(cmd)

    def remove_local_users():
        for user in users:
            cmd = f'userdel -rf {user}'
            session_multihost.client[0].run_command(cmd)
        for grp in groups:
            cmd = f'groupdel {grp}'
            session_multihost.client[0].run_command(cmd)
    request.addfinalizer(remove_local_users)


@pytest.fixture(scope='function')
def backupsssdconf(session_multihost, request):
    """ Backup and restore sssd.conf """
    bkup = 'cp -f %s %s.orig' % (SSSD_DEFAULT_CONF,
                                 SSSD_DEFAULT_CONF)
    session_multihost.client[0].run_command(bkup)
    session_multihost.client[0].service_sssd('stop')

    def restoresssdconf():
        """ Restore sssd.conf """
        restore = 'cp -f %s.orig %s' % (SSSD_DEFAULT_CONF, SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(restore)
    request.addfinalizer(restoresssdconf)
#+++++++++++++++
@pytest.fixture(scope="class")
def multihost(session_multihost, request):
    """ Multihost fixture to be used by tests
    :param obj session_multihost: multihost object
    :return obj session_multihost: return multihost object
    """
    if hasattr(request.cls(), 'class_setup'):
        request.cls().class_setup(session_multihost)
        request.addfinalizer(
            lambda: request.cls().class_teardown(session_multihost))
    return session_multihost


@pytest.fixture(scope='class')
def setup_sssd(session_multihost, request):
    """ Configure sssd.conf """
    tools = sssdTools(session_multihost.client[0])
    sssd_params = {'domains': 'files'}
    tools.sssd_conf('sssd', sssd_params)
    domain_section = 'domain/%s' % 'files'
    domain_params = { 'id_provider': 'files',
                     'debug_level': '9'}
    tools.sssd_conf(domain_section, domain_params)
    start_sssd = 'systemctl start sssd'
    session_multihost.client[0].run_command(start_sssd)

    def removesssd():
        """ Remove sssd configuration """
        stop_sssd = 'systemctl stop sssd'
        session_multihost.client[0].run_command(stop_sssd)
        removeconf = 'rm -f %s' % (SSSD_DEFAULT_CONF)
        session_multihost.client[0].run_command(removeconf)
    request.addfinalizer(removesssd)
