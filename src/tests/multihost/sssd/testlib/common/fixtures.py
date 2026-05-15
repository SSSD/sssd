import pytest
from pytest_multihost import make_multihost_fixture

from .qe_class import QeConfig


@pytest.fixture(scope="session", autouse=True)
def session_multihost(request):
    # pylint: disable=no-member
    """Multihost plugin fixture for session scope"""
    if pytest.num_ad > 0:
        mhost = make_multihost_fixture(request, descriptions=[
            {
                'type': 'sssd',
                'hosts':
                {
                    'master': pytest.num_masters,
                    'atomic': pytest.num_atomic,
                    'replica': pytest.num_replicas,
                    'client': pytest.num_clients,
                    'other': pytest.num_others,
                }
            },
            {
                'type': 'ad',
                'hosts':
                {
                    'ad': pytest.num_ad,
                },
            },
        ], config_class=QeConfig,)
    else:
        mhost = make_multihost_fixture(request, descriptions=[
            {
                'type': 'sssd',
                'hosts':
                {
                    'master': pytest.num_masters,
                    'atomic': pytest.num_atomic,
                    'replica': pytest.num_replicas,
                    'client': pytest.num_clients,
                    'other': pytest.num_others,
                }
            },
        ], config_class=QeConfig,)
    mhost.domain = mhost.config.domains[0]
    mhost.master = mhost.domain.hosts_by_role('master')
    mhost.atomic = mhost.domain.hosts_by_role('atomic')
    mhost.replica = mhost.domain.hosts_by_role('replica')
    mhost.client = mhost.domain.hosts_by_role('client')
    mhost.others = mhost.domain.hosts_by_role('other')
    mhost.ad = []

    if pytest.num_ad > 0:
        mhost.ad = []
        for i in range(1, pytest.num_ad + 1):
            print(i)
            print(mhost.config.domains[i].hosts_by_role('ad'))
            mhost.ad.extend(mhost.config.domains[i].hosts_by_role('ad'))

    yield mhost


@pytest.fixture(scope='session', autouse=True)
def create_testdir(session_multihost, request):
    """
    Create test dir on the hosts and backup resolv.conf
    @param session_multihost: Multihost fixture
    @param request: Pytest request
    """
    print(f"Testdir is '{session_multihost.config.test_dir}'")
    test_dir = session_multihost.config.test_dir if \
        session_multihost.config.test_dir else '/root/multihost_tests'
    config_dir_cmd = f"mkdir -p {test_dir}"
    env_file_cmd = f"touch {test_dir}/env.sh"
    rm_config_cmd = f"rm -rf {test_dir}"
    ad_test_dir = '/home/Administrator'
    ad_config_dir_cmd = f"mkdir -p {ad_test_dir}"
    ad_env_file_cmd = f"touch {ad_test_dir}/env.sh"
    ad_rm_config_cmd = f"rm -rf {ad_test_dir}"
    bkup_resolv_conf = 'cp -a /etc/resolv.conf /etc/resolv.conf.orig'
    restore_resolv_conf = 'mv /etc/resolv.conf.orig /etc/resolv.conf'

    for machine in session_multihost.atomic + session_multihost.others +\
            session_multihost.replica:
        machine.run_command(config_dir_cmd)
        machine.run_command(env_file_cmd)

    for machine in session_multihost.client + session_multihost.master:
        machine.run_command(config_dir_cmd)
        machine.run_command(env_file_cmd)
        machine.run_command(bkup_resolv_conf)

    for machine in session_multihost.ad:
        machine.run_command(ad_config_dir_cmd)
        machine.run_command(ad_env_file_cmd)

    def remove_test_dir():
        for machine in session_multihost.client + session_multihost.master:
            machine.run_command(rm_config_cmd)
            machine.run_command("chattr -i /etc/resolv.conf", raiseonerr=False)
            machine.run_command(restore_resolv_conf, raiseonerr=False)

        for machine in session_multihost.atomic + session_multihost.others +\
                session_multihost.replica:
            machine.run_command(config_dir_cmd)

        for machine in session_multihost.ad:
            machine.run_command(ad_rm_config_cmd)

    request.addfinalizer(remove_test_dir)


@pytest.fixture(scope='session', autouse=True)
def disable_journald_rate_limit(session_multihost, request):
    """
    Update journald.conf
    To turn off any kind of rate limiting, set RateLimitIntervalSec value to 0.
    """
    cmd = session_multihost.client[0].run_command(
        'test -f /etc/systemd/journald.conf', raiseonerr=False)
    if cmd.returncode == 0:
        j_config = '/etc/systemd/journald.conf'
    else:
        j_config = '/usr/lib/systemd/journald.conf'

    bkup_cmd = f'cp -Zpf {j_config} /tmp/journald.conf.bkup'
    session_multihost.client[0].run_command(bkup_cmd, raiseonerr=False)
    up_ratelimit = 'RateLimitIntervalSec=0'
    journald_conf = session_multihost.client[0].get_file_contents(
        j_config)
    if isinstance(journald_conf, bytes):
        contents = journald_conf.decode('utf-8')
    else:
        contents = journald_conf
    contents = contents.replace(up_ratelimit, '') + up_ratelimit
    session_multihost.client[0].put_file_contents(j_config, contents)
    session_multihost.client[0].run_command(
        "systemctl restart systemd-journald", raiseonerr=False)

    def restore_journalsssd():
        """ Restore journalsssd.conf """
        bkup_cmd = f'cp -Zpf /tmp/journald.conf.bkup {j_config}'
        session_multihost.client[0].run_command(bkup_cmd)
    request.addfinalizer(restore_journalsssd)
