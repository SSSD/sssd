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

    if pytest.num_ad > 0:
        mhost.ad = []
        for i in range(1, pytest.num_ad + 1):
            print(i)
            print(mhost.config.domains[i].hosts_by_role('ad'))
            mhost.ad.extend(mhost.config.domains[i].hosts_by_role('ad'))

    yield mhost
