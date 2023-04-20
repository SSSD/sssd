# Configuration file for multihost tests.

from __future__ import annotations

from pytest_mh import MultihostPlugin
from sssd_test_framework.config import SSSDMultihostConfig

# Load additional plugins
pytest_plugins = (
    "pytest_mh",
    "pytest_ticket",
    "pytest_tier",
    "sssd_test_framework.fixtures",
)


def pytest_plugin_registered(plugin) -> None:
    if isinstance(plugin, MultihostPlugin):
        plugin.config_class = SSSDMultihostConfig
