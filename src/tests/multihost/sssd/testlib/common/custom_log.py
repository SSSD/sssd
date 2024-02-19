from __future__ import annotations
import os
from collections import defaultdict

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    p = CustomLogPlugin(config)
    config.pluginmanager.register(p, 'custom_log_plugin')


class CustomLogPlugin:
    """
    Custom log class to dulicate or remove log from console
    and place it inside per-test log files
    """
    def __init__(self, config: pytest.Config) -> None:
        self.config: pytest.Config = config
        self.log_per_test: str = config.getoption("log_per_test")
        self.tests = defaultdict(dict)
        if self.log_per_test not in ["never", "duplicate"]:
            self.config.option.showlocals = True
            self.config.option.reportchars = 'a'
            self.config.option.tbstyle = 'long'
            self.config.option.showcapture = 'no'
            self.config.option.capture = 'fd'

    def _write_log(self, test: str, phases: list = None) -> None:
        """
        Write log for test, possibly only selected
        phases can be written.
        """
        if not phases:
            _phases = ["setup", "call", "teardown"]
        else:
            _phases = phases
        tr = self.tests[test]
        test_name = test.split("::")[-1]
        test_name = test_name.translate(
            str.maketrans('":<>|*? [/', "----------", "]()"))
        logdir = os.path.join(os.path.dirname(self.config.option.log_file),
            'logs')
        os.makedirs(logdir, exist_ok=True)
        logpath = os.path.join(logdir, f'{test_name}.log')
        with open(logpath, 'a+') as f:
            for phase in _phases:
                if phase not in tr:
                    # We do not fail on missing phase as 'call'
                    # could be missing when setup failed.
                    continue
                skip_out = skip_err = skip_log = 0
                if phase == 'call' and 'setup' in tr:
                    skip_out = len(tr['setup'].capstdout)
                    skip_err = len(tr['setup'].capstderr)
                    skip_log = len(tr['setup'].caplog)
                elif phase == 'teardown':
                    if 'setup' in tr:
                        skip_out += len(tr['setup'].capstdout)
                        skip_err += len(tr['setup'].capstderr)
                        skip_log += len(tr['setup'].caplog)
                    if 'call' in tr:
                        skip_out += len(tr['call'].capstdout)
                        skip_err += len(tr['call'].capstderr)
                        skip_log += len(tr['call'].caplog)

                f.write(f"\nPHASE: {phase.upper()} for {test_name}"
                        f"... [{tr[phase].outcome.upper()}]\n")
                if tr[phase].capstdout:
                    f.write(f"\n=== {test_name} {phase.upper()} OUT ===\n")
                    f.write(tr[phase].capstdout[skip_out:])
                if tr[phase].capstderr:
                    f.write(f"\n=== {test_name} {phase.upper()} ERR ===\n")
                    f.write(tr[phase].capstderr[skip_err:])
                if tr[phase].caplog:
                    f.write(f"\n=== {test_name} {phase.upper()} LOG ===\n")
                    f.write(tr[phase].caplog[skip_log:])
                if tr[phase].longreprtext:
                    f.write(f"'\n=== {test_name} {phase.upper()} INFO ===\n")
                    f.write(tr[phase].longreprtext)

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        """
        Hook called on finished test setup, call and teardown
        """
        self.tests[report.nodeid][report.when] = report
        if self.log_per_test == 'always':
            # When we write log always we can write it for each phase
            # This might help when some phase gets stuck.
            self._write_log(report.nodeid, phases=[report.when])
        elif report.when == 'teardown':
            # When writing on-failure we need to wait for teardown to decide
            test = self.tests[report.nodeid]
            if test['setup'].outcome == 'failed' or\
                    test['call'].outcome == 'failed' or\
                    test['teardown'].outcome == 'failed':
                self._write_log(report.nodeid)


def pytest_addoption(parser: pytest.Parser) -> None:
    """
    Pytest hook: add command line options.
    """
    parser.addoption(
        "--log-per-test",
        action="store",
        default="on-failure",
        nargs="?",
        choices=["never", "on-failure", "always", "duplicate"],
        help="Create per-test logfile. 'never': Log everything to console. "
             "'duplicate': Log to console and on-failure also to file. "
             "'always': Keep console clean and always log to file. "
             "'on-failure': Keep console clean and log to file only on "
             "a failure. (default: %(default)s)",
    )
