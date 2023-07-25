"""InfoPipe test cases

:requirement: IDM-SSSD-REQ : Configuration and Service Management
:casecomponent: sssd
:subsystemteam: sst_idm_sssd
:upstream: yes
:status: approved
"""
import pytest


class TestInfoPipe(object):
    """
    Test the InfoPipe responder
    """
    def test_ifp_extra_attributes_property(self, multihost):
        """
        :title: ifp: requesting the extraAttributes property works
        :id: 23b8c7e8-df4b-47ef-b38e-0503040e1d67
        see e.g.  https://github.com/SSSD/sssd/issues/4891
        """
        # Note that this test needs dbus-tools package that
        # is not implicitly installed here.
        check_ifp = "libsss_simpleifp" in multihost.master[0].run_command("rpm -qa").stdout_text
        if not check_ifp:
            pytest.skip("libsss_simpleifp is not present, skipping test.")
        dbus_send_cmd = \
            """
            dbus-send --print-reply --system \
            --dest=org.freedesktop.sssd.infopipe \
            /org/freedesktop/sssd/infopipe/Users/LDAP_2eTEST/123 \
            org.freedesktop.DBus.Properties.Get \
            string:"org.freedesktop.sssd.infopipe.Users.User" \
            string:"extraAttributes"
            """
        cmd = multihost.master[0].run_command(dbus_send_cmd)
        assert cmd.returncode == 0
