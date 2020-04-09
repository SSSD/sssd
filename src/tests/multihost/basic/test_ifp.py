"""
InfoPipe test cases
"""

import pytest


class TestInfoPipe(object):
    """
    Test the InfoPipe responder
    """
    def test_ifp_extra_attributes_property(self, multihost):
        """
        @Title: ifp: requesting the extraAttributes property works
        see e.g.  https://github.com/SSSD/sssd/issues/4891
        """
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
