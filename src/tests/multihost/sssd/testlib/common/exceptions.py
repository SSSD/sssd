"""
    Provide Exceptions for py.test framework
"""


class StandardException(Exception):
    """ Overrides Exception class """

    def __init__(self, msg=None, rval=1):
        if msg is None:
            msg = 'Error'
        self.msg = msg
        self.rval = rval
        super(StandardException, self).__init__(self.msg)

    def __str__(self):
        return "{} ({})".format(self.msg, self.rval)


class InvalidInput(StandardException):
    """
    Override StandardException used mainly when invalid input is passed
    """


class DirSrvException(StandardException):
    """
    Override StandardException, This exception is to be used for
    Directory Server related Errors
    """


class PkiLibException(StandardException):
    """
    Override StandardException,
    This exception is to be used for PKI/SSL related Errors
    """


class OSException(StandardException):
    """
    Override StandardException, This exception is to be used for
    Operating system errors.
    """


class LdapException(StandardException):
    """
    Override StandardException, This exception is to be used for LDAP Errors
    """


class RPMException(StandardException):
    """
    Override StandardException, This exception is to be used for RPM Errors
    """


class SSSDException(StandardException):
    """
     Override StandardException, This exception is to be used for SSSD Errors
    """


class SSHLoginException(StandardException):
    """
    Override StandardException,
    This exception is to be used for SSH Login Errors
    """
