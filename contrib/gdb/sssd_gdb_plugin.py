# SSSD and LDB debugging plugins
#
# Activate them by putting:
#   source /path/to/this/file.py
# to your .gdbinit file
#
# To bypass the pretty printer and print the raw values, use the "/r" option:
#   print /r foobar
import gdb


def gdb_printer_decorator(fn):
    gdb.pretty_printers.append(fn)
    return fn


def indent_string(s, indent):
    return '\n'.join(["%s%s" % ("\t" * indent, part)
                     for part in s.split('\n')])


class StringPrinter(object):
    "Shared code between different string-printing classes"
    def __init__(self, val):
        self.val = val

    def to_string(self):
        return self.as_string()


class LdbDnPrinter(StringPrinter):
    " print an ldb dn "

    def as_string(self, indent=0):
        ret = "{ <%s>\tlinearized:%s }" % (self.val.type,
                                           self.val['linearized'])
        return indent_string(ret, indent)


class LdbValPrinter(StringPrinter):
    " print a ldb value"

    def as_string(self, indent=0):
        ret = "data = %(data)s, length = %(length)s" % self.val
        return indent_string("{ <%s>\t%s }" % (self.val.type, ret), indent)


class LdbMessageElementPrinter(StringPrinter):
    " print a ldb message element "

    def as_string(self, indent=0):
        ret = "flags = %(flags)s, name = %(name)s, " \
            "num_values = %(num_values)s" % self.val
        try:
            nvals = int(self.val['num_values'])
        except ValueError:
            return "num_values is not numeric?"

        for i in range(nvals):
            ldbval = LdbValPrinter(self.val['values'][i])
            ret += "\n%s" % (ldbval.as_string(indent + 1))

        return indent_string("{ <%s>\t%s }" % (self.val.type, ret), indent)


class LdbMessagePrinter(StringPrinter):
    " print a ldb message "

    def as_string(self, indent=0):
        try:
            nels = int(self.val['num_elements'])
        except ValueError:
            return "num_elements is not numeric?"

        dn = LdbDnPrinter(self.val['dn'])
        dn_str = dn.as_string(indent)
        ret = "num_elements:\t%s\ndn:\t%s\nelements:\t" % (nels, dn_str)

        for i in range(nels):
            el = LdbMessageElementPrinter(self.val['elements'][i])
            ret += "\n%s" % (el.as_string(indent + 1))

        return indent_string("{ <%s>\n%s }" % (self.val.type, ret), indent)


class LdbResultPrinter(StringPrinter):
    " print a ldb message element "

    def as_string(self, indent=0):
        ret = "count = %(count)s, extended = %(extended)s, " \
            "controls = %(controls)s, refs = %(refs)s" % self.val
        try:
            count = int(self.val['count'])
        except ValueError:
            ret += 'Count is not numeric value?'
            return ret

        for i in range(count):
            msg = LdbMessagePrinter(self.val['msgs'][i])
            ret += "\n%s" % (msg.as_string(indent + 1))

        return indent_string("{ <%s>\t%s }" % (self.val.type, ret), indent)


class SysdbAttrsPrinter(StringPrinter):
    " print a struct sysdb attrs "

    def as_string(self, indent=0):
        ret = "num = %(num)s" % self.val

        try:
            num = int(self.val['num'])
        except ValueError:
            ret += 'num is not numeric value?'
            return ret

        for i in range(num):
            el = LdbMessageElementPrinter(self.val['a'][i])
            ret += "\n%s" % (el.as_string(indent + 1))

        return indent_string("{ <%s>\t%s }" % (self.val.type, ret), indent)


# ---
# --- register pretty printers ---
# ---
@gdb_printer_decorator
def ldb_dn_element_printer(val):
    if str(val.type) == 'struct ldb_dn':
        return LdbDnPrinter(val)
    return None


@gdb_printer_decorator
def ldb_val_element_printer(val):
    if str(val.type) == 'struct ldb_val':
        return LdbValPrinter(val)
    return None


@gdb_printer_decorator
def ldb_message_element_printer(val):
    if str(val.type) == 'struct ldb_message_element':
        return LdbMessageElementPrinter(val)
    return None


@gdb_printer_decorator
def ldb_message_printer(val):
    if str(val.type) == 'struct ldb_message':
        return LdbMessagePrinter(val)
    return None


@gdb_printer_decorator
def ldb_result_printer(val):
    if str(val.type) == 'struct ldb_result':
        return LdbResultPrinter(val)
    return None


@gdb_printer_decorator
def sysdb_attrs_printer(val):
    if str(val.type) == 'struct sysdb_attrs':
        return SysdbAttrsPrinter(val)
    return None


# ---
# --- set a breakpoint at the tevent_req finish fn ---
# ---
class TeventBreak(gdb.Command):
    """Break at the tevent finish location """

    def __init__(self):
        super(TeventBreak, self).__init__("tbr", gdb.COMMAND_BREAKPOINTS)

    def invoke(self, arg, from_tty):
        req = gdb.parse_and_eval(arg)
        if not hasattr(req, 'type'):
            print('cannot determine the type of the variable')
            return
        if str(req.type) != 'struct tevent_req *':
            print('wrong attribute - must be a tevent_req pointer')
            return

        try:
            fn = req['async']['fn']
        except KeyError:
            print("No async function defined?")
            return

        try:
            fnaddr = str(fn).split()[0].strip()
        except IndexError:
            print("Cannot get function address")
            return

        gdb.Breakpoint("*%s" % fnaddr)


TeventBreak()
