#
#   Authors:
#       Pavel Brezina <pbrezina@redhat.com>
#
#   Copyright (C) 2017 Red Hat
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import argparse
from collections import OrderedDict
from sbus_Introspection import Introspectable
from sbus_Template import TemplateFile
from sbus_Generator import Generator
from sbus_DataType import DataType


class CodeGen:
    """
        Code generator support multiple introspection annotations that can
        modify the generator behavior per interface, method or property.

        * Annotations on methods:
        - codegen.CustomHandler
          - boolean, default is false
          - custom input and output handler
        - codegen.CustomInputHandler
          - boolean, default is false
          - handler parses its input parameters manually
        - codegen.CustomOutputHandler
          - boolean, default is false
          - handler parses its output parameters manually

        * Annotations on interfaces, methods or properties:
        - codegen.Name
          - string, default is not set
          - Name used to override member name when generating caller
        - codegen.Caller
          - boolean, default is true
          - Generate both synchronous and asynchronous callers
        - codegen.SyncCaller
          - boolean, default is true
          - Generate synchronous callers
        - codegen.AsyncCaller
          - boolean, default is true
          - Generate asynchronous callers
    """
    def __init__(self, options):
        # Temporarily change working directory so we can load the templates
        self.options = options
        self.templates = CodeGen.Templates(options)
        self.interfaces = OrderedDict()
        return

    def add(self, introspection_file):
        interfaces = Introspectable.Introspect(introspection_file)
        merged = self.interfaces

        for name, interface in interfaces.items():
            if name in self.interfaces:
                raise ValueError("Interface %s already exist!" % name)
            merged[name] = interface

        self.interfaces = OrderedDict(sorted(merged.items()))
        return

    def generate(self):
        Generator.GenerateCode(self.templates, self.interfaces)

    class Options:
        def __init__(self,
                     SbusHeadersPath,
                     UtilHeadersPath,
                     GeneratedHeadersPath,
                     WritePath,
                     FilePrefix,
                     SymbolPrefix,
                     IncludeHeaders):
            self.SbusHeadersPath = SbusHeadersPath
            self.UtilHeadersPath = UtilHeadersPath
            self.GeneratedHeadersPath = GeneratedHeadersPath
            self.WritePath = WritePath
            self.FilePrefix = FilePrefix
            self.SymbolPrefix = SymbolPrefix
            self.IncludeHeaders = []

            if IncludeHeaders is not None:
                self.IncludeHeaders = IncludeHeaders

            self.AbsolutePath = os.path.dirname(os.path.realpath(__file__))
            return

        def path(self, relative_path):
            return "%s/%s" % (self.AbsolutePath, relative_path)

    class Templates:
        GeneratedFiles = [
            "interface.h",
            "symbols.c",
            "symbols.h",
            "arguments.c",
            "arguments.h",
            "invokers.c",
            "invokers.h",
            "keygens.c",
            "keygens.h",
            "client_properties.h",
            "client_async.c",
            "client_async.h",
            "client_sync.c",
            "client_sync.h",
            "server.h"
        ]

        def __init__(self, options):
            self.files = {}
            for file in self.GeneratedFiles:
                self.files[file] = self.File(file, options)

        def get(self, name):
            return self.files[name].template

        def write(self):
            for file in self.files.values():
                file.write()

        class File:
            def __init__(self, name, options):
                self.options = options

                self.name = name
                self.outputFile = self.getAbsFilePath(name)

                self.template = TemplateFile(
                    options.path('./templates/' + name + '.tpl')
                )
                self.setHeader()

            def write(self):
                self.setFooter()
                self.template.write(self.outputFile, self.postprocess)

            def setHeader(self):
                if not self.template.has("file-header"):
                    return

                tpl = self.template.get("file-header")

                for header in self.options.IncludeHeaders:
                    tpl.add("custom-type-header",
                            {'custom-type-header': header})

                keys = {'sbus-path': self.options.SbusHeadersPath,
                        'util-path': self.options.UtilHeadersPath,
                        'file-guard': self.getHeaderGuard(self.name)}

                for file in CodeGen.Templates.GeneratedFiles:
                    if not file.endswith(".h"):
                        continue

                    name = file.replace(".h", "")
                    keys["header:" + name] = self.getRelFilePath(file)

                tpl.set(keys)

            def setFooter(self):
                if not self.template.has("file-footer"):
                    return

                keys = {'file-guard': self.getHeaderGuard(self.name)}

                self.template.get("file-footer").set(keys)

            def getHeaderGuard(self, name):
                guard = "_%s%s_" % (self.options.FilePrefix, name)
                return guard.replace('.', '_').upper()

            def getAbsFilePath(self, name):
                return "%s/%s%s" % \
                    (self.options.WritePath,
                     self.options.FilePrefix,
                     name)

            def getRelFilePath(self, name):
                return "%s/%s%s" % \
                    (self.options.GeneratedHeadersPath,
                     self.options.FilePrefix,
                     name)

            def postprocess(self, output):
                if self.options.SymbolPrefix is None:
                    return output

                return output.replace("_sbus_",
                                      "_sbus_%s_" % self.options.SymbolPrefix)


def InitializeDataTypes():
    """Define which D-Bus types are supported by code generator."""

    # Standard types
    DataType.Create("y", "uint8_t", '" PRIu8 "')
    DataType.Create("b", "bool", "d")
    DataType.Create("n", "int16_t", '" PRId16 "')
    DataType.Create("q", "uint16_t", '" PRIu16 "')
    DataType.Create("i", "int32_t", '" PRId32 "')
    DataType.Create("u", "uint32_t", '" PRIu32 "')
    DataType.Create("x", "int64_t", '" PRId64 "')
    DataType.Create("t", "uint64_t", '" PRIu64 "')
    DataType.Create("d", "double", "f")

    # String types
    DataType.Create("s", "const char *", "s", DBusType="s", RequireTalloc=True)
    DataType.Create("S", "char *", "s", DBusType="s", RequireTalloc=True)
    DataType.Create("o", "const char *", "s", DBusType="o", RequireTalloc=True)
    DataType.Create("O", "char *", "s", DBusType="o", RequireTalloc=True)

    # Array types
    DataType.Create("ay", "uint8_t *", RequireTalloc=True)
    DataType.Create("ab", "bool *", RequireTalloc=True)
    DataType.Create("an", "int16_t *", RequireTalloc=True)
    DataType.Create("aq", "uint16_t *", RequireTalloc=True)
    DataType.Create("ai", "int32_t *", RequireTalloc=True)
    DataType.Create("au", "uint32_t *", RequireTalloc=True)
    DataType.Create("ax", "int64_t *", RequireTalloc=True)
    DataType.Create("at", "uint64_t *", RequireTalloc=True)
    DataType.Create("ad", "double *", RequireTalloc=True)

    # String arrays
    DataType.Create("as", "const char **", DBusType="as", RequireTalloc=True)
    DataType.Create("aS", "char **", DBusType="as", RequireTalloc=True)
    DataType.Create("ao", "const char **", DBusType="ao", RequireTalloc=True)
    DataType.Create("aO", "char **", DBusType="ao", RequireTalloc=True)

    # Custom types
    DataType.Create("pam_data", "struct pam_data *",
                    DBusType="issssssuayuayiu", RequireTalloc=True)
    DataType.Create("pam_response", "struct pam_data *",
                    DBusType="uua(uay)", RequireTalloc=True)
    DataType.Create("ifp_extra", "hash_table_t *",
                    DBusType="a{sas}", RequireTalloc=True)


def main():
    InitializeDataTypes()

    parser = argparse.ArgumentParser(
        description='Generate sbus server and client code.'
    )

    parser.add_argument(
        'introspection', nargs='+',
        help="Path to introspection file"
    )
    required = parser.add_argument_group('Required arguments')
    required.add_argument(
        '--sbus', action="store", dest="sbuspath",
        help="Path to sbus header files as used in #include",
        required=True
    )
    required.add_argument(
        '--util', action="store", dest="utilpath",
        help="Path to util header files as used in #include",
        required=True
    )
    required.add_argument(
        '--headers', action="store", dest="headerpath",
        help="Path to generated header files as used in #include",
        required=True
    )
    required.add_argument(
        '--dest', action="store", dest="destpath",
        help="Path where the generated code will be stored",
        required=True
    )
    required.add_argument(
        '--fileprefix', action="store", dest="fileprefix",
        help="Name prefix for generated files",
        required=True
    )
    optional = parser.add_argument_group('Optional generator arguments')
    optional.add_argument(
        '--symbolprefix', action="store", dest="symbolprefix",
        help="Name prefix for generated global symbols",
        required=False
    )
    optional.add_argument(
        '-i', '--include', action='append', dest="include",
        help="Include header with definition of custom types",
        required=False
    )
    cmdline = parser.parse_args()

    opts = CodeGen.Options(
        SbusHeadersPath=cmdline.sbuspath,
        UtilHeadersPath=cmdline.utilpath,
        GeneratedHeadersPath=cmdline.headerpath,
        WritePath=cmdline.destpath,
        FilePrefix=cmdline.fileprefix,
        SymbolPrefix=cmdline.symbolprefix,
        IncludeHeaders=cmdline.include
    )

    codegen = CodeGen(opts)
    for file in cmdline.introspection:
        codegen.add(file)
    codegen.generate()


if __name__ == "__main__":
    main()
