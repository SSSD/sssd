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

from collections import OrderedDict
from sbus_Invoker import Invoker, InvokerArgumentType, InvokerCaller, InvokerKeygen
from sbus_Introspection import SBus
from sbus_DataType import DataType


class Generator:
    @staticmethod
    def GenerateCode(templates, interfaces):
        """
            Generate asynchronous code for given interfaces.
        """

        class Callers:
            def __init__(self, interfaces, type):
                self.Methods = InvokerCaller.GatherMethodInvokers(interfaces,
                                                                  type)
                self.Signals = InvokerCaller.GatherSignalInvokers(interfaces,
                                                                  type)
                self.Getters = InvokerCaller.GatherGetInvokers(interfaces,
                                                               type)
                self.Setters = InvokerCaller.GatherSetInvokers(interfaces,
                                                               type)

        invokers = Invoker.GatherInvokers(interfaces)
        arguments = InvokerArgumentType.GatherArgumentTypes(interfaces)
        keygens = InvokerKeygen.GatherKeygens(interfaces)
        sync_callers = Callers(interfaces, "sync")
        async_callers = Callers(interfaces, "async")

        generators = [
            Generator.Interfaces(templates.get("interface.h"),
                                 interfaces),

            Generator.Symbols(templates.get("symbols.c"),
                              templates.get("symbols.h"),
                              interfaces),

            Generator.Arguments(templates.get("arguments.c"),
                                templates.get("arguments.h"),
                                arguments),

            Generator.Invokers(templates.get("invokers.c"),
                               templates.get("invokers.h"),
                               invokers),

            Generator.Keygens(templates.get("keygens.c"),
                              templates.get("keygens.h"),
                              keygens),

            Generator.Properties(templates.get("client_properties.h"),
                                 interfaces),

            Generator.MethodCalls(templates.get("client_async.c"),
                                  templates.get("client_async.h"),
                                  interfaces, "async", async_callers.Methods),

            Generator.SignalCalls(templates.get("client_async.c"),
                                  templates.get("client_async.h"),
                                  interfaces, "async", async_callers.Signals),

            Generator.PropertyCalls(templates.get("client_async.c"),
                                    templates.get("client_async.h"),
                                    interfaces, "async",
                                    async_callers.Getters,
                                    async_callers.Setters),

            Generator.MethodCalls(templates.get("client_sync.c"),
                                  templates.get("client_sync.h"),
                                  interfaces, "sync", sync_callers.Methods),

            Generator.SignalCalls(templates.get("client_sync.c"),
                                  templates.get("client_sync.h"),
                                  interfaces, "sync", sync_callers.Signals),

            Generator.PropertyCalls(templates.get("client_sync.c"),
                                    templates.get("client_sync.h"),
                                    interfaces, "sync",
                                    sync_callers.Getters,
                                    sync_callers.Setters)
        ]

        for generator in generators:
            generator.generate()

        templates.write()

    @staticmethod
    def FilterAnnotations(annotations):
        dict = OrderedDict()
        if annotations is None or not annotations:
            return dict

        for name, annotation in annotations.items():
            if not name.startswith("codegen."):
                dict[name] = annotation

        return dict

    class Base(object):
        """
            Base object for code generators.

            Children must implement generate() method.
        """

        def __init__(self):
            pass

        def generate(self):
            """ Make sure generate() method is implemented by children. """
            raise NotImplementedError("Method generate() is not implemented!")

        def tokenizeValue(self, *values):
            """ Concatenate valus into C token. """
            name = ""
            for value in values:
                name += '.' + value

            return name.strip('.').replace('.', '_')

        def tokenizeName(self, *values):
            """ Concatenate value.name into C token. """
            name = ""
            for value in values:
                name += '.' + value.name

            return name.strip('.').replace('.', '_')

        def setInputArguments(self, tpl, sbus_signature):
            """
                Set input arguments in template.
            """
            if Invoker.IsCustomInputHandler(sbus_signature):
                if tpl.hasLoop("in-raw"):
                    tpl.add("in-raw", {'type': "DBusMessageIter *"})
                return

            for idx, arg in enumerate(sbus_signature.arguments.values()):
                tpl.add("in", {'type': DataType.Find(arg.signature).inputCType,
                               'name': arg.name,
                               'index': idx})

        def setOutputArguments(self, tpl, sbus_signature):
            """
                Set output arguments in template.
            """
            if Invoker.IsCustomOutputHandler(sbus_signature):
                if tpl.hasLoop("out-raw"):
                    tpl.add("out-raw", {'type': "DBusMessageIter *"})
                return

            if tpl.hasLoop("out-static"):
                for idx, arg in enumerate(sbus_signature.arguments.values()):
                    type = DataType.Find(arg.signature)
                    if type.RequireTalloc:
                        continue

                    tpl.add("out-static", {'type': type.outputCType,
                                           'name': arg.name,
                                           'index': idx})

            if tpl.hasLoop("out-talloc"):
                for idx, arg in enumerate(sbus_signature.arguments.values()):
                    type = DataType.Find(arg.signature)
                    if not type.RequireTalloc:
                        continue

                    tpl.add("out-talloc", {'type': type.outputCType,
                                           'name': arg.name,
                                           'index': idx})

            if tpl.hasLoop("out"):
                for idx, arg in enumerate(sbus_signature.arguments.values()):
                    tpl.add("out", {
                        'type': DataType.Find(arg.signature).outputCType,
                        'name': arg.name,
                        'index': idx
                    })

        def getInterfaceName(self, iface):
            """
                If a codegen.Name annotation is specified, this name is used
                returned of a full D-Bus name.
            """
            annotation = "codegen.Name"
            iface_name = SBus.Annotation.Find(iface.annotations, annotation,
                                              iface.name)

            return self.tokenizeValue(iface_name)

        def getMemberName(self, iface, member):
            """
                If a codegen.Name annotation is specified, this name is used
                returned of a full D-Bus name.
            """
            annotation = "codegen.Name"
            member_name = SBus.Annotation.Find(member.annotations, annotation,
                                               member.name)

            return self.tokenizeValue(self.getInterfaceName(iface),
                                      member_name)

        def hasEmpty(self, invoker_signature):
            """
                Return true if the invoker signature has empty argument list.
            """
            return invoker_signature.invokerSignature == ""

        def hasRaw(self, invoker_signature):
            """
                Return true if the invoker signature has a custom handler.
            """
            return invoker_signature.invokerSignature == "raw"

        def hasAny(self, invoker_signature):
            """
                Return true if the invoker signature has any arguments.
            """
            return bool(invoker_signature.arguments) or \
                self.hasRaw(invoker_signature)

        def hasParsable(self, invoker_signature):
            """
                Return true if the invoker signature has any parsable
                arguments.
            """
            return invoker_signature.invokerSignature not in ["", "raw"]

        def outputNeedTalloc(self, invoker_signature):
            if self.hasRaw(invoker_signature):
                return True

            for idx, arg in enumerate(invoker_signature.arguments.values()):
                type = DataType.Find(arg.signature)
                if type.RequireTalloc:
                    return True

            return False

    class Interfaces(Base):
        """
            Generator for:

            - interfaces.h
        """

        def __init__(self, header, interfaces):
            super(Generator.Interfaces, self).__init__()

            self.header = header
            self.interfaces = interfaces

        def toggleKeygen(self, tpl, keys, member, sbus_signature):
            """
                Insert a keygen information if this member supports keying.
            """

            if not tpl.hasToggle("keygen"):
                return

            args = InvokerKeygen.GatherKeyArguments(member, sbus_signature)

            if args is None:
                tpl.show("keygen", False)
                return

            tpl.show('keygen', True)

            for idx, arg in args.items():
                type = DataType.Find(arg.signature)

                if type.keyFormat is None:
                    raise ValueError(
                        ('Data type "%s" does not '
                         'support key generator') % type.sbus_type
                    )

                tpl.add('key-argument', {
                    'key-index': idx,
                    'key-format': type.keyFormat
                })

            keys['key-signature'] = sbus_signature.signature

        def toggleAnnotations(self, tpl, annotations):
            """
                Make annotations section visible if there are any to show.
            """

            # We do not include codegen annotations.
            filtered = Generator.FilterAnnotations(annotations)

            show = True
            if filtered is None or not filtered:
                show = False

            tpl.show("annotations", show)

        def setMember(self, template_name, interface, member):
            tpl = self.header.get(template_name)

            invoker = Invoker(member.input, member.output)

            keys = {
                'interface': interface.name,
                'name': member.name,
                'token': self.tokenizeName(interface, member),
                'input-signature': invoker.input.invokerSignature,
                'output-signature': invoker.output.invokerSignature
            }

            if hasattr(member, 'type'):
                keys['type'] = DataType.SBusToDBusType(member.type)

            self.toggleKeygen(tpl, keys, member, member.input)
            self.toggleAnnotations(tpl, member.annotations)
            self.setInputArguments(tpl, member.input)
            self.setOutputArguments(tpl, member.output)

            tpl.set(keys)

        def setInterface(self, template_name, interface):
            tpl = self.header.get(template_name)

            self.toggleAnnotations(tpl, interface.annotations)

            keys = {
                'name': interface.name,
                'token': self.tokenizeName(interface),
            }

            tpl.set(keys)

        def generate(self):
            for interface in self.interfaces.values():
                self.setInterface('interface', interface)

                for method in interface.methods.values():
                    self.setMember('method', interface, method)

                for signal in interface.signals.values():
                    self.setMember('signal', interface, signal)

                for property in interface.properties.values():
                    self.setMember('property', interface, property)

    class Symbols(Base):
        """
            Generator for:

            - symbols.c
            - symbols.h
        """

        def __init__(self, source, header, interfaces):
            super(Generator.Symbols, self).__init__()

            self.source = source
            self.header = header
            self.interfaces = interfaces

        def annotation(self, annotation):
            value = "NULL"
            if annotation.value is not None:
                value = '"%s"' % annotation.value

            return {
                'annotation-name': annotation.name,
                'annotation-value': value
            }

        def argument(self, argument):
            return {
                'arg-type': DataType.SBusToDBusType(argument.signature),
                'arg-name': argument.name
            }

        def generateAnnotations(self, token, annotations):
            # We do not include codegen annotations.
            filtered = Generator.FilterAnnotations(annotations)

            if filtered is None or not filtered:
                return

            tpl = self.source.get('annotations')

            for annotation in filtered.values():
                tpl.add('annotation', self.annotation(annotation))

            keys = {'token': token}
            tpl.set(keys)
            self.header.get('annotations').set(keys)

        def generateMember(self, interface, member, type):
            token = self.tokenizeName(interface, member)
            keys = {'token': token}

            tpl = self.source.get(type)
            for arg in member.input.arguments.values():
                tpl.add('input', self.argument(arg))

            for arg in member.output.arguments.values():
                tpl.add('output', self.argument(arg))

            tpl.set(keys)
            self.header.get(type).set(keys)
            self.generateAnnotations(token, member.annotations)

        def generate(self):
            for interface in self.interfaces.values():
                self.generateAnnotations(self.tokenizeName(interface),
                                         interface.annotations)

                for method in interface.methods.values():
                    self.generateMember(interface, method, 'method')

                for signal in interface.signals.values():
                    self.generateMember(interface, signal, 'signal')

    class Arguments(Base):
        """
            Generator for:

            - arguments.c
            - arguments.h
        """

        def __init__(self, source, header, invoker_arguments):
            super(Generator.Arguments, self).__init__()

            self.source = source
            self.header = header
            self.invoker_arguments = invoker_arguments

        def generate(self):
            self.generateSource()
            self.generateHeader()

        def generateSource(self):
            tpl = self.source.get("arguments")
            for signature, args in self.invoker_arguments.items():
                for idx, arg in enumerate(args.values()):
                    type = DataType.Find(arg.signature)
                    memctx = "mem_ctx, " if type.RequireTalloc else ""
                    keys = {"arg-signature": arg.signature,
                            "talloc-context": memctx,
                            "index": idx}
                    tpl.add('read-argument', keys)
                    tpl.add('write-argument', keys)

                keys = {"signature": signature}
                tpl.set(keys)

        def generateHeader(self):
            tpl = self.header.get("arguments")
            for signature, args in self.invoker_arguments.items():
                for idx, arg in enumerate(args.values()):
                    keys = {"type": DataType.Find(arg.signature).inputCType,
                            "index": idx}
                    tpl.add('args', keys)

                keys = {"signature": signature}
                tpl.set(keys)

    class Invokers(Base):
        """
            Generator for:

            - invokers.c
            - invokers.h
        """

        def __init__(self, source, header, invokers):
            super(Generator.Invokers, self).__init__()

            self.source = source
            self.header = header
            self.invokers = invokers

        def generate(self):
            self.generateSource()
            self.generateHeader()

        def generateSource(self):
            tpl = self.source.get("invoker")
            for invoker in self.invokers.values():
                tpl.show("if-input-arguments",
                         self.hasParsable(invoker.input))
                tpl.show("if-output-arguments",
                         self.hasParsable(invoker.output))

                self.setInputArguments(tpl, invoker.input)
                self.setOutputArguments(tpl, invoker.output)

                keys = {"input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature}

                tpl.set(keys)

        def generateHeader(self):
            tpl = self.header.get("invoker")
            for invoker in self.invokers.values():
                keys = {"input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature}
                tpl.set(keys)

    class Keygens(Base):
        """
            Generator for:

            - keygens.c
            - keygens.h
        """

        def __init__(self, source, header, keygens):
            super(Generator.Keygens, self).__init__()

            self.source = source
            self.header = header
            self.keygens = keygens

        def generate(self):
            for pair in self.keygens.values():
                name = 'key' if pair.arguments else 'key-no-arguments'

                self.set(self.source.get(name), pair.signature, pair.arguments)
                self.set(self.header.get(name), pair.signature, pair.arguments)

        def set(self, tpl, signature, args):
            if args is None:
                return

            for idx, arg in args.items():
                type = DataType.Find(arg.signature)

                if type.keyFormat is None:
                    raise ValueError(
                        ('Data type "%s" does not '
                         'support key generator') % type.sbus_type
                    )

                tpl.add('key-argument', {
                    'key-index': idx,
                    'key-format': type.keyFormat
                })

            tpl.set({'key-signature': signature})

    class Properties(Base):
        """
            Generator for:

            - client_properties.h
        """

        def __init__(self, header, interfaces):
            super(Generator.Properties, self).__init__()

            self.header = header
            self.interfaces = interfaces

        def generate(self):
            tpl = self.header.get("properties")
            for iface in self.interfaces.values():
                if not iface.properties:
                    continue

                added = False

                for property in iface.properties.values():
                    if not property.isReadable():
                        continue

                    if not InvokerCaller.IsWanted(iface, property, "either"):
                        continue

                    added = True

                    type = DataType.Find(property.type)
                    tpl.add("property", {'name': property.name,
                                         'input-type': type.inputCType})

                # Do not generate GetAll caller if we are not interested in
                # properties callers.
                if not added:
                    tpl.clear()
                    continue

                keys = {"token": self.getInterfaceName(iface)}

                tpl.set(keys)

    class MethodCalls(Base):
        """
            Generator for sync and async method callers.
        """

        def __init__(self, source, header, interfaces, type, invokers):
            super(Generator.MethodCalls, self).__init__()

            self.source = source
            self.header = header
            self.interfaces = interfaces
            self.type = type
            self.invokers = invokers

        def generate(self):
            self.generateInvokers()
            self.generateCallers(self.source.get("method-caller"))
            self.generateCallers(self.header.get("method-caller"))

        def generateInvokers(self):
            tpl = self.source.get("method-invoker")
            for invoker in self.invokers.values():
                tpl.show("if-input-arguments",
                         self.hasParsable(invoker.input))
                tpl.show("if-output-arguments",
                         self.hasParsable(invoker.output))
                tpl.show("if-raw-input",
                         self.hasRaw(invoker.input))
                tpl.show("if-raw-output",
                         self.hasRaw(invoker.output))
                tpl.show("if-empty-input",
                         self.hasEmpty(invoker.input))
                tpl.show("if-has-output",
                         self.hasAny(invoker.output))
                tpl.show("if-use-talloc",
                         self.outputNeedTalloc(invoker.output))
                tpl.show("if-show-dummy",
                         self.showDummy(invoker))

                self.setInputArguments(tpl, invoker.input)
                self.setOutputArguments(tpl, invoker.output)

                keys = {"input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature}

                tpl.set(keys)

        def generateCallers(self, tpl):
            for iface in self.interfaces.values():
                for method in iface.methods.values():
                    if not InvokerCaller.IsWanted(iface, method, self.type):
                        continue

                    invoker = Invoker(method.input, method.output)
                    tpl.show("if-raw-input",
                             self.hasRaw(invoker.input))
                    tpl.show("if-raw-output",
                             self.hasRaw(invoker.output))
                    tpl.show("if-has-output",
                             self.hasAny(invoker.output))
                    tpl.show("if-use-talloc",
                             self.outputNeedTalloc(invoker.output))

                    self.setInputArguments(tpl, invoker.input)
                    self.setOutputArguments(tpl, invoker.output)

                    keygen = InvokerKeygen.BuildKeygenName(method,
                                                           method.input)
                    keys = {
                        "token": self.getMemberName(iface, method),
                        "iface": iface.name,
                        "method": method.name,
                        "keygen": keygen,
                        "input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature
                    }

                    tpl.set(keys)

        def showDummy(self, invoker):
            return self.hasEmpty(invoker.output) and not \
                self.hasParsable(invoker.input)

    class SignalCalls(Base):
        """
            Generator for sync and async signal callers.
        """

        def __init__(self, source, header, interfaces, type, invokers):
            super(Generator.SignalCalls, self).__init__()

            self.source = source
            self.header = header
            self.interfaces = interfaces
            self.type = type
            self.invokers = invokers

        def generate(self):
            self.generateInvokers()
            self.generateCallers(self.source.get("signal-caller"))
            self.generateCallers(self.header.get("signal-caller"))

        def generateInvokers(self):
            tpl = self.source.get("signal-invoker")
            for invoker in self.invokers.values():
                tpl.show("if-input-arguments", self.hasParsable(invoker.input))
                tpl.show("if-empty-input", self.hasEmpty(invoker.input))
                tpl.show("if-raw-input", self.hasRaw(invoker.input))

                self.setInputArguments(tpl, invoker.input)

                keys = {"input-signature": invoker.input.invokerSignature}

                tpl.set(keys)

        def generateCallers(self, tpl):
            for iface in self.interfaces.values():
                for signal in iface.signals.values():
                    if not InvokerCaller.IsWanted(iface, signal, self.type):
                        continue

                    invoker = Invoker(signal.input, signal.output)
                    tpl.show("if-raw-input", self.hasRaw(invoker.input))

                    self.setInputArguments(tpl, invoker.input)

                    keys = {"token": self.getMemberName(iface, signal),
                            "iface": iface.name,
                            "signal": signal.name,
                            "input-signature": invoker.input.invokerSignature}

                    tpl.set(keys)

    class PropertyCalls(Base):
        """
            Generator for sync and async property callers.
        """

        def __init__(self, source, header, interfaces, type,
                     get_invokers, set_invokers):
            super(Generator.PropertyCalls, self).__init__()

            self.source = source
            self.header = header
            self.interfaces = interfaces
            self.type = type
            self.get_invokers = get_invokers
            self.set_invokers = set_invokers

        def generate(self):
            self.generateInvokers(self.source.get("get-invoker"),
                                  self.get_invokers)
            self.generateInvokers(self.source.get("set-invoker"),
                                  self.set_invokers)
            self.generateCallers(self.source.get("property-caller"))
            self.generateCallers(self.header.get("property-caller"))
            self.generateGetAll(self.source.get("getall-caller"))
            self.generateGetAll(self.header.get("getall-caller"))

        def generateInvokers(self, tpl, invokers):
            for invoker in invokers.values():
                type = None
                if self.hasAny(invoker.input):
                    type = DataType.Find(
                        invoker.input.arguments['value'].signature
                    )
                elif self.hasAny(invoker.output):
                    type = DataType.Find(
                        invoker.output.arguments['value'].signature
                    )
                else:
                    raise ValueError(
                        'Invoker has no input nor output argument\n'
                    )

                tpl.show("if-use-talloc", type.RequireTalloc)

                keys = {"input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature,
                        "input-type": type.inputCType,
                        "output-type": type.outputCType,
                        "dbus-type": type.dbus_type}

                tpl.set(keys)

        def generateCallers(self, tpl):
            for iface in self.interfaces.values():
                for property in iface.properties.values():
                    if not InvokerCaller.IsWanted(iface, property, self.type):
                        continue

                    if property.isReadable():
                        tpl.show("get", True)

                    if property.isWritable():
                        tpl.show("set", True)

                    invoker = Invoker(property.input, property.output)
                    type = DataType.Find(property.type)

                    tpl.show("get-static", not type.RequireTalloc)
                    tpl.show("get-talloc", type.RequireTalloc)

                    keys = {
                        "token": self.getMemberName(iface, property),
                        "iface": iface.name,
                        "property": property.name,
                        "input-signature": invoker.input.invokerSignature,
                        "output-signature": invoker.output.invokerSignature,
                        "input-type": type.inputCType,
                        "output-type": type.outputCType
                    }

                    tpl.set(keys)

        def generateGetAll(self, tpl):
            for iface in self.interfaces.values():
                if not iface.properties:
                    continue

                added = False

                for property in iface.properties.values():
                    if not property.isReadable():
                        continue

                    if not InvokerCaller.IsWanted(iface, property, self.type):
                        continue

                    added = True

                    type = DataType.Find(property.type)
                    invoker = Invoker(property.input, property.output)

                    loop_name = 'property-static'
                    if type.RequireTalloc:
                        loop_name = 'property-talloc'

                    tpl.add(loop_name, {
                        'name': property.name,
                        'input-type': type.inputCType,
                        'output-type': type.outputCType,
                        'output-signature': invoker.output.invokerSignature
                    })

                # Do not generate GetAll caller if we are not interested in
                # properties callers.
                if not added:
                    tpl.clear()
                    continue

                keys = {"token": self.getInterfaceName(iface),
                        "iface": iface.name}

                tpl.set(keys)
