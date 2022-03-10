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
from sbus_Introspection import SBus


class Invoker:
    """ Invoker is a piece of C code that takes care of executing a method,
        signal and property handlers and returning their output values.

        SBus code generator tries to reduce amount of generated code by
        reusing invokers whenever possible. Therefore we must ensure that
        invoker for each input and output signature type is generated only
        once.

        Each invoker is associated with its input and output SBus signatures
        extended by a reserved keyword "raw" that says that the invoker input
        or output parameters are handled by its handler and caller respectively
        and are passed through as D-Bus iterators.
    """
    def __init__(self, sbus_input, sbus_output):
        self.input = self.getSignature(sbus_input,
                                       self.IsCustomInputHandler(sbus_input))

        self.output = self.getSignature(
            sbus_output,
            self.IsCustomOutputHandler(sbus_output)
        )

    def getSignature(self, sbus_signature, is_custom_handler):
        if sbus_signature is None:
            return InvokerSignature("", {}, {})

        invoker_signature = sbus_signature.signature
        if is_custom_handler:
            invoker_signature = "raw"

        return InvokerSignature(invoker_signature,
                                sbus_signature.arguments,
                                sbus_signature.annotations)

    @staticmethod
    def GatherInvokers(interfaces):
        """
            Gather all required invokers for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for method in iface.methods.values():
                Invoker.Add(dict, method.input, method.output)

            for signal in iface.signals.values():
                Invoker.Add(dict, signal.input, signal.output)

            for property in iface.properties.values():
                if property.isReadable():
                    Invoker.Add(dict, None, property.output)
                if property.isWritable():
                    Invoker.Add(dict, property.input, None)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def Add(dict, input, output):
        """
            Add a new invoker to dictionary if possible.
        """
        invoker = Invoker(input, output)
        key = "in:%s, out:%s" % (invoker.input.invokerSignature,
                                 invoker.output.invokerSignature)
        if key in dict:
            return

        dict[key] = invoker

    @staticmethod
    def IsCustomHandler(type, sbus_signature):
        if type == "input":
            return Invoker.IsCustomInputHandler(sbus_signature)
        elif type == "output":
            return Invoker.IsCustomOutputHandler(sbus_signature)
        else:
            raise ValueError("Invalid type: %s" % type)

    @staticmethod
    def IsCustomInputHandler(sbus_signature):
        names = ["codegen.CustomHandler",
                 "codegen.CustomInputHandler"]

        if sbus_signature is None:
            return False

        return SBus.Annotation.CheckIfTrue(names, sbus_signature.annotations)

    @staticmethod
    def IsCustomOutputHandler(sbus_signature):
        names = ["codegen.CustomHandler",
                 "codegen.CustomOutputHandler"]

        if sbus_signature is None:
            return False

        return SBus.Annotation.CheckIfTrue(names, sbus_signature.annotations)


class InvokerSignature:
    """ Contains information about Invoker signature and SBus arguments
        and annotations. Do not confuse with SBus.Signature.
    """
    def __init__(self, invoker_signature, sbus_arguments, sbus_annotations):
        self.invokerSignature = invoker_signature
        self.arguments = sbus_arguments
        self.annotations = sbus_annotations


class InvokerArgumentType:
    """ Argument reader/writer is a piece of C code that takes care of
        parsing D-Bus methods into C types.

        SBus code generator tries to reduce amount of generated code by
        reusing reades and writers whenever possible. Therefore we must ensure
        that only one reader and writer is generated for each input and output
        signature.
    """
    @staticmethod
    def GatherArgumentTypes(interfaces):
        """
            Gather all invoker argument types for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            InvokerArgumentType.AddObjects(dict, iface.methods)
            InvokerArgumentType.AddObjects(dict, iface.signals)
            InvokerArgumentType.AddObjects(dict, iface.properties)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def AddObjects(dict, objects):
        for object in objects.values():
            InvokerArgumentType.AddType(dict, "input", object.input)
            InvokerArgumentType.AddType(dict, "output", object.output)

    @staticmethod
    def AddType(dict, type, sbus_signature):
        """
            Add a new argument type to dictionary if possible.
        """
        # We don't generate readers and writers for empty arguments
        if sbus_signature is None or not sbus_signature.arguments:
            return

        # We don't generate readers and writers for custom handlers
        if Invoker.IsCustomHandler(type, sbus_signature):
            return

        # We generate each reader and writer only once
        if sbus_signature.signature in dict:
            return

        dict[sbus_signature.signature] = sbus_signature.arguments


class InvokerKeygen:
    """ Invoker Keygen is a piece of C code that takes care of
        chaining same request into one.

        SBus code generator tries to reduce amount of generated code by
        reusing keygens whenever possible. Therefore we must ensure
        that only one keygen is generated for each signature.
    """
    @staticmethod
    def BuildKey(sbus_member, sbus_signature, Args=None):
        """
            Return dictionary key for given SBUS member and signature or None
            if no keying is supported for this member.
        """
        args = Args if not None else \
            InvokerKeygen.GatherKeyArguments(sbus_member, sbus_signature)

        if args is None:
            return None

        key = sbus_signature.signature if args else "<no-arguments>"

        for idx, arg in args.items():
            key += ',%d' % idx

        return key

    @staticmethod
    def BuildKeygenName(sbus_member, sbus_signature):
        args = InvokerKeygen.GatherKeyArguments(sbus_member, sbus_signature)

        if args is None:
            return "NULL"

        keygen = "_sbus_key_%s" % sbus_signature.signature

        for idx, arg in args.items():
            keygen += '_%d' % idx

        return keygen

    @staticmethod
    def GatherKeyArguments(sbus_member, sbus_signature):
        """
            Gather list of key arguments for an SBus member with given
            signature.

            Return dictionary of <argument-index, argument> sorted by
            its key index or an empty dictionary if no arguments are
            necessary to construct a key.

            Return None for SBus members that do not allow keying.
        """
        keys = {}

        if sbus_signature is not None:
            for idx, arg in enumerate(sbus_signature.arguments.values()):
                if arg.key is not None:
                    keys[idx] = arg

        if not keys and sbus_member.key is None:
            return None

        return OrderedDict(sorted(keys.items(),
                           key=lambda p: p[1].key))

    @staticmethod
    def GatherKeygens(interfaces):
        """
            Gather all keygens needed to implement given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for method in iface.methods.values():
                InvokerKeygen.Add(dict, method, method.input)

            for signal in iface.signals.values():
                InvokerKeygen.Add(dict, signal, signal.input)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def Add(dict, sbus_member, sbus_signature):
        """
            Add a new keygen to dictionary if possible.
        """
        args = InvokerKeygen.GatherKeyArguments(sbus_member, sbus_signature)

        if args is None:
            return

        key = InvokerKeygen.BuildKey(sbus_member, sbus_signature, Args=args)
        dict[key] = InvokerKeygen.KeygenPair(sbus_signature, args)

    class KeygenPair:
        def __init__(self, sbus_signature, arguments):
            self.signature = sbus_signature.signature
            self.arguments = arguments


class InvokerCaller:
    """ Caller invoker is a piece of C code that takes care of executing
        an outgoing method, signal or property and returning their output.

        SBus code generator tries to reduce amount of generated code by
        reusing invokers whenever possible. Therefore we must ensure that
        invoker for each input and output signature type is generated only
        once.
    """
    @staticmethod
    def GatherMethodInvokers(interfaces, type):
        """
            Gather all required method invokers for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for method in iface.methods.values():
                if not InvokerCaller.IsWanted(iface, method, type):
                    continue

                InvokerCaller.Add(dict, method.input, method.output)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def GatherSignalInvokers(interfaces, type):
        """
            Gather all required signal invokers for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for signal in iface.signals.values():
                if not InvokerCaller.IsWanted(iface, signal, type):
                    continue

                InvokerCaller.Add(dict, signal.input, signal.output)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def GatherGetInvokers(interfaces, type):
        """
            Gather all required property getters for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for property in iface.properties.values():
                if not InvokerCaller.IsWanted(iface, property, type):
                    continue

                if not property.isReadable():
                    continue

                InvokerCaller.Add(dict, None, property.output)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def GatherSetInvokers(interfaces, type):
        """
            Gather all required property setters for given interfaces.
        """
        dict = {}
        for iface in interfaces.values():
            for property in iface.properties.values():
                if not InvokerCaller.IsWanted(iface, property, type):
                    continue

                if not property.isWritable():
                    continue

                InvokerCaller.Add(dict, property.input, None)

        return OrderedDict(sorted(dict.items()))

    @staticmethod
    def Add(dict, input, output):
        """
            Add a new invoker to dictionary if possible.
        """
        invoker = Invoker(input, output)
        key = "in:%s, out:%s" % (invoker.input.invokerSignature,
                                 invoker.output.invokerSignature)
        if key in dict:
            return

        dict[key] = invoker

    @staticmethod
    def IsWantedSync(interface, member):
        names = ["codegen.Caller", "codegen.SyncCaller"]
        # First see if the member has one of these annotations
        if SBus.Annotation.AtleastOneIsSet(names, member.annotations):
            return SBus.Annotation.CheckIfFalse(names, member.annotations)

        return SBus.Annotation.CheckIfFalse(names, interface.annotations)

    @staticmethod
    def IsWantedAsync(interface, member):
        names = ["codegen.Caller", "codegen.AsyncCaller"]

        # First see if the member has one of these annotations
        if SBus.Annotation.AtleastOneIsSet(names, member.annotations):
            return SBus.Annotation.CheckIfFalse(names, member.annotations)

        return SBus.Annotation.CheckIfFalse(names, interface.annotations)

    @staticmethod
    def IsWanted(interface, member, type):
        if type == "sync":
            return InvokerCaller.IsWantedSync(interface, member)
        elif type == "async":
            return InvokerCaller.IsWantedAsync(interface, member)

        wanted_sync = InvokerCaller.IsWantedSync(interface, member)
        wanted_async = InvokerCaller.IsWantedAsync(interface, member)

        return wanted_sync or wanted_async
