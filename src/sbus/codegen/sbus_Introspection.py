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
import xml.etree.ElementTree as etree


class Introspectable:
    class Element(object):
        """ This is a basic introspectable object. This class will make
            sure that the given xml element is of correct type and provide
            some helper functions to simplify work of the children.

            Children objects must implement TagName attribute, which contains
            the name of the expected xml tag.

            All introspectable objects contain the following properties:
            - name : str -- name of the object
            - annotations : OrderedDict -- available annotations
        """
        def __init__(self, element):
            self.check(element, self.TagName)

            self.element = element
            self.name = element.attrib["name"]
            self.annotations = self.find(SBus.Annotation)

        def find(self, object_class):
            return Introspectable.FindElements(self.element, object_class)

        def check(self, element, tagname):
            if element.tag != tagname:
                raise ValueError('Unexpected tag name "%s" (%s expected)!'
                                 % (element.tag, tagname))
            if "name" not in element.attrib:
                raise ValueError('Missing attribute name!')

        def getAttr(self, name, default_value):
            return self.element.attrib.get(name, default_value)

        def getExistingAttr(self, name):
            if name not in self.element.attrib:
                raise ValueError('Element %s name="%s" is missing attribute %s'
                                 % (self.TagName, self.name, name))

            return self.element.attrib[name]

    class Invokable(Element):
        """ This is a base class for invokable objects -- methods and signals.
            Invokable objects has available additional attributes:

            - input OrderedDict -- input signature and arguments
            - output : OrderedDict -- output signature and arguments
        """
        def __init__(self, element):
            super(Introspectable.Invokable, self).__init__(element)

            self.key = self.getAttr("key", None)

            self.arguments = self.find(SBus.Argument)
            input = self.getInputArguments()
            output = self.getOutputArguments()

            self.input = SBus.Signature(input, self.annotations)
            self.output = SBus.Signature(output, self.annotations)
            return

        def getInputArguments(self):
            return self.getArguments("in")

        def getOutputArguments(self):
            return self.getArguments("out")

        def getArguments(self, type):
            args = OrderedDict()

            for name, arg in self.arguments.items():
                if type == "in" and arg.isInput():
                    args[name] = arg
                    continue
                if type == "out" and arg.isOutput():
                    args[name] = arg
                    continue

            return args

    @staticmethod
    def Introspect(path):
        root = etree.parse(path).getroot()
        return Introspectable.FindElements(root, SBus.Interface)

    @staticmethod
    def FindElements(parent, object_class):
        dict = OrderedDict()
        for child in parent:
            if child.tag != object_class.TagName:
                continue
            object = object_class(child)

            if object.name in dict:
                raise ValueError('%s name="%s" is already present '
                                 'in the same parent element\n'
                                 % (object_class.TagName, object.name))

            dict[object.name] = object

        """
        Arguments can't be sorted and annotations order should be left on
        the author of introspection. Otherwise we want to sort the dictionary
        alphabetically based on keys.
        """
        if object_class in [SBus.Argument, SBus.Annotation]:
            return dict

        return OrderedDict(sorted(dict.items()))


class SBus:
    class Interface(Introspectable.Element):
        TagName = "interface"

        def __init__(self, element):
            super(SBus.Interface, self).__init__(element)

            self.methods = self.find(SBus.Method)
            self.signals = self.find(SBus.Signal)
            self.properties = self.find(SBus.Property)
            return

    class Method(Introspectable.Invokable):
        TagName = "method"

        def __init__(self, element):
            super(SBus.Method, self).__init__(element)

    class Signal(Introspectable.Invokable):
        TagName = "signal"

        def __init__(self, element):
            super(SBus.Signal, self).__init__(element)

    class Property(Introspectable.Invokable):
        TagName = "property"

        def __init__(self, element):
            self.name = element.attrib["name"]
            self.element = element
            self.access = self.getExistingAttr("access")
            self.type = self.getExistingAttr("type")

            super(SBus.Property, self).__init__(element)

            if self.key is not None:
                raise ValueError('Keying is not supported on properties: %s '
                                 % self.name)

        def getInputArguments(self):
            if not self.isWritable():
                return {}

            return {"value": SBus.Argument.Create("value", self.type, "in")}

        def getOutputArguments(self):
            if not self.isReadable():
                return {}

            return {"value": SBus.Argument.Create("value", self.type, "out")}

        def isReadable(self):
            return self.access == "read" or self.access == "readwrite"

        def isWritable(self):
            return self.access == "write" or self.access == "readwrite"

    class Annotation(Introspectable.Element):
        TagName = "annotation"

        def __init__(self, element):
            super(SBus.Annotation, self).__init__(element)

            self.value = self.getAttr("value", None)
            return

        @staticmethod
        def Find(annotations, name, default_value):
            if name in annotations:
                annotation = annotations[name]
                if annotation.value is None:
                    return default_value
                return annotation.value
            return default_value

        @staticmethod
        def FindBool(annotations, name, Assume=False):
            assume = "true" if Assume else "false"
            value = SBus.Annotation.Find(annotations, name, assume)
            if value.lower() == "true":
                return True
            else:
                return False

        @staticmethod
        def CheckIfTrue(names, annotations):
            for name in names:
                if SBus.Annotation.FindBool(annotations, name, False):
                    return True

            return False

        @staticmethod
        def CheckIfFalse(names, annotations):
            for name in names:
                if not SBus.Annotation.FindBool(annotations, name, True):
                    return False

            return True

        @staticmethod
        def AtleastOneIsSet(names, annotations):
            for name in names:
                value = SBus.Annotation.Find(annotations, name, None)
                if value is not None:
                    return True

            return False

    class Argument(Introspectable.Element):
        TagName = "arg"

        def __init__(self, element, Name=None, Type=None, Direction=None,
                     Key=None):
            if element is None:
                self.element = None
                self.name = Name
                self.signature = Type
                self.direction = Direction
                self.key = Key
                return

            super(SBus.Argument, self).__init__(element)

            self.signature = self.getExistingAttr("type")
            self.direction = self.getAttr("direction", "in")
            self.key = self.getAttr("key", None)

        def isInput(self):
            return self.direction == "in"

        def isOutput(self):
            return not self.isInput()

        @staticmethod
        def Create(name, type, direction):
            return SBus.Argument(element=None,
                                 Name=name,
                                 Type=type,
                                 Direction=direction)

    class Signature:
        def __init__(self, args, annotations):
            self.annotations = annotations
            self.signature = self.getSignature(args)
            self.arguments = args

        def getSignature(self, args):
            signature = ""
            for arg in args.values():
                signature += arg.signature

            return signature
