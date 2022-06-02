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
import re
import errno
import textwrap
import os.path


class Template:
    def __init__(self, name, templateFile, template):
        template = self.removeLines(template)

        self.templateFile = templateFile
        self.name = name
        self.loops = {}
        self.toggles = {}
        self.template = self.parse(template)
        self.output = ""

    def parse(self, template):
        template = self.parseLoops(template)
        template = self.parseToggles(template)
        return template

    def parseLoops(self, template):
        template = self.Pattern.Loop.sub(self.processLoops, template)
        return self.Pattern.LoopLine.sub(self.processLoops, template)

    def processLoops(self, match):
        name = match.group(1)
        template = self.removeLines(match.group(2))
        index = 0

        if name not in self.loops:
            self.loops[name] = self.Loop()

        index = self.loops[name].addTemplate(template)
        return '$${loop:%s:%d}' % (name, index)

    def parseToggles(self, template):
        template = self.Pattern.Toggle.sub(self.processToggles, template)
        return self.Pattern.ToggleLine.sub(self.processToggles, template)

    def processToggles(self, match):
        name = match.group(1)
        if_visible = self.removeLines(match.group(2))
        if_hidden = self.removeLines(match.group(4))
        index = 0

        if name not in self.toggles:
            self.toggles[name] = self.Toggle()

        index = self.toggles[name].addTemplate(if_visible, if_hidden)
        return '$${toggle:%s:%d}' % (name, index)

    def add(self, loop_name, values):
        """Add new item into <loop name="$loop_name"> template.
           Setting its attributes to $values.
        """
        if loop_name not in self.loops:
            return self
        self.loops[loop_name].set(values)
        return self

    def show(self, toggle_name, isVisible):
        """Make <toggle name="$toggle_name"> either visible or hidden
           within the template.
        """
        if not self.hasToggle(toggle_name):
            return

        self.toggles[toggle_name].show(isVisible)

    def hasToggle(self, name):
        return name in self.toggles

    def hasLoop(self, name):
        return name in self.loops

    def set(self, values):
        """Set template attributes to $values, push generated content into
           the output file and reset this template.
        """
        template = self.template
        for key, toggle in self.toggles.items():
            for idx, toggletpl in enumerate(toggle.templates):
                pattern = "$${toggle:%s:%d}" % (key, idx)
                template = template.replace(pattern, toggletpl.generate())

        self.output = self.Set(template, values)
        self.templateFile.push(self.generate())
        self.clear()

    def pushOriginal(self):
        """Push original template into the output file
        """
        self.templateFile.push(self.template)

    def clear(self):
        for loop in self.loops.values():
            loop.clear()

        for toggle in self.toggles.values():
            toggle.show(False)

        self.output = ""

    def generate(self):
        output = self.output
        for key, loop in self.loops.items():
            for idx, content in enumerate(loop.templates):
                pattern = "$${loop:%s:%d}" % (key, idx)
                output = output.replace(pattern, loop.get(idx), 1)
        return output

    @staticmethod
    def Set(content, values):
        output = content
        for key, value in values.items():
            output = output.replace("${" + key + "}", str(value))
        return output

    def removeLines(self, content):
        """Remove unneeded lines and spaces. There are some additional lines
           and spaces that may end up in the template after parsing. This
           method will remove new line after <@template-tag> and spaces
           from otherwise empty lines.
        """
        if content is None:
            return content

        content = self.Pattern.NewLine.sub('', content, 1)
        content = self.Pattern.EmptyLine.sub('', content)
        return content

    class Pattern:
        Template = re.compile(
            r' *<template name="(\S+)">(.*?)</template>\r?\n?',
            re.MULTILINE | re.DOTALL
        )

        Loop = re.compile(
            r' *<loop name="(\S+)">(.*?)</loop>\r?\n?',
            re.MULTILINE | re.DOTALL
        )

        LoopLine = re.compile(
            r'<loop line name="(\S+)">(.*?)</loop>',
            re.MULTILINE | re.DOTALL
        )

        Toggle = re.compile(
            r' *<toggle name="(\S+)">(.*?)(<or>(.*?))?</toggle>\r?\n?',
            re.MULTILINE | re.DOTALL
        )

        ToggleLine = re.compile(
            r'<toggle line name="(\S+)">(.*?)(<or>(.*?))?</toggle>',
            re.MULTILINE | re.DOTALL
        )

        NewLine = re.compile('^\r?\n')

        EmptyLine = re.compile('^ *$', re.MULTILINE)

    class Loop:
        def __init__(self):
            self.templates = []
            self.num_templates = 0

        def addTemplate(self, template):
            self.templates.append(self.LoopTemplate(template))
            self.num_templates += 1
            return self.num_templates - 1

        def set(self, values):
            for template in self.templates:
                template.set(values)

        def clear(self):
            for template in self.templates:
                template.clear()

        def get(self, index):
            return self.templates[index].generate()

        class LoopTemplate:
            def __init__(self, template):
                self.template = template
                self.output = ""

            def set(self, values):
                self.output += Template.Set(self.template, values)

            def clear(self):
                self.output = ""

            def generate(self):
                return self.output

    class Toggle:
        def __init__(self):
            self.templates = []
            self.num_templates = 0
            self.visible = False

        def addTemplate(self, if_visible, if_hidden):
            toggletpl = self.ToggleTemplate(self, if_visible, if_hidden)
            self.templates.append(toggletpl)
            self.num_templates += 1
            return self.num_templates - 1

        def show(self, isVisible):
            self.visible = isVisible

        class ToggleTemplate:
            def __init__(self, toggle, if_visible, if_hidden):
                self.toggle = toggle
                self.if_visible = if_visible
                self.if_hidden = if_hidden

            def generate(self):
                if self.toggle.visible:
                    return self.if_visible
                elif self.if_hidden is not None:
                    return self.if_hidden

                return ''


class TemplateFile:
    """Parse file contents into templates.

       Obtain template with .get and set its content. When all the content is
       set, you can call .generate to obtain generated content or .write
       to write it to a file.
    """

    def __init__(self, path):
        with open(path, "r") as file:
            contents = file.read()

        self.templates = {}
        self.output = ""
        self.parse(contents)

    def parse(self, template):
        for (name, content) in Template.Pattern.Template.findall(template):
            content = textwrap.dedent(content)
            self.templates[name] = Template(name, self, content)

    def get(self, name):
        return self.templates[name]

    def has(self, name):
        return name in self.templates

    def push(self, content):
        self.output += content

    def generate(self):
        return self.output

    def write(self, filename, postprocess=None):
        dirname = os.path.dirname(filename)
        if not os.path.exists(dirname):
            try:
                os.makedirs(dirname)
            except OSError as exception:
                if exception.errno == errno.EEXIST and os.path.isdir(filename):
                    pass
                else:
                    raise

        output = self.generate().rstrip() + '\n'
        if postprocess is not None:
            output = postprocess(output)

        if not self.needsOverride(filename, output):
            return

        with open(filename, "w") as file:
            file.write(output)

    def needsOverride(self, filename, content):
        """
            Do not override the file unless it is not yet present or its
            current content differs from the generated one. This ensure
            that the file is in correct state and yet it is not rebuild
            during make unless necessary.
        """
        if not os.path.isfile(filename):
            return True

        with open(filename, "r") as file:
            current_content = file.read()
            if current_content != content:
                return True

        return False

    def __str__(self):
        return self.generate()
