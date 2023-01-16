from __future__ import annotations

import yaml
from pytest_mh import TopologyMark
from sphinx.directives.code import CodeBlock

from lib.sssd.topology import KnownTopology, KnownTopologyGroup


class TopologyMarkDirective(CodeBlock):
    """
    Convert :class:`TopologyMark` into yaml and wrap it in code-block directive.
    """

    def run(self):
        obj = eval(self.arguments[0])
        if isinstance(obj, KnownTopology):
            self.content = self.export(obj.value)
        elif isinstance(obj, KnownTopologyGroup):
            out = []
            for known_topology in obj.value:
                out += self.export(known_topology.value) + [""]
            self.content = out
        elif isinstance(obj, TopologyMark):
            self.content = self.export(obj)
        else:
            raise ValueError(f"Invalid argument: {self.arguments[0]}")

        # Set language
        self.arguments[0] = "yaml"

        return super().run()

    def export(self, x: TopologyMark) -> list[str]:
        return yaml.dump(x.export(), sort_keys=False).splitlines()


def setup(app):
    app.add_directive("topology-mark", TopologyMarkDirective)

    return {
        "version": "0.1",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
