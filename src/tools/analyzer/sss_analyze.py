#!/usr/bin/env python

import click

import source_files

from modules import request


class Analyzer(object):
    def __init__(self, source="files", logdir="/var/log/sssd/"):
        self.source = source
        self.logdir = logdir


@click.group(help="Analyzer tool to assist with SSSD Log parsing")
@click.option('--source', default='files')
@click.option('--logdir', default='/var/log/sssd/', help="SSSD Log directory "
              "to parse log files from")
@click.pass_context
def cli(ctx, source, logdir):
    ctx.obj = Analyzer(source, logdir)


if __name__ == '__main__':
    cli.add_command(request.request)
    cli()
