# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

import argparse
import os
import re
import logging
from enum import Enum, auto
from argparse import _SubParsersAction, ArgumentParser
from typing import Any

from kafl_fuzzer.manager.core import start as fuzz_start
from kafl_fuzzer.debug.core import start as debug_start
from kafl_fuzzer.coverage import start as cov_start
from kafl_fuzzer.gui import start as gui_start
from kafl_fuzzer.plot import start as plot_start
from kafl_fuzzer.mcat import start as mcat_start

class KaflSubcommands(Enum):
    FUZZ = auto()
    DEBUG = auto()
    COV = auto()
    GUI = auto()
    PLOT = auto()
    MCAT = auto()

logger = logging.getLogger(__name__)

def parse_ignore_range(string):
    m = re.match(r"(\d+)(?:-(\d+))?$", string)
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")
    start = min(int(m.group(1)), int(m.group(2)))
    end = max(int(m.group(1)), int(m.group(2))) or start
    if end > (128 << 10):
        raise argparse.ArgumentTypeError("Value out of range (max 128KB).")

    if start == 0 and end == (128 << 10):
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])


def parse_range_ip_filter(string):
    m = re.match(r"([(0-9abcdef]{1,16})(?:-([0-9abcdef]{1,16}))?$", string.replace("0x", "").lower())
    if not m:
        raise argparse.ArgumentTypeError("'" + string + "' is not a range of number.")

    # print(m.group(1))
    # print(m.group(2))
    start = min(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16))
    end = max(int(m.group(1).replace("0x", ""), 16), int(m.group(2).replace("0x", ""), 16)) or start

    if start > end:
        raise argparse.ArgumentTypeError("Invalid range specified.")
    return list([start, end])

def hidden(msg, unmask=False):
    if unmask or 'KAFL_CONFIG_DEBUG' in os.environ:
        return msg
    return argparse.SUPPRESS

# General startup options used by fuzzer, qemu, and/or utilities
def add_args_general(parser):
    parser.add_argument('-h', '--help', action='help',
                        help='show this help message and exit')
    parser.add_argument('-w', '--work-dir', metavar='<dir>', required=True, help='path to the output/working directory.')
    parser.add_argument('--purge', required=False, help='purge the working directory at startup.',
                        action='store_true', default=False)
    parser.add_argument('-r', '--resume', required=False, help='use VM snapshot from existing workdir (for cov/gdb)',
                        action='store_true', default=False)
    parser.add_argument('-p', '--processes', required=False, metavar='<n>',
                        help='number of parallel processes')
    parser.add_argument('-v', '--verbose', required=False, action='store_true', default=False,
                        help='enable verbose output')
    parser.add_argument('-q', '--quiet', help='only print warnings and errors to console',
                        required=False, action='store_true', default=False)
    parser.add_argument('-l', '--log', help='enable logging to $workdir/debug.log',
                        action='store_true', default=False)
    parser.add_argument('--debug', help='enable extra debug checks and max logging verbosity',
                        action='store_true', default=False)

# kAFL/Fuzzer-specific options
def add_args_fuzzer(parser):
    parser.add_argument('--seed-dir', metavar='<dir>', help='path to the seed directory.')
    parser.add_argument('--dict', required=False, metavar='<file>',
                        help='import dictionary file for use in havoc stage.', default=None)
    parser.add_argument('--funky', required=False, help='perform extra validation and store funky inputs.',
                        action='store_true', default=False)
    parser.add_argument('-D', '--afl-dumb-mode', required=False, help='skip deterministic stage (dumb mode)',
                        action='store_true', default=False)
    parser.add_argument('--afl-no-effector', required=False, help=hidden('disable effector maps during deterministic stage'),
                        action='store_true', default=False)
    parser.add_argument('--afl-skip-zero', required=False, help=hidden('skip zero bytes during deterministic stage'),
                        action='store_true', default=False)
    # parser.add_argument('--afl-skip-range', required=False, type=parse_ignore_range, metavar="<start-end>", action='append',
    #                     help=hidden('skip byte range during deterministic stage'))
    parser.add_argument('--afl-arith-max', metavar='<n>', help=hidden("max arithmetic range for afl_arith_n mutation"), required=False)
    parser.add_argument('--radamsa', required=False, action='store_true', help='enable Radamsa as additional havoc stage')
    parser.add_argument('--grimoire', required=False, action='store_true', help='enable Grimoire analysis & mutation stages', default=False)
    parser.add_argument('--redqueen', required=False, action='store_true', help='enable Redqueen trace & insertion stages', default=False)
    parser.add_argument('--redqueen-hashes', required=False, action='store_true', help=hidden('enable Redqueen checksum fixer (broken)'), default=False)
    parser.add_argument('--redqueen-hammer', required=False, action='store_true', help=hidden('enable Redqueen jump table hammering'), default=False)
    parser.add_argument('--redqueen-simple', required=False, action='store_true', help=hidden('do not ignore simple matches in Redqueen'), default=False)
    parser.add_argument('--cpu-offset', metavar='<n>', help="start CPU pinning at offset <n>", required=False)
    parser.add_argument('--abort-time', metavar='<n>', help="exit after <n> hours", default=None)
    parser.add_argument('--abort-exec', metavar='<n>', help="exit after max <n> executions", default=None)
    parser.add_argument('-ts', '--t-soft', dest='timeout_soft', required=False, metavar='<n>', help="soft execution timeout (in seconds)")
    parser.add_argument('-tc', '--t-check', dest='timeout_check', required=False, action='store_true', help="validate timeouts against hard limit (slower)", default=False)
    parser.add_argument('--kickstart', metavar='<n>', help="kickstart fuzzing with <n> byte random strings (default 256, 0 to disable)", required=False)
    parser.add_argument('--radamsa-path', metavar='<file>', help=hidden('path to radamsa executable'), required=False)


# Qemu/Worker-specific launch options
def add_args_qemu(parser):

    # config_default_base   = '-enable-kvm -machine kAFL64-v1 -cpu kAFL64-Hypervisor-v1,+vmx -no-reboot -net none -display none'

    # BIOS/Image/Kernel load modes are partly exclusive, but we need at least one of them
    parser.add_argument('--image', dest='qemu_image', metavar='<qcow2>', help='path to Qemu disk image.')
    # parser.add_argument('--snapshot', dest='qemu_snapshot', metavar='<dir>', required=False, action=ExpandVars,
    #                     type=parse_is_dir, help='path to VM pre-snapshot directory.')
    # parser.add_argument('--bios', dest='qemu_bios', metavar='<file>', required=False, action=ExpandVars, type=parse_is_file,
    #                     help='path to the BIOS image.')
    # parser.add_argument('--kernel', dest='qemu_kernel', metavar='<file>', required=False, action=ExpandVars,
    #                     type=parse_is_file, help='path to the Kernel image.')
    # parser.add_argument('--initrd', dest='qemu_initrd', metavar='<file>', required=False, action=ExpandVars, type=parse_is_file,
    #                     help='path to the initrd/initramfs file.')
    # parser.add_argument('--append', dest='qemu_append', metavar='<str>', help='Qemu -append option',
    #                     type=str, required=False, default=None)
    # parser.add_argument('-m', '--memory', dest='qemu_memory', metavar='<n>', help='size of VM RAM in MB (default: 256).',
    #                     default=256, type=int)

    # parser.add_argument('--qemu-base', metavar='<str>', action=ExpandVars, help='base Qemu config (check defaults!)',
    #                     type=str, required=False, default=config_default_base)
    # parser.add_argument('--qemu-serial', metavar='<str>', help='Qemu serial emulation (redirected to file, see defaults)',
    #                     type=str, required=False, default=None)
    # parser.add_argument('--qemu-extra', metavar='<str>', action=ExpandVars, help='extra Qemu config (check defaults!)',
    #                     type=str, required=False, default=None)
    # parser.add_argument('--qemu-path', metavar='<file>', action=ExpandVars, help=hidden('path to Qemu-Nyx executable'),
    #                     type=parse_is_file, required=True, default=None)

    # parser.add_argument('-ip0', required=False, default=None, metavar='<n-m>', type=parse_range_ip_filter,
    #                     help='set IP trace filter range 0 (should be page-aligned)')
    # parser.add_argument('-ip1', required=False, default=None, metavar='<n-m>', type=parse_range_ip_filter,
    #                     help='Set IP trace filter range 1 (should be page-aligned)')
    # parser.add_argument('-ip2', required=False, default=None, metavar='<n-m>', type=parse_range_ip_filter,
    #                     help=hidden('Set IP trace filter range 2 (should be page-aligned)'))
    # parser.add_argument('-ip3', required=False, default=None, metavar='<n-m>', type=parse_range_ip_filter,
    #                     help=hidden('Set IP trace filter range 3 (should be page-aligned)'))

    # parser.add_argument('--sharedir', metavar='<dir>', required=False, action=ExpandVars,
    #                     type=parse_is_dir, help='path to the page buffer share directory.')
    # parser.add_argument('-R', '--reload', metavar='<n>', help='snapshot-reload every N execs (default: 1)',
    #                     type=int, required=False, default=1)
    # parser.add_argument('--gdbserver', required=False, help=hidden('enable Qemu gdbserver (use via kafl_debug.py!'),
    #                     action='store_true', default=False)
    # parser.add_argument('--log-hprintf', required=False, help="redirect hprintf logging to workdir/hprintf_NN.log",
    #                     action='store_true', default=False)
    # parser.add_argument('--log-crashes', required=False, help="store hprintf logs only for crashes/timeouts",
    #                     action='store_true', default=False)
    # parser.add_argument('-t', '--t-hard', dest='timeout_hard', required=False, metavar='<n>', help="hard execution timeout (seconds)",
    #                     type=float, default=4)
    # parser.add_argument('--payload-size', metavar='<n>', help=hidden("maximum payload size in bytes (minus headers)"),
    #                     type=int, required=False, default=131072)
    # parser.add_argument('--bitmap-size', metavar='<n>', help="size of feedback bitmap (must be power of 2)",
    #                     type=int, required=False, default=65536)
    # parser.add_argument('--trace', required=False, help='store binary PT traces of new inputs (fast).',
    #                     action='store_true', default=False)
    # parser.add_argument("--trace-cb", required=False, help='store decoded PT traces of new inputs (slow).',
    #                     action='store_true', default=False)


# kafl_debug launch options
def add_args_debug(parser):

    debug_modes = ["benchmark", "gdb", "trace", "single", "trace-qemu", "noise", "printk", "redqueen",
                   "redqueen-qemu", "verify"]
    
    debug_modes_help = '<benchmark>\tperform performance benchmark\n' \
                       '<gdb>\t\trun payload with Qemu gdbserver (must compile without redqueen!)\n' \
                       '<trace>\t\tperform trace run\n' \
                       '<trace-qemu>\tperform trace run and print QEMU stdout\n' \
                       '<noise>\t\tperform run and messure nondeterminism\n' \
                       '<printk>\t\tredirect printk calls to kAFL\n' \
                       '<redqueen>\trun redqueen debugger\n' \
                       '<redqueen-qemu>\trun redqueen debugger and print QEMU stdout\n' \
                       '<verify>\t\trun verifcation steps\n'
    
    parser.add_argument('--input', metavar='<file/dir>', action=ExpandVars, type=str,
                        help='path to input file or workdir.')
    parser.add_argument('-n', '--iterations', metavar='<n>', help='execute <n> times (for some actions)',
                        default=5, type=int)
    parser.add_argument('--action', required=False, metavar='<cmd>', choices=debug_modes,
                        help=debug_modes_help)
    parser.add_argument('--ptdump-path', metavar='<file>', action=ExpandVars, help=hidden('path to ptdump executable'),
                        type=parse_is_file, required=True, default=None)


class ConfigParserBuilder():

    def __call__(self, *args: Any, **kwds: Any) -> ArgumentParser:
        parser = self._base_parser()
        # add General args
        general_grp = parser.add_argument_group('General options')
        add_args_general(general_grp)
        # enable subcommands
        subcommands = parser.add_subparsers()
        # add subcommands
        self._add_fuzz_subcommand(subcommands)
        # self._add_debug_subcommand(subcommands)
        # self._add_cov_subcommand(subcommands)
        # self._add_gui_subcommand(subcommands)
        # self._add_plot_subcommand(subcommands)
        # self._add_mcat_subcommand(subcommands)
        return parser

    def _base_parser(self):
        short_usage = '%(prog)s --work-dir <dir> [fuzzer options] [qemu options]'
        return argparse.ArgumentParser(usage=short_usage, add_help=False, fromfile_prefix_chars='@')

    def _add_fuzz_subcommand(self, parser: _SubParsersAction):
        fuzz_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.FUZZ.name.lower(), help="kAFL Fuzzer")

        fuzzer_grp = fuzz_subcommand.add_argument_group('Fuzzer options')
        add_args_fuzzer(fuzzer_grp)

        qemu_grp = fuzz_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        fuzz_subcommand.set_defaults(func=fuzz_start)

    def _add_debug_subcommand(self, parser: _SubParsersAction):
        debug_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.DEBUG.name.lower(), help="kAFL Debugger")

        debug_grp = debug_subcommand.add_argument_group("Debug options")
        add_args_debug(debug_grp)

        qemu_grp = debug_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        debug_subcommand.set_defaults(func=debug_start)

    def _add_cov_subcommand(self, parser: _SubParsersAction):
        cov_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.COV.name.lower(), help="kAFL Coverage Analyzer")

        debug_grp = cov_subcommand.add_argument_group("Debug options")
        add_args_debug(debug_grp)

        qemu_grp = cov_subcommand.add_argument_group('Qemu/Nyx options')
        add_args_qemu(qemu_grp)

        cov_subcommand.set_defaults(func=cov_start)

    def _add_gui_subcommand(self, parser: _SubParsersAction):
        gui_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.GUI.name.lower(), help="kAFL GUI")

        gui_subcommand.set_defaults(func=gui_start)

    def _add_plot_subcommand(self, parser: _SubParsersAction):
        plot_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.PLOT.name.lower(), help="kAFL Plotter")

        plot_subcommand.set_defaults(func=plot_start)

    def _add_mcat_subcommand(self, parser: _SubParsersAction):
        mcat_subcommand: ArgumentParser = parser.add_parser(KaflSubcommands.MCAT.name.lower(), help="kAFL msgpack Pretty-Printer")

        mcat_subcommand.set_defaults(func=mcat_start)
