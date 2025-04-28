#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
 _ _   _ _   _     _ _
| | |_| | |_|_|___|_| |_
| | | . | . | |   | |  _|
|_|_|___|___|_|_|_|_|_|

lrt - redthing1's remix of lldbinit

Upstream: https://github.com/gdbinit/lldbinit

To list all implemented commands use 'lrtcmds' command.

How to install it:
------------------

$ cp lrt.py ~
$ echo "command script import ~/lrt.py" >> $HOME/.lldbinit

"""

if __name__ == "__main__":
    print("Run only as script from LLDB... Not as standalone program!")

import lldb
import sys
import re
import os
import struct
import argparse
import subprocess
import tempfile
import termios
import fcntl
import json
import hashlib
import datetime

try:
    import keystone

    CONFIG_KEYSTONE_AVAILABLE = 1
except ImportError:
    CONFIG_KEYSTONE_AVAILABLE = 0

    # # warn if keystone is not available
    # print(
    #     "\033[1m\033[31m[-] keystone not available, some features will be disabled.\033[0m"
    # )

    pass

VERSION = "3.3"
BUILD = "451"

# internal debugging
LRT_INTERNAL_DEBUG = os.environ.get("LRT_INTERNAL_DEBUG", 0)

#
# User configurable options
#
CONFIG_ENABLE_COLOR = 1
# light or dark mode
CONFIG_APPEARANCE = "redthing1" # Kept lrt's default
# display the instruction bytes in disassembler output
CONFIG_DISPLAY_DISASSEMBLY_BYTES = 1
# the maximum number of lines to display in disassembler output
CONFIG_DISASSEMBLY_LINE_COUNT = 8
# x/i and disas output customization - doesn't affect context disassembler output
CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT = 1
# enable all the register command shortcuts
CONFIG_ENABLE_REGISTER_SHORTCUTS = 1
# display stack contents on context stop
CONFIG_DISPLAY_STACK_WINDOW = 0
CONFIG_DISPLAY_FLOW_WINDOW = 0
# display data contents on context stop - an address for the data must be set with "datawin" command
CONFIG_DISPLAY_DATA_WINDOW = 0
# disassembly flavor 'intel' or 'att' - default is Intel unless AT&T syntax is your cup of tea
CONFIG_FLAVOR = "intel"

# setup the logging level, which is a bitmask of any of the following possible values (don't use spaces, doesn't seem to work)
#
# LOG_VERBOSE LOG_PROCESS LOG_THREAD LOG_EXCEPTIONS LOG_SHLIB LOG_MEMORY LOG_MEMORY_DATA_SHORT LOG_MEMORY_DATA_LONG LOG_MEMORY_PROTECTIONS LOG_BREAKPOINTS LOG_EVENTS LOG_WATCHPOINTS
# LOG_STEP LOG_TASK LOG_ALL LOG_DEFAULT LOG_NONE LOG_RNB_MINIMAL LOG_RNB_MEDIUM LOG_RNB_MAX LOG_RNB_COMM  LOG_RNB_REMOTE LOG_RNB_EVENTS LOG_RNB_PROC LOG_RNB_PACKETS LOG_RNB_ALL LOG_RNB_DEFAULT
# LOG_DARWIN_LOG LOG_RNB_NONE
#
# to see log (at least in macOS)
# $ log stream --process debugserver --style compact
# (or whatever style you like)
CONFIG_LOG_LEVEL = "LOG_NONE"

# removes the offsets and modifies the module name position
# reference: https://lldb.llvm.org/formats.html
CUSTOM_DISASSEMBLY_FORMAT = '"{${function.initial-function}{${function.name-without-args}} @ {${module.file.basename}}:\n}{${function.changed}\n{${function.name-without-args}} @ {${module.file.basename}}:\n}{${current-pc-arrow} }${addr-file-or-load}: "'

if CONFIG_ENABLE_COLOR:
    # Original styles and colors
    RESET = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    REVERSE = "\033[7m"
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Additional styles
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    BLINK = "\033[5m"
    HIDDEN = "\033[8m"

    # Background colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

    # Bright foreground colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"

    # Bright background colors
    BG_BRIGHT_BLACK = "\033[100m"
    BG_BRIGHT_RED = "\033[101m"
    BG_BRIGHT_GREEN = "\033[102m"
    BG_BRIGHT_YELLOW = "\033[103m"
    BG_BRIGHT_BLUE = "\033[104m"
    BG_BRIGHT_MAGENTA = "\033[105m"
    BG_BRIGHT_CYAN = "\033[106m"
    BG_BRIGHT_WHITE = "\033[107m"
else:
    # Original empty strings for compatibility
    RESET = ""
    BOLD = ""
    UNDERLINE = ""
    REVERSE = ""
    BLACK = ""
    RED = ""
    GREEN = ""
    YELLOW = ""
    BLUE = ""
    MAGENTA = ""
    CYAN = ""
    WHITE = ""

    # Additional styles and colors set to empty strings when colors are disabled
    DIM = ITALIC = BLINK = HIDDEN = ""
    BG_BLACK = BG_RED = BG_GREEN = BG_YELLOW = BG_BLUE = BG_MAGENTA = BG_CYAN = (
        BG_WHITE
    ) = ""
    BRIGHT_BLACK = BRIGHT_RED = BRIGHT_GREEN = BRIGHT_YELLOW = BRIGHT_BLUE = (
        BRIGHT_MAGENTA
    ) = BRIGHT_CYAN = BRIGHT_WHITE = ""
    BG_BRIGHT_BLACK = BG_BRIGHT_RED = BG_BRIGHT_GREEN = BG_BRIGHT_YELLOW = (
        BG_BRIGHT_BLUE
    ) = BG_BRIGHT_MAGENTA = BG_BRIGHT_CYAN = BG_BRIGHT_WHITE = ""

if CONFIG_APPEARANCE == "light":
    COLOR_REGVAL = BLACK
    COLOR_REGNAME = GREEN
    COLOR_CPUFLAGS = BOLD + UNDERLINE + MAGENTA
    COLOR_SEPARATOR = BOLD + BLUE
    COLOR_HIGHLIGHT_LINE = RED
    COLOR_REGVAL_MODIFIED = RED
    COLOR_SYMBOL_NAME = BLUE
    COLOR_CURRENT_PC = RED
    COLOR_DISASM_LISTING = BLACK
    COLOR_CONDITIONAL_YES = REVERSE + GREEN
    COLOR_CONDITIONAL_NO = REVERSE + RED
    COLOR_HEXDUMP_HEADER = BLUE
    COLOR_HEXDUMP_ADDR = BLACK
    COLOR_HEXDUMP_DATA = BLACK
    COLOR_HEXDUMP_ASCII = BLACK
    COLOR_COMMENT = GREEN
    COLOR_LOGDEBUG = BRIGHT_BLACK
    COLOR_LOGINFO = BRIGHT_BLUE
    COLOR_LOGWARN = BRIGHT_YELLOW
    COLOR_LOGERROR = BRIGHT_RED
    COLOR_ERROR = BRIGHT_RED
elif CONFIG_APPEARANCE == "dark":
    COLOR_REGVAL = WHITE
    COLOR_REGNAME = GREEN
    COLOR_CPUFLAGS = BOLD + UNDERLINE + MAGENTA
    COLOR_SEPARATOR = CYAN
    COLOR_HIGHLIGHT_LINE = RED
    COLOR_REGVAL_MODIFIED = RED
    COLOR_SYMBOL_NAME = BLUE
    COLOR_CURRENT_PC = RED
    COLOR_DISASM_LISTING = WHITE
    COLOR_CONDITIONAL_YES = REVERSE + GREEN
    COLOR_CONDITIONAL_NO = REVERSE + RED
    COLOR_HEXDUMP_HEADER = BLUE
    COLOR_HEXDUMP_ADDR = WHITE
    COLOR_HEXDUMP_DATA = WHITE
    COLOR_HEXDUMP_ASCII = WHITE
    COLOR_COMMENT = GREEN
    COLOR_LOGDEBUG = BRIGHT_BLACK
    COLOR_LOGINFO = GREEN
    COLOR_LOGWARN = YELLOW
    COLOR_LOGERROR = RED
    COLOR_ERROR = RED
elif CONFIG_APPEARANCE == "redthing1":
    COLOR_REGVAL = DIM + WHITE
    COLOR_REGNAME = GREEN
    COLOR_CPUFLAGS = BRIGHT_MAGENTA
    COLOR_SEPARATOR = BRIGHT_BLACK
    COLOR_HIGHLIGHT_LINE = RED
    COLOR_REGVAL_MODIFIED = BRIGHT_RED
    COLOR_SYMBOL_NAME = BLUE
    COLOR_CURRENT_PC = RED
    COLOR_DISASM_LISTING = DIM + WHITE
    COLOR_CONDITIONAL_YES = REVERSE + GREEN
    COLOR_CONDITIONAL_NO = REVERSE + RED
    COLOR_HEXDUMP_HEADER = BLUE
    COLOR_HEXDUMP_ADDR = WHITE
    COLOR_HEXDUMP_DATA = WHITE
    COLOR_HEXDUMP_ASCII = WHITE
    COLOR_COMMENT = GREEN
    COLOR_LOGDEBUG = BRIGHT_BLACK
    COLOR_LOGINFO = BRIGHT_BLUE
    COLOR_LOGWARN = BRIGHT_YELLOW
    COLOR_LOGERROR = BRIGHT_RED
    COLOR_ERROR = BRIGHT_RED
else:
    print("[-] Invalid CONFIG_APPEARANCE value.")


# configure the separator character between the "windows" and their size
SEPARATOR = "-"
# minimum terminal width 120 chars
I386_TOP_SIZE = 81
I386_HEADER_SIZE = I386_TOP_SIZE - 11
I386_STACK_SIZE = I386_TOP_SIZE - 1
I386_BOTTOM_SIZE = 87
# minimum terminal width 125 chars
X64_TOP_SIZE = 119
X64_HEADER_SIZE = X64_TOP_SIZE - 11
X64_STACK_SIZE = X64_TOP_SIZE - 1
X64_BOTTOM_SIZE = 125
# minimum terminal width 108 chars
ARM_TOP_SIZE = 102
ARM_HEADER_SIZE = ARM_TOP_SIZE - 11
ARM_STACK_SIZE = ARM_TOP_SIZE - 1
ARM_BOTTOM_SIZE = 108

# turn on debugging output - you most probably don't need this
DEBUG = 0

#
# Don't mess after here unless you know what you are doing!
#

DATA_WINDOW_ADDRESS = 0
POINTER_SIZE = 8

old_x86 = {
    "eax": 0,
    "ecx": 0,
    "edx": 0,
    "ebx": 0,
    "esp": 0,
    "ebp": 0,
    "esi": 0,
    "edi": 0,
    "eip": 0,
    "eflags": 0,
    "cs": 0,
    "ds": 0,
    "fs": 0,
    "gs": 0,
    "ss": 0,
    "es": 0,
}

old_x64 = {
    "rax": 0,
    "rcx": 0,
    "rdx": 0,
    "rbx": 0,
    "rsp": 0,
    "rbp": 0,
    "rsi": 0,
    "rdi": 0,
    "rip": 0,
    "r8": 0,
    "r9": 0,
    "r10": 0,
    "r11": 0,
    "r12": 0,
    "r13": 0,
    "r14": 0,
    "r15": 0,
    "rflags": 0,
    "cs": 0,
    "fs": 0,
    "gs": 0,
}

old_arm64 = {
    "x0": 0,
    "x1": 0,
    "x2": 0,
    "x3": 0,
    "x4": 0,
    "x5": 0,
    "x6": 0,
    "x7": 0,
    "x8": 0,
    "x9": 0,
    "x10": 0,
    "x11": 0,
    "x12": 0,
    "x13": 0,
    "x14": 0,
    "x15": 0,
    "x16": 0,
    "x17": 0,
    "x18": 0,
    "x19": 0,
    "x20": 0,
    "x21": 0,
    "x22": 0,
    "x23": 0,
    "x24": 0,
    "x25": 0,
    "x26": 0,
    "x27": 0,
    "x28": 0,
    "fp": 0,
    "lr": 0,
    "sp": 0,
    "pc": 0,
    "cpsr": 0,
}

int3patches = {}

crack_cmds = []
crack_cmds_noret = []
modules_list = []

g_current_target = ""
g_target_hash = ""
g_home = ""
g_sessionfile = "" # Renamed from g_db
g_sessiondata = {} # Renamed from g_dbdata

# dyld modes
dyld_mode_dict = {
    0: "dyld_image_adding",
    1: "dyld_image_removing",
    2: "dyld_image_info_change",
    3: "dyld_image_dyld_moved",
}

MIN_COLUMNS = 125
MIN_ROWS = 25
LLDB_MAJOR = 0
LLDB_MINOR = 0
 # apple or clang: the built-in apple LLDB vs. clang's LLDB (they have different version IDs)
LLDB_VARIANT = None

# current sessions storage version
SESSION_VERSION = 2

def __lldb_init_module(debugger, internal_dict):
    """we can execute lldb commands using debugger.HandleCommand() which makes all output to default
    lldb console. With SBDebugger.GetCommandinterpreter().HandleCommand() we can consume all output
    with SBCommandReturnObject and parse data before we send it to output (eg. modify it);

    in practice there is nothing here in initialization or anywhere else that we want to modify
    """

    # don't load if we are in Xcode since it is not compatible and will block Xcode
    if os.getenv("PATH").startswith("/Applications/Xcode"):
        return

    # test terminal - idea from https://github.com/ant4g0nist/lisa.py/
    try:
        tty_rows, tty_columns = struct.unpack(
            "hh", fcntl.ioctl(1, termios.TIOCGWINSZ, "1234")
        )
        # i386 is fine with 87x21
        # x64 is fine with 125x23
        # aarch64 is fine with 108x26
        if tty_columns < MIN_COLUMNS or tty_rows < MIN_ROWS:
            print(
                "\033[1m\033[31m[!] current terminal size is {:d}x{:d}".format(
                    tty_columns, tty_rows
                )
            )
            print(
                "[!] lrt is best experienced with a terminal size at least {}x{}\033[0m".format(
                    MIN_COLUMNS, MIN_ROWS
                )
            )
    except Exception as e:
        print("\033[1m\033[31m[-] failed to find out terminal size.")
        print(
            "[!] lrt is best experienced with a terminal size at least {}x{}\033[0m".format(
                MIN_COLUMNS, MIN_ROWS
            )
        )

    global g_home, LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR

    if g_home == "":
        g_home = os.getenv("HOME")

    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    # settings
    ci.HandleCommand("settings set target.x86-disassembly-flavor " + CONFIG_FLAVOR, res)
    # set prompt
    ci.HandleCommand('settings set prompt "(lrt) "', res)
    ci.HandleCommand("settings set stop-disassembly-count 0", res)
    # set the log level - must be done on startup?
    ci.HandleCommand(
        "settings set target.process.extra-startup-command QSetLogging:bitmask="
        + CONFIG_LOG_LEVEL
        + ";",
        res,
    )
    if CONFIG_USE_CUSTOM_DISASSEMBLY_FORMAT == 1:
        ci.HandleCommand(
            "settings set disassembly-format " + CUSTOM_DISASSEMBLY_FORMAT, res
        )

    # the hook that makes everything possible :-)
    # Note: HandleProcessLaunchHook seems unused, consider removing if confirmed
    ci.HandleCommand(
        "command script add -h '(lrt)' -f lrt.HandleProcessLaunchHook HandleProcessLaunchHook",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) The main lrt hook.' -f lrt.HandleHookStopOnTarget HandleHookStopOnTarget",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Display the current disassembly/CPU context.' -f lrt.HandleHookStopOnTarget context",
        res,
    )
    ci.HandleCommand(
        "command alias -h '(lrt) Alias to context command.' -- ctx HandleHookStopOnTarget",
        res,
    )
    # commands
    ci.HandleCommand(
        "command script add -h '(lrt) Print list of available commands.' -f lrt.cmd_lrtcmds lrtcmds",
        res,
    )
    # Added from upstream
    ci.HandleCommand("command script add -h '(lrt) List threads.' -f lrt.cmd_listthreads tl", res)
    ci.HandleCommand("command script add -h '(lrt) Suspend a thread.' -f lrt.cmd_suspendthread ts", res)
    # Kept from lrt
    ci.HandleCommand(
        "command script add -h '(lrt) Connect to debugserver running on iPhone.' -f lrt.cmd_IphoneConnect iphone",
        res,
    )
    #
    # comments commands
    #
    ci.HandleCommand(
        "command script add -h '(lrt) Add disassembly comment.' -f lrt.cmd_addcomment acm",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Remove disassembly comment.' -f lrt.cmd_delcomment dcm",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) List disassembly comments.' -f lrt.cmd_listcomments lcm",
        res,
    )

    # Added from upstream
    ci.HandleCommand(
        "command script add -h '(lrt) Save breakpoint session.' -f lrt.cmd_save_session ss",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Restore breakpoint session.' -f lrt.cmd_restore_session rs",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) List breakpoint sessions.' -f lrt.cmd_list_sessions ls",
        res,
    )
    #
    # dump memory commands
    #
    ci.HandleCommand(
        "command script add -h '(lrt) Memory hex dump in byte format.' -f lrt.cmd_db db",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Memory hex dump in word format.' -f lrt.cmd_dw dw",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Memory hex dump in double word format.' -f lrt.cmd_dd dd",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Memory hex dump in quad word format.' -f lrt.cmd_dq dq",
        res,
    )
    # XXX: fix help
    ci.HandleCommand(
        "command script add -h '(lrt) Disassemble instructions at address.' -f lrt.cmd_DumpInstructions u",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Memory search.' -f lrt.cmd_findmem findmem",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Display process memory regions.' -f lrt.cmd_showregions showregions",
        res,
    )
    #
    # Settings related commands
    #
    ci.HandleCommand(
        "command script add -h '(lrt) Configure lldb and lrt options.' -f lrt.cmd_enable enable",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Configure lldb and lrt options.' -f lrt.cmd_disable disable",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set number of instruction lines in code window.' -f lrt.cmd_contextcodesize contextcodesize",
        res,
    )
    # a few settings aliases
    ci.HandleCommand(
        "command alias -h '(lrt) Enable the stop on library load events.' -- enablesolib enable solib",
        res,
    )
    ci.HandleCommand(
        "command alias -h '(lrt) Disable the stop on library load events.' -- disablesolib disable solib",
        res,
    )
    ci.HandleCommand(
        "command alias -h '(lrt) Enable target ASLR.' -- enableaslr enable aslr",
        res,
    )
    ci.HandleCommand(
        "command alias -h '(lrt) Disable target ASLR.' -- disableaslr disable aslr",
        res,
    )
    #
    # Breakpoint related commands
    #
    # # replace the default alias with our own version
    # the original b command supports useful stuff: -a <address-expression> and -s <shlib-name>. it's useful to set breakpoints in specific modules
    # until we support that let's leave the original 'b' alone
    # ci.HandleCommand("command unalias b", res)
    # software breakpoints
    ci.HandleCommand(
        "command script add -h '(lrt) Set a software breakpoint.' -f lrt.cmd_bp bb", # Kept bb alias from lrt
        res,
    )
    # alias "bp" command that exists in gdbinit
    ci.HandleCommand("command alias -h '(lrt) Alias to b.' -- bp b", res)
    ci.HandleCommand(
        "command script add -h '(lrt) Set a temporary software breakpoint.' -f lrt.cmd_bpt bpt",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set a temporary breakpoint on next instruction.' -f lrt.cmd_bpn bpn",
        res,
    )
    # hardware breakpoints
    ci.HandleCommand(
        "command script add -h '(lrt) Set an hardware breakpoint.' -f lrt.cmd_bh bh",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set a temporary hardware breakpoint.' -f lrt.cmd_bht bht",
        res,
    )
    # module breakpoints
    ci.HandleCommand(
        "command script add -h '(lrt) Breakpoint on module load.' -f lrt.cmd_bm bm",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Clear all module load breakpoints.' -f lrt.cmd_bmc bmc",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) List all on module load breakpoints.' -f lrt.cmd_bml bml",
        res,
    )
    # misc breakpoint commands
    ci.HandleCommand(
        "command script add -h '(lrt) Temporarily breakpoint all instructions with mnemonic.' -f lrt.cmd_bpmnm bpmnm",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Enable anti-anti-debugging measures.' -f lrt.cmd_antidebug antidebug",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Print all images available at gdb_image_notifier() breakpoint.' -f lrt.cmd_print_notifier_images print_images",
        res,
    )
    # disable a breakpoint or all
    ci.HandleCommand(
        "command script add -h '(lrt) Disable a breakpoint.' -f lrt.cmd_bpd bpd",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Disable all breakpoints.' -f lrt.cmd_bpda bpda",
        res,
    )
    # clear a breakpoint or all
    ci.HandleCommand(
        "command script add -h '(lrt) Clear a breakpoint.' -f lrt.cmd_bpc bpc",
        res,
    )
    ci.HandleCommand(
        "command alias -h '(lrt) Clear all breakpoints' -- bpca breakpoint delete",
        res,
    )
    # enable a breakpoint or all
    ci.HandleCommand(
        "command script add -h '(lrt) Enable a breakpoint.' -f lrt.cmd_bpe bpe",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Enable all breakpoints.' -f lrt.cmd_bpea bpea",
        res,
    )
    # commands to set temporary int3 patches and restore original bytes
    ci.HandleCommand(
        "command script add -h '(lrt) Patch memory address with INT3.' -f lrt.cmd_int3 int3",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Restore original byte at address patched with INT3.' -f lrt.cmd_rint3 rint3",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) List all INT3 patched addresses.' -f lrt.cmd_listint3 listint3",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Patch memory address with NOP.' -f lrt.cmd_nop nop",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Patch memory address with NULL.' -f lrt.cmd_null null",
        res,
    )
    # change eflags commands
    ci.HandleCommand(
        "command script add -h '(lrt) Change adjust CPU flag.' -f lrt.cmd_cfa cfa",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change carry CPU flag.' -f lrt.cmd_cfc cfc",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change direction CPU flag.' -f lrt.cmd_cfd cfd",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change interrupt CPU flag.' -f lrt.cmd_cfi cfi",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change overflow CPU flag.' -f lrt.cmd_cfo cfo",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change parity CPU flag.' -f lrt.cmd_cfp cfp",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change sign CPU flag.' -f lrt.cmd_cfs cfs",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change trap CPU flag.' -f lrt.cmd_cft cft",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change zero CPU flag.' -f lrt.cmd_cfz cfz",
        res,
    )
    # change NZCV flags - exclusive commands to AArch64 (Z, C are common)
    ci.HandleCommand(
        "command script add -h '(lrt) Change negative CPU flag.' -f lrt.cmd_cfn cfn",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Change overflow CPU flag.' -f lrt.cmd_cfv cfv",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Skip current instruction.' -f lrt.cmd_skip skip",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step over calls and loop instructions.' -f lrt.cmd_stepo stepo",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step over calls and loop instructions, using hardware breakpoints.' -f lrt.cmd_stepoh stepoh",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step until call stack changes.' -f lrt.cmd_sutcs sutcs",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step until branch is taken.' -f lrt.cmd_sutbt sutbt",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step until end of basic block.' -f lrt.cmd_suebb suebb",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Step until instruction mnemonic.' -f lrt.cmd_sumnm sumnm",
        res,
    )
    # cracking friends
    ci.HandleCommand(
        "command script add -h '(lrt) Return from current function.' -f lrt.cmd_crack crack",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set a breakpoint and return from that function.' -f lrt.cmd_crackcmd crackcmd",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set a breakpoint and set a register value. doesn\\'t return from function.' -f lrt.cmd_crackcmd_noret crackcmd_noret", # Using lrt help text wording
        res,
    )
    # alias for existing breakpoint commands
    # list all breakpoints
    ci.HandleCommand(
        "command script add -h '(lrt) List breakpoints.' -f lrt.cmd_bpl bpl",
        res,
    )
    # to set breakpoint commands - I hate typing too much
    ci.HandleCommand(
        "command alias -h '(lrt) breakpoint command add alias.' -- bcmd breakpoint command add",
        res,
    )
    # launch process and stop at entrypoint (not exactly as gdb command that just inserts breakpoint)
    # replace the default run alias with our version
    # ci.HandleCommand("command unalias r", res)
    # ci.HandleCommand("command unalias run", res)
    ci.HandleCommand(
        "command script add -h '(lrt) Start the target and stop at entrypoint.' -f lrt.cmd_run rr", # Kept lrt's rr alias
        res,
    )
    # ci.HandleCommand("command alias -h '(lrt) Start the target and stop at entrypoint.' -- run r", res)

    # usually it will be inside dyld and not the target main()
    ci.HandleCommand(
        "command alias -h '(lrt) Start target and stop at entrypoint.' -- break_entrypoint process launch --stop-at-entry",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Show otool output of Mach-O load commands.' -f lrt.cmd_show_loadcmds show_loadcmds",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Show otool output of Mach-O header.' -f lrt.cmd_show_header show_header",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Test function - do not use :-).' -f lrt.cmd_tester tester",
        res,
    )
    ci.HandleCommand(
        "command script add -h '(lrt) Set start address to display on data window.' -f lrt.cmd_datawin datawin",
        res,
    )
    # used mostly for aliases below but can be called as other commands
    ci.HandleCommand(
        "command script add -h '(lrt) Update register function to be used by all the register alias.' -f lrt.cmd_update_register update_register",
        res,
    )
    # shortcut command to modify registers content
    if CONFIG_ENABLE_REGISTER_SHORTCUTS == 1:
        # x64
        ci.HandleCommand(
            "command alias -h '(lrt) Update RIP register.' -- rip update_register rip",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RAX register.' -- rax update_register rax",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RBX register.' -- rbx update_register rbx",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RBP register.' -- rbp update_register rbp",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RSP register.' -- rsp update_register rsp",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RDI register.' -- rdi update_register rdi",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RSI register.' -- rsi update_register rsi",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RDX register.' -- rdx update_register rdx",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update RCX register.' -- rcx update_register rcx",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R8 register.' -- r8 update_register r8",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R9 register.' -- r9 update_register r9",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R10 register.' -- r10 update_register r10",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R11 register.' -- r11 update_register r11",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R12 register.' -- r12 update_register r12",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R13 register.' -- r13 update_register r13",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R14 register.' -- r14 update_register r14",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update R15 register.' -- r15 update_register r15",
            res,
        )
        # x86
        ci.HandleCommand(
            "command alias -h '(lrt) Update EIP register.' -- eip update_register eip",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update EAX register.' -- eax update_register eax",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update EBX register.' -- ebx update_register ebx",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update EBP register.' -- ebp update_register ebp",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update ESP register.' -- esp update_register esp",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update EDI register.' -- edi update_register edi",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update ESI register.' -- esi update_register esi",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update EDX register.' -- edx update_register edx",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update ECX register.' -- ecx update_register ecx",
            res,
        )
        # ARM64
        ci.HandleCommand(
            "command alias -h '(lrt) Update X0 register.' -- x0 update_register x0",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X1 register.' -- x1 update_register x1",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X2 register.' -- x2 update_register x2",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X3 register.' -- x3 update_register x3",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X4 register.' -- x4 update_register x4",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X5 register.' -- x5 update_register x5",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X6 register.' -- x6 update_register x6",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X7 register.' -- x7 update_register x7",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X8 register.' -- x8 update_register x8",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X9 register.' -- x9 update_register x9",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X10 register.' -- x10 update_register x10",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X11 register.' -- x11 update_register x11",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X12 register.' -- x12 update_register x12",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X13 register.' -- x13 update_register x13",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X14 register.' -- x14 update_register x14",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X15 register.' -- x15 update_register x15",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X16 register.' -- x16 update_register x16",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X17 register.' -- x17 update_register x17",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X18 register.' -- x18 update_register x18",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X19 register.' -- x19 update_register x19",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X20 register.' -- x20 update_register x20",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X21 register.' -- x21 update_register x21",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X22 register.' -- x22 update_register x22",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X23 register.' -- x23 update_register x23",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X24 register.' -- x24 update_register x24",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X25 register.' -- x25 update_register x25",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X26 register.' -- x26 update_register x26",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X27 register.' -- x27 update_register x27",
            res,
        )
        ci.HandleCommand(
            "command alias -h '(lrt) Update X28 register.' -- x28 update_register x28",
            res,
        )
        # register write recognizes x29 and x30 but they don't exist in SBFrame
        ci.HandleCommand("command alias -h '(lrt) Update FP register.' -- fp update_register fp", res)
        ci.HandleCommand("command alias -h '(lrt) Update LR register.' -- lr update_register lr", res)
        ci.HandleCommand("command alias -h '(lrt) Update SP register.' -- sp update_register sp", res)
        ci.HandleCommand("command alias -h '(lrt) Update PC register.' -- pc update_register pc", res)

    if CONFIG_KEYSTONE_AVAILABLE == 1:
        ci.HandleCommand(
            "command script add -h '(lrt) 32 bit x86 interactive Keystone based assembler.' -f lrt.cmd_asm32 asm32",
            res,
        )
        ci.HandleCommand(
            "command script add -h '(lrt) 64 bit x86 interactive Keystone based assembler.' -f lrt.cmd_asm64 asm64",
            res,
        )
        ci.HandleCommand(
            "command script add -h '(lrt) 32 bit ARM interactive Keystone based assembler.' -f lrt.cmd_arm32 arm32",
            res,
        )
        ci.HandleCommand(
            "command script add -h '(lrt) 64 bit ARM interactive Keystone based assembler.' -f lrt.cmd_arm64 arm64",
            res,
        )
        ci.HandleCommand(
            "command script add -h '(lrt) 32 bit ARM Thumb interactive Keystone based assembler.' -f lrt.cmd_armthumb armthumb",
            res,
        )
    # add the hook - we don't need to wait for a target to be loaded
    # Note: since I removed the original stop-disassembly-count trick to allegedly avoid
    # double loading it had a side effect to keep adding multiple copies of the hook
    # when doing multiple imports of the script (for testing mostly)
    # a check is now implemented where the hook is only added if no previous hook exist
    ci.HandleCommand("target stop-hook list", res)
    if res.Succeeded():
        # XXX: older lldb crashes if we set the -s option...
        # if "HandleProcessLaunchHook" not in res.GetOutput():
        #     ci.HandleCommand("target stop-hook add -n _dyld_start -s /usr/lib/dyld -o 'HandleProcessLaunchHook'", res)
        if "HandleHookStopOnTarget" not in res.GetOutput():
            ci.HandleCommand("target stop-hook add -o 'lrt.HandleHookStopOnTarget'", res) # Prefix with module name
    else:
        err_msg("Failed to list stop hooks and our hook isn't loaded.")

    ci.HandleCommand(
        "command script add -h '(lrt) Display lrt banner.' --function lrt.cmd_banner banner",
        res,
    )
    # Added from upstream
    ci.HandleCommand("command script add -h '(lrt) Display command man page.' -f lrt.cmd_man man", res)

    # custom commands (kept from lrt)
    ci.HandleCommand(
        "command script add -h '(lrt) Fix return breakpoint.' -f lrt.cmd_fixret fixret",
        res,
    )
    # displays the version banner when lldb is loaded
    LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR = get_lldb_version(debugger)
    debugger.HandleCommand("banner")
    return


def get_lldb_version(debugger):
    version_string = debugger.GetVersionString()
    # print("[+] lldb version: " + version_string)

    apple_pattern = r"lldb-(\d+)(?:\.(\d+))?(?:\.(\d+))?"
    clang_pattern = r"lldb version (\d+)(?:\.(\d+))?(?:\.(\d+))?"

    # match apple lldb pattern (e.g: lldb-1500.0.404.7)
    apple_match = re.search(apple_pattern, version_string, re.IGNORECASE)
    if apple_match:
        variant = "apple"
        major = int(apple_match.group(1))
        minor = int(apple_match.group(2) or 0)
        return variant, major, minor

    # match clang lldb pattern (e.g: lldb version 18.1.8)
    clang_match = re.search(clang_pattern, version_string, re.IGNORECASE)
    if clang_match:
        variant = "clang"
        major = int(clang_match.group(1))
        minor = int(clang_match.group(2) or 0)
        return variant, major, minor

    # If no match is found, raise an exception
    raise ValueError(
        "Unable to determine LLDB variant and version from string: " + version_string
    )

# helper function to print standardized and colored error messages
def err_msg(msg):
    print(COLOR_ERROR + "[-] ERROR: " + RESET + "{}".format(msg))

# internal debug messages
def dbg_msg(msg):
    if LRT_INTERNAL_DEBUG:
        print(COLOR_LOGDEBUG + "[*] DEBUG: " + RESET + "{}".format(msg))

# XXX: kinda hacky and ugly since not adapting to terminal width etc
def help_msg(help_dict):
    print(BOLD + "NAME")
    print(BOLD + "\t{}".format(help_dict["cmd"]) + RESET + " -- {}".format(help_dict["short"]) + "\n")
    print(BOLD + "SYNOPSIS")
    print(BOLD + "\t{}".format(help_dict["cmd"]) + RESET + " " + "{}".format(help_dict.get("args", "")) + "\n") # Use .get for optional args
    print(BOLD + "DESCRIPTION" + RESET)
    # Handle potential multi-line descriptions
    desc = help_dict.get("desc", "")
    print("\t{}".format(desc.replace("\n", "\n\t")))
    print("")
    if "options" in help_dict:
        print(BOLD + "OPTIONS" + RESET)
        for opt in help_dict["options"]:
            print(BOLD + "\t{}".format(opt["name"]) + RESET + "\n\t\t{}".format(opt["desc"]))
            if "values" in opt:
                print("")
                for v in opt["values"]:
                    print("\t\t{}\t{}".format(v.get("n", ""), v.get("d", ""))) # Use .get
        print("")

    if "example" in help_dict:
        print(BOLD + "EXAMPLES" + RESET)
        print("\t{}".format(help_dict["example"]))
        print("")

    if "notes" in help_dict and len(help_dict["notes"]) > 0:
        print(BOLD + "NOTES" + RESET)
        for note in help_dict["notes"]:
            print("\t{}".format(note))
        print("")

# --- Added cmd_man from upstream ---
# just a silly shortcut - requires the command to have the help option
def cmd_man(debugger, command, result, dict):
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The man command requires an argument.")
        return

    res = lldb.SBCommandReturnObject()
    # just call the target command with the help option
    # We assume the target command uses the new help system
    target_cmd_name = cmd[0]
    # Need to find the actual function object to call its help logic if possible,
    # but simply calling `cmd help` is easier and usually works if commands implement it.
    debugger.GetCommandInterpreter().HandleCommand(target_cmd_name + " help", res)
    if res.GetErrorSize() > 0 or "unrecognized command" in res.GetOutput().lower() or "unrecognized command" in res.GetError().lower():
        # Check output too, as HandleCommand might succeed but print an error
         err_msg("Requested man page for unknown command '{}' or it doesn't support 'help' argument.".format(target_cmd_name))
    else:
        # Print the help output obtained
        if res.GetOutputSize() > 0:
            print(res.GetOutput())
        if res.GetErrorSize() > 0: # Print errors too, e.g., if help logic itself fails
             print(res.GetError())


def cmd_banner(debugger, command, result, dict):
    global LLDB_VARIANT, LLDB_MAJOR, LLDB_MINOR
    print(
        f"{GREEN}[+] lrt v{VERSION}.{BUILD} @ lldb-{LLDB_MAJOR}.{LLDB_MINOR} ({LLDB_VARIANT}){RESET}"
    )


def cmd_lrtcmds(debugger, command, result, dict):
    """Display all available lrt commands."""

    help_table = [
        ["lrtcmds", "this command"],
        ["man", "display command man page"], # Added from upstream
        ["----[ Settings ]----", ""],
        ["enable", "configure lldb and lrt options"],
        ["disable", "configure lldb and lrt options"],
        ["contextcodesize", "set number of instruction lines in code window"],
        ["enablesolib/disablesolib", "enable/disable the stop on library load events"],
        ["enableaslr/disableaslr", "enable/disable process ASLR"],
        ["datawin", "set start address to display on data window"],
        ["----[ Sessions ]----", ""], # Added from upstream
        ["ls", "display available sessions"],
        ["ss", "save current session"],
        ["rs", "restore session"],
        ["----[ Breakpoints ]----", ""],
        ["bb", "set a software breakpoint (alias for bp)"], # Kept lrt's bb alias
        ["b", "set a software breakpoint"], # Default lldb command, often aliased
        ["bp", "alias to b (set software breakpoint)"],
        ["bpt", "set a temporary software breakpoint"],
        ["bh", "set an hardware breakpoint"],
        ["bht", "set a temporary hardware breakpoint"], # Added from upstream
        ["bpc", "clear breakpoint"],
        ["bpca", "clear all breakpoints"],
        ["bpd", "disable breakpoint"],
        ["bpda", "disable all breakpoints"],
        ["bpe", "enable a breakpoint"],
        ["bpea", "enable all breakpoints"],
        ["bcmd", "alias to breakpoint command add"],
        ["bpl", "list all breakpoints"],
        ["bpn", "temporarly breakpoint next instruction"],
        ["bm", "breakpoint on module load"],
        ["bmc", "clear all module load breakpoints"],
        ["bml", "list all on module load breakpoints"],
        ["bpmnm", "temporarily breakpoint all instructions with mnemonic"], # Kept from lrt
        ["break_entrypoint", "launch target and stop at entrypoint"],
        ["int3", "patch memory address with INT3/BRK"],
        ["rint3", "restore original byte at address patched with INT3/BRK"],
        ["listint3", "list all INT3/BRK patched addresses"],
        ["lb", "load breakpoints from file (unimplemented?)"], # Kept, but likely needs review/impl
        ["lbrva", "load breakpoints from file (RVA, unimplemented?)"], # Kept, but likely needs review/impl
        ["print_images", "print all images available at gdb_image_notifier() breakpoint"],
        ["----[ Stepping ]----", ""],
        ["skip", "skip current instruction"],
        ["stepo", "step over calls and loop instructions"],
        ["stepoh", "step over calls and loop instructions (hardware bp)"], # Added from upstream
        ["sutcs", "Step until call stack changes"], # Kept from lrt
        ["sutbt", "Step until branch is taken"], # Kept from lrt
        ["suebb", "Step until end of basic block (branch)"], # Kept from lrt
        ["sumnm", "Step until instruction mnemonic"], # Kept from lrt
        ["----[ Memory ]----", ""],
        ["nop", "patch memory address with NOP"],
        ["null", "patch memory address with NULL"],
        ["db/dw/dd/dq", "memory hex dump in different formats"],
        ["findmem", "search memory"],
        ["showregions", "display process memory regions"],
        ["----[ Disassembly ]----", ""],
        ["u", "dump instructions"],
        ["ctx/context", "show current instruction pointer CPU context"],
        ["acm", "add disassembly comment"],
        ["dcm", "remove disassembly comment"],
        ["lcm", "list disassembly comments"],
        ["----[ Registers and CPU Flags ]----", ""],
        ["rip/rax/rbx/etc", "shortcuts to modify x64 registers"],
        ["eip/eax/ebx/etc", "shortcuts to modify x86 registers"],
        ["x{0..28}/fp/lr/sp/pc", "shortcuts to modify ARM64 registers"], # Added fp/lr/sp/pc
        ["cfa/cfc/cfd/cfi/cfo/cfp/cfs/cft/cfz", "change x86/x64 CPU flags"],
        ["cfn/cfz/cfc/cfv", "change AArch64 CPU flags (NZCV register)"],
        ["----[ File headers ]----", ""],
        ["show_loadcmds", "show otool output of Mach-O load commands"],
        ["show_header", "show otool output of Mach-O header"],
        ["----[ Cracking ]----", ""],
        ["crack", "return from current function"],
        ["crackcmd", "set a breakpoint and return from that function"],
        ["crackcmd_noret", "set a breakpoint and set a register value. doesn\\'t return from function"],
        ["----[ Misc ]----", ""],
        ["iphone", "connect to debugserver running on iPhone"], # Kept from lrt
        ["tl", "list threads"], # Added from upstream
        ["ts", "suspend thread"], # Added from upstream
        ["fixret", "fix return breakpoint anti-debugging"], # Kept from lrt
        ["----[ Assembler ]----", ""],
        ["asm32/asm64", "x86/x64 assembler using keystone"],
        ["arm32/arm64/armthumb", "ARM assembler using keystone"],
    ]

    # lrt style print
    print("lrt available commands:")

    for row in help_table:
        if not row[1]: # Section header
            print(" {: <20} {: <30}".format(*row))
        else:
            print(" {: <20} - {: <30}".format(*row))

    print("\nUse 'cmdname help' or 'man cmdname' for extended command help.")


# placeholder to make tests
def cmd_tester(debugger, command, result, dict):
    # Using the new help system
    help_dict = {
    "cmd": "tester",
    "short": "test command",
    "desc": """Testing the help command.\nThis is a multiline test.""",
    "args": "<settings> [<size>]",
    "options": [
        {
            "name": "settings",
            "desc": "The available settings are:",
            "values": [
                {
                    "n": "solib",
                    "d": "Enable stop on library events trick."
                },
                {
                    "n": "aslr",
                    "d": "Enable process ASLR."
                }
            ],
        },
        {
            "name": "size",
            "desc": "The number of bytes to patch. Default is 1."
        }
    ],
    "example": "tester solib 4",
    "notes": [
        "This is note1.",
        "This is note2."
        ]
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    print("Tester command executed with:", command)
    return


# -------------------------
# Settings related commands
# -------------------------


def cmd_enable(debugger, command, result, dict):
    """Enable certain lldb and lrt options. Use 'enable help' for more information."""
    help_dict = {
        "cmd": "enable",
        "short": "enable configuration options",
        "desc": "Enable certain lldb and lrt configuration options.",
        "args": "<setting>",
        "options": [
            {
                "name": "settings",
                "desc": "The available settings are:",
                "values": [
                    {"n": "solib", "d": "Enable stop on library events trick."},
                    {"n": "aslr", "d": "Enable process ASLR."},
                    {"n": "stack", "d": "Enable stack window in context display."},
                    {"n": "data", "d": "Enable data window in context display, configure address with datawin."},
                    {"n": "flow", "d": "Enable call targets and objective-c class/methods window in context display."},
                ],
            },
        ],
        "example": "enable stack"
    }
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The command requires an argument.")
        help_msg(help_dict)
        return

    setting = cmd[0].lower() # Case-insensitive compare

    if setting == "solib":
        debugger.HandleCommand(
            "settings set target.process.stop-on-sharedlibrary-events true"
        )
        print("[+] Enabled stop on library events trick.")
    elif setting == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr false")
        print("[+] Enabled ASLR.")
    elif setting == "stack":
        CONFIG_DISPLAY_STACK_WINDOW = 1
        print("[+] Enabled stack window in context display.")
    elif setting == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 1
        print("[+] Enabled indirect control flow window in context display.")
    elif setting == "data":
        CONFIG_DISPLAY_DATA_WINDOW = 1
        print(
            "[+] Enabled data window in context display. Configure address with 'datawin' cmd."
        )
    elif setting == "help":
        help_msg(help_dict)
    else:
        err_msg("Unrecognized setting: '{}'".format(setting))
        help_msg(help_dict)

    return


def cmd_disable(debugger, command, result, dict):
    """Disable certain lldb and lrt options. Use 'disable help' for more information."""
    help_dict = {
        "cmd": "disable",
        "short": "disable configuration options",
        "desc": "Disable certain lldb and lrt configuration options.",
        "args": "<setting>",
        "options": [
            {
                "name": "settings",
                "desc": "The available settings are:",
                "values": [
                    {"n": "solib", "d": "Disable stop on library events trick."},
                    {"n": "aslr", "d": "Disable process ASLR."},
                    {"n": "stack", "d": "Disable stack window in context display."},
                    {"n": "data", "d": "Disable data window in context display."},
                    {"n": "flow", "d": "Disable call targets and objective-c class/methods window in context display."},
                ],
            },
        ],
        "example": "disable aslr"
    }
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW

    cmd = command.split()
    if len(cmd) == 0:
        err_msg("The command requires an argument.")
        help_msg(help_dict)
        return

    setting = cmd[0].lower()

    if setting == "solib":
        debugger.HandleCommand(
            "settings set target.process.stop-on-sharedlibrary-events false"
        )
        print("[+] Disabled stop on library events trick.")
    elif setting == "aslr":
        debugger.HandleCommand("settings set target.disable-aslr true")
        print("[+] Disabled ASLR.")
    elif setting == "stack":
        CONFIG_DISPLAY_STACK_WINDOW = 0
        print("[+] Disabled stack window in context display.")
    elif setting == "flow":
        CONFIG_DISPLAY_FLOW_WINDOW = 0
        print("[+] Disabled indirect control flow window in context display.")
    elif setting == "data":
        CONFIG_DISPLAY_DATA_WINDOW = 0
        print("[+] Disabled data window in context display.")
    elif setting == "help":
        help_msg(help_dict)
    else:
        err_msg("Unrecognized setting: '{}'".format(setting))
        help_msg(help_dict)
    return


def cmd_contextcodesize(debugger, command, result, dict):
    """Set the number of disassembly lines in code window. Use 'contextcodesize help' for more information."""
    help_dict = {
        "cmd": "contextcodesize",
        "short": "set disassembly lines",
        "desc": "Configures the number of disassembly lines displayed in code window.",
        "args": "<line_count>",
        "options": [{"name": "line_count", "desc": "Number of disassembly lines to display. Default is 8."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "contextcodesize 10"
    }
    global CONFIG_DISASSEMBLY_LINE_COUNT
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert the number of disassembly lines to display.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        print("Current configuration value is: {:d}".format(CONFIG_DISASSEMBLY_LINE_COUNT))
        return

    value = evaluate(cmd[0])
    if value is None or value <= 0: # Add check for positive value
        err_msg("Invalid input value. Must be a positive integer.")
        help_msg(help_dict)
        return

    CONFIG_DISASSEMBLY_LINE_COUNT = value
    print("[+] Context code size set to {} lines.".format(value))

    return


# ---------------------------------
# Color and output related commands
# ---------------------------------

# This function is now effectively just print, but kept for potential future use or clarity
def output(x):
    """Prints the given string x without a newline."""
    print(x, end='')

# ---------------------------------
# Threads related commands (Added from upstream)
# ---------------------------------
def cmd_listthreads(debugger, command, result, dict):
    """List current threads. Use 'tl help' for more information."""
    help_dict = {
        "cmd": "tl",
        "short": "list threads",
        "desc": "List current running threads.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    proc = get_process()
    if not proc or not proc.IsValid():
         err_msg("No valid process found.")
         return

    num_threads = proc.GetNumThreads()
    if num_threads == 0:
        err_msg("No threads available. Is the target running?")
        return

    print(f"Process {proc.GetProcessID()} has {num_threads} thread{'s' if num_threads != 1 else ''}:")
    selected_thread = proc.GetSelectedThread()
    current_tid = selected_thread.GetThreadID() if selected_thread else None

    for i in range(num_threads):
        thread = proc.GetThreadAtIndex(i)
        tid = thread.GetThreadID()
        index_id = thread.GetIndexID() # LLDB's internal index
        state = lldb.SBDebugger.StateAsCString(thread.GetState())
        stop_reason_str = lldb.SBDebugger.StopReasonString(thread.GetStopReason())
        is_stopped = thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid
        queue_name = thread.GetQueueName() if thread.GetQueueName() else ""
        thread_name = thread.GetName() if thread.GetName() else ""

        prefix = "*" if tid == current_tid else " "
        info = f"  {prefix} tid={tid:<6} index={index_id:<3} state={state:<10}"
        if is_stopped:
            info += f" stop_reason={stop_reason_str}"
        if thread_name:
            info += f" name='{thread_name}'"
        if queue_name:
             info += f" queue='{queue_name}'"

        print(info)

def cmd_suspendthread(debugger, command, result, dict):
    """Suspend a thread. Use 'ts help' for more information."""
    help_dict = {
        "cmd": "ts",
        "short": "suspend thread",
        "desc": "Suspend a thread by its index ID.",
        "args": "<thread_index>",
        "options": [{"name": "thread_index", "desc": "The thread index ID to suspend. List available threads with 'thread list' or 'tl'."}],
        "example": "ts 2"
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a thread index ID.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    try:
        thread_index = int(cmd[0])
    except ValueError:
        err_msg("Invalid input value - only a thread index ID (integer) is valid.")
        help_msg(help_dict)
        return

    proc = get_process()
    if not proc or not proc.IsValid():
        err_msg("No valid process found.")
        return

    thread = proc.GetThreadByIndexID(thread_index)
    if not thread or not thread.IsValid():
        err_msg(f"Thread with index ID {thread_index} not found.")
        return

    if thread.Suspend():
        print(f"[+] Thread index {thread_index} (tid={thread.GetThreadID()}) suspended.")
    else:
        err_msg(f"Failed to suspend thread index {thread_index}.")
    return


# ---------------------------
# Breakpoint related commands
# ---------------------------

ANTIDEBUG_SYSCTL_OBJS = []


# the second step breakpoint callback of the sysctl antidebug bypass
# we are at the return address of sysctl symbol
# and we simply remove the P_TRACED flag if it exists
def antidebug_callback_step2(frame, bp_loc, dict):
    P_TRACED = 0x800
    global ANTIDEBUG_SYSCTL_OBJS
    # print("[+] Hit antidebug_callback_step2")
    target = get_target() # Added target retrieval
    process = target.GetProcess() # Added process retrieval

    # Iterate safely over a copy
    objects_to_process = list(ANTIDEBUG_SYSCTL_OBJS)
    ANTIDEBUG_SYSCTL_OBJS = [] # Clear original list

    for i in objects_to_process:
        # offset to kp_proc.p_flag - this should be stable
        offset = 0x20
        error = lldb.SBError()
        # read the current value so we can modify and write again
        value = process.ReadUnsignedFromMemory(i + offset, 4, error)
        # remove P_TRACED flag if it exists
        if error.Success() and (value & P_TRACED):
            print("[+] Hit sysctl antidebug request - removing P_TRACED flag.")
            value = value ^ P_TRACED
            # WriteMemory accepts bytes or bytearray in Python 3
            patch = struct.pack("<I", value) # Use little-endian for consistency if needed
            result = process.WriteMemory(i + offset, patch, error)
            if not error.Success():
                err_msg("Failed to write memory at 0x{:x} (Error: {}).".format(i + offset, error))
                continue # Try next object if write fails
        elif not error.Success():
            err_msg("Failed to read memory for P_TRACED flag at 0x{:x} (Error: {}).".format(i + offset, error))

    # Only continue if the script didn't encounter critical errors?
    # Assuming automatic continuation is desired after attempting patches.
    process.Continue()


# the first step breakpoint callback of the sysctl antidebug bypass
# this deals with the breakpoint at sysctl symbol
# the purpose is to verify the request and set a second stage on return address
# where the debug flag is removed
def antidebug_callback_step1(frame, bp_loc, dict):
    global ANTIDEBUG_SYSCTL_OBJS
    error = lldb.SBError()

    if frame is None:
        return 0

    target = get_target()
    process = target.GetProcess() # Added process retrieval

    if is_x64():
        src_reg = "rdi"
        dst_reg = "rdx"
        ret_reg = "rip" # x86_64 uses rip for instruction pointer
    elif is_arm():
        src_reg = "x0"
        dst_reg = "x2"
        ret_reg = "pc" # ARM uses pc
    else:
        # Assuming i386 otherwise
        src_reg = "eax" # Placeholder, need actual i386 ABI for sysctl args
        dst_reg = "edx" # Placeholder
        ret_reg = "eip"
        err_msg("Sysctl anti-debug step 1 requires specific i386 argument handling.")
        # Need to read args from stack for i386
        # For now, let's prevent processing for i386 until implemented
        process.Continue()
        return 0

    mib_addr = int(frame.FindRegister(src_reg).GetValue(), 16)

    mib0 = process.ReadUnsignedFromMemory(mib_addr, 4, error)
    if not error.Success():
        err_msg("Failed to read mib0.")
        process.Continue()
        return
    mib1 = process.ReadUnsignedFromMemory(mib_addr + 4, 4, error)
    if not error.Success():
        err_msg("Failed to read mib1.")
        process.Continue()
        return
    mib2 = process.ReadUnsignedFromMemory(mib_addr + 8, 4, error)
    if not error.Success():
        err_msg("Failed to read mib2.")
        process.Continue()
        return
    # check if it's a potential AmIBeingDebugged request
    # it's a common request from some apps
    # so we need to verify on the return and remove the flag
    # CTL_KERN (1) - KERN_PROC (14) - KERN_PROC_PID (1)
    if mib0 == 1 and mib1 == 14 and mib2 == 1:
        # print("[+] Hit sysctl antidebug request check")
        # the pointer to the sysctl output oldp
        oldp = int(frame.FindRegister(dst_reg).GetValue(), 16)
        if oldp == 0:
            print("[!] Warning: oldp == 0 in sysctl call, cannot patch.")
        else:
            ANTIDEBUG_SYSCTL_OBJS.append(oldp)
            # Determine return address - usually LR on ARM, value on stack top for x86
            # For simplicity, let's assume we need to find the 'ret' instruction after the syscall.
            # A more robust way might involve reading LR or stack.
            # This part is tricky and architecture-dependent.
            # Let's try finding the return instruction address after the current PC.
            # THIS IS HEURISTIC AND MAY FAIL. A better approach uses `thread step-out`.

            current_pc_val = frame.FindRegister(ret_reg).GetValueAsUnsigned()
            mem_sbaddr = lldb.SBAddress(current_pc_val, target)
            inst = target.ReadInstructions(mem_sbaddr, 64, CONFIG_FLAVOR) # Use CONFIG_FLAVOR

            return_found = False
            for i in inst:
                # Need to find the *actual* return address, which isn't necessarily the next instruction.
                # On x86, it's on the stack. On ARM, it's in LR.
                # The previous code set a breakpoint *after* the sysctl call, this is more correct.
                # Let's read the return address properly.

                actual_ret_addr = 0
                if is_x64() or is_i386():
                     sp_val = frame.FindRegister("rsp" if is_x64() else "esp").GetValueAsUnsigned()
                     actual_ret_addr = process.ReadPointerFromMemory(sp_val, error)
                     if not error.Success():
                         err_msg("Failed to read return address from stack.")
                         break
                elif is_arm():
                     actual_ret_addr = frame.FindRegister("lr").GetValueAsUnsigned()

                if actual_ret_addr != 0:
                    # print(f"[DEBUG] Setting one-shot breakpoint at return address: {hex(actual_ret_addr)}")
                    nextbp = target.BreakpointCreateByAddress(actual_ret_addr)
                    nextbp.SetOneShot(True)
                    nextbp.SetThreadID(frame.GetThread().GetThreadID())
                    nextbp.SetScriptCallbackFunction("lrt.antidebug_callback_step2")
                    return_found = True
                    break # Found the return address, set BP, exit loop

            if not return_found:
                err_msg("Could not determine return address to set step2 breakpoint.")
                # Clean up object if we couldn't set breakpoint
                if oldp != 0 and oldp in ANTIDEBUG_SYSCTL_OBJS:
                    ANTIDEBUG_SYSCTL_OBJS.remove(oldp)

    # everything automatic here so continue in any case
    process.Continue()


# bypass PT_DENY_ATTACH via ptrace() call
def antidebug_ptrace_callback(frame, bp_loc, dict):
    PT_DENY_ATTACH = 31
    error = lldb.SBError()
    process = get_process() # Added process retrieval

    if is_x64():
        req_reg = "rdi"
        ret_reg = "rax"
    elif is_arm():
        req_reg = "x0"
        ret_reg = "x0"
    elif is_i386():
        # Need to read ptrace args from stack for i386
        err_msg("Ptrace anti-debug requires specific i386 argument handling.")
        process.Continue()
        return
    else:
        err_msg("Unsupported architecture for ptrace anti-debug.")
        process.Continue()
        return

    request = frame.FindRegister(req_reg).GetValueAsUnsigned()

    if request == PT_DENY_ATTACH:
        print("[+] Hit ptrace(PT_DENY_ATTACH) anti-debug request")
        # we are essentially bypassing the whole call to return a value of 0
        reg_value_obj = frame.registers[0].GetChildMemberWithName(ret_reg) # GPRs are usually index 0
        if not reg_value_obj:
             err_msg(f"Failed to get {ret_reg} register object.")
             process.Continue()
             return

        success = reg_value_obj.SetValueFromCString("0x0", error)
        if not success or not error.Success():
            err_msg("Failed to write 0 to {} register. Error: {}".format(ret_reg, error))
            process.Continue()
            return

        # and return immediately to the caller without executing any ptrace() code
        thread = frame.GetThread()
        if not thread.ReturnFromFrame(frame, reg_value_obj):
             err_msg(f"Failed to return from frame after patching {ret_reg}.")
             # If return fails, just continue
             process.Continue()
        # If ReturnFromFrame succeeds, execution continues from caller automatically.
    else:
        # Not the request we care about, just continue
        process.Continue()


# debugger detection via the mach exception ports
def antidebug_task_exception_ports_callback(frame, bp_loc, dict):
    process = get_process() # Added process retrieval
    if frame is None:
        process.Continue()
        return 0

    if is_x64():
        mask_reg = "rsi" # exception_mask is the 2nd arg
    elif is_arm():
        mask_reg = "x1"  # exception_mask is the 2nd arg
    elif is_i386():
        # Need to read args from stack for i386
        err_msg("Task exception port anti-debug requires specific i386 argument handling.")
        process.Continue()
        return
    else:
        err_msg("Unsupported architecture for task exception port anti-debug.")
        process.Continue()
        return

    mask_reg_obj = frame.FindRegister(mask_reg)
    if not mask_reg_obj:
        err_msg(f"Could not find register {mask_reg}.")
        process.Continue()
        return

    exception_mask = mask_reg_obj.GetValueAsUnsigned()

    # EXC_MASK_ALL includes breakpoint and exception traps used by debuggers
    # If the mask includes debugger-related exceptions, clear it.
    # Relevant masks: EXC_MASK_BREAKPOINT, EXC_MASK_SOFTWARE, EXC_MASK_SYSCALL?
    # Let's simplify: if *any* mask is being set/get, assume it might be anti-debug
    # and clear the mask being passed in. A more refined approach would check specific bits.
    if exception_mask != 0x0:
        print("[+] Hit {} anti-debug request (mask=0x{:x}) - clearing mask".format(frame.symbol.name, exception_mask))
        error = lldb.SBError()
        # Modify the register containing the mask argument
        gpr_set = frame.registers[0] # Assume GPRs are the first set
        mask_val_obj = gpr_set.GetChildMemberWithName(mask_reg)
        if not mask_val_obj:
            err_msg(f"Failed to get SBValue for register {mask_reg}.")
            process.Continue()
            return

        result = mask_val_obj.SetValueFromCString("0x0", error)
        if not result or not error.Success():
            err_msg("Failed to write 0 to {} register. Error: {}".format(mask_reg, error))
            # Continue even if patching fails, maybe the original call is harmless
            process.Continue()
            return
        # If patch succeeds, continue the original function call with the modified mask
        process.Continue()
    else:
        # Mask is already 0, harmless call, just continue
        process.Continue()


def cmd_antidebug(debugger, command, result, dict):
    """Enable anti-anti-debugging. Use 'antidebug help' for more information."""
    help_dict = {
        "cmd": "antidebug",
        "short": "enable anti-anti-debugging",
        "desc": "Enable anti-anti-debugging measures.\nBypasses debugger detection via sysctl, ptrace PT_DENY_ATTACH, and task exception ports.",
        "args": "",
        "notes": ["Sets breakpoints on relevant system calls."]
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    target = get_target()
    if not target:
        err_msg("No target selected.")
        return

    # Check if symbols/libs exist before setting breakpoints
    sysctl_bp = target.BreakpointCreateByName("sysctl", "libsystem_c.dylib")
    ptrace_bp = target.BreakpointCreateByName("ptrace", "libsystem_kernel.dylib")
    task_get_bp = target.BreakpointCreateByName("task_get_exception_ports", "libsystem_kernel.dylib")
    task_set_bp = target.BreakpointCreateByName("task_set_exception_ports", "libsystem_kernel.dylib")

    bps_set = 0
    if sysctl_bp and sysctl_bp.IsValid():
        sysctl_bp.SetScriptCallbackFunction("lrt.antidebug_callback_step1")
        bps_set += 1
        print("[+] Set sysctl anti-debug breakpoint.")
    else:
        print("[!] Warning: Could not set breakpoint on sysctl.")

    if ptrace_bp and ptrace_bp.IsValid():
        ptrace_bp.SetScriptCallbackFunction("lrt.antidebug_ptrace_callback")
        bps_set += 1
        print("[+] Set ptrace anti-debug breakpoint.")
    else:
        print("[!] Warning: Could not set breakpoint on ptrace.")

    if task_get_bp and task_get_bp.IsValid():
        task_get_bp.SetScriptCallbackFunction("lrt.antidebug_task_exception_ports_callback")
        bps_set += 1
        print("[+] Set task_get_exception_ports anti-debug breakpoint.")
    else:
        print("[!] Warning: Could not set breakpoint on task_get_exception_ports.")

    if task_set_bp and task_set_bp.IsValid():
        task_set_bp.SetScriptCallbackFunction("lrt.antidebug_task_exception_ports_callback")
        bps_set += 1
        print("[+] Set task_set_exception_ports anti-debug breakpoint.")
    else:
        print("[!] Warning: Could not set breakpoint on task_set_exception_ports.")

    if bps_set > 0:
         print(f"[+] Enabled {bps_set} anti-anti-debugging measure(s).")
    else:
         err_msg("Failed to enable any anti-anti-debugging measures.")


# the callback for the specific module loaded breakpoint
# supports x64, i386, arm64
def module_breakpoint_callback(frame, bp_loc, dict):
    global modules_list
    # rdx contains the module address
    # rdx+8 contains pointer to the module name string
    if frame is None:
        return 0 # Must return integer

    target = get_target() # Added target retrieval
    process = target.GetProcess() # Added process retrieval
    error = lldb.SBError()

    i386 = is_i386()
    x64 = is_x64()
    arm = is_arm()
    if not i386 and not x64 and not arm:
        err_msg("Unsupported architecture.")
        process.Continue() # Continue if unsupported
        return 0

    # Arguments for gdb_image_notifier / lldb_image_notifier
    # static void notifier(enum dyld_image_mode mode, uint32_t infoCount, const dyld_image_info info[])
    mode_reg, count_reg, info_reg = None, None, None

    if x64:
        mode_reg, count_reg, info_reg = "rdi", "rsi", "rdx"
    elif arm:
        mode_reg, count_reg, info_reg = "x0", "x1", "x2"
    elif i386:
        # i386 args are on the stack after return address
        sp = frame.FindRegister("esp").GetValueAsUnsigned()
        mode_addr = sp + 4
        count_addr = sp + 8
        info_addr = sp + 12

        mode = process.ReadUnsignedFromMemory(mode_addr, 4, error)
        if not error.Success(): err_msg("Failed to read mode from stack."); process.Continue(); return 0
        infoCount = process.ReadUnsignedFromMemory(count_addr, 4, error)
        if not error.Success(): err_msg("Failed to read infoCount from stack."); process.Continue(); return 0
        info_ptr = process.ReadUnsignedFromMemory(info_addr, 4, error) # This is the pointer *to* the array
        if not error.Success(): err_msg("Failed to read info array pointer from stack."); process.Continue(); return 0
    else: # Should not happen based on earlier check
        process.Continue(); return 0

    # Read register arguments if not i386
    if not i386:
        mode = frame.FindRegister(mode_reg).GetValueAsUnsigned()
        infoCount = frame.FindRegister(count_reg).GetValueAsUnsigned()
        info_ptr = frame.FindRegister(info_reg).GetValueAsUnsigned()

    # only interested in new images being added
    # enum dyld_image_mode { dyld_image_adding=0, dyld_image_removing=1, dyld_image_info_change=2, dyld_image_dyld_moved=3 };
    if mode != 0:
        process.Continue()
        return 0

    # Determine pointer size and struct size based on architecture
    ptr_size = 8 if (x64 or arm) else 4
    # struct dyld_image_info { const struct mach_header* imageLoadAddress; const char* imageFilePath; uintptr_t imageFileModDate; };
    # On 64-bit: pointer, pointer, uintptr_t -> 8 + 8 + 8 = 24
    # On 32-bit: pointer, pointer, uintptr_t -> 4 + 4 + 4 = 12
    dyld_image_info_size = ptr_size * 3

    hit = False
    current_info_item_ptr = info_ptr
    # go over all the images being added and try to find the ones we are interested in
    for x in range(infoCount):
        # Read imageLoadAddress (pointer)
        address = process.ReadPointerFromMemory(current_info_item_ptr, error)
        if not error.Success():
            err_msg(f"Failed to read imageLoadAddress from info structure at {hex(current_info_item_ptr)}: {error}")
            process.Continue(); return 0

        # Read imageFilePath (pointer)
        string_ptr = process.ReadPointerFromMemory(current_info_item_ptr + ptr_size, error)
        if not error.Success():
            err_msg(f"Failed to read imageFilePath pointer from info structure at {hex(current_info_item_ptr + ptr_size)}: {error}")
            process.Continue(); return 0

        # Read the path string
        string = process.ReadCStringFromMemory(string_ptr, 1024, error)
        if not error.Success():
            err_msg(f"Failed to read module name string from {hex(string_ptr)}: {error}")
            # Continue reading next item even if string fails
            current_info_item_ptr += dyld_image_info_size
            continue

        # Check against our list of modules to break on
        for module_to_find in modules_list:
            # Match basename or full path? Let's match full path for now.
            # Normalize paths for comparison if needed
            if module_to_find == string:
                hit = True
                print("[+] Hit module loading: {0} @ {1}".format(string, hex(address)))
                # Don't continue automatically, let the user inspect
                return 0 # Stop execution

        # If we found the module, no need to check further in this callback invocation
        if hit:
            return 0

        # Advance to next dyld_image_info struct in the array
        current_info_item_ptr += dyld_image_info_size

    # nothing found so we resume execution
    if not hit:
        process.Continue()

    return 0 # Default return


# breakpoint on specific module
def cmd_bm(debugger, command, result, dict):
    """Set breakpoint on specific module load. Use 'bm help' for more information."""
    help_dict = {
        "cmd": "bm",
        "short": "set breakpoint on module load",
        "desc": """Set breakpoint on dyld's image notifier function (_gdb_image_notifier or _lldb_image_notifier).
Similar to stop-on-sharedlibrary-events but stops only on configured module paths.
Issue the command multiple times to add different modules.
If no module path is specified, it sets a breakpoint at the notifier entry point. Use 'print_images' there to show all images being loaded.""",
        "args": "[<full path to module>]",
        "notes": ["The _gdb_image_notifier symbol was removed in macOS Monterey and later. _lldb_image_notifier might be used instead or the mechanism might differ.",
                  "Requires the process to be started, e.g., using 'r' or 'process launch -s' first."],
        "example": "bm /System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    }
    global modules_list
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    target = get_target()
    if not target or not target.IsValid():
        err_msg("No valid target.")
        return

    process = target.GetProcess()
    if not process or not process.IsValid() or process.GetState() == lldb.eStateExited:
         err_msg("Process is not running or has exited. Use 'r' or 'process launch -s' first.")
         return

    # convert everything to a single string for the path
    modpath = " ".join([str(item) for item in cmd])

    notifier_symbol_name = "_lldb_image_notifier" # Default modern name
    # Try older name if the first one fails
    notifier_symbols_to_try = ["_lldb_image_notifier", "_gdb_image_notifier"]
    notifier_bp = None
    notifier_addr = lldb.LLDB_INVALID_ADDRESS

    for sym_name in notifier_symbols_to_try:
        bps = target.BreakpointCreateByName(sym_name, "dyld")
        if bps and bps.IsValid() and bps.GetNumLocations() > 0:
            notifier_bp = bps
            notifier_addr = notifier_bp.GetLocationAtIndex(0).GetLoadAddress()
            print(f"[+] Found image notifier symbol '{sym_name}'")
            break # Found a valid symbol

    if not notifier_bp or not notifier_bp.IsValid():
        err_msg(f"Failed to find or set breakpoint on dyld image notifier symbols: {notifier_symbols_to_try}. Is dyld loaded?")
        return

    # Check if the breakpoint already has our callback (maybe set by a previous 'bm' command)
    existing_callback = notifier_bp.GetScriptCallbackFunction()

    callback_func_name = "lrt.module_breakpoint_callback"

    if modpath: # If a module path was specified
        if modpath not in modules_list:
            modules_list.append(modpath)
            print(f"[+] Added '{modpath}' to list of modules to break on.")
        else:
             print(f"[!] Module '{modpath}' is already in the list.")

        # Ensure the callback is set if we're tracking specific modules
        if not existing_callback or existing_callback != callback_func_name:
            notifier_bp.SetScriptCallbackFunction(callback_func_name)
            print(f"[+] Set script callback '{callback_func_name}' on image notifier breakpoint #{notifier_bp.GetID()}.")
        else:
             print(f"[+] Script callback '{callback_func_name}' already set on breakpoint #{notifier_bp.GetID()}.")

    else: # No module path specified, just set the breakpoint
        print(f"[+] Set breakpoint on image notifier '{notifier_bp.GetFunctionName()}' at {hex(notifier_addr)} (Breakpoint #{notifier_bp.GetID()}).")
        # If tracking specific modules previously, remove callback if user now wants generic break?
        # Or keep the callback and let it handle the empty modules_list case? Let's keep it simple and leave callback if it was there.


def cmd_bmc(debugger, command, result, dict):
    """Clear all modules being watched by 'bm'. Use 'bmc help' for more information."""
    help_dict = {
        "cmd": "bmc",
        "short": "clear module breakpoints list",
        "desc": "Clear the list of modules being watched by the 'bm' command. Does not remove the underlying breakpoint on the image notifier.",
        "args": "",
    }
    global modules_list
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    if len(modules_list) > 0:
        print(f"[+] Cleared {len(modules_list)} module(s) from the watch list.")
        modules_list = []
    else:
        print("[+] Module watch list is already empty.")


def cmd_bml(debugger, command, result, dict):
    """List all modules being watched by 'bm'."""
    help_dict = {
        "cmd": "bml",
        "short": "list watched modules",
        "desc": "List all modules currently being watched by the 'bm' command.",
        "args": "",
    }
    # cmd = command.split()
    # if len(cmd) > 0 and cmd[0] == "help":
    #     help_msg(help_dict)
    #     return
    # Handle help explicitly if passed (though no args expected)
    if command.strip() == "help":
        help_msg(help_dict)
        return

    if len(modules_list) == 0:
        print("No modules currently being watched by 'bm'.")
        return
    print("Modules being watched by 'bm':")
    for i in modules_list:
        print("- " + i)


# Kept from lrt
def cmd_bpmnm(debugger, command, result, dict):
    """
    Set temporary breakpoint on all instructions in a module with a specific mnemonic.
    Use 'bpmnm help' for more information.
    """
    help_dict = { # Using dict format
        "cmd": "bpmnm",
        "short": "breakpoint mnemonic in module",
        "desc": "Set temporary breakpoints on all instructions matching a specific mnemonic within a given module.",
        "args": "<module_name> <mnemonic>",
        "example": "bpmnm MyApp mov",
        "notes": ["Breakpoints are one-shot and thread-specific to the current thread."]
    }

    # Parse and validate command arguments
    cmd = command.strip().split()
    if len(cmd) == 1 and cmd[0].lower() == "help":
         help_msg(help_dict)
         return
    if len(cmd) != 2:
        err_msg("Invalid arguments.")
        help_msg(help_dict)
        return

    target_module_name = cmd[0]
    mnemonic = cmd[1].lower()  # Convert to lowercase for case-insensitive comparison
    target_module = None

    # Retrieve the current target
    target = get_target()
    if not target:
        err_msg("No target found.")
        return

    # Find the matching module (case-insensitive filename match)
    for module in target.module_iter():
        module_name = module.GetFileSpec().GetFilename()
        if module_name and module_name.lower() == target_module_name.lower():
            target_module = module
            break

    if target_module is None:
        err_msg(f"Module '{target_module_name}' not found.")
        return

    # Display search initiation message
    n_symbols = target_module.GetNumSymbols()
    print(
        f"[+] Searching module '{target_module.GetFileSpec().GetFilename()}' ({n_symbols} symbols) for mnemonic '{mnemonic}'"
    )

    n_bps = 0
    n_insn_searched = 0

    # Retrieve the current frame and thread information once
    try:
        frame = get_frame()
        if not frame or not frame.IsValid():
            raise Exception("No current frame available.")
        thread = frame.GetThread()
        if not thread or not thread.IsValid():
            raise Exception("No current thread available.")
        thread_id = thread.GetThreadID()
    except Exception as e:
        err_msg(f"Error getting current context: {e}. Is the process stopped and the module loaded?")
        return

    # Iterate over executable sections only
    for section in target_module:
        if not section.IsExecutable():
            continue

        section_start_addr = section.GetLoadAddress(target)
        section_end_addr = section_start_addr + section.GetFileByteSize() # Use FileByteSize as approx size

        if section_start_addr == lldb.LLDB_INVALID_ADDRESS or section_end_addr == lldb.LLDB_INVALID_ADDRESS:
            continue

        # print(f"[DEBUG] Searching section {section.GetName()} from {hex(section_start_addr)} to {hex(section_end_addr)}")

        # Read instructions in chunks
        chunk_size = 4096  # Process in reasonable chunks
        current_addr = section_start_addr
        while current_addr < section_end_addr:
            read_count = min(chunk_size, section_end_addr - current_addr)
            if read_count <= 0: break # Should not happen, but safeguard

            sb_addr = lldb.SBAddress(current_addr, target)
            instructions_mem = target.ReadInstructions(sb_addr, read_count) # Read count is estimate

            if not instructions_mem or not instructions_mem.IsValid() or instructions_mem.GetSize() == 0:
                # Failed to read or empty chunk, advance past it
                current_addr += read_count # Advance based on requested count
                continue

            last_inst_addr = 0
            last_inst_size = 0
            for inst in instructions_mem:
                inst_addr = inst.GetAddress().GetLoadAddress(target)

                # Stop if we go past the section end address
                if inst_addr >= section_end_addr:
                    current_addr = section_end_addr # Mark as finished
                    break

                n_insn_searched += 1
                inst_mnemonic = inst.GetMnemonic(target).lower()

                if inst_mnemonic == mnemonic:
                    if inst_addr == lldb.LLDB_INVALID_ADDRESS:
                        continue  # Skip invalid addresses

                    # Create a one-shot breakpoint at the instruction's address
                    # Check if breakpoint already exists at this address to avoid duplicates if run multiple times?
                    # For simplicity, let's assume LLDB handles duplicates or user clears first.
                    bp = target.BreakpointCreateByAddress(inst_addr)
                    bp.SetOneShot(True)
                    bp.SetThreadID(thread_id) # Thread specific
                    bp.SetEnabled(True) # Ensure it's enabled
                    n_bps += 1

                last_inst_addr = inst_addr
                last_inst_size = inst.GetByteSize()
                if last_inst_size == 0: last_inst_size = 1 # Avoid infinite loop on zero-size instruction

            # Update address for next chunk read
            if instructions_mem.GetSize() > 0:
                current_addr = last_inst_addr + last_inst_size
            else:
                # If GetSize() was 0 but read was attempted, advance minimally
                current_addr += 1 # Or chunk_size? Let's try minimal advance

    print(
        f"[+] Set {n_bps} one-shot breakpoint{'s' if n_bps != 1 else ''} on mnemonic '{mnemonic}' in module '{target_module.GetFileSpec().GetFilename()}' (searched {n_insn_searched} instructions)"
    )


def cmd_print_notifier_images(debugger, command, result, dict):
    """Print all images available at gdb_image_notifier/lldb_image_notifier breakpoint."""
    help_dict = {
        "cmd": "print_images",
        "short": "print target modules at notifier",
        "desc": """Print all modules available at the dyld image notifier breakpoint (_gdb_image_notifier or _lldb_image_notifier).\nOnly valid when stopped inside the notifier function.""",
        "args": "",
        "notes": ["The _gdb_image_notifier symbol was removed in macOS Monterey and later."],
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    frame = get_frame()
    if not frame or not frame.IsValid():
        err_msg("No valid frame. Ensure you are stopped inside the image notifier.")
        return 0

    # Verify we are in the expected function
    func_name = frame.GetFunctionName()
    if not func_name or ("_image_notifier" not in func_name):
         err_msg(f"Not stopped in an image notifier function (current: {func_name}).")
         return 0

    target = get_target() # Added target retrieval
    process = target.GetProcess() # Added process retrieval
    error = lldb.SBError()

    i386 = is_i386()
    x64 = is_x64()
    arm = is_arm()
    if not i386 and not x64 and not arm:
        err_msg("Unsupported architecture.")
        return 0

    # Arguments retrieval (same as module_breakpoint_callback)
    mode_reg, count_reg, info_reg = None, None, None
    mode, infoCount, info_ptr = 0, 0, 0
    ptr_size = 8 if (x64 or arm) else 4
    dyld_image_info_size = ptr_size * 3

    if x64: mode_reg, count_reg, info_reg = "rdi", "rsi", "rdx"
    elif arm: mode_reg, count_reg, info_reg = "x0", "x1", "x2"
    elif i386:
        sp = frame.FindRegister("esp").GetValueAsUnsigned()
        mode = process.ReadUnsignedFromMemory(sp + 4, 4, error)
        if not error.Success(): err_msg("Failed to read mode from stack."); return 0
        infoCount = process.ReadUnsignedFromMemory(sp + 8, 4, error)
        if not error.Success(): err_msg("Failed to read infoCount from stack."); return 0
        info_ptr = process.ReadUnsignedFromMemory(sp + 12, 4, error)
        if not error.Success(): err_msg("Failed to read info array pointer from stack."); return 0
    else: return 0

    if not i386:
        mode = frame.FindRegister(mode_reg).GetValueAsUnsigned()
        infoCount = frame.FindRegister(count_reg).GetValueAsUnsigned()
        info_ptr = frame.FindRegister(info_reg).GetValueAsUnsigned()

    print(f"Image Notifier Info ({func_name}):")
    print(f"Mode: {mode} ({dyld_mode_dict.get(mode, 'Unknown')})")
    print(f"Image Count: {infoCount}")

    if infoCount == 0:
        return 0

    print("----------------------------------------------------------------------")
    print(f"{'Load Address':<18} | Path")
    print("----------------------------------------------------------------------")

    current_info_item_ptr = info_ptr
    for x in range(infoCount):
        address = process.ReadPointerFromMemory(current_info_item_ptr, error)
        if not error.Success():
            err_msg(f"Failed to read imageLoadAddress at {hex(current_info_item_ptr)}"); break

        string_ptr = process.ReadPointerFromMemory(current_info_item_ptr + ptr_size, error)
        if not error.Success():
             err_msg(f"Failed to read imageFilePath ptr at {hex(current_info_item_ptr + ptr_size)}"); break

        string = process.ReadCStringFromMemory(string_ptr, 1024, error)
        if not error.Success():
             # Print address even if string fails
             print(f"0x{address:<16x} | <Failed to read path from {hex(string_ptr)}>")
        else:
             print(f"0x{address:<16x} | {string}")

        current_info_item_ptr += dyld_image_info_size
    print("----------------------------------------------------------------------")
    return 0 # Return required by breakpoint callback


# software breakpoint (bb alias)
def cmd_bp(debugger, command, result, dict):
    """Set a software breakpoint. Use 'bb help' or 'man bb' for more information."""
    help_dict = {
        "cmd": "bb", # Help for the alias
        "short": "set software breakpoint",
        "desc": """Set a software breakpoint.""",
        "args": "<address> [<breakpoint_name>]",
        "options": [
                {"name": "address", "desc": "The breakpoint address (expression supported)."},
                {"name": "breakpoint_name", "desc": "Optional name for the breakpoint (no spaces)."},
            ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "bb main\nbb 0x1000+0x40 my_break"
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid address expression: '{}'".format(cmd[0]))
        help_msg(help_dict)
        return

    # accept spaces and replace them with underscores for name
    name = ""
    if len(cmd) > 1:
        name = "_".join(cmd[1:]) # Join remaining parts for name

    target = get_target()
    if not target: err_msg("No target found."); return

    breakpoint = target.BreakpointCreateByAddress(value)
    if not breakpoint or not breakpoint.IsValid():
         err_msg(f"Failed to create breakpoint at {hex(value)}.")
         return

    if name:
        breakpoint.AddName(name)
        print(f"[+] Software breakpoint #{breakpoint.GetID()} set at {hex(value)} with name '{name}'.")
    else:
        print(f"[+] Software breakpoint #{breakpoint.GetID()} set at {hex(value)}.")
    return


# temporary software breakpoint
def cmd_bpt(debugger, command, result, dict):
    """Set a temporary software breakpoint. Use 'bpt help' for more information."""
    help_dict = {
        "cmd": "bpt",
        "short": "set temporary software breakpoint",
        "desc": "Set a temporary software breakpoint. Breakpoint is deleted on first hit.",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The breakpoint address (expression supported)."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "bpt 0x1000+0x40"
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid address expression: '{}'".format(cmd[0]))
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return
    frame = get_frame() # Needed for thread ID
    if not frame: err_msg("Cannot set temporary breakpoint without a current frame/thread."); return

    breakpoint = target.BreakpointCreateByAddress(value)
    if not breakpoint or not breakpoint.IsValid():
        err_msg(f"Failed to create breakpoint at {hex(value)}.")
        return

    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(frame.GetThread().GetThreadID()) # Make it thread-specific

    print(f"[+] Temporary software breakpoint #{breakpoint.GetID()} set at {hex(value)} for current thread.")


# hardware breakpoint
def cmd_bh(debugger, command, result, dict):
    """Set an hardware breakpoint."""
    help_dict = {
        "cmd": "bh",
        "short": "set hardware breakpoint",
        "desc": """Set an hardware breakpoint.""",
        "args": "<address> [<breakpoint_name>]",
        "options": [
                {"name": "address", "desc": "The breakpoint address (expression supported)."},
                {"name": "breakpoint_name", "desc": "Optional name for the breakpoint (no spaces)."}
        ],
        "notes": [
                "Expressions are supported, do not use spaces between operators.",
                "Availability and number of hardware breakpoints depend on the target architecture.",
                "Breakpoint name must *not* use spaces." # Kept note
        ],
         "example": "bh 0x1000+0x40 my_hw_break"
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid address expression: '{}'".format(cmd[0]))
        help_msg(help_dict)
        return

    name = ""
    if len(cmd) > 1:
        name = "_".join(cmd[1:]) # Join remaining parts for name

    res = lldb.SBCommandReturnObject()
    # the python API doesn't seem to support hardware breakpoints directly easily
    # so we set it via command line interpreter
    cli_command = f"breakpoint set -H -a {hex(value)}"
    if name:
        cli_command += f" -N {name}"

    debugger.GetCommandInterpreter().HandleCommand(cli_command, res)

    if res.Succeeded():
         # Success often just means the command ran. Need to parse output for actual BP ID.
         output = res.GetOutput()
         match = re.search(r"Breakpoint (\d+):", output)
         if match:
             bp_id = match.group(1)
             msg = f"[+] Hardware breakpoint #{bp_id} set at {hex(value)}"
             if name: msg += f" with name '{name}'"
             print(msg + ".")
         else:
             # Command succeeded but no ID found? Maybe HW BP not supported.
             print(f"[+] Hardware breakpoint command executed for address {hex(value)}. Check 'bpl' for details.")
             if "warning:" in output: print(f"[!] {output.strip()}") # Print warnings
    else:
        err_msg(f"Failed to set hardware breakpoint at {hex(value)}.")
        print(res.GetError()) # Print LLDB error

    return


# temporary hardware breakpoint
def cmd_bht(debugger, command, result, dict):
    """Set a temporary hardware breakpoint."""
    help_dict = {
        "cmd": "bht",
        "short": "set temporary hardware breakpoint",
        "desc": """Set a temporary hardware breakpoint. Breakpoint is deleted on first hit.""",
        "args": "<address>",
        "options": [{"name": "address", "desc": "The breakpoint address (expression supported)."}],
        "notes": ["Expressions are supported, do not use spaces between operators.",
                  "Availability depends on the target architecture.",
                  "Breakpoint is thread-specific to the current thread."],
        "example": "bht 0x1000+0x40"
    }
    cmd = command.split()
    if len(cmd) < 1:
        err_msg("Please insert a breakpoint address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    value = evaluate(cmd[0])
    if value is None:
        err_msg("Invalid address expression: '{}'".format(cmd[0]))
        help_msg(help_dict)
        return

    frame = get_frame() # Needed for thread ID
    if not frame: err_msg("Cannot set temporary hardware breakpoint without a current frame/thread."); return

    res = lldb.SBCommandReturnObject()
    # Use CLI for hardware breakpoints, make it one-shot and thread-specific
    cli_command = f"breakpoint set -H --one-shot true -t {frame.GetThread().GetThreadID()} -a {hex(value)}"
    debugger.GetCommandInterpreter().HandleCommand(cli_command, res)

    if res.Succeeded():
         output = res.GetOutput()
         match = re.search(r"Breakpoint (\d+):", output)
         if match:
             bp_id = match.group(1)
             print(f"[+] Temporary hardware breakpoint #{bp_id} set at {hex(value)} for current thread.")
         else:
             print(f"[+] Temporary hardware breakpoint command executed for address {hex(value)}. Check 'bpl' for details.")
             if "warning:" in output: print(f"[!] {output.strip()}")
    else:
        err_msg(f"Failed to set temporary hardware breakpoint at {hex(value)}.")
        print(res.GetError())

    return


# clear breakpoint number
def cmd_bpc(debugger, command, result, dict):
    """Clear a breakpoint. Use 'bpc help' for more information."""
    help_dict = {
        "cmd": "bpc",
        "short": "clear breakpoint",
        "desc": "Clear (delete) a breakpoint by its ID number.",
        "args": "<breakpoint_id>",
        "options": [
                {"name": "breakpoint_id", "desc": "The breakpoint ID number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint ID numbers are valid, not addresses.",
                "Expressions are supported for the ID number."
        ],
        "example": "bpc 3"
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint ID number.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    try:
        # breakpoint ID must be an integer
        bp_id = int(evaluate(cmd[0])) # Evaluate potential expressions
    except (ValueError, TypeError):
         err_msg("Invalid input value - only a breakpoint ID number is valid.")
         help_msg(help_dict)
         return

    target = get_target()
    if not target: err_msg("No target found."); return

    if target.BreakpointDelete(bp_id):
        print(f"[+] Deleted breakpoint #{bp_id}.")
    else:
        # BreakpointDelete returns false if ID doesn't exist
        err_msg(f"Breakpoint #{bp_id} not found or could not be deleted.")

    return


# disable breakpoint number
def cmd_bpd(debugger, command, result, dict):
    """Disable a breakpoint. Use 'bpd help' for more information."""
    help_dict = {
        "cmd": "bpd",
        "short": "disable breakpoint",
        "desc": "Disable a breakpoint by its ID number.",
        "args": "<breakpoint_id>",
        "options": [
                {"name": "breakpoint_id", "desc": "The breakpoint ID number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint ID numbers are valid, not addresses.",
                "Expressions are supported for the ID number."
        ],
         "example": "bpd 3"
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint ID number.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    try:
        bp_id = int(evaluate(cmd[0]))
    except (ValueError, TypeError):
         err_msg("Invalid input value - only a breakpoint ID number is valid.")
         help_msg(help_dict)
         return

    target = get_target()
    if not target: err_msg("No target found."); return

    breakpoint = target.FindBreakpointByID(bp_id)
    if breakpoint and breakpoint.IsValid():
        if breakpoint.IsEnabled():
            breakpoint.SetEnabled(False)
            print(f"[+] Disabled breakpoint #{bp_id}.")
        else:
            print(f"[!] Breakpoint #{bp_id} was already disabled.")
    else:
         err_msg(f"Breakpoint #{bp_id} not found.")

    return


# disable all breakpoints
def cmd_bpda(debugger, command, result, dict):
    """Disable all breakpoints. Use 'bpda help' for more information."""
    help_dict = {
        "cmd": "bpda",
        "short": "disable all breakpoints",
        "desc": "Disable all breakpoints in the current target.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return

    num_breakpoints = target.GetNumBreakpoints()
    if num_breakpoints == 0:
        print("[+] No breakpoints to disable.")
        return

    # SBTarget.DisableAllBreakpoints() is deprecated, iterate instead
    disabled_count = 0
    for i in range(num_breakpoints):
        bp = target.GetBreakpointAtIndex(i)
        if bp and bp.IsValid() and bp.IsEnabled():
            bp.SetEnabled(False)
            disabled_count += 1

    if disabled_count > 0:
        print(f"[+] Disabled {disabled_count} breakpoint(s).")
    else:
        print("[+] All breakpoints were already disabled.")

    return


# enable breakpoint number
def cmd_bpe(debugger, command, result, dict):
    """Enable a breakpoint. Use 'bpe help' for more information."""
    help_dict = {
        "cmd": "bpe",
        "short": "enable breakpoint",
        "desc": "Enable a breakpoint by its ID number.",
        "args": "<breakpoint_id>",
        "options": [
                {"name": "breakpoint_id", "desc": "The breakpoint ID number. Use the 'bpl' command to list breakpoints."}
        ],
        "notes": [
                "Only breakpoint ID numbers are valid, not addresses.",
                "Expressions are supported for the ID number."
        ],
        "example": "bpe 3"
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a breakpoint ID number.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    try:
        bp_id = int(evaluate(cmd[0]))
    except (ValueError, TypeError):
         err_msg("Invalid input value - only a breakpoint ID number is valid.")
         help_msg(help_dict)
         return

    target = get_target()
    if not target: err_msg("No target found."); return

    breakpoint = target.FindBreakpointByID(bp_id)
    if breakpoint and breakpoint.IsValid():
        if not breakpoint.IsEnabled():
            breakpoint.SetEnabled(True)
            print(f"[+] Enabled breakpoint #{bp_id}.")
        else:
            print(f"[!] Breakpoint #{bp_id} was already enabled.")
    else:
         err_msg(f"Breakpoint #{bp_id} not found.")

    return


# enable all breakpoints
def cmd_bpea(debugger, command, result, dict):
    """Enable all breakpoints. Use 'bpea help' for more information."""
    help_dict = {
        "cmd": "bpea",
        "short": "enable all breakpoints",
        "desc": "Enable all breakpoints in the current target.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return

    num_breakpoints = target.GetNumBreakpoints()
    if num_breakpoints == 0:
        print("[+] No breakpoints to enable.")
        return

    # SBTarget.EnableAllBreakpoints() is deprecated, iterate instead
    enabled_count = 0
    for i in range(num_breakpoints):
        bp = target.GetBreakpointAtIndex(i)
        if bp and bp.IsValid() and not bp.IsEnabled():
            bp.SetEnabled(True)
            enabled_count += 1

    if enabled_count > 0:
        print(f"[+] Enabled {enabled_count} breakpoint(s).")
    else:
        print("[+] All breakpoints were already enabled.")

    return


# list all breakpoints
def cmd_bpl(debugger, command, result, dict):
    """List all breakpoints. Use 'bpl help' or 'man bpl' for more information."""
    help_dict = {
        "cmd": "bpl",
        "short": "list breakpoints",
        "desc": "List all breakpoints, similar to 'breakpoint list' but with extra info.",
        "args": "[-e]",
        "options": [{"name": "-e", "desc": "Display only enabled breakpoints."}],
    }
    enabled_only = False
    cmd = command.split()
    if len(cmd) > 1:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return
    if len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        elif cmd[0] == "-e":
            enabled_only = True
        else:
            err_msg(f"Unrecognized argument: {cmd[0]}")
            help_msg(help_dict)
            return

    target = get_target()
    if not target: err_msg("No target found."); return

    num_breakpoints = target.GetNumBreakpoints()
    if num_breakpoints == 0:
        print("No breakpoints currently set.")
        return

    total_shown = 0
    hw_total = 0
    sw_total = 0
    hw_enabled = 0
    sw_enabled = 0

    # Determine column widths dynamically? For now, use fixed widths.
    hdr = "{:<4} {:<19} {:<4} {:<7} {:<5} {:<8} {:<24} {}".format(
              "#", "Address", "Type", "Enabled", "Hits", "Cmds", "Module", "Name/Condition")
    print(hdr)
    print("-" * len(hdr))

    for i in range(num_breakpoints):
        bpt = target.GetBreakpointAtIndex(i)
        if not bpt or not bpt.IsValid(): continue

        is_enabled = bpt.IsEnabled()
        if enabled_only and not is_enabled:
            continue

        bp_type = "H" if bpt.IsHardware() else "S"
        if bpt.IsOneShot(): bp_type += "*"

        enabled_str = "Y" if is_enabled else "N"
        hit_count = bpt.GetHitCount()

        # Get breakpoint commands count
        commands = lldb.SBStringList()
        has_cmds = bpt.GetCommandLineCommands(commands)
        cmds_count = commands.GetSize() if has_cmds else 0
        cmds_str = str(cmds_count) if cmds_count > 0 else "-"

        # Get name and condition
        names = lldb.SBStringList()
        bpt.GetNames(names)
        name = names.GetStringAtIndex(0) if names.IsValid() and names.GetSize() > 0 else ""
        condition = bpt.GetCondition()
        name_cond_str = name
        if condition:
            if name_cond_str: name_cond_str += " " # Add space if name exists
            name_cond_str += f"[Cond: {condition}]"
        if not name_cond_str: name_cond_str = "-"


        # Iterate locations (usually 1, but can be more for regex/source breakpoints)
        loc_infos = []
        for j in range(bpt.GetNumLocations()):
             loc = bpt.GetLocationAtIndex(j)
             if not loc or not loc.IsValid() or not loc.GetAddress() or not loc.GetAddress().IsValid():
                  loc_infos.append(f"  <Location {j+1}: Invalid>")
                  continue

             loc_addr = loc.GetLoadAddress()
             loc_addr_str = hex(loc_addr) if loc_addr != lldb.LLDB_INVALID_ADDRESS else "<Not Resolved>"

             module = loc.GetAddress().GetModule()
             module_name = module.GetFileSpec().GetFilename() if module and module.IsValid() else "<No Module>"

             loc_infos.append(f"{loc_addr_str:<19} {module_name:<24}")

        # Print main line
        print("{:<4} {:<19} {:<4} {:<7} {:<5} {:<8} {:<24} {}".format(
              bpt.GetID(),
              loc_infos[0].split()[0] if loc_infos else "<No Location>", # Show first addr
              bp_type, enabled_str, hit_count, cmds_str,
              loc_infos[0].split()[1] if len(loc_infos) > 0 and len(loc_infos[0].split()) > 1 else "<No Module>", # Show first module
              name_cond_str))

        # Print additional locations if any
        for k in range(1, len(loc_infos)):
            addr_part = loc_infos[k].split()[0]
            mod_part = loc_infos[k].split()[1] if len(loc_infos[k].split()) > 1 else "<No Module>"
            print("{:<4} {:<19} {:<4} {:<7} {:<5} {:<8} {:<24} {}".format(
                  "", addr_part, "", "", "", "", mod_part, f"(Location {k+1})"))


        # Update counts
        total_shown += 1
        if bpt.IsHardware():
            hw_total += 1
            if is_enabled: hw_enabled += 1
        else:
            sw_total += 1
            if is_enabled: sw_enabled += 1

    print("-" * len(hdr))
    print(f"Total Shown: {total_shown} - SW Enabled: {sw_enabled}/{sw_total} - HW Enabled: {hw_enabled}/{hw_total}")


# skip current instruction - just advances PC to next instruction but doesn't execute it
def cmd_skip(debugger, command, result, dict):
    """Advance PC to instruction at next address. Use 'skip help' for more information."""
    help_dict = {
        "cmd": "skip",
        "short": "skip current instruction",
        "desc": "Advance current instruction pointer (PC) to the next instruction without executing the current one.",
        "args": "",
        "notes": ["The control flow is not respected (e.g., jumps are ignored); it advances to the next sequential instruction in memory."],
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help_dict)
        return

    frame = get_frame()
    if not frame: err_msg("No current frame."); return

    current_pc = frame.GetPC()
    if current_pc == lldb.LLDB_INVALID_ADDRESS:
        err_msg("Could not get current PC.")
        return

    inst_size = get_inst_size(current_pc)
    if inst_size == 0:
        err_msg("Could not determine instruction size at current PC.")
        return

    next_addr = current_pc + inst_size

    if not frame.SetPC(next_addr):
         err_msg(f"Failed to set PC to {hex(next_addr)}.")
         return
    else:
         print(f"[+] PC advanced to {hex(next_addr)}.")

    # show the updated context automatically
    debugger.HandleCommand("context")


def cmd_int3(debugger, command, result, dict):
    """Patch at address to a breakpoint instruction (INT3 for x86, BRK #0 for AArch64). Use 'int3 help' for more information."""
    help_dict = {
        "cmd": "int3",
        "short": "patch memory with int3/brk",
        "desc": """Patch process memory with a breakpoint instruction (INT 3 on x86, BRK #0 on ARM) at the given address.
Useful in cases where debugger breakpoints aren't respected but a software breakpoint instruction will trigger the debugger.""",
        "args": "[<address>]",
        "options": [
                {"name": "address", "desc": "The address to patch (expression supported). Defaults to the current PC."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators. Example: int3 $pc+0x10"],
        "example": "int3 0x10004000"
    }
    global int3patches
    error = lldb.SBError()
    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return

    cmd = command.split()
    int3_addr_expr = ""
    if len(cmd) == 0:
        frame = get_frame()
        if not frame: err_msg("Cannot get current PC without a frame."); return
        int3_addr = frame.GetPC()
        if int3_addr == lldb.LLDB_INVALID_ADDRESS:
            err_msg("Invalid current PC address.")
            return
        int3_addr_expr = "$pc" # For display
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        int3_addr_expr = cmd[0]
        int3_addr = evaluate(int3_addr_expr)
        if int3_addr is None:
            err_msg(f"Invalid address expression: '{int3_addr_expr}'")
            help_msg(help_dict)
            return
    else:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return

    # Determine patch bytes and size based on architecture
    patch_bytes = None
    patch_size = 0
    if is_i386() or is_x64():
        patch_bytes = b"\xCC"
        patch_size = 1
    elif is_arm():
        patch_bytes = b"\x00\x00\x20\xd4" # BRK #0 instruction encoding
        patch_size = 4
    else:
        err_msg("Unsupported architecture for int3/brk patch.")
        return

    # Read original bytes
    bytes_string = process.ReadMemory(int3_addr, patch_size, error)
    if not error.Success() or len(bytes_string) != patch_size:
        err_msg(f"Failed to read {patch_size} byte(s) at {hex(int3_addr)}. Error: {error}")
        return

    original_bytes_read = bytes(bytes_string) # Ensure it's bytes type

    # Write the patch
    bytes_written = process.WriteMemory(int3_addr, patch_bytes, error)
    if not error.Success() or bytes_written != patch_size:
        err_msg(f"Failed to write patch memory at {hex(int3_addr)}. Error: {error}")
        return

    # Save original bytes for later restore, using address as key
    int3patches[str(int3_addr)] = original_bytes_read
    print(f"[+] Patched breakpoint at {hex(int3_addr)} (original byte(s): {original_bytes_read.hex()})")
    return


def cmd_rint3(debugger, command, result, dict):
    """Restore byte(s) at address from a previously patched breakpoint instruction. Use 'rint3 help' for more information."""
    help_dict = {
        "cmd": "rint3",
        "short": "restore original byte(s)",
        "desc": "Restore the original byte(s) at an address previously patched using the 'int3' command.",
        "args": "[<address>]",
        "options": [{"name": "address", "desc": "The address to restore (expression supported). Defaults to the current PC."}],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "rint3 0x10004000"
    }
    global int3patches
    error = lldb.SBError()
    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return

    cmd = command.split()
    rint3_addr_expr = ""
    if len(cmd) == 0:
        frame = get_frame()
        if not frame: err_msg("Cannot get current PC without a frame."); return
        rint3_addr = frame.GetPC()
        if rint3_addr == lldb.LLDB_INVALID_ADDRESS:
            err_msg("Invalid current PC address.")
            return
        rint3_addr_expr = "$pc" # For display
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        rint3_addr_expr = cmd[0]
        rint3_addr = evaluate(rint3_addr_expr)
        if rint3_addr is None:
            err_msg(f"Invalid address expression: '{rint3_addr_expr}'")
            help_msg(help_dict)
            return
    else:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return

    rint3_addr_str = str(rint3_addr)

    if len(int3patches) == 0:
        err_msg("No breakpoint patched addresses are currently stored.")
        return

    if rint3_addr_str not in int3patches:
        err_msg(f"No breakpoint patch found stored for address {hex(rint3_addr)}.")
        return

    original_bytes = int3patches[rint3_addr_str]
    patch_size = len(original_bytes)

    # Optional: Verify that the memory currently contains the expected patch?
    current_mem = process.ReadMemory(rint3_addr, patch_size, error)
    expected_patch = b"\xCC" if (is_i386() or is_x64()) else b"\x00\x00\x20\xd4"
    if not error.Success() or bytes(current_mem) != expected_patch[:patch_size]:
        print(f"[!] Warning: Memory at {hex(rint3_addr)} does not contain the expected patch ({expected_patch.hex()}). Current: {bytes(current_mem).hex() if error.Success() else 'Read Failed'}. Restoring anyway.")

    # Restore original bytes
    bytes_written = process.WriteMemory(rint3_addr, original_bytes, error)
    if not error.Success() or bytes_written != patch_size:
        err_msg(f"Failed to write original memory at {hex(rint3_addr)}. Error: {error}")
        # Keep the entry in int3patches if restore failed? Or remove? Let's remove.
        del int3patches[rint3_addr_str]
        return

    # remove element from original bytes list
    del int3patches[rint3_addr_str]
    print(f"[+] Restored original byte(s) at {hex(rint3_addr)}.")
    return


def cmd_listint3(debugger, command, result, dict):
    """List all addresses patched with breakpoint instructions. Use 'listint3 help' for more information."""
    help_dict = {
        "cmd": "listint3",
        "short": "list int3/brk addresses",
        "desc": "List all addresses currently patched with the 'int3' command.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help_dict)
        return

    if len(int3patches) == 0:
        print("No breakpoint patched addresses are currently stored.")
        return

    print("Current breakpoint patched addresses (Address: Original Bytes):")
    for address_str, byte_val in int3patches.items():
        # Address is stored as string, convert back for hex formatting if needed
        address_int = int(address_str)
        print(f"- {hex(address_int)}: {byte_val.hex()}")

    return


def cmd_nop(debugger, command, result, dict):
    """NOP byte(s) at address. Use 'nop help' for more information."""
    help_dict = {
        "cmd": "nop",
        "short": "NOP patch address",
        "desc": "Patch process memory with NOP instruction(s) at the given address.",
        "args": "<address> [<count>]",
        "options": [
                {"name": "address", "desc": "The address to patch (expression supported)."},
                {"name": "count", "desc": "The number of NOP instructions (not bytes) to write. Default is 1."}
        ],
        "notes": [
                "Writes one NOP instruction per count (0x90 for x86, 0xd503201f for ARM64).",
                "Expressions are supported, do not use spaces between operators. Example: nop $pc+10 3"
        ],
        "example": "nop 0x10004000 5"
    }
    error = lldb.SBError()
    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return

    cmd = command.split()
    nop_addr_expr = ""
    patch_count = 1 # Default NOP count

    if len(cmd) == 0:
        err_msg("Please insert a target address.")
        help_msg(help_dict)
        return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        nop_addr_expr = cmd[0]
    elif len(cmd) == 2:
        nop_addr_expr = cmd[0]
        try:
            patch_count = int(evaluate(cmd[1]))
            if patch_count <= 0: raise ValueError("Count must be positive")
        except (ValueError, TypeError):
            err_msg("Invalid count value. Must be a positive integer.")
            help_msg(help_dict)
            return
    else:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return

    nop_addr = evaluate(nop_addr_expr)
    if nop_addr is None:
        err_msg(f"Invalid address expression: '{nop_addr_expr}'")
        help_msg(help_dict)
        return

    # Determine NOP bytes and size based on architecture
    nop_bytes = None
    nop_size = 0
    if is_i386() or is_x64():
        nop_bytes = b"\x90"
        nop_size = 1
    elif is_arm():
        nop_bytes = b"\x1f\x20\x03\xd5" # NOP instruction encoding (mov x0, x0 -> d503201f)
        nop_size = 4
    else:
        err_msg("Unsupported architecture for NOP patch.")
        return

    current_patch_addr = nop_addr
    total_bytes_to_write = nop_size * patch_count
    all_nop_bytes = nop_bytes * patch_count

    # Write all NOPs in one go if possible
    bytes_written = process.WriteMemory(current_patch_addr, all_nop_bytes, error)
    if not error.Success() or bytes_written != total_bytes_to_write:
        # Fallback: Try writing one by one if bulk write fails
        print(f"[!] Bulk NOP write failed (requested {total_bytes_to_write}, wrote {bytes_written}, error: {error}). Trying one by one...")
        succeeded_count = 0
        for i in range(patch_count):
            bytes_written_single = process.WriteMemory(current_patch_addr, nop_bytes, error)
            if not error.Success() or bytes_written_single != nop_size:
                err_msg(f"Failed to write NOP #{i+1} at {hex(current_patch_addr)}. Error: {error}")
                break # Stop on first error in single mode
            current_patch_addr += nop_size
            succeeded_count += 1
        if succeeded_count > 0:
            print(f"[+] Successfully wrote {succeeded_count} NOP instruction(s) starting at {hex(nop_addr)}.")
    else:
         print(f"[+] Wrote {patch_count} NOP instruction(s) ({total_bytes_to_write} bytes) starting at {hex(nop_addr)}.")

    return


def cmd_null(debugger, command, result, dict):
    """Patch byte(s) at address to NULL (0x00). Use 'null help' for more information."""
    help_dict = {
        "cmd": "null",
        "short": "write NULL bytes to memory",
        "desc": "Patch process memory with NULL (0x00) byte(s) at the given address.",
        "args": "<address> [<size>]",
        "options": [
            {"name": "address", "desc": "The address to patch (expression supported)."},
            {"name": "size", "desc": "The number of NULL bytes to write. Default is 1 byte."}
        ],
        "example": "null 0x100000 0x10",
        "notes": ["Expressions are supported, do not use spaces between operators. Example: null $pc+0x10"],
    }
    error = lldb.SBError()
    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return

    cmd = command.split()
    null_addr_expr = ""
    patch_size = 1 # Default size

    if len(cmd) == 0:
        err_msg("Please insert a target address.")
        help_msg(help_dict)
        return
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        null_addr_expr = cmd[0]
    elif len(cmd) == 2:
        null_addr_expr = cmd[0]
        try:
            patch_size = int(evaluate(cmd[1]))
            if patch_size <= 0: raise ValueError("Size must be positive")
        except (ValueError, TypeError):
            err_msg("Invalid size value. Must be a positive integer.")
            help_msg(help_dict)
            return
    else:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return

    null_addr = evaluate(null_addr_expr)
    if null_addr is None:
        err_msg(f"Invalid address expression: '{null_addr_expr}'")
        help_msg(help_dict)
        return

    # Create null bytes
    null_bytes = b"\x00" * patch_size

    # Write null bytes
    bytes_written = process.WriteMemory(null_addr, null_bytes, error)
    if not error.Success() or bytes_written != patch_size:
        err_msg(f"Failed to write {patch_size} NULL bytes at {hex(null_addr)}. Wrote {bytes_written}. Error: {error}")
        return
    else:
        print(f"[+] Wrote {patch_size} NULL byte(s) at {hex(null_addr)}.")

    return


# Implements the stepover command.
def cmd_stepo(debugger, command, result, dict):
    """Step over calls and some other instructions so we don't need to step into them. Use 'stepo help' for more information."""
    help_dict = { # Using dict format
        "cmd": "stepo",
        "short": "step over calls and loops",
        "desc": """Step over calls and certain repeating instructions without stepping into them.
Uses temporary software breakpoints on the next instruction.
Affected instructions:
- x86: call, movs*, stos*, cmps*, loop*
- ARM64: bl, blr, blr** (PAC variants)""",
        "args": "",
         "notes": ["Use 'stepoh' for a version using hardware breakpoints."]
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return
    frame = get_frame()
    if not frame: err_msg("No current frame."); return
    thread = frame.GetThread()
    if not thread: err_msg("No current thread."); return

    debugger.SetAsync(True) # Allow continue

    pc_addr = frame.GetPC()
    if pc_addr == lldb.LLDB_INVALID_ADDRESS:
        err_msg("Invalid current address.")
        debugger.SetAsync(False)
        return

    inst_size = get_inst_size(pc_addr)
    if inst_size == 0:
        err_msg("Could not get instruction size.")
        debugger.SetAsync(False)
        return

    next_addr = pc_addr + inst_size
    mnemonic = get_mnemonic(pc_addr)

    if is_arm():
        # Includes Pointer Authentication codes (PAC) variants automatically if mnemonic starts with blr/bl
        branch_mnemo_prefixes = ("bl",) # bl, blr, blraa, blraaz, blrab, blrabz etc.
        if any(mnemonic.startswith(prefix) for prefix in branch_mnemo_prefixes):
            breakpoint = target.BreakpointCreateByAddress(next_addr)
            if not breakpoint or not breakpoint.IsValid(): err_msg(f"Failed to set temp breakpoint at {hex(next_addr)}"); debugger.SetAsync(False); return
            breakpoint.SetThreadID(thread.GetThreadID())
            breakpoint.SetOneShot(True)
            process.Continue()
        else:
            debugger.SetAsync(False) # Set back to sync for single step
            thread.StepInstruction(False) # False means step *into* by default, but we only do this if *not* a branch-link
    elif is_i386() or is_x64():
        # x86 instructions to step over
        step_list_prefixes = ("call", "loop", "movs", "stos", "cmps")
        if any(mnemonic.startswith(prefix) for prefix in step_list_prefixes):
            breakpoint = target.BreakpointCreateByAddress(next_addr)
            if not breakpoint or not breakpoint.IsValid(): err_msg(f"Failed to set temp breakpoint at {hex(next_addr)}"); debugger.SetAsync(False); return
            breakpoint.SetThreadID(thread.GetThreadID())
            breakpoint.SetOneShot(True)
            process.Continue()
        else:
            debugger.SetAsync(False)
            thread.StepInstruction(False)
    else:
         err_msg("Unsupported architecture for stepo.")
         debugger.SetAsync(False)

# Added from upstream
# Implements the stepover command using hardware breakpoints.
def cmd_stepoh(debugger, command, result, dict):
    """Step over calls and some other instructions using hardware breakpoints. Use 'stepoh help' for more information."""
    help_dict = {
        "cmd": "stepoh",
        "short": "step over calls/loops (HW bp)",
        "desc": """Step over calls and certain repeating instructions without stepping into them.
Uses temporary hardware breakpoints on the next instruction.
Affected instructions:
- x86: call, movs*, stos*, cmps*, loop*
- ARM64: bl, blr, blr** (PAC variants)""",
        "args": "",
        "notes": ["Requires available hardware breakpoints on the target.",
                  "Use 'stepo' for a version using software breakpoints."]
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return
    process = target.GetProcess()
    if not process: err_msg("No process found."); return
    frame = get_frame()
    if not frame: err_msg("No current frame."); return
    thread = frame.GetThread()
    if not thread: err_msg("No current thread."); return

    debugger.SetAsync(True) # Allow continue

    pc_addr = frame.GetPC()
    if pc_addr == lldb.LLDB_INVALID_ADDRESS:
        err_msg("Invalid current address.")
        debugger.SetAsync(False)
        return

    inst_size = get_inst_size(pc_addr)
    if inst_size == 0:
        err_msg("Could not get instruction size.")
        debugger.SetAsync(False)
        return

    next_addr = pc_addr + inst_size
    mnemonic = get_mnemonic(pc_addr)
    res = lldb.SBCommandReturnObject()

    step_over = False
    if is_arm():
        branch_mnemo_prefixes = ("bl",)
        if any(mnemonic.startswith(prefix) for prefix in branch_mnemo_prefixes):
            step_over = True
    elif is_i386() or is_x64():
        step_list_prefixes = ("call", "loop", "movs", "stos", "cmps")
        if any(mnemonic.startswith(prefix) for prefix in step_list_prefixes):
            step_over = True
    else:
         err_msg("Unsupported architecture for stepoh.")
         debugger.SetAsync(False)
         return

    if step_over:
        # setup temporary hardware breakpoint for current thread only
        cli_command = f"breakpoint set -H --one-shot true -t {thread.GetThreadID()} -a {hex(next_addr)}"
        debugger.GetCommandInterpreter().HandleCommand(cli_command, res)
        if res.Succeeded():
            # Check output for success/warnings
            output = res.GetOutput()
            match = re.search(r"Breakpoint (\d+):", output)
            if match:
                # print(f"[DEBUG] Temp HW breakpoint #{match.group(1)} set at {hex(next_addr)}.")
                process.Continue()
            else:
                print(f"[!] HW Breakpoint command for {hex(next_addr)} succeeded but no ID found. May not be supported.")
                if "warning:" in output: print(f"[!] {output.strip()}")
                # Decide whether to continue or stop if BP might not be set
                process.Continue() # Continue optimistically
        else:
            err_msg(f"Failed to set temporary hardware breakpoint at {hex(next_addr)}.")
            print(res.GetError())
            debugger.SetAsync(False) # Stop if BP fails
    else:
        # Not an instruction to step over, just step normally
        debugger.SetAsync(False)
        thread.StepInstruction(False)

def cmd_sutcs(debugger, command, result, dict):
    """Step until call stack changes. Use 'sutcs help' for more information."""
    help_dict = { # Using dict format
        "cmd": "sutcs",
        "short": "Step until call stack changes",
        "desc": "Steps instructions one by one until the call stack depth changes (indicating a call or return).",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    thread = get_thread()
    if not thread: err_msg("No current thread."); return

    start_num_frames = thread.GetNumFrames()
    if start_num_frames == 0:
        err_msg("No frames available on the current thread.")
        return

    print(f"[+] Stepping until call stack depth ({start_num_frames}) changes...")
    debugger.SetAsync(False) # Step synchronously

    step_count = 0
    max_steps = 10000 # Safety break
    while step_count < max_steps:
        thread.StepInstruction(False) # Step one instruction
        # Check stop reason - bail out on crash, exit, signal etc.
        stop_reason = thread.GetStopReason()
        if stop_reason != lldb.eStopReasonPlanComplete and stop_reason != lldb.eStopReasonTrace:
            err_msg(f"Execution stopped unexpectedly: {lldb.SBDebugger.StopReasonString(stop_reason)}. Aborting sutcs.")
            debugger.HandleCommand("context") # Show context where it stopped
            return

        new_frame_count = thread.GetNumFrames()
        if new_frame_count != start_num_frames:
            print(
                COLOR_LOGINFO
                + f"[+] Call stack depth changed: {start_num_frames} -> {new_frame_count} after {step_count+1} steps."
                + RESET
            )
            debugger.HandleCommand("context") # Show context
            return

        step_count += 1

    err_msg(f"sutcs stopped after {max_steps} steps without call stack change.")
    debugger.HandleCommand("context")


def cmd_sutbt(debugger, command, result, dict):
    """Step until branch is taken. Use 'sutbt help' for more information."""
    help_dict = { # Using dict format
        "cmd": "sutbt",
        "short": "Step until branch is taken",
        "desc": "Steps instructions one by one until the program counter (PC) does not match the next sequential instruction address.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    thread = get_thread()
    if not thread: err_msg("No current thread."); return
    frame = get_frame()
    if not frame: err_msg("No current frame."); return

    print(f"[+] Stepping until branch is taken...")
    debugger.SetAsync(False) # Step synchronously

    step_count = 0
    max_steps = 10000 # Safety break
    while step_count < max_steps:
        curr_pc = frame.GetPC()
        if curr_pc == lldb.LLDB_INVALID_ADDRESS: err_msg("Invalid PC before step."); return
        inst_size = get_inst_size(curr_pc)
        if inst_size == 0: err_msg("Cannot get instruction size before step."); return
        expected_next_pc = curr_pc + inst_size

        thread.StepInstruction(False) # Step one instruction

        # Check stop reason
        stop_reason = thread.GetStopReason()
        if stop_reason != lldb.eStopReasonPlanComplete and stop_reason != lldb.eStopReasonTrace:
            err_msg(f"Execution stopped unexpectedly: {lldb.SBDebugger.StopReasonString(stop_reason)}. Aborting sutbt.")
            debugger.HandleCommand("context")
            return

        # Refresh frame after step
        frame = thread.GetSelectedFrame()
        if not frame: err_msg("Lost frame after step."); return
        new_pc = frame.GetPC()
        if new_pc == lldb.LLDB_INVALID_ADDRESS: err_msg("Invalid PC after step."); return

        if new_pc != expected_next_pc:
            print(
                COLOR_LOGINFO
                + f"[+] Branch detected: PC changed from {hex(curr_pc)} to {hex(new_pc)} (expected {hex(expected_next_pc)}) after {step_count+1} steps."
                + RESET
            )
            debugger.HandleCommand("context") # Show context
            return

        step_count += 1

    err_msg(f"sutbt stopped after {max_steps} steps without detecting a branch.")
    debugger.HandleCommand("context")


def cmd_suebb(debugger, command, result, dict):
    """Step until end of basic block. Use 'suebb help' for more information."""
    help_dict = { # Using dict format
        "cmd": "suebb",
        "short": "Step until end of basic block",
        "desc": "Steps instructions one by one until a control flow instruction (branch, call, ret) is encountered.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) != 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    thread = get_thread()
    if not thread: err_msg("No current thread."); return
    target = get_target()
    if not target: err_msg("No target."); return


    print(f"[+] Stepping until end of basic block...")
    debugger.SetAsync(False) # Step synchronously

    step_count = 0
    max_steps = 10000 # Safety break
    while step_count < max_steps:
        frame = thread.GetSelectedFrame()
        if not frame: err_msg("Lost frame during step."); return
        pc = frame.GetPC()
        if pc == lldb.LLDB_INVALID_ADDRESS: err_msg("Invalid PC before step."); return

        insn = get_instruction(pc)
        if not insn or not insn.IsValid(): err_msg("Could not get instruction."); return

        # Check if the *current* instruction is control flow before stepping past it
        does_branch = insn.DoesBranch()
        # GetControlFlowKind seems less reliable / implemented across archs
        # is_controlflow_insn = does_branch

        # Let's define control flow as DoesBranch() OR is a return instruction
        mnemonic = insn.GetMnemonic(target)
        is_return = mnemonic.startswith("ret") # Basic check for x86/ARM ret

        if does_branch or is_return:
            print(
                COLOR_LOGINFO
                + f"[+] End of basic block reached at {hex(pc)} ({mnemonic}) after {step_count} steps."
                + RESET
            )
            debugger.HandleCommand("context") # Show context at the control flow instruction
            return

        # If not control flow, step the instruction
        thread.StepInstruction(False)

        # Check stop reason
        stop_reason = thread.GetStopReason()
        if stop_reason != lldb.eStopReasonPlanComplete and stop_reason != lldb.eStopReasonTrace:
            err_msg(f"Execution stopped unexpectedly: {lldb.SBDebugger.StopReasonString(stop_reason)}. Aborting suebb.")
            debugger.HandleCommand("context")
            return

        step_count += 1

    err_msg(f"suebb stopped after {max_steps} steps without reaching end of basic block.")
    debugger.HandleCommand("context")


def cmd_sumnm(debugger, command, result, dict):
    """Step until matching instruction mnemonic. Use 'sumnm help' for more information."""
    help_dict = { # Using dict format
        "cmd": "sumnm",
        "short": "Step until mnemonic",
        "desc": "Steps instructions one by one until an instruction with the specified mnemonic is encountered.",
        "args": "<mnemonic>",
        "example": "sumnm cmp"
    }
    cmd = command.split()
    if len(cmd) != 1 or (len(cmd) == 1 and cmd[0] == "help"):
        help_msg(help_dict)
        return

    target_mnemonic = cmd[0].lower() # Case-insensitive compare

    thread = get_thread()
    if not thread: err_msg("No current thread."); return
    target = get_target()
    if not target: err_msg("No target."); return


    print(f"[+] Stepping until mnemonic '{target_mnemonic}'...")
    debugger.SetAsync(False) # Step synchronously

    step_count = 0
    max_steps = 10000 # Safety break
    while step_count < max_steps:
        frame = thread.GetSelectedFrame()
        if not frame: err_msg("Lost frame during step."); return
        pc = frame.GetPC()
        if pc == lldb.LLDB_INVALID_ADDRESS: err_msg("Invalid PC before step."); return

        insn = get_instruction(pc)
        if not insn or not insn.IsValid(): err_msg("Could not get instruction."); return

        current_mnemonic = insn.GetMnemonic(target).lower()

        if current_mnemonic == target_mnemonic:
            print(
                COLOR_LOGINFO
                + f"[+] Matched mnemonic '{target_mnemonic}' at {hex(pc)} after {step_count} steps."
                + RESET
            )
            debugger.HandleCommand("context") # Show context at the matched instruction
            return

        # If not matched, step the instruction
        thread.StepInstruction(False)

        # Check stop reason
        stop_reason = thread.GetStopReason()
        if stop_reason != lldb.eStopReasonPlanComplete and stop_reason != lldb.eStopReasonTrace:
            err_msg(f"Execution stopped unexpectedly: {lldb.SBDebugger.StopReasonString(stop_reason)}. Aborting sumnm.")
            debugger.HandleCommand("context")
            return

        step_count += 1

    err_msg(f"sumnm stopped after {max_steps} steps without matching mnemonic '{target_mnemonic}'.")
    debugger.HandleCommand("context")


# Temporarily breakpoint next instruction
def cmd_bpn(debugger, command, result, dict):
    """Temporarily breakpoint instruction at next address. Use 'bpn help' for more information."""
    help_dict = {
        "cmd": "bpn",
        "short": "breakpoint next instruction",
        "desc": "Sets a temporary, one-shot, thread-specific breakpoint on the next sequential instruction.",
        "args": "",
        "notes": ["Control flow is not respected; it breakpoints the instruction immediately following the current one in memory.",
                 "Useful for stepping over loops without using 'stepo' repeatedly."],
    }
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("The command doesn't take any arguments.")
        help_msg(help_dict)
        return

    target = get_target()
    if not target: err_msg("No target found."); return
    frame = get_frame()
    if not frame: err_msg("No current frame."); return
    thread = frame.GetThread()
    if not thread: err_msg("No current thread."); return

    start_addr = frame.GetPC()
    if start_addr == lldb.LLDB_INVALID_ADDRESS: err_msg("Invalid current PC."); return

    inst_size = get_inst_size(start_addr)
    if inst_size == 0: err_msg("Cannot get instruction size."); return

    next_addr = start_addr + inst_size

    breakpoint = target.BreakpointCreateByAddress(next_addr)
    if not breakpoint or not breakpoint.IsValid():
        err_msg(f"Failed to create breakpoint at {hex(next_addr)}.")
        return

    breakpoint.SetOneShot(True)
    breakpoint.SetThreadID(thread.GetThreadID())

    print(f"[+] Set temporary breakpoint #{breakpoint.GetID()} at {hex(next_addr)} for current thread.")


# command that sets rax/eax/x0 to 1 or 0 and returns right away from current function
def cmd_crack(debugger, command, result, dict):
    """Return from current function and set return value. Use 'crack help' for more information."""
    help_dict = {
        "cmd": "crack",
        "short": "return from current function",
        "desc": """Immediately return from the current function, setting the return value.
Sets the standard return register (RAX/EAX/X0) to the specified value.
Most useful when used at the beginning of a function you want to skip.""",
        "args": "<return_value>",
        "options": [{"name": "return_value", "desc": "The integer value to set in the return register (expression supported)."}],
        "example": "crack 1",
        "notes": ["Uses 'thread return'."]
    }
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a return value.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    ret_val_expr = cmd[0]
    ret_value_int = evaluate(ret_val_expr) # Evaluate potential expressions
    if ret_value_int is None:
        err_msg(f"Invalid return value expression: '{ret_val_expr}'")
        help_msg(help_dict)
        return

    frame = get_frame()
    if not frame: err_msg("No current frame."); return
    thread = frame.GetThread()
    if not thread: err_msg("No current thread."); return

    # Determine the return register based on architecture
    return_reg_name = None
    if is_x64(): return_reg_name = "rax"
    elif is_arm(): return_reg_name = "x0"
    elif is_i386(): return_reg_name = "eax"
    else: err_msg("Unsupported architecture for setting return value."); return

    # Get the SBValue for the return register
    # Need to get the GPR set first
    gpr_set = frame.registers[0] # Assuming GPRs are the first set
    if not gpr_set or not gpr_set.IsValid(): err_msg("Could not get GPR register set."); return
    return_reg_sbvalue = gpr_set.GetChildMemberWithName(return_reg_name)
    if not return_reg_sbvalue or not return_reg_sbvalue.IsValid():
        err_msg(f"Could not find return register '{return_reg_name}'."); return

    # Set the value
    return_reg_sbvalue.value = str(ret_value_int) # SetValueAsString implicitly converts

    # Perform the return
    if thread.ReturnFromFrame(frame, return_reg_sbvalue):
        print(f"[+] Returning from function {frame.GetFunctionName()} with {return_reg_name} = {ret_value_int} ({hex(ret_value_int)}).")
        # Execution continues automatically after return. Context will update on next stop.
    else:
        err_msg("Failed to return from frame.")


# set a breakpoint with return command associated when hit
def cmd_crackcmd(debugger, command, result, dict):
    """Breakpoint an address, when hit return from function and set return value. Use 'crackcmd help' for more information."""
    help_dict = {
        "cmd": "crackcmd",
        "short": "breakpoint and return",
        "desc": """Set a breakpoint at the specified address. When the breakpoint is hit, immediately return from the function, setting the return value (in RAX/EAX/X0).""",
        "args": "<address> <return_value>",
        "options": [
            {"name": "address", "desc": "The breakpoint address (expression supported)."},
            {"name": "return_value", "desc": "The integer value to set in the return register (expression supported)."}
        ],
        "example": "crackcmd check_license 0",
        "notes": ["Uses a script callback on the breakpoint."]
    }
    global crack_cmds # Store address->return_value mapping
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return
    if len(cmd) != 2:
        err_msg("Please provide both address and return value.")
        help_msg(help_dict)
        return

    addr_expr = cmd[0]
    ret_val_expr = cmd[1]

    address = evaluate(addr_expr)
    if address is None:
        err_msg(f"Invalid address expression: '{addr_expr}'")
        help_msg(help_dict)
        return

    return_value = evaluate(ret_val_expr)
    if return_value is None:
        err_msg(f"Invalid return value expression: '{ret_val_expr}'")
        help_msg(help_dict)
        return

    # Check for existing command at this address
    for tmp_entry in crack_cmds:
        if tmp_entry["address"] == address:
            err_msg(f"Address {hex(address)} already has a crack command.")
            return

    target = get_target()
    if not target: err_msg("No target found."); return

    # Set the breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    if not breakpoint or not breakpoint.IsValid():
        err_msg(f"Failed to create breakpoint at {hex(address)}.")
        return

    # Add info to our tracking list *before* setting callback
    new_crack_entry = {}
    new_crack_entry["address"] = address
    new_crack_entry["return_value"] = return_value
    new_crack_entry["bp_id"] = breakpoint.GetID() # Store BP ID for potential cleanup
    crack_cmds.append(new_crack_entry)

    # Set the callback
    breakpoint.SetScriptCallbackFunction("lrt.crackcmd_callback")
    print(f"[+] Set crack command breakpoint #{breakpoint.GetID()} at {hex(address)} to return {return_value}.")

# Callback for crackcmd
def crackcmd_callback(frame, bp_loc, internal_dict):
    global crack_cmds
    if not frame or not bp_loc: return # Basic validation

    current_bp_addr = bp_loc.GetLoadAddress()
    if current_bp_addr == lldb.LLDB_INVALID_ADDRESS: return

    print("[!] Hit crack command breakpoint at 0x{:x}".format(current_bp_addr))

    crack_entry = None
    for tmp_entry in crack_cmds:
        # Match by address (could also match by bp_id if needed)
        if tmp_entry["address"] == current_bp_addr:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        err_msg(f"Internal error: Breakpoint hit at {hex(current_bp_addr)}, but no matching crack command found in list.")
        # Decide how to handle - continue? stop? For safety, let's just return (which stops).
        return

    # Determine return register
    return_reg_name = None
    if is_x64(): return_reg_name = "rax"
    elif is_arm(): return_reg_name = "x0"
    elif is_i386(): return_reg_name = "eax"
    else: err_msg("Unsupported architecture in crackcmd callback."); return

    # Get return register SBValue
    gpr_set = frame.registers[0]
    if not gpr_set: err_msg("Could not get GPR set in callback."); return
    return_reg_sbvalue = gpr_set.GetChildMemberWithName(return_reg_name)
    if not return_reg_sbvalue: err_msg(f"Could not get {return_reg_name} SBValue in callback."); return

    # Set the return value
    return_reg_sbvalue.value = str(crack_entry["return_value"])

    # Perform return
    thread = frame.GetThread()
    if not thread.ReturnFromFrame(frame, return_reg_sbvalue):
         err_msg("crackcmd callback failed to return from frame.")
         # If return fails, execution stops here.

    # If ReturnFromFrame succeeded, execution continues automatically.
    # No explicit Continue() needed here.


# set a breakpoint with a command that doesn't return, just sets the specified register to a value
def cmd_crackcmd_noret(debugger, command, result, dict):
    """Set a breakpoint and a register to a value when hit. Use 'crackcmd_noret help' for more information."""
    help_dict = {
        "cmd": "crackcmd_noret",
        "short": "breakpoint and set register value",
        "desc": "Sets a breakpoint at the specified address. When hit, sets the specified register to the given value and resumes execution.",
        "args": "<address> <register> <value>",
        "options": [
            {"name": "address", "desc": "The breakpoint address (expression supported)."},
            {"name": "register", "desc": "The register to modify (e.g., rax, x1)."},
            {"name": "value", "desc": "The integer value to set in the register (expression supported)."}
        ],
        "example": "crackcmd_noret validate_input rdi 1",
        "notes": ["Uses a script callback on the breakpoint."]
    }
    global crack_cmds_noret # Store address->(register, value) mapping
    cmd = command.split()

    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return
    if len(cmd) != 3: # Expect exactly 3 args now
        err_msg("Please provide address, register, and value.")
        help_msg(help_dict)
        return

    addr_expr = cmd[0]
    register_name = cmd[1].lower() # Normalize register name
    value_expr = cmd[2]

    address = evaluate(addr_expr)
    if address is None:
        err_msg(f"Invalid address expression: '{addr_expr}'")
        help_msg(help_dict)
        return

    value = evaluate(value_expr)
    if value is None:
        err_msg(f"Invalid value expression: '{value_expr}'")
        help_msg(help_dict)
        return

    # Basic validation of register name format (doesn't check arch-specific validity here)
    if not re.match(r"^[a-zA-Z0-9]+$", register_name):
         err_msg(f"Invalid register name format: '{register_name}'")
         help_msg(help_dict)
         return

    # Check for existing command at this address
    for tmp_entry in crack_cmds_noret:
        if tmp_entry["address"] == address:
            err_msg(f"Address {hex(address)} already contains a crackcmd_noret command.")
            return

    target = get_target()
    if not target: err_msg("No target found."); return

    # Set the breakpoint
    breakpoint = target.BreakpointCreateByAddress(address)
    if not breakpoint or not breakpoint.IsValid():
        err_msg(f"Failed to create breakpoint at {hex(address)}.")
        return

    # Add info to tracking list
    new_crack_entry = {}
    new_crack_entry["address"] = address
    new_crack_entry["register"] = register_name
    new_crack_entry["value"] = value
    new_crack_entry["bp_id"] = breakpoint.GetID()
    crack_cmds_noret.append(new_crack_entry)

    # Set the callback
    breakpoint.SetScriptCallbackFunction("lrt.crackcmd_noret_callback")
    print(f"[+] Set crackcmd_noret breakpoint #{breakpoint.GetID()} at {hex(address)} to set {register_name}={value}.")

# Callback for crackcmd_noret
def crackcmd_noret_callback(frame, bp_loc, internal_dict):
    global crack_cmds_noret
    if not frame or not bp_loc: return

    current_bp_addr = bp_loc.GetLoadAddress()
    if current_bp_addr == lldb.LLDB_INVALID_ADDRESS: return

    print("[!] Hit crackcmd_noret breakpoint at 0x{:x}".format(current_bp_addr))

    crack_entry = None
    for tmp_entry in crack_cmds_noret:
        if tmp_entry["address"] == current_bp_addr:
            crack_entry = tmp_entry
            break

    if crack_entry is None:
        err_msg(f"Internal error: Breakpoint hit at {hex(current_bp_addr)}, but no matching crackcmd_noret found.")
        return # Stop execution

    register_name = crack_entry["register"]
    value_to_set = crack_entry["value"]

    # Get register SBValue
    gpr_set = frame.registers[0]
    if not gpr_set: err_msg("Could not get GPR set in callback."); return
    reg_sbvalue = gpr_set.GetChildMemberWithName(register_name)
    if not reg_sbvalue or not reg_sbvalue.IsValid():
        err_msg(f"Could not find register '{register_name}' in frame. Arch mismatch?"); return

    # Set the value
    reg_sbvalue.value = str(value_to_set) # Set as string

    print(f"[+] crackcmd_noret: Set {register_name} to {value_to_set} ({hex(value_to_set)}). Continuing execution.")
    # Continue execution automatically
    process = frame.GetThread().GetProcess()
    process.Continue()


# -----------------------
# Memory related commands
# -----------------------

"""
    Output nice memory hexdumps...
"""

# display byte values and ASCII characters
def cmd_db(debugger, command, result, dict):
    """Display hex dump in byte values and ASCII characters. Use 'db help' for more information."""
    help_dict = {
        "cmd": "db",
        "short": "display memory bytes",
        "desc": "Display memory hex dump in byte values and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display (expression supported). Defaults to current PC."},
            {"name": "size", "desc": "The amount of memory to display in bytes (expression supported). Default is 256 bytes."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "db rsp 512"
    }
    size = 0x100 # Default size
    dump_addr_expr = "$pc" # Default address expr

    cmd = command.split()
    if len(cmd) == 0:
        pass # Use defaults
    elif len(cmd) == 1:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        dump_addr_expr = cmd[0]
    elif len(cmd) == 2:
        dump_addr_expr = cmd[0]
        size_expr = cmd[1]
        size_val = evaluate(size_expr)
        if size_val is None or size_val <= 0:
            err_msg(f"Invalid size expression: '{size_expr}'")
            help_msg(help_dict)
            return
        size = size_val
    else:
        err_msg("Too many arguments.")
        help_msg(help_dict)
        return

    dump_addr = evaluate(dump_addr_expr)
    if dump_addr is None:
        err_msg(f"Invalid address expression: '{dump_addr_expr}'")
        help_msg(help_dict)
        return

    process = get_process()
    if not process: err_msg("No process found."); return
    err = lldb.SBError()

    membuf_data = process.ReadMemory(dump_addr, size, err)
    if not err.Success() or not membuf_data:
        err_msg(f"Failed to read {size} bytes from address {hex(dump_addr)}. Error: {error}")
        # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle status
        return

    membuf = bytes(membuf_data) # Ensure it's bytes type

    # --- Replaced output() with print() ---
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}"
    print(COLOR_HEXDUMP_HEADER + "[" + addr_fmt.format(dump_addr) + "]" + RESET, end='')
    print(COLOR_HEXDUMP_HEADER + "------------------------------------------------------" + RESET, end='')
    print(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET)

    offset = 0
    while offset < len(membuf):
        hex_str = ""
        ascii_str = ""
        current_line_addr = dump_addr + offset
        hex_str += BOLD + COLOR_HEXDUMP_ADDR
        hex_str += addr_fmt.format(current_line_addr) + "  "
        hex_str += RESET

        chunk = membuf[offset : offset + 16]
        hex_vals = []
        ascii_vals = []

        for i in range(16):
            if i < len(chunk):
                byte_val = chunk[i]
                hex_vals.append("{:02x}".format(byte_val))
                ascii_vals.append(chr(byte_val) if 32 <= byte_val <= 126 else ".")
            else:
                hex_vals.append("  ") # Pad if line ends early
                ascii_vals.append(" ")

            if i == 7: # Add mid-point space
                 hex_vals.append("") # Add space visually

        hex_str += COLOR_HEXDUMP_DATA + " ".join(hex_vals) + RESET
        ascii_str = "".join(ascii_vals)

        print(hex_str + "  " + BOLD + COLOR_HEXDUMP_ASCII + ascii_str + RESET)
        offset += 16

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle


# display word values and ASCII characters
def cmd_dw(debugger, command, result, dict):
    """Display hex dump in word values and ASCII characters. Use 'dw help' for more information."""
    help_dict = {
        "cmd": "dw",
        "short": "display memory words",
        "desc": "Display memory hex dump in word (2-byte) values and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display (expression supported). Defaults to current PC."},
            {"name": "size", "desc": "The amount of memory to display in bytes (expression supported). Default is 256 bytes. Must be multiple of 16."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
         "example": "dw rsp 64"
    }
    size = 0x100 # Default size
    dump_addr_expr = "$pc" # Default address expr

    cmd = command.split()
    if len(cmd) == 0: pass
    elif len(cmd) == 1:
        if cmd[0] == "help": help_msg(help_dict); return
        dump_addr_expr = cmd[0]
    elif len(cmd) == 2:
        dump_addr_expr = cmd[0]
        size_expr = cmd[1]
        size_val = evaluate(size_expr)
        if size_val is None or size_val <= 0:
            err_msg(f"Invalid size expression: '{size_expr}'"); help_msg(help_dict); return
        if size_val % 16 != 0:
             err_msg("Size must be a multiple of 16 bytes for dw.")
             help_msg(help_dict); return
        size = size_val
    else:
        err_msg("Too many arguments."); help_msg(help_dict); return

    dump_addr = evaluate(dump_addr_expr)
    if dump_addr is None: err_msg(f"Invalid address expression: '{dump_addr_expr}'"); help_msg(help_dict); return

    process = get_process(); error = lldb.SBError()
    if not process: err_msg("No process found."); return

    membuf_data = process.ReadMemory(dump_addr, size, error)
    if not error.Success() or not membuf_data: err_msg(f"Failed to read memory. Error: {error}"); return
    membuf = bytes(membuf_data)

    # --- Replaced output() with print() ---
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}"
    print(COLOR_HEXDUMP_HEADER + "[" + addr_fmt.format(dump_addr) + "]" + RESET, end='')
    print(COLOR_HEXDUMP_HEADER + "--------------------------------------------" + RESET, end='')
    print(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET)

    index = 0
    while index < size:
        chunk = membuf[index : index + 16]
        # Read 8 words (assuming little-endian for unpack)
        try:
            words = struct.unpack("<HHHHHHHH", chunk) # Use '<' for little-endian
        except struct.error:
            err_msg(f"Could not unpack 16 bytes into words at offset {index}.")
            break

        current_line_addr = dump_addr + index
        addr_str = BOLD + COLOR_HEXDUMP_ADDR + addr_fmt.format(current_line_addr) + " :" + RESET

        # Format words
        word_strs = ["{:04x}".format(w) for w in words]
        data_str = COLOR_HEXDUMP_DATA + " {} {} {} {}  {} {} {} {}".format(*word_strs) + RESET # Add midpoint space

        ascii_str = BOLD + COLOR_HEXDUMP_ASCII + quotechars(chunk) + RESET

        print(addr_str + data_str + " " + ascii_str)

        index += 16

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle


# display dword values and ASCII characters
def cmd_dd(debugger, command, result, dict):
    """Display hex dump in double word values and ASCII characters. Use 'dd help' for more information."""
    help_dict = {
        "cmd": "dd",
        "short": "display memory dwords",
        "desc": "Display memory hex dump in doubleword (4-byte) values and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display (expression supported). Defaults to current PC."},
            {"name": "size", "desc": "The amount of memory to display in bytes (expression supported). Default is 256 bytes. Must be multiple of 16."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "dd rsp"
    }
    size = 0x100
    dump_addr_expr = "$pc"

    cmd = command.split()
    if len(cmd) == 0: pass
    elif len(cmd) == 1:
        if cmd[0] == "help": help_msg(help_dict); return
        dump_addr_expr = cmd[0]
    elif len(cmd) == 2:
        dump_addr_expr = cmd[0]
        size_expr = cmd[1]
        size_val = evaluate(size_expr)
        if size_val is None or size_val <= 0: err_msg(f"Invalid size expression: '{size_expr}'"); help_msg(help_dict); return
        if size_val % 16 != 0: err_msg("Size must be a multiple of 16 bytes for dd."); help_msg(help_dict); return
        size = size_val
    else: err_msg("Too many arguments."); help_msg(help_dict); return

    dump_addr = evaluate(dump_addr_expr)
    if dump_addr is None: err_msg(f"Invalid address expression: '{dump_addr_expr}'"); help_msg(help_dict); return

    process = get_process(); error = lldb.SBError()
    if not process: err_msg("No process found."); return

    membuf_data = process.ReadMemory(dump_addr, size, error)
    if not error.Success() or not membuf_data: err_msg(f"Failed to read memory. Error: {error}"); return
    membuf = bytes(membuf_data)

    # --- Replaced output() with print() ---
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}"
    print(COLOR_HEXDUMP_HEADER + "[" + addr_fmt.format(dump_addr) + "]" + RESET, end='')
    print(COLOR_HEXDUMP_HEADER + "----------------------------------------" + RESET, end='')
    print(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET)

    index = 0
    while index < size:
        chunk = membuf[index : index + 16]
        # Read 4 dwords
        try:
            dwords = struct.unpack("<IIII", chunk) # Little-endian
        except struct.error:
            err_msg(f"Could not unpack 16 bytes into dwords at offset {index}.")
            break

        current_line_addr = dump_addr + index
        addr_str = BOLD + COLOR_HEXDUMP_ADDR + addr_fmt.format(current_line_addr) + " :" + RESET

        # Format dwords
        dword_strs = ["{:08x}".format(dw) for dw in dwords]
        data_str = COLOR_HEXDUMP_DATA + " {} {}  {} {}".format(*dword_strs) + RESET # Midpoint space

        ascii_str = BOLD + COLOR_HEXDUMP_ASCII + quotechars(chunk) + RESET

        print(addr_str + data_str + " " + ascii_str)

        index += 16

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle


# display quad values
def cmd_dq(debugger, command, result, dict):
    """Display hex dump in quad values. Use 'dq help' for more information."""
    help_dict = {
        "cmd": "dq",
        "short": "display memory qwords",
        "desc": "Display memory hex dump in quadword (8-byte) values and ASCII representation.",
        "args": "[<address>] [<size>]",
        "options": [
            {"name": "address", "desc": "The target address to display (expression supported). Defaults to current PC."},
            {"name": "size", "desc": "The amount of memory to display in bytes (expression supported). Default is 256 bytes. Must be multiple of 16 (or 32 for better alignment?)."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators."],
        "example": "dq rsp 128"
    }
    size = 0x100
    dump_addr_expr = "$pc"

    cmd = command.split()
    if len(cmd) == 0: pass
    elif len(cmd) == 1:
        if cmd[0] == "help": help_msg(help_dict); return
        dump_addr_expr = cmd[0]
    elif len(cmd) == 2:
        dump_addr_expr = cmd[0]
        size_expr = cmd[1]
        size_val = evaluate(size_expr)
        if size_val is None or size_val <= 0: err_msg(f"Invalid size expression: '{size_expr}'"); help_msg(help_dict); return
        # DQ displays 2 qwords per line (16 bytes). Let's require size multiple of 16.
        if size_val % 16 != 0: err_msg("Size must be a multiple of 16 bytes for dq."); help_msg(help_dict); return
        size = size_val
    else: err_msg("Too many arguments."); help_msg(help_dict); return

    dump_addr = evaluate(dump_addr_expr)
    if dump_addr is None: err_msg(f"Invalid address expression: '{dump_addr_expr}'"); help_msg(help_dict); return

    process = get_process(); error = lldb.SBError()
    if not process: err_msg("No process found."); return

    membuf_data = process.ReadMemory(dump_addr, size, error)
    if not error.Success() or not membuf_data: err_msg(f"Failed to read memory. Error: {error}"); return
    membuf = bytes(membuf_data)

    # --- Replaced output() with print() ---
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}" # DQ mostly makes sense on 64-bit
    print(COLOR_HEXDUMP_HEADER + "[" + addr_fmt.format(dump_addr) + "]" + RESET, end='')
    # Adjusted separator length for 2 qwords
    print(COLOR_HEXDUMP_HEADER + "---------------------------------------------------" + RESET, end='')
    print(BOLD + COLOR_HEXDUMP_HEADER + "[data]" + RESET)

    index = 0
    while index < size:
        chunk = membuf[index : index + 16] # Read 16 bytes for 2 qwords
        if len(chunk) < 16: break # Not enough data for a full line

        # Read 2 qwords
        try:
            qwords = struct.unpack("<QQ", chunk) # Little-endian
        except struct.error:
            err_msg(f"Could not unpack 16 bytes into qwords at offset {index}.")
            break

        current_line_addr = dump_addr + index
        addr_str = BOLD + COLOR_HEXDUMP_ADDR + addr_fmt.format(current_line_addr) + " :" + RESET

        # Format qwords
        qword_strs = ["{:016x}".format(qw) for qw in qwords]
        data_str = COLOR_HEXDUMP_DATA + " {} {}".format(*qword_strs) + RESET

        ascii_str = BOLD + COLOR_HEXDUMP_ASCII + quotechars(chunk) + RESET

        print(addr_str + data_str + " " + ascii_str)

        index += 16

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle


# thx poupas :-)
def byte_to_int(b):
    # Handles both Python 2 str and Python 3 bytes
    if isinstance(b, int):
        return b
    return ord(b) if isinstance(b, str) else b # Py2 ord(), Py3 already int


def hexdump(addr, chars, sep, width, lines=5):
    """Formats memory bytes into a hexdump string."""
    out_lines = []
    line_count = 0
    offset = 0
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}"

    while offset < len(chars):
        if line_count >= lines:
            break

        current_line_addr = addr + offset
        line_bytes = chars[offset : offset + width]
        offset += width

        hex_vals = []
        ascii_vals = []
        for i in range(width):
             if i < len(line_bytes):
                  byte_val = line_bytes[i]
                  hex_vals.append("{:02X}".format(byte_to_int(byte_val)))
                  ascii_vals.append(chr(byte_to_int(byte_val)) if 32 <= byte_to_int(byte_val) <= 126 else ".")
             else:
                  hex_vals.append("  ")
                  ascii_vals.append(" ")
             if i == (width // 2) - 1: # Add midpoint space
                  hex_vals.append("")

        addr_part = BOLD + COLOR_HEXDUMP_ADDR + addr_fmt.format(current_line_addr) + " :" + RESET
        hex_part = COLOR_HEXDUMP_DATA + " " + sep.join(hex_vals) + RESET
        ascii_part = BOLD + COLOR_HEXDUMP_ASCII + "".join(ascii_vals) + RESET

        out_lines.append(addr_part + hex_part + "  " + ascii_part)
        line_count += 1

    return "\n".join(out_lines)


def quotechars(chars):
    """Converts bytes to printable ASCII or '.'."""
    data = ""
    # Iterate directly over bytes/ints
    for x_int in bytearray(chars): # Ensure iteration over integer values
        if 0x20 <= x_int <= 0x7E:
            data += chr(x_int)
        else:
            data += "."
    return data


# find memory command
def cmd_findmem(debugger, command, result, dict):
    """Search process memory for a pattern."""
    # Using upstream style help dict
    help_dict = {
        "cmd": "findmem",
        "short": "search process memory",
        "desc": """Search readable memory regions of the target process for a given pattern.
Unlike 'memory find', this searches across all readable regions automatically.""",
        "args": "<options> <pattern>",
        "options": [
             {"name": "-s <string>", "desc": "Search for the given string (UTF-8 encoded)."},
             {"name": "-b <hexbytes>", "desc": "Search for the given sequence of hex bytes (e.g., -b 414243)."},
             {"name": "-q <qword>", "desc": "Search for the given qword (8-byte integer, e.g., -q 0x4141414141414141)."},
             # -f option seems less common, keeping it commented for now
             # {"name": "-f <filepath>", "desc": "Load search pattern from the specified file."},
             {"name": "-c <count>", "desc": "Stop after finding N occurrences (default is find all)."},
             {"name": "-x", "desc": "Search only executable regions."},
             {"name": "-w", "desc": "Search only writable regions."},
             {"name": "-v", "desc": "Verbose output (show regions being searched)."}
         ],
        "example": "findmem -s \"Error occurred\"\nfindmem -b 4889e5 -x"
    }

    # Use a custom parser to handle potential issues with LLDB's input processing
    parser = argparse.ArgumentParser(prog="findmem", description="Search process memory.", add_help=False) # Disable default help
    parser.add_argument("-s", "--string")
    parser.add_argument("-b", "--binary")
    parser.add_argument("-d", "--dword")
    parser.add_argument("-q", "--qword")
    # parser.add_argument("-f", "--file")
    parser.add_argument("-c", "--count")
    parser.add_argument("-x", "--executable", action="store_true")
    parser.add_argument("-w", "--writable", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument('pattern', nargs='?') # Allow pattern directly for simple cases, or use options

    # Handle 'help' manually
    if command.strip() == "help":
         help_msg(help_dict)
         return

    try:
        # Split command string respecting quotes might be needed for complex strings
        # For now, basic split works for options and simple patterns
        args = parser.parse_args(command.split())
    except SystemExit: # Prevent argparse from exiting LLDB
        err_msg("Failed to parse arguments.")
        help_msg(help_dict)
        return

    search_pattern_bytes = None
    search_term = ""

    # Determine search pattern based on options
    if args.string:
        search_pattern_bytes = args.string.encode('utf-8')
        search_term = f'string "{args.string}"'
    elif args.binary:
        try:
            hex_str = args.binary.replace("0x", "").replace(" ", "")
            if len(hex_str) % 2 != 0: raise ValueError("Odd hex string length")
            search_pattern_bytes = bytes.fromhex(hex_str)
            search_term = f'binary {args.binary}'
        except ValueError as e:
            err_msg(f"Invalid binary hex string '{args.binary}': {e}")
            return
    elif args.dword:
        try:
            dword_val = int(evaluate(args.dword)) # Evaluate allows expressions
            # Assume native endianness for now. Could add options.
            search_pattern_bytes = struct.pack(struct.calcsize('I')*'c', *dword_val.to_bytes(4, sys.byteorder)) # Pack as native int
            search_term = f'dword {args.dword} ({hex(dword_val)})'
        except (ValueError, TypeError, struct.error) as e:
            err_msg(f"Invalid dword value '{args.dword}': {e}")
            return
    elif args.qword:
         try:
            qword_val = int(evaluate(args.qword))
            search_pattern_bytes = struct.pack(struct.calcsize('Q')*'c', *qword_val.to_bytes(8, sys.byteorder)) # Pack as native qword
            search_term = f'qword {args.qword} ({hex(qword_val)})'
         except (ValueError, TypeError, struct.error) as e:
            err_msg(f"Invalid qword value '{args.qword}': {e}")
            return
    # elif args.file: # If file option is re-enabled
    #     try:
    #         with open(args.file, "rb") as f:
    #             search_pattern_bytes = f.read()
    #             search_term = f'file {args.file}'
    #     except IOError as e:
    #         err_msg(f"Could not read file '{args.file}': {e}")
    #         return
    else:
        # If no option used, assume last arg is a string pattern
        if args.pattern:
            search_pattern_bytes = args.pattern.encode('utf-8')
            search_term = f'string "{args.pattern}"'
        else:
            err_msg("No search pattern specified.")
            help_msg(help_dict)
            return

    if not search_pattern_bytes:
        err_msg("Search pattern is empty.")
        return

    max_count = -1
    if args.count:
        try:
            max_count = int(evaluate(args.count))
            if max_count <= 0: raise ValueError("Count must be positive")
        except (ValueError, TypeError):
            err_msg(f"Invalid count value '{args.count}'.")
            return

    process = get_process()
    target = get_target()
    if not process or not target: err_msg("No active process or target."); return

    print(f"[+] Searching for {search_term} (Pattern: {search_pattern_bytes.hex()})...")
    found_count = 0
    addr_fmt = "0x{0:016x}" if POINTER_SIZE == 8 else "0x{0:08x}"
    regions = process.GetMemoryRegions()
    error = lldb.SBError()

    for i in range(regions.GetSize()):
        if max_count != -1 and found_count >= max_count:
            break

        region_info = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(i, region_info):
            continue

        # Filter regions based on permissions
        if not region_info.IsReadable(): continue
        if args.executable and not region_info.IsExecutable(): continue
        if args.writable and not region_info.IsWritable(): continue

        start_addr = region_info.GetRegionBase()
        end_addr = region_info.GetRegionEnd()
        region_size = end_addr - start_addr

        if region_size == 0 or region_size < len(search_pattern_bytes): continue

        if args.verbose:
            perms = ("r" if region_info.IsReadable() else "-") + \
                    ("w" if region_info.IsWritable() else "-") + \
                    ("x" if region_info.IsExecutable() else "-")
            print(f"[...] Searching region {i}: {addr_fmt.format(start_addr)} - {addr_fmt.format(end_addr)} (size={hex(region_size)}, {perms})")

        # Read memory in chunks to avoid huge allocations
        chunk_size = 1024 * 1024 # 1MB chunks
        overlap = len(search_pattern_bytes) - 1 if len(search_pattern_bytes) > 0 else 0 # Overlap needed for finding patterns across chunks
        current_addr = start_addr

        while current_addr < end_addr:
            if max_count != -1 and found_count >= max_count: break

            read_addr = current_addr
            read_size = min(chunk_size + overlap, end_addr - read_addr)
            if read_size < len(search_pattern_bytes): break # Not enough space left

            mem_data = process.ReadMemory(read_addr, read_size, error)
            if not error.Success() or not mem_data:
                if args.verbose: print(f"[!] Warning: Failed to read memory chunk at {addr_fmt.format(read_addr)}. Skipping.")
                current_addr += chunk_size # Skip chunk on read failure
                continue

            mem_bytes = bytes(mem_data)
            search_offset = 0
            while True:
                 if max_count != -1 and found_count >= max_count: break

                 # Find pattern within the current chunk
                 found_index = mem_bytes.find(search_pattern_bytes, search_offset)
                 if found_index == -1:
                     break # Not found in the rest of this chunk

                 # Calculate absolute address
                 match_addr = read_addr + found_index
                 # Avoid reporting matches found entirely within the overlap of the *previous* chunk
                 if match_addr < current_addr:
                     search_offset = found_index + 1 # Continue searching after the match within overlap
                     continue

                 found_count += 1
                 print(f"Found #{found_count} at address: {addr_fmt.format(match_addr)}")

                 # Display context around the match? (Optional)
                 # context_size = 16
                 # context_start = max(start_addr, match_addr - context_size)
                 # context_end = min(end_addr, match_addr + len(search_pattern_bytes) + context_size)
                 # context_data = process.ReadMemory(context_start, context_end - context_start, error)
                 # if error.Success() and context_data:
                 #      print(hexdump(context_start, bytes(context_data), " ", 16, 3)) # Show a few lines

                 if max_count != -1 and found_count >= max_count:
                     break # Stop searching entirely

                 # Continue searching after this match
                 search_offset = found_index + 1 # Start next search after this match

            # Move to the next chunk start position
            current_addr += chunk_size

    print(f"[+] Search finished. Found {found_count} occurrence(s).")
    return


# display information about process memory regions similar to vmmap
def cmd_showregions(debugger, command, result, dict):
    """Display memory regions information."""
    help_dict = {
        "cmd": "showregions",
        "short": "display memory regions",
        "desc": """Display process memory regions similar to vmmap (but potentially with less detail depending on OS/LLDB version).""",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    process = get_process()
    target = get_target()
    if not process or not target: err_msg("No active process or target."); return

    regions = process.GetMemoryRegions()
    if regions.GetSize() == 0:
        print("No memory regions found for this process.")
        return

    # Dynamic formatting based on pointer size
    if POINTER_SIZE == 4:
        addr_width = 10 # 0xAAAAAAAA
        size_width = 10 # 0xAAAAAAAA
        hdr_fmt = "{:<{aw}} {:<{aw}} {:<{sw}} {:<4} {:<16} {:<s}"
        ptr_fmt = "0x{:08x}"
        hdr_labels = ("START", "END", "SIZE", "PROT", "TYPE", "PATH/NAME")
    else: # Assume 8
        addr_width = 18 # 0xAAAAAAAAAAAAAAAA
        size_width = 18
        hdr_fmt = "{:<{aw}} {:<{aw}} {:<{sw}} {:<4} {:<16} {:<s}"
        ptr_fmt = "0x{:016x}"
        hdr_labels = ("START", "END", "SIZE", "PROT", "TYPE", "PATH/NAME")

    header_line = hdr_fmt.format(*hdr_labels, aw=addr_width, sw=size_width)
    print(header_line)
    print("-" * len(header_line))

    for i in range(regions.GetSize()):
        reg = lldb.SBMemoryRegionInfo()
        if not regions.GetMemoryRegionAtIndex(i, reg): continue

        start = reg.GetRegionBase()
        end = reg.GetRegionEnd()
        # Skip zero-sized regions or invalid regions
        if start == lldb.LLDB_INVALID_ADDRESS or end == lldb.LLDB_INVALID_ADDRESS or start >= end:
            continue
        size = end - start

        r = "r" if reg.IsReadable() else "-"
        w = "w" if reg.IsWritable() else "-"
        x = "x" if reg.IsExecutable() else "-"
        perms = f"{r}{w}{x}"

        # Try to determine type heuristically or from name
        region_type = ""
        try:
            # GetName() might not be available or return None
            name = reg.GetName()
            if name: region_type = name
        except AttributeError:
            pass # Ignore if GetName doesn't exist

        # If no name, try heuristics
        if not region_type:
             error = lldb.SBError()
             if reg.IsReadable() and size >= 4: # Only read if readable and large enough
                 magic_bytes = process.ReadMemory(start, 4, error)
                 if error.Success() and len(magic_bytes) == 4:
                     magic_int = struct.unpack("<I", magic_bytes)[0] # Little-endian check
                     if magic_int == 0xFEEDFACF or magic_int == 0xFEEDFACE or magic_int == 0xCFFAEDFE or magic_int == 0xCEFAEDFE: # Mach-O 32/64 LE/BE
                         region_type = "Mach-O"
                     elif magic_bytes.startswith(b"\x7fELF"):
                          region_type = "ELF"
                     elif magic_bytes.startswith(b"MZ"):
                          region_type = "PE/DOS"
                     # Add more heuristics if needed (e.g., dyld cache magic)

        # Try to find module path associated with the start address
        module_path = ""
        sb_addr = target.ResolveLoadAddress(start) # More reliable than SBAddress(start, target)
        if sb_addr.IsValid() and sb_addr.GetModule().IsValid():
            module = sb_addr.GetModule()
            spec = module.GetFileSpec()
            path = spec.GetDirectory()
            filename = spec.GetFilename()
            if path and filename:
                module_path = os.path.join(path, filename)
            elif filename:
                module_path = filename

        # Combine type and path/name info
        type_path_info = region_type
        if module_path:
            if type_path_info: type_path_info += " " # Add space if type exists
            type_path_info += f"({module_path})"
        if not type_path_info: type_path_info = "-" # Placeholder if nothing found

        print(hdr_fmt.format(ptr_fmt.format(start), ptr_fmt.format(end), ptr_fmt.format(size),
                             perms, region_type if region_type else "-", module_path if module_path else "-",
                             aw=addr_width, sw=size_width)) # Print formatted line

    return


def cmd_datawin(debugger, command, result, dict):
    """Configure address to display in data window. Use 'datawin help' for more information."""
    help_dict = {
        "cmd": "datawin",
        "short": "configure data window address",
        "desc": """Configure the starting address for the optional data window display in the context view.
The data window, if enabled ('enable data'), will show a hex dump starting at this fixed address.
Useful to observe specific memory locations like buffers or structures.""",
        "args": "<address>",
        "options": [
            {"name": "address", "desc": "The address to display (expression supported)."}
        ],
        "notes": ["Expressions are supported, do not use spaces between operators.",
                  "Use 'enable data' / 'disable data' to toggle the window itself."],
        "example": "datawin $rsp+0x20"
    }
    global DATA_WINDOW_ADDRESS
    cmd = command.split()
    if len(cmd) == 0:
        err_msg("Please insert an address.")
        help_msg(help_dict)
        return

    if cmd[0] == "help":
        help_msg(help_dict)
        print(f"Current data window address: {hex(DATA_WINDOW_ADDRESS) if DATA_WINDOW_ADDRESS else 'Not Set'}")
        return

    addr_expr = cmd[0]
    dump_addr = evaluate(addr_expr)
    if dump_addr is None:
        err_msg(f"Invalid address expression: '{addr_expr}'")
        help_msg(help_dict)
        DATA_WINDOW_ADDRESS = 0 # Reset on error? Or keep old? Let's reset.
        return

    DATA_WINDOW_ADDRESS = dump_addr
    print(f"[+] Data window address set to {hex(DATA_WINDOW_ADDRESS)}. Use 'enable data' to view.")


# ----------------------------------------------------------
# Functions to extract internal and process lldb information
# ----------------------------------------------------------


def is_python2():
    # Kept for compatibility checks if needed elsewhere, though modern LLDB often uses Python 3.
    return sys.version_info[0] < 3


def get_arch():
    """Gets the architecture string (e.g., x86_64, arm64) from the current target."""
    target = get_target()
    # Target can be None if no file is loaded
    if not target:
        # Try getting from debugger hosttriple as fallback?
        host_triple = lldb.debugger.GetHostTriple()
        if host_triple: return host_triple.split('-')[0]
        return "unknown" # Or raise error?
    arch = target.triple.split('-')[0]
    # Normalize common variations if needed
    if arch == "aarch64": return "arm64" # Use consistent naming?
    return arch


# return frame for stopped thread... there should be one at least...
def get_frame():
    """Gets the frame of the currently stopped thread."""
    process = get_process()
    if not process: return None
    thread = process.GetSelectedThread()
    # Check if the selected thread is stopped
    if not thread or not thread.IsValid() or (thread.GetStopReason() == lldb.eStopReasonNone or thread.GetStopReason() == lldb.eStopReasonInvalid):
        # If not stopped, try finding *any* stopped thread (less ideal)
        for t in process:
             if t.IsValid() and (t.GetStopReason() != lldb.eStopReasonNone and t.GetStopReason() != lldb.eStopReasonInvalid):
                  thread = t
                  # Select this thread? Maybe not, just use it for context.
                  # process.SetSelectedThread(thread) # <-- Potentially disruptive
                  break
    # If still no valid stopped thread found
    if not thread or not thread.IsValid() or (thread.GetStopReason() == lldb.eStopReasonNone or thread.GetStopReason() == lldb.eStopReasonInvalid):
         # raise Exception("[!] Warning: get_frame() failed. No stopped thread found.") # Changed to return None
         return None

    frame = thread.GetSelectedFrame()
    if not frame or not frame.IsValid():
         # raise Exception("[!] Warning: get_frame() failed. Could not get frame from stopped thread.") # Changed to return None
         return None
    return frame


def get_thread():
    """Gets the currently selected thread."""
    process = get_process()
    if not process: return None
    thread = process.GetSelectedThread()
    if not thread or not thread.IsValid():
        # Fallback: Try first thread if none selected?
        if process.GetNumThreads() > 0:
             thread = process.GetThreadAtIndex(0)
             if thread and thread.IsValid():
                 # print("[!] Warning: No thread selected, using first thread.")
                 return thread
        # print("[!] Warning: get_thread() failed. No valid thread found.")
        return None
    return thread


def get_target():
    """Gets the currently selected target."""
    target = lldb.debugger.GetSelectedTarget()
    # No exception raised, commands should check the return value
    # if not target:
    #     raise Exception("[-] ERROR: No target available. Please add a target to lldb.")
    return target


def get_process():
    """Gets the process associated with the current target."""
    target = get_target()
    if not target: return None
    process = target.GetProcess()
    # Check if process is valid and not exited
    if not process or not process.IsValid() or process.GetState() == lldb.eStateExited:
         return None
    return process


# evaluate an expression and return the value it represents
def evaluate(command):
    """Evaluates an expression in the current frame context or target context."""
    value = None
    # Try frame context first
    frame = get_frame()
    if frame and frame.IsValid():
        value = frame.EvaluateExpression(command)
        if value and value.IsValid():
             # Try converting to integer (common use case)
             try:
                 # Use GetValueAsSigned or GetValueAsUnsigned for direct integer
                 # return value.GetValueAsSigned() # Or Unsigned? Depends on expected use. Let's try unsigned first.
                 # Using string parsing allows hex etc.
                 val_str = value.GetValue()
                 if val_str is None: return None # Handle None case
                 return int(val_str, 0) # Base 0 auto-detects hex/oct/dec
             except (ValueError, TypeError):
                 # If not an integer, maybe return string or SBValue itself?
                 # For now, assume failure if not parsable as int.
                 # err_msg(f"Expression '{command}' evaluated but result '{value.GetValue()}' is not an integer.")
                 return None # Indicate evaluation worked but type is wrong for typical use
        # else: Fall through to target evaluation

    # If no frame or frame evaluation failed, try target context
    target = get_target()
    if target and target.IsValid():
        value = target.EvaluateExpression(command)
        if value and value.IsValid():
             try:
                 val_str = value.GetValue()
                 if val_str is None: return None
                 return int(val_str, 0)
             except (ValueError, TypeError):
                 # err_msg(f"Expression '{command}' evaluated in target context but result '{value.GetValue()}' is not an integer.")
                 return None # Indicate evaluation worked but type is wrong

    # If both failed
    # err_msg(f"Failed to evaluate expression: '{command}'")
    return None


def is_i386():
    return get_arch() == "i386"


def is_x64():
    # StartsWith allows for x86_64-*, etc.
    return get_arch().startswith("x86_64")


def is_arm():
    # Covers arm64, aarch64
    return get_arch().startswith("arm6") or get_arch().startswith("aarch64")


def get_pointer_size():
    """Gets the pointer size (4 or 8) for the current target."""
    target = get_target()
    if not target: return 8 # Default assumption if no target
    return target.addr_size


# from https://github.com/facebook/chisel/blob/main/fbchisellldbobjcruntimehelpers.py
# returns a string with an expression to evaluate to retrieve the target object for ObjC msgSend
def get_instance_object():
    """Returns the LLDB expression string to get the object instance (self) for objc_msgSend."""
    instanceObject = None
    arch = get_arch()
    if arch == "i386":
        # First arg on stack after return address
        instanceObject = "*(id*)($esp+4)" # Corrected for i386 stack layout
    elif arch.startswith("x86_64"):
        instanceObject = "(id)$rdi" # First arg in RDI
    elif arch.startswith("arm6"): # Covers arm64, aarch64
        instanceObject = "(id)$x0" # First arg in X0
    return instanceObject


# -------------------------
# Register related commands
# -------------------------


# return the int value of a general purpose register
def get_gp_register(reg_name):
    """Gets the value of a specific general-purpose register as an unsigned integer."""
    frame = get_frame()
    if not frame: return 0

    # Find register in the GPR set
    gpr_set = get_registers("general") # Use "general" as common name
    if gpr_set:
         reg_value = gpr_set.GetChildMemberWithName(reg_name)
         if reg_value and reg_value.IsValid():
             return reg_value.GetValueAsUnsigned()

    # Fallback: try searching all registers (less efficient)
    # reg_value = frame.FindRegister(reg_name)
    # if reg_value and reg_value.IsValid():
    #     return reg_value.GetValueAsUnsigned()

    # err_msg(f"Register '{reg_name}' not found in GPRs.") # Avoid spamming errors
    return 0


def get_gp_registers():
    """Gets a dictionary of all general-purpose registers and their unsigned integer values."""
    registers = {}
    frame = get_frame()
    if not frame: return registers

    gpr_set = get_registers("general")
    if gpr_set:
        for i in range(gpr_set.GetNumChildren()):
            reg = gpr_set.GetChildAtIndex(i)
            if reg and reg.IsValid():
                registers[reg.GetName()] = reg.GetValueAsUnsigned()
    return registers


# This seems redundant with get_gp_register if value needed, or frame.FindRegister if SBValue needed.
# def get_register(reg_name):
#     """Gets the string value of a register."""
#     frame = get_frame()
#     if not frame: return "0"
#     reg = frame.FindRegister(reg_name)
#     if reg and reg.IsValid():
#         return reg.GetValue() # Returns string representation
#     return "0"


def get_registers(kind):
    """Returns the SBValue representing the register set of the specified kind (e.g., 'general')."""
    frame = get_frame()
    if frame is None: return None

    registerSet = frame.GetRegisters() # Returns SBValueList
    for value in registerSet:
        # Match kind loosely (case-insensitive) in the register set name
        if kind.lower() in value.GetName().lower():
            return value # Return the SBValue for the whole set
    # print(f"[!] Register set kind '{kind}' not found.")
    return None


# retrieve current instruction pointer via platform independent $pc register
def get_current_pc():
    """Gets the current program counter (instruction pointer) value."""
    frame = get_frame()
    if not frame: return 0 # Return 0 or LLDB_INVALID_ADDRESS? Let's use 0 for simplicity here.
    # PC is guaranteed to be valid if frame is valid
    return frame.GetPC()


# retrieve current stack pointer via registers information
def get_current_sp():
    """Gets the current stack pointer value."""
    frame = get_frame()
    if not frame: return 0
    sp_reg = frame.GetSPRegister() # Use dedicated SP register getter
    if sp_reg and sp_reg.IsValid():
         return sp_reg.GetValueAsUnsigned()
    # Fallback using name (less reliable)
    # sp_name = "rsp" if is_x64() else ("esp" if is_i386() else ("sp" if is_arm() else None))
    # if sp_name: return get_gp_register(sp_name)
    err_msg("Could not determine stack pointer.")
    return 0


# function that updates given register
def cmd_update_register(debugger, command, result, dict):
    """Update register with a new value. Internal command used by aliases."""
    help_dict = {
        "cmd": "update_register",
        "short": "update register value",
        "desc": """Update the value of a specified register in the current frame.
This is primarily used internally by the register shortcut commands (e.g., 'rax', 'x0').""",
        "args": "<register_name> <value>",
        "options": [
            {"name": "register_name", "desc": "The name of the register to update."},
            {"name": "value", "desc": "The new integer value for the register (expression supported)."}
        ],
        "notes": ["If using the register aliases (e.g., 'rax 0x100'), only the value is needed."],
        "example": "update_register rcx 0\nrcx 0" # Show internal and alias usage
    }
    cmd = command.split()
    if len(cmd) == 0: err_msg("Internal error: update_register called with no arguments."); return
    if cmd[0] == "help": help_msg(help_dict); return
    if len(cmd) != 2:
        err_msg("Missing arguments. Expected register name and value.")
        help_msg(help_dict)
        return

    register_name = cmd[0].lower() # Normalize name
    value_expr = cmd[1]

    value = evaluate(value_expr)
    if value is None:
        err_msg(f"Invalid input value expression: '{value_expr}'")
        help_msg(help_dict)
        return

    frame = get_frame()
    if not frame: err_msg("No current frame to update registers in."); return

    # Find the register SBValue
    reg_sbvalue = None
    gpr_set = get_registers("general")
    if gpr_set: reg_sbvalue = gpr_set.GetChildMemberWithName(register_name)
    # Fallback: try FindRegister if not in GPRs (e.g., maybe flags register was intended)
    if not reg_sbvalue or not reg_sbvalue.IsValid():
        reg_sbvalue = frame.FindRegister(register_name)

    if not reg_sbvalue or not reg_sbvalue.IsValid():
        err_msg(f"Register '{register_name}' not found in current frame.")
        return

    # Set the value as a string (LLDB handles conversion)
    # Format as hex for consistency, ensure no 'L' suffix from Python 2 hex()
    hex_value_str = format(value, '#x')
    success = reg_sbvalue.SetValueFromCString(hex_value_str)

    if success:
         # print(f"[+] Register {register_name} set to {hex_value_str}") # Optional confirmation
         # Refresh context automatically after register change?
         debugger.HandleCommand("context")
    else:
         err_msg(f"Failed to set register {register_name} to {hex_value_str}.")

    return


# -----------------------------
# modify eflags/rflags commands
# -----------------------------


def modify_eflags(flag_char):
    """Flips a specific x86 EFLAGS/RFLAGS bit (CF, PF, AF, ZF, SF, TF, IF, DF, OF)."""
    frame = get_frame()
    if not frame: err_msg("No frame to modify flags in."); return

    flags_reg_name = "rflags" if is_x64() else ("eflags" if is_i386() else None)
    if not flags_reg_name:
        err_msg("modify_eflags called on unsupported architecture."); return

    flags_reg = frame.FindRegister(flags_reg_name)
    if not flags_reg or not flags_reg.IsValid():
        err_msg(f"Could not find flags register '{flags_reg_name}'."); return

    current_flags = flags_reg.GetValueAsUnsigned()

    # Map character to bit position
    masks = {"C": 0, "P": 2, "A": 4, "Z": 6, "S": 7, "T": 8, "I": 9, "D": 10, "O": 11}
    flag_upper = flag_char.upper()

    if flag_upper not in masks:
        err_msg(f"Requested flag '{flag_char}' not supported for EFLAGS/RFLAGS.")
        return

    bit_pos = masks[flag_upper]
    # Flip the bit
    new_flags = current_flags ^ (1 << bit_pos)

    # Update the register value
    success = flags_reg.SetValueFromCString(format(new_flags, '#x'))
    if not success:
        err_msg(f"Failed to update {flags_reg_name}.")
    # else: # Optionally show updated context
    #      lldb.debugger.HandleCommand("context")


def modify_cpsr(flag_char):
    """Flips a specific ARM CPSR flag bit (N, Z, C, V)."""
    if not is_arm(): # Explicitly check for ARM
        err_msg("modify_cpsr called on non-ARM architecture."); return

    frame = get_frame()
    if not frame: err_msg("No frame to modify flags in."); return

    flags_reg_name = "cpsr" # LLDB uses 'cpsr' even for AArch64 representation
    flags_reg = frame.FindRegister(flags_reg_name)
    if not flags_reg or not flags_reg.IsValid():
        err_msg("Could not find CPSR register."); return

    current_flags = flags_reg.GetValueAsUnsigned()

    # Map character to bit position (AArch64 standard positions)
    masks = {"N": 31, "Z": 30, "C": 29, "V": 28}
    flag_upper = flag_char.upper()

    if flag_upper not in masks:
        err_msg(f"Requested flag '{flag_char}' not supported for CPSR (NZCV).")
        return

    bit_pos = masks[flag_upper]
    # Flip the bit
    new_flags = current_flags ^ (1 << bit_pos)

    # Update the register value
    success = flags_reg.SetValueFromCString(format(new_flags, '#x'))
    if not success:
        err_msg("Failed to update CPSR.")
    # else: # Optionally show updated context
    #      lldb.debugger.HandleCommand("context")

# Helper for flag commands to reduce boilerplate
def _flag_cmd_helper(debugger, command, result, flag_char, help_dict):
    cmd = command.split()
    if len(cmd) != 0:
        if cmd[0] == "help":
           help_msg(help_dict)
           return
        err_msg("Command takes no arguments.")
        help_msg(help_dict)
        return

    if is_arm():
        if flag_char.upper() in "NZCV":
            modify_cpsr(flag_char)
        else:
            err_msg(f"Flag '{flag_char}' not applicable to ARM CPSR (NZCV).")
    elif is_x64() or is_i386():
         if flag_char.upper() in "CPASZTFIDO":
             modify_eflags(flag_char)
         else:
             err_msg(f"Flag '{flag_char}' not applicable to x86 EFLAGS/RFLAGS.")
    else:
         err_msg("Unsupported architecture for flag modification.")

    # Automatically refresh context after flag change
    debugger.HandleCommand("context")


# AArch64 NZCV register negative bit
def cmd_cfn(debugger, command, result, dict):
    """Change negative flag. Use 'cfn help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfn",
        "short": "flip negative (N) flag",
        "desc": "Flip the Negative (N) flag in the ARM CPSR register.",
        "args": "",
        "notes": ["Only applicable to ARM targets."]
    }
    _flag_cmd_helper(debugger, command, result, "N", help_dict)

# AArch NZCV register overflow bit
def cmd_cfv(debugger, command, result, dict):
    """Change overflow flag. Use 'cfv help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfv",
        "short": "flip overflow (V) flag",
        "desc": "Flip the Overflow (V) flag in the ARM CPSR register.",
        "args": "",
        "notes": ["Only applicable to ARM targets."]
    }
    _flag_cmd_helper(debugger, command, result, "V", help_dict)

def cmd_cfa(debugger, command, result, dict):
    """Change adjust flag. Use 'cfa help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfa",
        "short": "flip auxiliary carry (AF) flag",
        "desc": "Flip the Auxiliary Carry (AF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "A", help_dict)

def cmd_cfc(debugger, command, result, dict):
    """Change carry flag. Use 'cfc help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfc",
        "short": "flip carry (CF/C) flag",
        "desc": "Flip the Carry (CF/C) flag in the x86 EFLAGS/RFLAGS or ARM CPSR register.",
        "args": "",
    }
    _flag_cmd_helper(debugger, command, result, "C", help_dict)

def cmd_cfd(debugger, command, result, dict):
    """Change direction flag. Use 'cfd help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfd",
        "short": "flip direction (DF) flag",
        "desc": "Flip the Direction (DF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "D", help_dict)

def cmd_cfi(debugger, command, result, dict):
    """Change interrupt flag. Use 'cfi help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfi",
        "short": "flip interrupt enable (IF) flag",
        "desc": "Flip the Interrupt Enable (IF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "I", help_dict)

def cmd_cfo(debugger, command, result, dict):
    """Change overflow flag. Use 'cfo help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfo",
        "short": "flip overflow (OF) flag",
        "desc": "Flip the Overflow (OF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "O", help_dict)

def cmd_cfp(debugger, command, result, dict):
    """Change parity flag. Use 'cfp help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfp",
        "short": "flip parity (PF) flag",
        "desc": "Flip the Parity (PF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "P", help_dict)

def cmd_cfs(debugger, command, result, dict):
    """Change sign flag. Use 'cfs help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfs",
        "short": "flip sign (SF) flag",
        "desc": "Flip the Sign (SF) flag in the x86 EFLAGS/RFLAGS register.",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "S", help_dict)

def cmd_cft(debugger, command, result, dict):
    """Change trap flag. Use 'cft help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cft",
        "short": "flip trap (TF) flag",
        "desc": "Flip the Trap (TF) flag in the x86 EFLAGS/RFLAGS register (used for single-stepping).",
        "args": "",
         "notes": ["Only applicable to x86 targets."]
    }
    _flag_cmd_helper(debugger, command, result, "T", help_dict)

def cmd_cfz(debugger, command, result, dict):
    """Change zero flag. Use 'cfz help' for more information."""
    help_dict = { # Using dict format
        "cmd": "cfz",
        "short": "flip zero (ZF/Z) flag",
        "desc": "Flip the Zero (ZF/Z) flag in the x86 EFLAGS/RFLAGS or ARM CPSR register.",
        "args": "",
    }
    _flag_cmd_helper(debugger, command, result, "Z", help_dict)


def dump_eflags(eflags_val):
    """Formats the x86 EFLAGS/RFLAGS value into a standard string."""
    eflagsTuples = [
        ("O", 11), ("D", 10), ("I", 9), ("T", 8), ("S", 7),
        ("Z", 6), ("A", 4), ("P", 2), ("C", 0),
    ]
    out = []
    for flag_char, bit_pos in eflagsTuples:
        if bool(eflags_val & (1 << bit_pos)):
            out.append(flag_char) # Uppercase if set
        else:
            out.append(flag_char.lower()) # Lowercase if clear
    return " ".join(out)


def dump_cpsr(cpsr_val):
    """Formats the ARM CPSR value into a standard string (NZCV)."""
    # Only show NZCV flags which are the primary condition code flags in AArch64
    cpsrTuples = [("N", 31), ("Z", 30), ("C", 29), ("V", 28)]
    # Other flags like I, F, A exist but are less relevant for conditional execution display
    # cpsrTuples64 = [("N", 31), ("Z", 30), ("C", 29), ("V", 28), ("A", 8), ("I", 7), ("F", 6)] # Includes interrupt masks

    out = []
    for flag_char, bit_pos in cpsrTuples:
        if bool(cpsr_val & (1 << bit_pos)):
            out.append(flag_char)
        else:
            out.append(flag_char.lower())
    return " ".join(out)


# returns the result of a conditional AArch64 instruction and the flags condition text
def dump_conditionalaarch64(cpsr_val):
    """Evaluates the condition of the current ARM instruction based on CPSR flags."""
    target = get_target()
    if not target: return False, ""
    frame = get_frame()
    if not frame: return False, ""

    pc_addr = frame.GetPC()
    if pc_addr == lldb.LLDB_INVALID_ADDRESS: return False, ""

    insn = get_instruction(pc_addr)
    if not insn or not insn.IsValid(): return False, ""

    mnemo = insn.GetMnemonic(target)
    operands = insn.GetOperands(target)

    # Only evaluate conditions for conditional branches or conditional selects/moves etc.
    # DoesBranch doesn't cover conditional select etc. Check mnemonic suffix?
    is_conditional = mnemo.startswith('b.') or \
                     mnemo in ('cbz', 'cbnz', 'tbz', 'tbnz') or \
                     mnemo.startswith(('csel', 'csinc', 'csinv', 'csneg', 'cset', 'csetm'))

    if not is_conditional:
        return False, "" # Not a conditional instruction we handle here

    taken = False # Default assumption
    reason = ""

    # Condition codes mapping (from ARM manual) and evaluation logic
    N = bool(cpsr_val & (1 << 31))
    Z = bool(cpsr_val & (1 << 30))
    C = bool(cpsr_val & (1 << 29))
    V = bool(cpsr_val & (1 << 28))

    cond_suffix = ""
    if '.' in mnemo: cond_suffix = mnemo.split('.')[-1]
    elif mnemo.startswith('c'): # For csel etc.
         # Extract condition from operand (e.g., csel w8, w9, w10, eq -> eq)
         parts = operands.split(',')
         if len(parts) > 0:
             last_part = parts[-1].strip().lower()
             if last_part in ['eq', 'ne', 'cs', 'hs', 'cc', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv']: # Check if last part is a condition code
                 cond_suffix = last_part

    # Dictionary mapping condition code to evaluation function (lambda) and reason string
    conditions = {
        "eq": (lambda: Z, "Z==1"), "ne": (lambda: not Z, "Z==0"),
        "cs": (lambda: C, "C==1"), "hs": (lambda: C, "C==1"), # cs/hs are aliases
        "cc": (lambda: not C, "C==0"), "lo": (lambda: not C, "C==0"), # cc/lo are aliases
        "mi": (lambda: N, "N==1"), "pl": (lambda: not N, "N==0"),
        "vs": (lambda: V, "V==1"), "vc": (lambda: not V, "V==0"),
        "hi": (lambda: C and not Z, "C==1 && Z==0"), "ls": (lambda: not C or Z, "C==0 || Z==1"),
        "ge": (lambda: N == V, "N==V"), "lt": (lambda: N != V, "N!=V"),
        "gt": (lambda: not Z and (N == V), "Z==0 && N==V"), "le": (lambda: Z or (N != V), "Z==1 || N!=V"),
        "al": (lambda: True, "Always"), # Always
        # nv condition code exists but is rarely used directly in branches
    }

    # Handle CBZ/CBNZ/TBZ/TBNZ separately as they don't use NZCV directly
    if mnemo in ('cbz', 'cbnz', 'tbz', 'tbnz'):
        try:
            ops = [o.strip() for o in operands.split(',')]
            reg_name = ops[0]
            reg_val = get_gp_register(reg_name)

            if mnemo == 'cbz':
                taken = (reg_val == 0)
                reason = f"{reg_name} == 0"
            elif mnemo == 'cbnz':
                taken = (reg_val != 0)
                reason = f"{reg_name} != 0"
            elif mnemo == 'tbz':
                bit_imm = int(ops[1].replace('#',''))
                taken = not (reg_val & (1 << bit_imm))
                reason = f"bit #{bit_imm} of {reg_name} == 0"
            elif mnemo == 'tbnz':
                bit_imm = int(ops[1].replace('#',''))
                taken = bool(reg_val & (1 << bit_imm))
                reason = f"bit #{bit_imm} of {reg_name} != 0"
        except Exception as e:
             reason = f"Error parsing {mnemo} operands: {e}"
             taken = False # Error state

    # Handle standard conditions
    elif cond_suffix in conditions:
        eval_func, reason_str = conditions[cond_suffix]
        taken = eval_func()
        reason = reason_str
    else:
        # Condition not recognized or instruction doesn't use standard suffixes
        reason = f"Unknown condition '{cond_suffix}'" if cond_suffix else "Non-std conditional"
        taken = False # Unknown state

    return taken, reason


# function to dump the conditional jumps results
def dump_jumpx86(eflags_val):
    """Evaluates and returns a string describing the outcome of the current x86 conditional jump."""
    target = get_target()
    if not target: return ""
    frame = get_frame()
    if not frame: return ""

    pc_addr = frame.GetPC()
    if pc_addr == lldb.LLDB_INVALID_ADDRESS: return ""

    mnemonic = get_mnemonic(pc_addr)
    # Only process conditional jump instructions
    if not mnemonic.startswith('j') or mnemonic in ('jmp', 'call'): # Basic filter
        return ""

    # Flags evaluation
    masks = {"C": 0, "P": 2, "A": 4, "Z": 6, "S": 7, "O": 11} # Relevant flags for jcc
    flags = {key: bool(eflags_val & (1 << value)) for key, value in masks.items()}

    taken = False # Default
    reason = ""

    # Evaluate based on mnemonic (using common conditions)
    if mnemonic in ("je", "jz"): taken, reason = flags["Z"], "Z==1"
    elif mnemonic in ("jne", "jnz"): taken, reason = not flags["Z"], "Z==0"
    elif mnemonic in ("js",): taken, reason = flags["S"], "S==1"
    elif mnemonic in ("jns",): taken, reason = not flags["S"], "S==0"
    elif mnemonic in ("jo",): taken, reason = flags["O"], "O==1"
    elif mnemonic in ("jno",): taken, reason = not flags["O"], "O==0"
    elif mnemonic in ("jb", "jnae", "jc"): taken, reason = flags["C"], "C==1"
    elif mnemonic in ("jnb", "jae", "jnc"): taken, reason = not flags["C"], "C==0"
    elif mnemonic in ("jbe", "jna"): taken, reason = flags["C"] or flags["Z"], "C==1 || Z==1"
    elif mnemonic in ("ja", "jnbe"): taken, reason = not flags["C"] and not flags["Z"], "C==0 && Z==0"
    elif mnemonic in ("jl", "jnge"): taken, reason = flags["S"] != flags["O"], "S!=O"
    elif mnemonic in ("jge", "jnl"): taken, reason = flags["S"] == flags["O"], "S==O"
    elif mnemonic in ("jle", "jng"): taken, reason = flags["Z"] or (flags["S"] != flags["O"]), "Z==1 || S!=O"
    elif mnemonic in ("jg", "jnle"): taken, reason = not flags["Z"] and (flags["S"] == flags["O"]), "Z==0 && S==O"
    elif mnemonic in ("jp", "jpe"): taken, reason = flags["P"], "P==1"
    elif mnemonic in ("jnp", "jpo"): taken, reason = not flags["P"], "P==0"
    elif mnemonic in ("jcxz", "jecxz", "jrcxz"): # Need register value for these
        reg_name = "rcx" if is_x64() else "ecx" # Assume correct size based on mnemonic/arch
        cx_val = get_gp_register(reg_name)
        taken, reason = (cx_val == 0), f"{reg_name}==0"
    else:
        # Not a standard conditional jump we handle here
        return ""

    # Format output string
    outcome = "Taken" if taken else "Not taken"
    output_string = f"=> {outcome} ({reason})"
    color = COLOR_CONDITIONAL_YES if taken else COLOR_CONDITIONAL_NO

    # Add padding based on arch for alignment in context view
    padding = "  " if is_x64() else " "
    return padding + color + output_string + RESET


def showreg64(reg, val):
    """Helper to print a single 64-bit register with modification highlight."""
    print(COLOR_REGNAME + "  {:>3s}: ".format(reg) + RESET, end='')
    c = COLOR_REGVAL_MODIFIED if val != old_x64.get(reg, -1) else COLOR_REGVAL # Use .get with default
    print(c + "0x{:016x}".format(val) + RESET, end='') # Use format specifier
    old_x64[reg] = val # Update old value

def reg64():
    """Prints the 64-bit general purpose registers."""
    current = get_gp_registers()
    if not current: print("Could not retrieve registers."); return

    # First line
    showreg64("rax", current.get("rax", 0))
    showreg64("rbx", current.get("rbx", 0))
    showreg64("rbp", current.get("rbp", 0))
    showreg64("rsp", current.get("rsp", 0))
    rflags = current.get("rflags", 0)
    print("  " + COLOR_CPUFLAGS + dump_eflags(rflags) + RESET) # Flags on right

    # Second line
    showreg64("rdi", current.get("rdi", 0))
    showreg64("rsi", current.get("rsi", 0))
    showreg64("rdx", current.get("rdx", 0))
    showreg64("rcx", current.get("rcx", 0))
    showreg64("rip", current.get("rip", 0))
    print() # Newline

    # Third line
    showreg64("r8", current.get("r8", 0))
    showreg64("r9", current.get("r9", 0))
    showreg64("r10", current.get("r10", 0))
    showreg64("r11", current.get("r11", 0))
    showreg64("r12", current.get("r12", 0))
    print() # Newline

    # Fourth line
    showreg64("r13", current.get("r13", 0))
    showreg64("r14", current.get("r14", 0))
    showreg64("r15", current.get("r15", 0))
    # Add jump condition info
    print(dump_jumpx86(rflags)) # Print conditional info

    # Segment registers (less commonly modified, show simpler)
    print(COLOR_REGNAME + "  CS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("cs", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  FS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("fs", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  GS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("gs", 0)) + RESET)
    # Update old values for segments if needed for highlighting (less critical)
    old_x64["cs"] = current.get("cs", 0)
    old_x64["fs"] = current.get("fs", 0)
    old_x64["gs"] = current.get("gs", 0)


def showreg32(reg, val):
    """Helper to print a single 32-bit register with modification highlight."""
    print(COLOR_REGNAME + "  {:>3s}: ".format(reg) + RESET, end='')
    c = COLOR_REGVAL_MODIFIED if val != old_x86.get(reg, -1) else COLOR_REGVAL
    print(c + "0x{:08x}".format(val) + RESET, end='')
    old_x86[reg] = val

def reg32():
    """Prints the 32-bit general purpose registers."""
    current = get_gp_registers()
    if not current: print("Could not retrieve registers."); return

    # First line
    showreg32("eax", current.get("eax", 0))
    showreg32("ebx", current.get("ebx", 0))
    showreg32("ecx", current.get("ecx", 0))
    showreg32("edx", current.get("edx", 0))
    eflags = current.get("eflags", 0)
    print("  " + COLOR_CPUFLAGS + dump_eflags(eflags) + RESET) # Flags on right

    # Second line
    showreg32("esi", current.get("esi", 0))
    showreg32("edi", current.get("edi", 0))
    showreg32("ebp", current.get("ebp", 0))
    showreg32("esp", current.get("esp", 0))
    showreg32("eip", current.get("eip", 0))
    print() # Newline

    # Segment registers
    print(COLOR_REGNAME + "  CS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("cs", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  DS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("ds", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  ES:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("es", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  FS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("fs", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  GS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("gs", 0)) + RESET, end='')
    print(COLOR_REGNAME + "  SS:" + RESET + COLOR_REGVAL + "{:04x}".format(current.get("ss", 0)) + RESET, end='')
    # Add conditional jump info
    print(dump_jumpx86(eflags))
    # Update old segment values
    for seg in ["cs", "ds", "es", "fs", "gs", "ss"]: old_x86[seg] = current.get(seg, 0)


def showregarm64(reg, val):
     """Helper to print a single ARM64 register with modification highlight."""
     print(COLOR_REGNAME + "  {:>3s}: ".format(reg) + RESET, end='')
     c = COLOR_REGVAL_MODIFIED if val != old_arm64.get(reg, -1) else COLOR_REGVAL
     print(c + "0x{:016x}".format(val) + RESET, end='')
     old_arm64[reg] = val

def regarm64():
    """Prints the ARM64 general purpose registers."""
    current = get_gp_registers()
    if not current: print("Could not retrieve registers."); return

    # Register display order (4 columns)
    display_rows = [
        ("x0", "x8",  "x16", "x24"), ("x1", "x9",  "x17", "x25"),
        ("x2", "x10", "x18", "x26"), ("x3", "x11", "x19", "x27"),
        ("x4", "x12", "x20", "x28"), ("x5", "x13", "x21", "fp"), # x29 is fp
        ("x6", "x14", "x22", "lr"), ("x7", "x15", "x23", "sp"), # x30 is lr
    ]

    for row in display_rows:
        for reg_name in row:
            showregarm64(reg_name, current.get(reg_name, 0))
        print() # Newline after each row

    # PC and CPSR line
    print(COLOR_REGNAME + "   PC: " + RESET, end='')
    pc_val = current.get("pc", 0)
    c = COLOR_REGVAL_MODIFIED if pc_val != old_arm64.get("pc", -1) else COLOR_REGVAL
    print(c + "0x{:016x}".format(pc_val) + RESET, end='')
    old_arm64["pc"] = pc_val

    cpsr_val = current.get("cpsr", 0)
    old_arm64["cpsr"] = cpsr_val # Update old cpsr
    flags_str = dump_cpsr(cpsr_val)
    taken, reason = dump_conditionalaarch64(cpsr_val)

    print("  " + COLOR_CPUFLAGS + flags_str + RESET, end='')

    if reason: # Only print conditional info if relevant
        outcome = "Taken" if taken else "Not taken"
        color = COLOR_CONDITIONAL_YES if taken else COLOR_CONDITIONAL_NO
        print("  " + color + f"=> {outcome} ({reason})" + RESET)
    else:
        print() # Just newline if no condition


def print_registers():
    """Prints the registers appropriate for the current architecture."""
    if is_i386():
        reg32()
    elif is_x64():
        reg64()
    elif is_arm():
        regarm64()
    else:
        print("Registers display not supported for this architecture.")


# ------------------------------
# Disassembler related functions
# ------------------------------

"""
    Handles 'u' command which displays instructions.
"""

def cmd_DumpInstructions(debugger, command, result, dict):
    """Dump instructions at address. Use 'u help' for more information."""
    help_dict = {
        "cmd": "u",
        "short": "disassemble memory",
        "desc": "Disassembles memory at the specified address, similar to SoftICE 'u' command.",
        "args": "[<address>] [<count>]",
        "options": [
             {"name": "address", "desc": "Address to start disassembly (expression supported). Defaults to current PC."},
             {"name": "count", "desc": "Number of instructions to disassemble (expression supported). Defaults to CONFIG_DISASSEMBLY_LINE_COUNT."}
        ],
        "example": "u main\nu $pc 20"
    }
    target = get_target()
    if not target: err_msg("No target found."); return

    # Determine address and count
    addr_expr = "$pc"
    count_expr = str(CONFIG_DISASSEMBLY_LINE_COUNT)

    cmd = command.split()
    if len(cmd) == 0: pass # Use defaults
    elif len(cmd) == 1:
        if cmd[0] == "help": help_msg(help_dict); return
        addr_expr = cmd[0]
    elif len(cmd) == 2:
        addr_expr = cmd[0]
        count_expr = cmd[1]
    else: err_msg("Too many arguments."); help_msg(help_dict); return

    address = evaluate(addr_expr)
    if address is None: err_msg(f"Invalid address expression: '{addr_expr}'"); help_msg(help_dict); return

    count = evaluate(count_expr)
    if count is None or count <= 0: err_msg(f"Invalid count expression: '{count_expr}'"); help_msg(help_dict); return

    # Call the internal disassemble function (used by context view)
    disassemble(address, count)
    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle


# return the SBInstruction at input address
def get_instruction(target_addr):
    """Reads and returns the SBInstruction at the given address."""
    target = get_target()
    if not target or target_addr == lldb.LLDB_INVALID_ADDRESS: return None

    # Use the configured flavor
    # Create SBAddress correctly for reading
    mem_sbaddr = target.ResolveLoadAddress(target_addr)
    if not mem_sbaddr.IsValid():
         # err_msg(f"Could not resolve load address {hex(target_addr)}") # Avoid spam
         return None

    instruction_list = target.ReadInstructions(mem_sbaddr, 1, CONFIG_FLAVOR)
    if not instruction_list or instruction_list.GetSize() == 0:
        # err_msg(f"Failed to read instruction at {hex(target_addr)}") # Avoid spam
        return None
    return instruction_list.GetInstructionAtIndex(0)


# return the instruction mnemonic at input address
def get_mnemonic(target_addr):
    """Gets the mnemonic string of the instruction at the given address."""
    target = get_target() # Ensure target exists
    if not target: return ""
    instruction = get_instruction(target_addr)
    if instruction and instruction.IsValid():
        return instruction.GetMnemonic(target)
    return ""


# returns the instruction operands string
def get_operands(target_addr):
    """Gets the operands string of the instruction at the given address."""
    target = get_target() # Ensure target exists
    if not target: return ""
    instruction = get_instruction(target_addr)
    if instruction and instruction.IsValid():
        return instruction.GetOperands(target)
    return ""


# find out the size of an instruction using internal disassembler
def get_inst_size(target_addr):
    """Gets the size in bytes of the instruction at the given address."""
    instruction = get_instruction(target_addr)
    if instruction and instruction.IsValid():
        return instruction.GetByteSize()
    return 0


# the disassembler we use on stop context
def disassemble(start_address, nrlines):
    """Prints formatted disassembly starting at address for nrlines."""
    target = get_target()
    if not target: return
    process = target.GetProcess() # Needed for reading comments etc.
    if not process: return

    addr_fmt = "0x{:016x}" if POINTER_SIZE == 8 else "0x{:08x}"

    # Resolve start address to handle potential file/load address differences
    mem_sbaddr = target.ResolveLoadAddress(start_address)
    if not mem_sbaddr or not mem_sbaddr.IsValid():
        err_msg(f"Cannot resolve disassembly address {hex(start_address)}")
        return

    # Read instructions using the resolved (load) address
    instructions = target.ReadInstructions(mem_sbaddr, nrlines, CONFIG_FLAVOR)
    if not instructions or instructions.GetSize() == 0:
        print(f"No instructions found at {hex(start_address)}")
        return

    # Find max instruction byte size and mnemonic length for alignment
    max_byte_size = 0
    max_mnem_size = 0
    for i in range(instructions.GetSize()):
        inst = instructions.GetInstructionAtIndex(i)
        if inst.GetByteSize() > max_byte_size: max_byte_size = inst.GetByteSize()
        mnem_len = len(inst.GetMnemonic(target))
        if mnem_len > max_mnem_size: max_mnem_size = mnem_len

    # Ensure minimum width for common instructions
    if max_mnem_size < 6: max_mnem_size = 6
    # Max reasonable byte display width (e.g., 15 bytes for x86)
    if max_byte_size > 15: max_byte_size = 15

    current_pc = get_current_pc()
    current_func_name = None # Track function boundaries

    for idx in range(instructions.GetSize()):
        inst = instructions.GetInstructionAtIndex(idx)
        inst_addr_obj = inst.GetAddress()
        if not inst_addr_obj or not inst_addr_obj.IsValid(): continue

        mem_addr = inst_addr_obj.GetLoadAddress(target)
        if mem_addr == lldb.LLDB_INVALID_ADDRESS: continue

        # --- Function / Module Header ---
        symbol = inst_addr_obj.GetSymbol()
        func_name = symbol.GetName() if symbol and symbol.IsValid() else None
        module = inst_addr_obj.GetModule()
        mod_name = module.GetFileSpec().GetFilename() if module and module.IsValid() else "<unknown>"

        # Print function header only when it changes
        if func_name and func_name != current_func_name:
             print(COLOR_SYMBOL_NAME + f"{func_name} @ {mod_name}:" + RESET)
             current_func_name = func_name
        elif not func_name and current_func_name is not None:
             # Left the known function, clear the tracker (might print module again if needed)
             current_func_name = None
             # Optionally print module header if we left a function?
             # print(COLOR_SYMBOL_NAME + f"@ {mod_name}:" + RESET)


        # --- Instruction Formatting ---
        is_current_pc = (mem_addr == current_pc)
        prefix = COLOR_CURRENT_PC + "->" + RESET if is_current_pc else "  "

        # Address part (Load address only for now, file addr adds complexity)
        addr_part = addr_fmt.format(mem_addr)

        # Bytes part
        bytes_str = ""
        if CONFIG_DISPLAY_DISASSEMBLY_BYTES == 1:
            inst_data = inst.GetData(target)
            if inst_data and inst_data.IsValid():
                 # Read appropriate number of bytes, up to max_byte_size
                 num_bytes = min(inst.GetByteSize(), max_byte_size)
                 byte_list = []
                 for k in range(num_bytes):
                     byte_val = inst_data.GetUnsignedInt8(error, k)
                     if error.Success():
                         byte_list.append("{:02x}".format(byte_val))
                     else:
                         byte_list.append("??") # Error reading byte
                 bytes_str = " ".join(byte_list)
            # Pad bytes string
            padding = (max_byte_size * 3 - 1) - len(bytes_str) # Each byte is 2 chars + 1 space (except last)
            bytes_str = bytes_str.ljust(len(bytes_str) + max(0, padding))
        bytes_part = COLOR_DISASM_LISTING + bytes_str + RESET if bytes_str else "" # Apply color only if bytes are shown

        # Mnemonic and Operands
        mnem = inst.GetMnemonic(target)
        operands = inst.GetOperands(target)
        # Pad mnemonic
        mnem = mnem.ljust(max_mnem_size)
        mnem_oper_part = COLOR_DISASM_LISTING + f"{mnem} {operands}" + RESET

        # --- Comments ---
        comment = ""
        # LLDB's comment
        lldb_comment = inst.GetComment(target)
        if lldb_comment: comment += lldb_comment

        # lrt's user comments
        user_comment = ""
        if module and module.IsValid() and "comments" in g_sessiondata:
            mod_uuid = module.GetUUIDString().lower()
            mod_base = get_module_base(module)
            if mod_base != -1:
                inst_offset = mem_addr - mod_base
                inst_offset_hex = hex(inst_offset)
                for cmt in g_sessiondata.get("comments", []):
                    if cmt.get("uuid") == mod_uuid and cmt.get("offset") == inst_offset_hex:
                        user_comment = cmt.get("text", "")
                        break # Found comment
        if user_comment:
            if comment: comment += " " # Add separator
            comment += COLOR_COMMENT + "; " + user_comment + RESET # Prepend semicolon

        # --- Branch Target Info ---
        branch_target_info = ""
        if inst.DoesBranch():
            flow_addr = get_indirect_flow_address(mem_addr) # Handles direct and indirect
            if flow_addr is not None and flow_addr != -1:
                flow_target_str = addr_fmt.format(flow_addr)
                flow_sym = target.ResolveLoadAddress(flow_addr).GetSymbol()
                flow_name = flow_sym.GetName() if flow_sym and flow_sym.IsValid() else None
                flow_mod = target.ResolveLoadAddress(flow_addr).GetModule()
                flow_mod_name = flow_mod.GetFileSpec().GetFilename() if flow_mod and flow_mod.IsValid() else None

                branch_target_info = f"-> {flow_target_str}"
                if flow_name: branch_target_info += f" <{flow_name}>"
                if flow_mod_name: branch_target_info += f" @ {flow_mod_name}"

                branch_target_info = COLOR_SYMBOL_NAME + branch_target_info + RESET

        # --- Objective-C Info ---
        objc_info = ""
        if is_sending_objc_msg(): # Check if current instruction calls objc_msgSend
             className, selectorName = get_objectivec_selector(mem_addr)
             if className:
                  objc_info = f" [{className}"
                  if selectorName: objc_info += f" {selectorName}"
                  objc_info += "]"
                  objc_info = COLOR_MAGENTA + objc_info + RESET # Use a different color

        # Assemble the line
        line = f"{prefix}  {addr_part}: {bytes_part}  {mnem_oper_part}"
        # Append comments and info smartly
        extra_info = ""
        if comment: extra_info += comment
        if branch_target_info:
             if extra_info and not extra_info.endswith(" "): extra_info += " "
             extra_info += branch_target_info
        if objc_info:
             if extra_info and not extra_info.endswith(" "): extra_info += " "
             extra_info += objc_info

        if extra_info: line += f"    {extra_info}" # Add padding before comments/info

        print(line)

    return


# ------------------------------------
# Commands that use external utilities
# ------------------------------------

def cmd_show_loadcmds(debugger, command, result, dict):
    """Show otool output of Mach-O load commands. Use 'show_loadcmds help' for more information."""
    help_dict = {
        "cmd": "show_loadcmds",
        "short": "display Mach-O load commands",
        "desc": "Reads the Mach-O header and load commands from memory at the specified address and displays the 'otool -l' output.",
        "args": "<header_address>",
        "options": [{"name": "header_address", "desc": "The address of the Mach-O header in memory (expression supported)."}],
        "notes": ["Requires 'otool' (Xcode command line tools).", "Reads a fixed amount of memory (may truncate for very large headers).",
                 "Expressions are supported, do not use spaces between operators."],
        "example": "show_loadcmds 0x100000000"
    }
    error = lldb.SBError()
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a valid Mach-O header address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    header_addr_expr = cmd[0]
    header_addr = evaluate(header_addr_expr)
    if header_addr is None:
        err_msg(f"Invalid header address value: '{header_addr_expr}'")
        help_msg(help_dict)
        return

    otool_path = "/usr/bin/otool"
    if not os.path.isfile(otool_path):
        err_msg(f"{otool_path} not found. Please install Xcode or Xcode command line tools.")
        return

    process = get_process()
    if not process: err_msg("No active process."); return

    # Read a reasonable amount of memory for header + load commands
    # Adjust size as needed, might need to parse header to find sizeofcmds
    read_size = 4096 * 10
    bytes_string = process.ReadMemory(header_addr, read_size, error)
    if not error.Success() or not bytes_string:
        err_msg(f"Failed to read memory at {hex(header_addr)}. Error: {error}")
        return

    # Use temp file for otool input
    try:
        with tempfile.NamedTemporaryFile(delete=True, mode='wb') as f: # Open in binary write mode
            f.write(bytes_string)
            f.flush() # Ensure data is written before otool reads it
            # Pass output to otool
            try:
                output_data = subprocess.check_output([otool_path, "-l", f.name], stderr=subprocess.STDOUT)
                # show the data
                print(output_data.decode('utf-8', errors='ignore')) # Decode for printing
            except subprocess.CalledProcessError as e:
                 err_msg(f"'otool -l' failed (return code {e.returncode}):")
                 print(e.output.decode('utf-8', errors='ignore')) # Print error output from otool
    except IOError as e:
         err_msg(f"Failed to create or write temporary file: {e}")

    return


def cmd_show_header(debugger, command, result, dict):
    """Show otool output of Mach-O header. Use 'show_header help' for more information."""
    help_dict = {
        "cmd": "show_header",
        "short": "display Mach-O header",
        "desc": "Reads the Mach-O header from memory at the specified address and displays the 'otool -hv' output.",
        "args": "<header_address>",
        "options": [{"name": "header_address", "desc": "The address of the Mach-O header in memory (expression supported)."}],
        "notes": ["Requires 'otool' (Xcode command line tools).",
                  "Expressions are supported, do not use spaces between operators."],
         "example": "show_header 0x100000000"
    }
    error = lldb.SBError()
    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert a valid Mach-O header address.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    header_addr_expr = cmd[0]
    header_addr = evaluate(header_addr_expr)
    if header_addr is None:
        err_msg(f"Invalid header address value: '{header_addr_expr}'")
        help_msg(help_dict)
        return

    otool_path = "/usr/bin/otool"
    if not os.path.isfile(otool_path):
        err_msg(f"{otool_path} not found. Please install Xcode or Xcode command line tools.")
        return

    process = get_process()
    if not process: err_msg("No active process."); return

    # Read enough for header (e.g., 1KB should be sufficient)
    read_size = 1024
    bytes_string = process.ReadMemory(header_addr, read_size, error)
    if not error.Success() or not bytes_string:
        err_msg(f"Failed to read memory at {hex(header_addr)}. Error: {error}")
        return

    try:
        with tempfile.NamedTemporaryFile(delete=True, mode='wb') as f:
            f.write(bytes_string)
            f.flush()
            try:
                output_data = subprocess.check_output([otool_path, "-hv", f.name], stderr=subprocess.STDOUT)
                print(output_data.decode('utf-8', errors='ignore'))
            except subprocess.CalledProcessError as e:
                 err_msg(f"'otool -hv' failed (return code {e.returncode}):")
                 print(e.output.decode('utf-8', errors='ignore'))
    except IOError as e:
         err_msg(f"Failed to create or write temporary file: {e}")

    return


# use keystone-engine.org to assemble
def assemble_keystone(arch, mode, code, syntax=0):
    """Assembles code using Keystone and prints the output."""
    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone engine not available.")
        return

    try:
        ks = keystone.Ks(arch, mode)
        if syntax != 0:
            ks.syntax = syntax # Example: keystone.KS_OPT_SYNTAX_NASM
    except keystone.KsError as e:
        err_msg(f"Keystone initialization failed: {e}")
        return

    print("\nKeystone Assembly Output:\n" + "-"*25)
    all_bytes = bytearray()
    success = True
    for idx, inst in enumerate(code):
        try:
            encoding, count = ks.asm(inst)
            if not encoding: # Handle instructions that assemble to nothing (e.g., comments if KS supported)
                print(f"{inst:<30} -> (No bytes)")
                continue
            hex_bytes = " ".join("{:02x}".format(b) for b in encoding)
            print(f"{inst:<30} -> {hex_bytes}")
            all_bytes.extend(encoding)
        except keystone.KsError as e:
            err_msg(f"  ERROR Line {idx+1} ('{inst}'): {e}")
            success = False
            # Continue assembling next lines? Or break? Let's continue.

    if success and all_bytes:
         print("-"*25)
         print("All bytes: " + all_bytes.hex())
    elif not all_bytes:
         print("-"*25)
         print("No bytes generated.")
    else: # Errors occurred
         print("-"*25)
         print("Assembly failed for some instructions.")


# Shared helper for assembler commands
def _assembler_cmd_helper(debugger, command, help_dict, ks_arch, ks_mode, ks_syntax=0):
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return
    if len(cmd) != 0: # No arguments expected for interactive mode
         err_msg("Command takes no arguments for interactive mode.")
         help_msg(help_dict)
         return

    if CONFIG_KEYSTONE_AVAILABLE == 0:
        err_msg("Keystone python bindings not available. Please install from www.keystone-engine.org.")
        return

    print(f"Entering interactive assembler mode ({help_dict['short']}).")
    print("Type instructions one per line. Enter 'end' or 'stop' to finish.")
    inst_list = []
    while True:
        try:
            # Use simple prompt
            line = input('asm> ')
        except EOFError: # Handle Ctrl+D
            break
        line = line.strip()
        if line.lower() in ("stop", "end", "quit", "exit"):
            break
        if line: # Ignore empty lines
            inst_list.append(line)

    if inst_list:
        assemble_keystone(ks_arch, ks_mode, inst_list, ks_syntax)
    else:
        print("No instructions entered.")


def cmd_asm32(debugger, command, result, dict):
    """32 bit x86 interactive Keystone based assembler. Use 'asm32 help' for more information."""
    help_dict = {
        "cmd": "asm32",
        "short": "interactive 32 bit x86 assembler",
        "desc": """Enter interactive mode to assemble 32-bit x86 instructions using Keystone.""",
        "args": "",
        "notes": ["Requires Keystone Python bindings.", "Uses Intel syntax by default (Keystone's default)."],
    }
    _assembler_cmd_helper(debugger, command, help_dict, keystone.KS_ARCH_X86, keystone.KS_MODE_32)

def cmd_asm64(debugger, command, result, dict):
    """64 bit x86 interactive Keystone based assembler. Use 'asm64 help' for more information."""
    help_dict = {
        "cmd": "asm64",
        "short": "interactive 64 bit x86 assembler",
        "desc": """Enter interactive mode to assemble 64-bit x86 instructions using Keystone.""",
        "args": "",
        "notes": ["Requires Keystone Python bindings.", "Uses Intel syntax by default."],
    }
    _assembler_cmd_helper(debugger, command, help_dict, keystone.KS_ARCH_X86, keystone.KS_MODE_64)

def cmd_arm32(debugger, command, result, dict):
    """32 bit ARM interactive Keystone based assembler. Use 'arm32 help' for more information."""
    help_dict = {
        "cmd": "arm32",
        "short": "interactive 32 bit ARM assembler",
        "desc": """Enter interactive mode to assemble 32-bit ARM instructions (ARM mode) using Keystone.""",
        "args": "",
        "notes": ["Requires Keystone Python bindings."],
    }
    _assembler_cmd_helper(debugger, command, help_dict, keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM)

def cmd_armthumb(debugger, command, result, dict):
    """32 bit ARM Thumb interactive Keystone based assembler. Use 'armthumb help' for more information."""
    help_dict = {
        "cmd": "armthumb",
        "short": "interactive 32 bit ARM Thumb assembler",
        "desc": """Enter interactive mode to assemble 32-bit ARM Thumb instructions (Thumb mode) using Keystone.""",
        "args": "",
        "notes": ["Requires Keystone Python bindings."],
    }
    _assembler_cmd_helper(debugger, command, help_dict, keystone.KS_ARCH_ARM, keystone.KS_MODE_THUMB)

def cmd_arm64(debugger, command, result, dict):
    """64 bit ARM interactive Keystone based assembler. Use 'arm64 help' for more information."""
    help_dict = {
        "cmd": "arm64",
        "short": "interactive 64 bit ARM assembler",
        "desc": """Enter interactive mode to assemble 64-bit ARM (AArch64) instructions using Keystone.""",
        "args": "",
        "notes": ["Requires Keystone Python bindings."],
    }
    # Keystone mode (using LITTLE_ENDIAN explicitly if needed, though often default) ---
    # Default mode for ARM64 in Keystone is usually sufficient (implies little endian)
    # mode = keystone.KS_MODE_LITTLE_ENDIAN
    mode = keystone.KS_MODE_ARM # Keystone uses KS_MODE_ARM for AArch64 as well
    _assembler_cmd_helper(debugger, command, help_dict, keystone.KS_ARCH_ARM64, mode)


# --- Kept cmd_IphoneConnect from lrt ---
def cmd_IphoneConnect(debugger, command, result, dict):
    """Connect to debugserver running on iPhone. Use 'iphone help' for more information."""
    help_dict = { # Use dict format
        "cmd": "iphone",
        "short": "connect to remote iOS debugserver",
        "desc": "Sets the platform to remote-ios and connects to the specified debugserver.",
        "args": "<ip_address:port>",
        "example": "iphone 192.168.1.10:12345",
        "notes": ["Requires a debugserver running on the target iOS device accessible at the specified address and port."]
    }

    if not command or ":" not in command or command.strip() == "help":
        help_msg(help_dict)
        return

    target_address = command.strip()
    res = lldb.SBCommandReturnObject()
    ci = debugger.GetCommandInterpreter()

    print("[+] Setting platform to remote-ios...")
    ci.HandleCommand("platform select remote-ios", res)
    if res.Succeeded():
        print(res.GetOutput().strip()) # Print output from platform select
    else:
        err_msg("Failed to run 'platform select remote-ios'.")
        print(res.GetError())
        return # Stop if platform selection fails

    connect_url = "connect://" + target_address
    print(f"[+] Connecting to {connect_url}...")
    ci.HandleCommand(f"process connect {connect_url}", res)
    if res.Succeeded():
        # Output often contains connection success details
        print(f"[+] Connection attempt output:\n{res.GetOutput().strip()}")
    else:
        err_msg(f"Failed to connect to {target_address}.")
        print(res.GetError())

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle

# Helper for stack/data display
def _display_memory_window(start_addr, title, num_lines=4):
     process = get_process()
     if not process: return # No process
     if start_addr == 0 or start_addr == lldb.LLDB_INVALID_ADDRESS: return # No valid address

     error = lldb.SBError()
     bytes_to_read = 16 * num_lines # Read enough for N lines of 16 bytes
     membuf_data = process.ReadMemory(start_addr, bytes_to_read, error)

     if not error.Success() or not membuf_data:
         # Print title even if read fails, to indicate the section
         print(COLOR_SEPARATOR + SEPARATOR * (X64_TOP_SIZE if is_x64() else (ARM_TOP_SIZE if is_arm() else I386_TOP_SIZE))) # Rough separator
         print(BOLD + f"[{title}]" + RESET)
         print(f"  (Failed to read memory at {hex(start_addr)})")
         return

     membuf = bytes(membuf_data)
     # Use hexdump helper function
     dump_output = hexdump(start_addr, membuf, " ", 16, num_lines)

     # Print separator, title, and dump
     print(COLOR_SEPARATOR + SEPARATOR * (X64_TOP_SIZE if is_x64() else (ARM_TOP_SIZE if is_arm() else I386_TOP_SIZE)))
     print(BOLD + f"[{title}]" + RESET)
     print(dump_output)


def display_stack():
    """Displays the stack window content."""
    sp = get_current_sp()
    _display_memory_window(sp, "stack", num_lines=4)


def display_data():
    """Displays the data window content."""
    _display_memory_window(DATA_WINDOW_ADDRESS, "data", num_lines=4)

# This seems overly complex/potentially incorrect for RIP-relative.
# LLDB's disassembler usually resolves RIP-relative directly.
# Let's rely on get_indirect_flow_target which uses SBInstruction.
# def get_rip_relative_addr(src_address): ... (Removed/Commented out)

# find out the target address of an indirect instruction
def get_indirect_flow_target(src_address):
    """Gets the target address of an indirect call/jmp/branch instruction."""
    target = get_target()
    if not target: return None
    process = get_process()
    if not process: return None
    frame = get_frame() # Needed for register values / evaluation
    if not frame: return None

    instruction = get_instruction(src_address)
    if not instruction or not instruction.IsValid(): return None

    operands = instruction.GetOperands(target).lower()
    mnemonic = instruction.GetMnemonic(target).lower()
    error = lldb.SBError()

    # Check if LLDB already resolved it (e.g., direct branch, RIP-relative resolved)
    # SBInstruction doesn't directly expose the *target* address easily.
    # We might need to parse operands or evaluate expressions based on instruction type.

    # 1. Register targets (e.g., call rax, blr x0, br x1)
    register_target_mnemonics = ("call", "jmp", "br", "blr", "retaa", "retab", # ARM ret PAC variants use LR implicitly usually
                                "braa", "braaz", "brab", "brabz", "blraa", "blraaz", "blrab", "blrabz") # ARM branch PAC
    if mnemonic in register_target_mnemonics:
         # Extract register name from operands
         reg_name = None
         if operands:
             # Simple extraction: assume first operand is the register if it starts with known prefixes
             # Handle potential PAC modifier like ", x16"
             op1 = operands.split(',')[0].strip()
             if op1.startswith(('r', 'e', 'x', 'w', 'lr', 'sp')): # Check common GPR/special reg names
                 reg_name = op1
         elif mnemonic.startswith('ret'): # Implicit LR for ret on ARM?
             if is_arm(): reg_name = "lr"

         if reg_name:
              # Get register value
              # print(f"[DEBUG] Getting value for register: {reg_name}")
              reg_value = frame.FindRegister(reg_name)
              if reg_value and reg_value.IsValid():
                   addr = reg_value.GetValueAsUnsigned()
                   # Handle PAC stripping if necessary (basic version)
                   pac_mnemonics = ("braa", "braaz", "brab", "brabz", "blraa", "blraaz", "blrab", "blrabz", "retaa", "retab")
                   if is_arm() and mnemonic in pac_mnemonics:
                       # Apply a mask. Exact mask depends on system/kernel config.
                       # Using 48-bit address space mask as a common case for user space.
                       addr &= 0xFFFFFFFFFFFF
                   return addr
              else:
                   # err_msg(f"Could not read register {reg_name} for indirect target.")
                   return None

    # 2. Memory Dereference targets (e.g., call [rax+0x10], jmp qword ptr [rip+0x1234])
    if '[' in operands and ']' in operands:
        # Extract expression inside brackets
        match = re.search(r"\[(.*)\]", operands)
        if match:
            expr_inside = match.group(1).strip()
            # Convert to LLDB expression syntax (e.g., rip -> $pc, rax -> $rax)
            expr_lldb = expr_inside.replace("rip", "$pc") # Common case
            # More complex replacements might be needed for other registers/syntax
            expr_lldb = re.sub(r"\b(r[a-z0-9]+|e[a-z]{2}|x[0-9]+|sp|lr|fp)\b", r"$\1", expr_lldb)

            # Evaluate the address *to read from*
            # print(f"[DEBUG] Evaluating memory address expression: {expr_lldb}")
            addr_to_read_val = frame.EvaluateExpression(expr_lldb)
            if addr_to_read_val and addr_to_read_val.IsValid():
                addr_to_read = addr_to_read_val.GetValueAsUnsigned()
                # Read the target pointer from that address
                target_addr = process.ReadPointerFromMemory(addr_to_read, error)
                if error.Success():
                    # print(f"[DEBUG] Indirect target via memory {hex(addr_to_read)} -> {hex(target_addr)}")
                    return target_addr
                else:
                    # err_msg(f"Failed to read target pointer from {hex(addr_to_read)}. Error: {error}")
                    return None
            # else: err_msg(f"Failed to evaluate memory expression: {expr_lldb}")

    # 3. Direct/RIP-relative address already in operands (e.g., call 0x12345, jmp $pc+0x20)
    # LLDB often resolves these directly in the operand string
    match_hex = re.search(r"0x[0-9a-fA-F]+", operands)
    if match_hex:
        try:
            return int(match_hex.group(0), 16)
        except ValueError:
            pass # Ignore if not a valid hex number

    # If none of the above matched
    return None


def get_ret_address(pc_addr):
    """Gets the expected return address for the instruction at pc_addr."""
    target = get_target()
    process = get_process()
    frame = get_frame()
    if not target or not process or not frame: return None

    instruction = get_instruction(pc_addr)
    if not instruction or not instruction.IsValid(): return None
    mnemonic = instruction.GetMnemonic(target).lower()
    operands = instruction.GetOperands(target).lower()

    if mnemonic.startswith("ret"):
        if is_arm():
            # Handle standard 'ret' which usually uses LR (x30)
            # Also handle 'ret xN' if specified
            ret_reg = "lr"
            if operands.startswith("x") and len(operands) <= 3: # Check if specific reg is given
                ret_reg = operands
            # Handle PAC return variants (retaa, retab) - they also use LR implicitly
            # For PAC, need to strip PAC bits from LR value
            lr_val = frame.FindRegister(ret_reg).GetValueAsUnsigned()
            if mnemonic in ("retaa", "retab"):
                 lr_val &= 0xFFFFFFFFFFFF # Basic PAC strip
            return lr_val
        elif is_x64() or is_i386():
            # Return address is on the stack
            sp_addr = frame.GetSP()
            if sp_addr == lldb.LLDB_INVALID_ADDRESS: return None
            error = lldb.SBError()
            ret_addr = process.ReadPointerFromMemory(sp_addr, error)
            if error.Success():
                return ret_addr
            else:
                err_msg(f"Failed to read return address from stack {hex(sp_addr)}. Error: {error}")
                return None
    # Not a return instruction
    return None


def is_sending_objc_msg():
    """Checks if the current instruction is likely calling objc_msgSend or similar."""
    target = get_target()
    if not target: return False

    pc_addr = get_current_pc()
    if pc_addr == 0: return False

    call_addr = get_indirect_flow_target(pc_addr) # Get target of call/jmp/branch
    if call_addr is None or call_addr == lldb.LLDB_INVALID_ADDRESS:
        return False

    # Resolve symbol at the target address
    sym_addr = target.ResolveLoadAddress(call_addr)
    if not sym_addr or not sym_addr.IsValid(): return False

    symbol = sym_addr.GetSymbol()
    if not symbol or not symbol.IsValid(): return False

    # Check common message sending functions
    msgSend_variants = ("objc_msgSend", "objc_msgSendSuper", "objc_msgSendSuper2",
                        "objc_msgSend_stret", "objc_msgSendSuper_stret") # Add others? Fpret?
    return symbol.GetName() in msgSend_variants


# displays the contents of the flow window
def display_indirect_flow():
    """Displays information about potential control flow targets or ObjC messages."""
    target = get_target()
    if not target: return
    pc_addr = get_current_pc()
    if pc_addr == 0: return

    addr_fmt = "0x{:016x}" if POINTER_SIZE == 8 else "0x{:08x}"
    flow_info = ""

    # Check for return first
    ret_addr = get_ret_address(pc_addr) # Checks if current insn is ret
    if ret_addr is not None:
        flow_info = f"Return to: {addr_fmt.format(ret_addr)}"
        sym = target.ResolveLoadAddress(ret_addr).GetSymbol()
        if sym and sym.IsValid(): flow_info += f" <{sym.GetName()}>"
    else:
        # Check for other branches/calls
        flow_addr = get_indirect_flow_address(pc_addr)
        if flow_addr is not None and flow_addr != -1:
            flow_info = f"Flow to:   {addr_fmt.format(flow_addr)}"
            sym = target.ResolveLoadAddress(flow_addr).GetSymbol()
            if sym and sym.IsValid(): flow_info += f" <{sym.GetName()}>"

    # Check for ObjC message send *at the current instruction*
    objc_info = ""
    if is_sending_objc_msg():
        className, selectorName = get_objectivec_selector(pc_addr)
        if className:
            objc_info = f"ObjC Msg: [{className}"
            if selectorName: objc_info += f" {selectorName}"
            objc_info += "]"

    # Print gathered info
    if flow_info: print(flow_info)
    if objc_info: print(objc_info)
    if not flow_info and not objc_info:
         print("  (No indirect flow or ObjC message detected)")


# find out the target address of ret, and indirect call and jmp/branch
def get_indirect_flow_address(src_addr):
    """Gets the target address for branch/call/ret at src_addr."""
    instruction = get_instruction(src_addr)
    if not instruction or not instruction.IsValid(): return None # Use None for invalid/not applicable

    mnemonic = instruction.GetMnemonic(get_target()).lower()

    if mnemonic.startswith("ret"):
        return get_ret_address(src_addr) # Can return None
    elif instruction.DoesBranch(): # Covers call, jmp, b, bl, br, etc.
        return get_indirect_flow_target(src_addr) # Handles direct/indirect, can return None
    else:
        return None # Not a branch/call/ret instruction


# retrieve the module full path name an address belongs to
def get_module_name(src_addr):
    """Gets the full path of the module containing the address."""
    target = get_target()
    if not target or src_addr == lldb.LLDB_INVALID_ADDRESS: return ""

    sb_addr = target.ResolveLoadAddress(src_addr)
    if not sb_addr or not sb_addr.IsValid(): return ""

    module = sb_addr.GetModule()
    if not module or not module.IsValid(): return ""

    filespec = module.GetFileSpec()
    if not filespec or not filespec.IsValid(): return ""

    # Reconstruct full path
    directory = filespec.GetDirectory()
    filename = filespec.GetFilename()
    if directory and filename:
        return os.path.join(directory, filename)
    elif filename:
        return filename
    else:
        return ""


# tries to retrieve the class name of object being sent a message and the selector
def get_objectivec_selector(src_addr):
    """Retrieves the Objective-C class and selector for a msgSend call at src_addr."""
    target = get_target()
    process = get_process()
    frame = get_frame()
    if not target or not process or not frame: return "", ""

    # First, confirm the instruction at src_addr actually calls msgSend
    if not is_sending_objc_msg(): # Check at the current PC (src_addr)
        return "", ""

    error = lldb.SBError()

    # Get instance object expression based on arch
    instance_expr = get_instance_object()
    if not instance_expr: return "", "" # Unsupported arch

    # Evaluate class name
    classname_command = f"(const char *)object_getClassName((id){instance_expr})"
    classname_value = frame.EvaluateExpression(classname_command)

    className = ""
    if classname_value and classname_value.IsValid() and classname_value.GetSummary():
        # Check error first
        eval_error = classname_value.GetError()
        if eval_error.Success():
            summary = classname_value.GetSummary()
            if summary: className = summary.strip('"') # Remove quotes from summary
        # else: err_msg(f"Error evaluating class name: {eval_error}") # Optional error

    # Get selector address from the appropriate argument register/stack
    selector_addr = 0
    if is_x64():
        selector_addr = frame.FindRegister("rsi").GetValueAsUnsigned()
    elif is_arm():
        selector_addr = frame.FindRegister("x1").GetValueAsUnsigned()
    elif is_i386():
        sp = frame.GetSP()
        if sp != lldb.LLDB_INVALID_ADDRESS:
             selector_addr = process.ReadPointerFromMemory(sp + 8, error) # Arg after object and return addr
             if not error.Success(): selector_addr = 0 # Failed read
    # else: Arch check already done by get_instance_object

    selectorName = ""
    if selector_addr != 0:
        selectorName = process.ReadCStringFromMemory(selector_addr, 256, error) # Read C string for selector
        if not error.Success():
            # err_msg(f"Failed to read selector string from {hex(selector_addr)}. Error: {error}") # Optional
            selectorName = "" # Clear name on error

    return className, selectorName


# ----------------
# CUSTOM COMMANDS (Kept from lrt)
# ----------------


def cmd_fixret(debugger, command, result, dict):
    """Fix return breakpoint anti-debugging. Use 'fixret help' for more information."""
    help_dict = {
        "cmd": "fixret",
        "short": "fix suspected return address manipulation",
        "desc": """Attempts to fix a common anti-debugging technique where the return address on the stack is manipulated before a RET instruction.
It reads the return address from the current stack pointer, sets the instruction pointer (RIP/EIP/PC) to that address, and increments the stack pointer.
Optionally continues execution.""",
        "args": "[-nc]",
        "options": [{"name":"-nc", "desc": "Do not continue execution after fixing."}],
        "notes": ["Only effective if stopped right before the manipulated RET instruction.",
                  "Assumes standard stack layout for return addresses."]
    }
    cmd = command.split()
    no_continue = False
    if len(cmd) > 0:
        if cmd[0] == "help":
            help_msg(help_dict)
            return
        elif cmd[0] == "-nc":
            no_continue = True
        else:
            err_msg(f"Unrecognized argument: {cmd[0]}")
            help_msg(help_dict)
            return

    frame = get_frame()
    process = get_process()
    target = get_target() # Get target
    if not frame or not process or not target:
        err_msg("Cannot fix return address without a valid frame and process.")
        return

    sp = frame.GetSP()
    if sp == lldb.LLDB_INVALID_ADDRESS:
        err_msg("Could not get stack pointer.")
        return

    error = lldb.SBError()
    ptr_size = target.addr_size
    ret_addr = process.ReadPointerFromMemory(sp, error)

    if not error.Success():
        err_msg(f"Failed to read return address from stack ({hex(sp)}). Error: {error}")
        return

    print(f"[+] Read potential return address {hex(ret_addr)} from {hex(sp)}.")

    # Set PC to the read return address
    if not frame.SetPC(ret_addr):
        err_msg(f"Failed to set PC to {hex(ret_addr)}.")
        return
    else:
        print(f"[+] Set PC to {hex(ret_addr)}.")

    # Increment stack pointer
    new_sp = sp + ptr_size
    sp_reg = frame.GetSPRegister()
    if sp_reg and sp_reg.IsValid():
        sp_reg.value = str(new_sp) # Set SP register value
        print(f"[+] Incremented SP to {hex(new_sp)}.")
    else:
        err_msg("Could not find or set SP register.")
        # Continue anyway? Or stop? Let's stop.
        return

    if no_continue:
        print("[+] Return address fixed. Execution paused.")
        debugger.HandleCommand("context") # Show updated context
    else:
        print("[+] Return address fixed. Continuing execution...")
        process.Continue()


def aux_find_module(address):
    """Finds the SBModule containing the given address."""
    target = get_target()
    if not target or address == lldb.LLDB_INVALID_ADDRESS: return None
    sb_addr = target.ResolveLoadAddress(address)
    if sb_addr and sb_addr.IsValid():
        module = sb_addr.GetModule()
        if module and module.IsValid():
            return module
    return None


def get_module_base(module):
    """Gets the base load address of a module, handling __PAGEZERO."""
    if module is None or not module.IsValid(): return -1

    target = get_target()
    if not target: return -1

    # Iterate through segments to find the first one with a valid load address
    for i in range(module.GetNumSections()):
         section = module.GetSectionAtIndex(i)
         # Check if it's a top-level segment (no parent section)
         if section.IsValid() and not section.GetParent().IsValid():
             load_addr = section.GetLoadAddress(target)
             if load_addr != lldb.LLDB_INVALID_ADDRESS:
                  # Skip __PAGEZERO by checking name or address==0? Checking address is simpler.
                  if load_addr != 0: # Assume base is not 0 unless it's the only segment
                      return load_addr

    # Fallback or if only __PAGEZERO found (unlikely for loaded code)
    return -1


def get_module_offset(address, module):
    """Calculates the offset of an address within its module."""
    if module is None or address == lldb.LLDB_INVALID_ADDRESS: return -1
    base = get_module_base(module)
    if base == -1: return -1
    return address - base


def cmd_addcomment(debugger, command, result, dict):
    """Add comment to address. Use 'acm help' for more information."""
    help_dict = {
        "cmd": "acm",
        "short": "add disassembly comment",
        "desc": "Adds or updates a user comment for a specific address in the disassembly view.",
        "args": "<address> <comment_text>",
        "options": [
            {"name": "address", "desc": "The address to associate the comment with (expression supported)."},
            {"name": "comment_text", "desc": "The text of the comment. Spaces are allowed."}
        ],
        "notes": ["Comments are saved automatically to the current session file.",
                  "Expressions are supported for the address."],
        "example": "acm main+10 \"Entry point adjustments\""
    }
    global g_sessiondata
    global g_sessionfile # Needed for saving

    cmd = command.split()
    if len(cmd) == 1 and cmd[0] == "help": # Allow help with just 'acm help'
        help_msg(help_dict)
        return
    if len(cmd) < 2:
        err_msg("Please insert an address and comment text.")
        help_msg(help_dict)
        return

    # Check if session data is loaded (usually happens on first stop)
    if "comments" not in g_sessiondata:
        err_msg("Session data not initialized. Please start the target first.")
        return

    addr_expr = cmd[0]
    comment_text = " ".join(cmd[1:]) # Join the rest as comment text

    address = evaluate(addr_expr)
    if address is None:
        err_msg(f"Invalid address expression: '{addr_expr}'")
        help_msg(help_dict)
        return

    module = aux_find_module(address)
    if not module:
        err_msg(f"Could not find module for address {hex(address)}. Cannot save comment.")
        return

    offset = get_module_offset(address, module)
    if offset == -1:
         err_msg(f"Could not calculate offset for address {hex(address)} in module {module.GetFileSpec().GetFilename()}.")
         return

    mod_uuid = module.GetUUIDString().lower()
    offset_hex = hex(offset)

    # Find if comment already exists for this offset+uuid
    found_entry = None
    if "comments" in g_sessiondata:
        for item in g_sessiondata["comments"]:
            if item.get("uuid") == mod_uuid and item.get("offset") == offset_hex:
                found_entry = item
                break

    if found_entry:
        print(f"[+] Updating comment at {hex(address)} (offset {offset_hex} in {module.GetFileSpec().GetFilename()}).")
        found_entry["text"] = comment_text
    else:
        print(f"[+] Adding comment at {hex(address)} (offset {offset_hex} in {module.GetFileSpec().GetFilename()}).")
        new_entry = {
            "offset": offset_hex,
            "text": comment_text,
            "uuid": mod_uuid,
            "module": module.GetFileSpec().GetFilename() # Store filename for readability
        }
        # Ensure comments list exists
        if "comments" not in g_sessiondata: g_sessiondata["comments"] = []
        g_sessiondata["comments"].append(new_entry)

    # Save the updated session data
    save_json_session(g_sessionfile)
    # Refresh context view to show new/updated comment
    debugger.HandleCommand("context")


def cmd_delcomment(debugger, command, result, dict):
    """Delete comment from address. Use 'dcm help' for more information."""
    help_dict = {
        "cmd": "dcm",
        "short": "delete disassembly comment",
        "desc": "Deletes a user comment associated with a specific address.",
        "args": "<address>",
        "options": [
            {"name": "address", "desc": "The address whose comment should be deleted (expression supported)."}
        ],
        "notes": ["Changes are saved automatically to the current session file."],
        "example": "dcm main+10"
    }
    global g_sessiondata
    global g_sessionfile

    cmd = command.split()
    if len(cmd) != 1:
        err_msg("Please insert the address of the comment to delete.")
        help_msg(help_dict)
        return
    if cmd[0] == "help":
        help_msg(help_dict)
        return

    if "comments" not in g_sessiondata or not g_sessiondata["comments"]:
        err_msg("No comments available to delete.")
        return

    addr_expr = cmd[0]
    address = evaluate(addr_expr)
    if address is None:
        err_msg(f"Invalid address expression: '{addr_expr}'")
        help_msg(help_dict)
        return

    module = aux_find_module(address)
    if not module:
        err_msg(f"Could not find module for address {hex(address)}. Cannot find comment.")
        return

    offset = get_module_offset(address, module)
    if offset == -1:
         err_msg(f"Could not calculate offset for address {hex(address)}.")
         return

    mod_uuid = module.GetUUIDString().lower()
    offset_hex = hex(offset)

    # Find and remove the comment
    initial_len = len(g_sessiondata["comments"])
    g_sessiondata["comments"] = [
        item for item in g_sessiondata["comments"]
        if not (item.get("uuid") == mod_uuid and item.get("offset") == offset_hex)
    ]
    final_len = len(g_sessiondata["comments"])

    if final_len < initial_len:
        print(f"[+] Deleted comment at {hex(address)}.")
        save_json_session(g_sessionfile)
        debugger.HandleCommand("context") # Refresh view
    else:
        err_msg(f"No comment found at address {hex(address)} (offset {offset_hex} in {module.GetFileSpec().GetFilename()}).")


def cmd_listcomments(debugger, command, result, dict):
    """List all user comments. Use 'lcm help' for more information."""
    help_dict = {
        "cmd": "lcm",
        "short": "list disassembly comments",
        "desc": "Lists all user-added disassembly comments stored in the current session.",
        "args": "",
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    if "comments" not in g_sessiondata or not g_sessiondata["comments"]:
        print("No user comments found in the current session.")
        return

    print("{:<18} {:<18} {:<32} {}".format("Address", "Offset", "Module", "Comment"))
    print("-" * 80)

    # Sort comments? Maybe by module then offset?
    sorted_comments = sorted(g_sessiondata["comments"], key=lambda x: (x.get("module", ""), int(x.get("offset", "0x0"), 16)))

    target = get_target() # Needed to resolve addresses
    modules_by_uuid = {m.GetUUIDString().lower(): m for m in target.module_iter()} if target else {}

    for comment in sorted_comments:
        offset_str = comment.get("offset", "N/A")
        mod_uuid = comment.get("uuid", "")
        mod_name = comment.get("module", "<Unknown Module>") # Use stored name as fallback
        text = comment.get("text", "")

        # Try to resolve current address
        addr_str = "<Module Not Loaded>"
        if mod_uuid in modules_by_uuid:
            module = modules_by_uuid[mod_uuid]
            base_addr = get_module_base(module)
            if base_addr != -1:
                try:
                    offset_int = int(offset_str, 16)
                    current_addr = base_addr + offset_int
                    addr_fmt = "0x{:016x}" if POINTER_SIZE == 8 else "0x{:08x}"
                    addr_str = addr_fmt.format(current_addr)
                except ValueError:
                    addr_str = "<Invalid Offset>"
            # Update mod_name with current filespec name if module is loaded
            mod_name = module.GetFileSpec().GetFilename()

        print("{:<18} {:<18} {:<32} {}".format(addr_str, offset_str, mod_name, text))


# hash the r-x region of the target process main executable
# def hash_target():
#     """Hashes the first executable segment of the main executable."""
#     target = get_target()
#     if not target: return ""
#     process = get_process()
#     if not process: return "" # Need process for reading memory

#     exe_module = target.GetModuleAtIndex(0) # Assume index 0 is main executable
#     if not exe_module or not exe_module.IsValid():
#          err_msg("Could not get main executable module.")
#          return ""

#     first_exec_section = None
#     for section in exe_module:
#         if section.IsExecutable():
#             first_exec_section = section
#             break

#     if not first_exec_section:
#          err_msg("Could not find executable section in main module to hash.")
#          return ""

#     start_addr = first_exec_section.GetLoadAddress(target)
#     size = first_exec_section.GetFileByteSize() # Use file size as approximation

#     if start_addr == lldb.LLDB_INVALID_ADDRESS or size == 0:
#         err_msg("Invalid address or size for executable section.")
#         return ""

#     error = lldb.SBError()
#     # Read memory carefully - avoid reading huge sections if possible
#     # Maybe hash first N bytes? Or hash section headers?
#     # For simplicity, let's try reading the section (can be large!)
#     # Consider adding a size limit for hashing.
#     MAX_HASH_SIZE = 10 * 1024 * 1024 # Limit hash to 10MB?
#     read_size = min(size, MAX_HASH_SIZE)

#     # print(f"[DEBUG] Hashing {read_size} bytes starting at {hex(start_addr)}...")
#     mem_data = process.ReadMemory(start_addr, read_size, error)
#     if not error.Success() or not mem_data:
#          err_msg(f"Failed to read memory for hashing. Error: {error}")
#          return ""

#     try:
#         hash_obj = hashlib.sha256(bytes(mem_data))
#         hex_digest = hash_obj.hexdigest()
#         if DEBUG: print(f"[DEBUG] Target hash: {hex_digest}")
#         return hex_digest
#     except Exception as e:
#         err_msg(f"Hashing failed: {e}")
#         return ""

def hash_target():
    """
    Hashes the primary executable code section of the main executable module
    across different platforms (Mach-O, ELF, PE), verifying it's loaded into
    executable memory. Handles module name prefixes in section names.

    Returns:
        str: The SHA256 hash of the code section as a hex string, or an empty string on error.
    """
    target = get_target()
    if not target:
        err_msg("No target selected.")
        return ""
    process = get_process()
    if not process:
        err_msg("Target has no process.")
        return ""

    # Assume index 0 is the main executable module.
    exe_module = target.GetModuleAtIndex(0)
    if not exe_module or not exe_module.IsValid():
        err_msg("Could not get main executable module.")
        return ""
    module_name = exe_module.GetFileSpec().GetFilename()
    dbg_msg(f"Checking module: {module_name}.")

    # Determine target section name suffix based on platform
    triple = target.GetTriple()
    dbg_msg(f"Detected target triple: {triple}.")

    expected_contain = None
    platform_desc = "Unknown"
    if 'apple' in triple or 'darwin' in triple or 'ios' in triple:
        # Mach-O uses segment.section, LLDB often prepends module name.
        platform_desc = "Mach-O (Apple)"
        expected_contain = "__text"
    elif 'linux' in triple:
        # ELF commonly uses '.text'
        platform_desc = "ELF (Linux)"
        expected_contain = "text"
    elif 'windows' in triple:
         # PE/COFF commonly uses '.text'
        platform_desc = "PE/COFF (Windows)"
        expected_contain = "text"
    else:
        err_msg(f"Unsupported platform triple: {triple}. Cannot determine code section suffix.")
        return ""

    dbg_msg(f"Platform detected as: {platform_desc}. Expecting section contains: '{expected_contain}' and type Code.")

    # --- Find the section by iterating and checking suffix and type ---
    section_to_hash = None
    section_name_for_log = f"section ending with '{expected_contain}'"

    def process_section(section):
        sec_name = section.GetName()
        sec_type = section.GetSectionType()

        # # print every field in section
        # for item in dir(section):
        #     # skip "data"
        #     if item == "data":
        #         continue
        #     if not item.startswith("__") and not item.startswith("Get"):
        #         try:
        #             value = getattr(section, item)
        #             dbg_msg(f"Section {i}: {item} = {value}")
        #         except Exception as e:
        #             err_msg(f"Error accessing section attribute '{item}': {e}")

        # Check if name ends with the expected suffix AND type is Code
        if sec_name and expected_contain in sec_name and sec_type == lldb.eSectionTypeCode:
            dbg_msg(f"Found code section: Index={i}, Name='{sec_name}', Type={sec_type}.")
            return section
        # elif sec_name:
        #     dbg_msg(f"Checked section index {i}: Name='{sec_name}', Type={sec_type} (no match).")
        
        # iterate over subsections
        for subsection in section:
            ret = process_section(subsection)
            if ret is not None:
                dbg_msg(f"Found code subsection: {ret}")
                return ret
        
        # If no match found, return None
        return None


    num_sections = exe_module.GetNumSections()
    dbg_msg(f"Searching {num_sections} sections...")
    for i in range(num_sections):
        section = exe_module.GetSectionAtIndex(i)
        if section and section.IsValid():
            ret = process_section(section)
            if ret is not None:
                dbg_msg(f"Selected code section: {ret}.")
                section_to_hash = ret
                section_name_for_log = section.GetName()
                break
        # else:
        #     dbg_msg(f"Skipping invalid section at index {i}.")

    # If the section wasn't found after iterating
    if not section_to_hash:
        err_msg(f"Could not find a suitable code section (e.g., containing '{expected_contain}' with type Code) in module {module_name}.")
        return ""

    # --- Validate the found section ---
    sec_load_addr = section_to_hash.GetLoadAddress(target)
    dbg_msg(f"Validating section '{section_name_for_log}'. Load addr: {hex(sec_load_addr)}.")

    if sec_load_addr == lldb.LLDB_INVALID_ADDRESS:
        err_msg(f"Section '{section_name_for_log}' has invalid load address.")
        return ""

    size = section_to_hash.GetByteSize()
    if size == 0:
        dbg_msg(
            f"Section '{section_name_for_log}' GetByteSize is 0, using GetFileByteSize."
        )
        size = section_to_hash.GetFileByteSize()
        if size == 0:
            err_msg(
                f"Section '{section_name_for_log}' has size 0 (checked GetByteSize and GetFileByteSize)."
            )
            return ""

    # --- Check memory permissions ---
    region_info = lldb.SBMemoryRegionInfo()
    error = process.GetMemoryRegionInfo(sec_load_addr, region_info)
    mem_is_executable = error.Success() and region_info.IsExecutable()

    if not mem_is_executable:
        perms_str = "n/a"
        region_str = "n/a"
        if error.Success():
            perms_str = f"r={str(region_info.IsReadable()).lower()} w={str(region_info.IsWritable()).lower()} x={str(region_info.IsExecutable()).lower()}"
            region_str = f"[{hex(region_info.GetRegionBase())}-{hex(region_info.GetRegionEnd())})"
        err_msg(
             f"Memory for section '{section_name_for_log}' at {hex(sec_load_addr)} is not executable. Region: {region_str}, Perms: {perms_str}, Error: {error}."
        )
        return ""

    # If all checks passed.
    dbg_msg(
        f"Section '{section_name_for_log}' validated. Addr={hex(sec_load_addr)}, Size={size}, MemExecutable=true."
    )
    start_addr = sec_load_addr

    # --- Hashing logic ---
    error_hash = lldb.SBError()
    max_hash_size = 10 * 1024 * 1024  # 10MB limit.
    read_size = min(size, max_hash_size)
    dbg_msg(
        f"Hashing {read_size} bytes from section '{section_name_for_log}' starting at {hex(start_addr)}."
    )

    if size > max_hash_size:
        print(
            f"[Info] Section size ({size} bytes) exceeds limit ({max_hash_size}), hashing only the first {read_size} bytes."
        )

    mem_data = process.ReadMemory(start_addr, read_size, error_hash)

    if not error_hash.Success() or not mem_data:
        err_msg(
            f"Failed to read memory for hashing section '{section_name_for_log}' (addr: {hex(start_addr)}, size: {read_size}). Error: {error_hash}."
        )
        return ""

    try:
        hash_obj = hashlib.sha256(mem_data)
        hex_digest = hash_obj.hexdigest()
        dbg_msg(f"Target hash ({section_name_for_log} section): {hex_digest}.")
        return hex_digest
    except Exception as e:
        err_msg(f"Hashing failed: {e}.")
        return ""

# save the session data to JSON file
def save_json_session(filepath):
    """Saves the global g_sessiondata dictionary to a JSON file."""
    global g_sessiondata
    if not filepath:
        err_msg("Session file path is not set. Cannot save.")
        return

    session_dir = os.path.dirname(filepath)
    if not os.path.exists(session_dir):
        try:
            os.makedirs(session_dir)
        except OSError as e:
            err_msg(f"Failed to create session directory '{session_dir}': {e}")
            return

    # Make backup copy first
    backup_filepath = filepath + ".bak"
    if os.path.isfile(filepath):
        try:
            # Using shutil.copy2 preserves metadata
            import shutil
            shutil.copy2(filepath, backup_filepath)
            if DEBUG: print(f"Backed up session to {backup_filepath}")
        except Exception as e:
            err_msg(f"Failed to make session backup: {e}")
            # Continue trying to save anyway? Or stop? Let's try to save.

    # Write the new data
    try:
        # Ensure version is up-to-date before saving
        g_sessiondata['version'] = SESSION_VERSION
        with open(filepath, "w") as json_file:
            json.dump(g_sessiondata, json_file, sort_keys=True, indent=4)
        if DEBUG: print(f"Saved session data to {filepath}")
    except Exception as e:
        err_msg(f"Failed to write session file '{filepath}': {e}")
        # XXX: Restore backup on failure? This is complex.


# save the breakpoint session
def cmd_save_session(debugger, command, result, dict):
    """Save current breakpoints to a named session. Use 'ss help' for more information."""
    help_dict = {
        "cmd": "ss",
        "short": "save session breakpoints",
        "desc": "Saves the current target's breakpoints (excluding temporary ones) to a named session within the session file.",
        "args": "[<session_name>]",
        "options": [{"name": "session_name", "desc": "The name for the session (no spaces). Defaults to 'default'."}],
        "notes": ["Saves breakpoint properties like offset, enabled state, name, conditions, and commands.",
                  "Overwrites existing session with the same name."]
    }
    global g_sessiondata
    global g_sessionfile

    cmd = command.split()
    session_name = "default"
    if len(cmd) > 0:
        if cmd[0] == "help":
            help_msg(help_dict); return
        session_name = cmd[0] # Use first arg as name
        if len(cmd) > 1: err_msg("Too many arguments."); help_msg(help_dict); return

    # Ensure session infrastructure is initialized
    if "sessions" not in g_sessiondata:
        err_msg("Session data not initialized. Please start the target first.")
        return
    # --- Removed version check that was incompatible ---
    # if isinstance(g_sessiondata["sessions"], str): ...

    target = get_target()
    if not target: err_msg("No target found."); return

    print(f"[+] Saving breakpoints to session '{session_name}'...")
    current_breakpoints_data = [] # Store list of breakpoint dicts for this session

    for i in range(target.GetNumBreakpoints()):
        bpt = target.GetBreakpointAtIndex(i)
        if not bpt or not bpt.IsValid(): continue
        if bpt.IsOneShot(): continue # Skip temporary breakpoints

        # Need at least one valid location to save
        saved_loc = False
        for j in range(bpt.GetNumLocations()):
             loc = bpt.GetLocationAtIndex(j)
             if not loc or not loc.IsValid() or not loc.GetAddress() or not loc.GetAddress().IsValid(): continue

             address = loc.GetAddress()
             module = address.GetModule()
             if not module or not module.IsValid(): continue # Need module info

             bp_addr = loc.GetLoadAddress() # Current load address
             file_addr = address.GetFileAddress() # Address within the file (no ASLR/base)

             offset = get_module_offset(bp_addr, module)
             if offset == -1:
                  print(f"[!] Warning: Could not get offset for BP #{bpt.GetID()} Loc #{j+1} at {hex(bp_addr)}. Skipping location.")
                  continue

             mod_uuid = module.GetUUIDString().lower()
             mod_path = get_module_name(bp_addr) # Get full path

             # Get other properties (once per breakpoint, not per location)
             name = ""
             names = lldb.SBStringList(); bpt.GetNames(names)
             if names.IsValid() and names.GetSize() > 0: name = names.GetStringAtIndex(0)

             cmds = []
             commands = lldb.SBStringList();
             if bpt.GetCommandLineCommands(commands):
                 cmds = [commands.GetStringAtIndex(k) for k in range(commands.GetSize())]

             hardware = bpt.IsHardware()
             condition = bpt.GetCondition() if bpt.GetCondition() else ""
             enabled = bpt.IsEnabled()

             entry = {
                 "offset": hex(offset),
                 # Store file_addr for reference, offset+uuid is primary key
                 "address": hex(file_addr) if file_addr != lldb.LLDB_INVALID_ADDRESS else "N/A",
                 "enabled": enabled,
                 "name": name,
                 "hardware": hardware,
                 "module": os.path.basename(mod_path) if mod_path else "<Unknown>", # Store basename for readability
                 "uuid": mod_uuid,
                 "commands": cmds,
                 "condition": condition,
             }
             current_breakpoints_data.append(entry)
             saved_loc = True
             break # Only save the first valid location's offset/module info per breakpoint

        if not saved_loc:
            print(f"[!] Warning: Could not find valid module/offset for breakpoint #{bpt.GetID()}. Skipping.")


    # Update the session data
    g_sessiondata["sessions"][session_name] = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "description": "", # Placeholder for future description field
        "breakpoints": current_breakpoints_data
    }

    save_json_session(g_sessionfile)
    print(f"[+] Saved {len(current_breakpoints_data)} breakpoint(s) to session '{session_name}'.")
    if DEBUG: print(g_sessiondata["sessions"][session_name])


# restore the breakpoint session
def cmd_restore_session(debugger, command, result, dict):
    """Restore breakpoints from a named session. Use 'rs help' for more information."""
    help_dict = {
        "cmd": "rs",
        "short": "restore session breakpoints",
        "desc": "Restores breakpoints from a previously saved session.",
        "args": "[<session_name>]",
        "options": [{"name": "session_name", "desc": "The name of the session to restore. Defaults to 'default'."}],
        "notes": ["Restores breakpoints based on module UUID and offset.",
                  "Only restores breakpoints for modules currently loaded in the target.",
                  "Does not delete existing breakpoints."]
    }
    global g_sessiondata

    cmd = command.split()
    session_name = "default"
    if len(cmd) > 0:
        if cmd[0] == "help":
            help_msg(help_dict); return
        session_name = cmd[0]
        if len(cmd) > 1: err_msg("Too many arguments."); help_msg(help_dict); return

    # Check session infrastructure
    if "sessions" not in g_sessiondata:
        err_msg("Session data not initialized. Please start the target first.")
        return
    # --- Removed version check ---
    if session_name not in g_sessiondata["sessions"]:
        err_msg(f"Session '{session_name}' not found.")
        cmd_list_sessions(debugger, "", result, dict) # Show available sessions
        return

    session_to_restore = g_sessiondata["sessions"][session_name]
    if not session_to_restore.get("breakpoints"):
        print(f"No breakpoints found in session '{session_name}'.")
        return

    target = get_target()
    if not target: err_msg("No target found."); return

    print(f"[+] Restoring breakpoints from session '{session_name}'...")
    # Build dict of loaded modules by UUID for quick lookup
    modules_by_uuid = {m.GetUUIDString().lower(): m for m in target.module_iter() if m.GetUUIDString()}
    # Build set of existing breakpoint addresses to avoid exact duplicates?
    # existing_bps = {bp.GetLocationAtIndex(0).GetLoadAddress() for bp in target if bp.GetNumLocations() > 0}

    restored_count = 0
    skipped_count = 0
    failed_count = 0

    for bp_data in session_to_restore["breakpoints"]:
        mod_uuid = bp_data.get("uuid")
        offset_str = bp_data.get("offset")
        mod_name_stored = bp_data.get("module", "?") # For messages

        if not mod_uuid or not offset_str:
             print(f"[!] Skipping invalid breakpoint entry in session: {bp_data}")
             skipped_count += 1
             continue

        if mod_uuid not in modules_by_uuid:
             if DEBUG: print(f"[DEBUG] Module UUID {mod_uuid} ({mod_name_stored}) not loaded. Skipping BP at offset {offset_str}.")
             skipped_count += 1
             continue

        module = modules_by_uuid[mod_uuid]
        base_addr = get_module_base(module)
        if base_addr == -1:
             print(f"[!] Warning: Could not get base address for loaded module {module.GetFileSpec().GetFilename()} (UUID: {mod_uuid}). Skipping BP at offset {offset_str}.")
             skipped_count += 1
             continue

        try:
            offset = int(offset_str, 16)
            target_addr = base_addr + offset
        except ValueError:
             print(f"[!] Skipping breakpoint with invalid offset '{offset_str}' for module {mod_name_stored}.")
             skipped_count += 1
             continue

        # Check if breakpoint address is valid within the module?
        # For now, assume offset is correct relative to base.

        # Create the breakpoint
        res = lldb.SBCommandReturnObject()
        bp = None
        if bp_data.get("hardware"):
             # Restore hardware breakpoint via CLI
             cli_cmd = f"breakpoint set -H -a {hex(target_addr)}"
             if not bp_data.get("enabled", True): cli_cmd += " -d"
             if bp_data.get("name"): cli_cmd += f" -N \"{bp_data['name']}\"" # Quote name
             if bp_data.get("condition"): cli_cmd += f" -c \"{bp_data['condition']}\"" # Quote condition
             # Add commands? CLI doesn't easily support multiline script commands.
             # Maybe just add simple commands?
             simple_cmds = [c for c in bp_data.get("commands", []) if '\n' not in c]
             for c in simple_cmds: cli_cmd += f" -C \"{c}\"" # Quote command

             debugger.GetCommandInterpreter().HandleCommand(cli_cmd, res)
             if res.Succeeded():
                 # Try to find the created breakpoint to confirm
                 match = re.search(r"Breakpoint (\d+):", res.GetOutput())
                 if match: bp = target.FindBreakpointByID(int(match.group(1)))
                 else: print(f"[!] Warning: HW BP command succeeded for {hex(target_addr)} but couldn't find BP ID in output.")
             else:
                 print(f"[-] Error setting HW breakpoint at {hex(target_addr)}: {res.GetError()}")
                 failed_count += 1
                 continue # Skip to next entry on failure
        else:
             # Restore software breakpoint
             bp = target.BreakpointCreateByAddress(target_addr)

        if bp and bp.IsValid():
             # Set common properties using Python API if BP object exists
             if bp_data.get("name"): bp.AddName(str(bp_data["name"]))
             if not bp_data.get("enabled", True): bp.SetEnabled(False)
             if bp_data.get("condition"): bp.SetCondition(str(bp_data["condition"]))

             # Set script commands if not hardware or if simple CLI commands failed
             if not bp_data.get("hardware") and bp_data.get("commands"):
                  cmds = lldb.SBStringList()
                  for c in bp_data.get("commands", []): cmds.AppendString(str(c))
                  bp.SetCommandLineCommands(cmds)

             if DEBUG: print(f"[DEBUG] Restored BP #{bp.GetID()} at {hex(target_addr)}")
             restored_count += 1
        elif not bp_data.get("hardware"): # Only log error if SW BP failed (HW handled above)
             print(f"[-] Failed to create software breakpoint at {hex(target_addr)}.")
             failed_count += 1

    print(f"[+] Restore complete. Restored: {restored_count}, Skipped (Module not loaded/etc.): {skipped_count}, Failed: {failed_count}.")


# list all the available breakpoint sessions
def cmd_list_sessions(debugger, command, result, dict):
    """List saved breakpoint sessions. Use 'ls help' for more information."""
    help_dict = {
        "cmd": "ls",
        "short": "list saved sessions",
        "desc": "Lists all breakpoint sessions saved in the current target's session file.",
        "args": ""
    }
    global g_sessiondata
    global g_target_hash # Show target hash

    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    if "sessions" not in g_sessiondata:
        print("Session data not initialized or file not found.")
        return

    # --- Removed incompatible version check ---
    sessions = g_sessiondata.get("sessions", {})
    if not sessions:
        print(f"No saved sessions found for target hash: {g_target_hash[:12]}...")
        return

    print(f"Saved sessions for target hash: {g_target_hash[:12]}...")
    print("{:<20} {:<12} {:<20}".format("Session Name", "# BPs", "Last Modified"))
    print("-" * 54)

    # Sort sessions by name for consistent listing
    sorted_session_names = sorted(sessions.keys())

    for name in sorted_session_names:
        session_info = sessions[name]
        num_bps = len(session_info.get("breakpoints", []))
        last_mod = session_info.get("time", "N/A")
        print("{:<20} {:<12} {:<20}".format(name, num_bps, last_mod))

    print("-" * 54)


# Run command alias/wrapper
def cmd_run(debugger, command, result, dict):
    """Run the target, stopping at entry. Pass arguments after 'rr'. Use 'rr help' for more information."""
    help_dict = {
        "cmd": "rr", # Using lrt's 'rr' alias name
        "short": "run target and stop at entry",
        "desc": """Run the target process, ensuring it stops at the initial entry point (usually in dyld or the dynamic loader).
Equivalent to 'process launch -s -X true -- [args...]'.
Any arguments provided after 'rr' are passed to the target process.""",
        "args": "[<target_arguments>]",
        "example": "rr --input file.txt --verbose",
        "notes": ["Replaces the default 'r'/'run' alias if previously defined by LLDB."]
    }
    cmd = command.split()
    if len(cmd) > 0 and cmd[0] == "help":
        help_msg(help_dict)
        return

    # Reset internal state variables? (If needed, do it here)
    # global old_x64, old_x86, old_arm64
    # Resetting old registers might be desirable on each run
    # old_x64 = {k:0 for k in old_x64}
    # old_x86 = {k:0 for k in old_x86}
    # old_arm64 = {k:0 for k in old_arm64}
    # print("[+] Resetting internal register state for new run.")

    res = lldb.SBCommandReturnObject()
    debugger.SetAsync(True) # Ensure async for process launch

    # Pass the original command string (arguments for the target)
    cli_command = f"process launch -s -X true -- {command}"
    print(f"[+] Executing: {cli_command}")
    debugger.GetCommandInterpreter().HandleCommand(cli_command, res)

    # Check result? Launch errors are usually printed by LLDB itself.
    if not res.Succeeded():
         print(f"[!] Warning: Process launch command failed.\n{res.GetError()}")
    # Context will be displayed by the stop hook


# ------------------------------------------------------------
# The heart of lrt - when lldb stops this is where we land
# ------------------------------------------------------------

# This seems unused based on the setup. The stop hook is HandleHookStopOnTarget.
def HandleProcessLaunchHook(debugger, command, result, dict):
    print("[lrt] Process Launch Hook Triggered (This hook is likely unused).")
    return 0 # Required return


# Main stop hook
def HandleHookStopOnTarget(debugger, command, result, dict):
    """Displays the context view (registers, stack, code) when the debugger stops."""
    global g_current_target
    global g_sessiondata
    global g_home
    global g_target_hash
    global g_sessionfile
    global CONFIG_DISPLAY_STACK_WINDOW
    global CONFIG_DISPLAY_FLOW_WINDOW
    global CONFIG_DISPLAY_DATA_WINDOW
    global POINTER_SIZE

    # blacklist
    path_blacklist = [
        "/Applications/Xcode"
    ]
    # don't run in blacklisted paths
    for path in path_blacklist:
        if os.getenv("PATH", "").startswith(path): return

    target = get_target()
    # if not target or not target.IsValid(): return # No target, nothing to show
    if not target or not target.IsValid():
        err_msg("No valid target found. Please start the target first.")

    process = target.GetProcess()
    # if not process or not process.IsValid(): return # No process, nothing to show
    if not process or not process.IsValid():
        err_msg("No valid process found. Please start the target first.")
        return

    # Avoid running if process is exited or not stopped properly
    state = process.GetState()
    # if state in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid): return
    if state in (lldb.eStateExited, lldb.eStateDetached, lldb.eStateInvalid):
        err_msg(f"Process state is {state}. Not displaying context.")
        return

    # Check if *any* thread is stopped
    stopped_thread = None
    for thread in process:
        if thread.IsValid() and thread.GetStopReason() != lldb.eStopReasonNone and thread.GetStopReason() != lldb.eStopReasonInvalid:
            stopped_thread = thread
            break
    # if not stopped_thread: return # No thread actually stopped, nothing to show context for
    if not stopped_thread:
        err_msg("No thread is currently stopped. Cannot display context.")
        return

    # Use the stopped thread to get the frame
    frame = stopped_thread.GetSelectedFrame()
    if not frame or not frame.IsValid():
         # This can happen briefly during setup or teardown
         # print("[!] No valid frame for stopped thread.")
         err_msg("No valid frame for stopped thread.")
         return

    # --- Session Loading/Initialization ---
    exe = target.executable
    current_exe_path = exe.fullpath if exe else ""

    # Check if target changed or session not loaded
    if g_current_target != current_exe_path or not g_sessiondata:
        g_current_target = current_exe_path
        g_target_hash = hash_target() # Hash the new target

        if g_target_hash:
            if not g_home: g_home = os.getenv("HOME", ".") # Ensure g_home is set
            g_sessionfile = os.path.join(g_home, ".lldb", f"{g_target_hash}.json")
            print(f"[lrt] Target changed/loaded. Hash: {g_target_hash[:12]}... Session file: {g_sessionfile}")

            # Load existing session file or initialize new one
            if os.path.exists(g_sessionfile):
                try:
                    with open(g_sessionfile, "r") as f:
                        loaded_data = json.load(f)
                        # Basic validation/migration if needed
                        if isinstance(loaded_data, dict) and loaded_data.get("version") == SESSION_VERSION:
                             g_sessiondata = loaded_data
                             print(f"[lrt] Loaded session data version {SESSION_VERSION}.")
                        elif isinstance(loaded_data, dict) and loaded_data.get("version") == 1:
                             err_msg(f"Session file {g_sessionfile} is v1. Please use lrt v3.1 or update file structure. Reinitializing.")
                             g_sessiondata = {} # Force reinit
                        else:
                             err_msg(f"Session file {g_sessionfile} has unrecognized format or version. Reinitializing.")
                             g_sessiondata = {} # Force reinit

                except (IOError, json.JSONDecodeError) as e:
                    err_msg(f"Failed to load session file '{g_sessionfile}': {e}. Reinitializing.")
                    g_sessiondata = {} # Reinitialize on load error
            else:
                 print(f"[lrt] No existing session file found. Initializing new session data.")
                 g_sessiondata = {} # Initialize empty if file doesn't exist

            # Ensure basic structure exists if data was empty or reinitialized
            if not g_sessiondata:
                g_sessiondata['version'] = SESSION_VERSION
                g_sessiondata['comments'] = []
                g_sessiondata['sessions'] = {}
                g_sessiondata['target'] = {
                    "name": exe.basename if exe else "unknown",
                    "path": current_exe_path if current_exe_path else "unknown",
                    "hash": g_target_hash
                }
                save_json_session(g_sessionfile) # Save the initial structure

        else: # Hashing failed
             err_msg("Could not hash target. Session features will be unavailable.")
             g_sessionfile = ""
             g_sessiondata = {}


    # --- Context Display ---
    # Determine separator lengths based on architecture
    top_sep, header_sep, stack_sep, bottom_sep = "", "", "", ""
    arch = get_arch()
    if arch == "i386":
        top_sep = SEPARATOR * I386_TOP_SIZE; header_sep = SEPARATOR * I386_HEADER_SIZE
        stack_sep = SEPARATOR * I386_STACK_SIZE; bottom_sep = SEPARATOR * I386_BOTTOM_SIZE
    elif arch.startswith("x86_64"):
        top_sep = SEPARATOR * X64_TOP_SIZE; header_sep = SEPARATOR * X64_HEADER_SIZE
        stack_sep = SEPARATOR * X64_STACK_SIZE; bottom_sep = SEPARATOR * X64_BOTTOM_SIZE
    elif arch.startswith("arm6") or arch.startswith("aarch64"):
        top_sep = SEPARATOR * ARM_TOP_SIZE; header_sep = SEPARATOR * ARM_HEADER_SIZE
        stack_sep = SEPARATOR * ARM_STACK_SIZE; bottom_sep = SEPARATOR * ARM_BOTTOM_SIZE
    else:
        err_msg(f"Context view layout not defined for architecture: {arch}")
        # Use x64 as default?
        top_sep = SEPARATOR * X64_TOP_SIZE; header_sep = SEPARATOR * X64_HEADER_SIZE
        stack_sep = SEPARATOR * X64_STACK_SIZE; bottom_sep = SEPARATOR * X64_BOTTOM_SIZE


    # Update dynamic pointer size
    global POINTER_SIZE # Ensure global is modified
    POINTER_SIZE = target.addr_size

    # Get stop reason info (breakpoint name)
    bp_name = ""
    stop_reason = stopped_thread.GetStopReason()
    if stop_reason == lldb.eStopReasonBreakpoint:
        # Stop reason data is breakpoint ID(s)
        if stopped_thread.GetStopReasonDataCount() > 0:
            bp_id = stopped_thread.GetStopReasonDataAtIndex(0) # Get first BP ID
            bpx = target.FindBreakpointByID(bp_id)
            if bpx and bpx.IsValid():
                names = lldb.SBStringList()
                bpx.GetNames(names)
                if names.IsValid() and names.GetSize() > 0:
                    bp_name = names.GetStringAtIndex(0) # Get first name

    # Print context view using direct print()
    # Thread ID Header
    print(COLOR_SEPARATOR + f"[ Tid:{stopped_thread.GetIndexID():<3} ]" + header_sep + RESET)

    # Registers
    print(BOLD + "[regs]" + RESET)
    print_registers() # This function now uses direct print

    # Stack Window
    if CONFIG_DISPLAY_STACK_WINDOW == 1:
        display_stack() # This function now uses direct print and handles separator/title

    # Data Window
    if CONFIG_DISPLAY_DATA_WINDOW == 1:
        display_data() # This function now uses direct print and handles separator/title

    # Flow Window
    if CONFIG_DISPLAY_FLOW_WINDOW == 1:
        print(COLOR_SEPARATOR + top_sep + RESET) # Separator
        print(BOLD + "[flow]" + RESET)
        display_indirect_flow() # This function now uses direct print

    # Code Window
    print(COLOR_SEPARATOR + top_sep + RESET) # Separator
    print(BOLD + "[code]" + RESET)
    disassemble(get_current_pc(), CONFIG_DISASSEMBLY_LINE_COUNT) # This uses direct print

    # Bottom separator and extra info
    print(COLOR_SEPARATOR + bottom_sep + RESET)
    if bp_name:
        print("Stopped at breakpoint: " + COLOR_YELLOW + bp_name + RESET)
    else:
        # Print general stop reason if not a named breakpoint
        stop_reason_str = lldb.SBDebugger.StopReasonString(stop_reason)
        print(f"Stop reason: {stop_reason_str}")

    # Final newline handled implicitly by last print? Add one for safety.
    print()

    # result.SetStatus(lldb.eReturnStatusSuccessFinishResult) # Let LLDB handle status
    return # Stop hook doesn't need return value
