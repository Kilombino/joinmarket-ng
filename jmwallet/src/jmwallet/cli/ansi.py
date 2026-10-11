"""
Shared ANSI color helpers for CLI output.

Centralized so every CLI view (wallet info views, renderers, selectors) gates
colors the same way. Colors are only emitted on interactive terminals; piped
or redirected output stays plain (see :func:`color_enabled`).
"""

from __future__ import annotations

import os
import sys

# ANSI SGR codes. Kept as named constants so the call sites stay readable and
# the escape sequences are not scattered as raw literals.
ANSI_RESET = "\033[0m"
ANSI_BOLD_YELLOW = "\033[1;33m"
ANSI_BOLD_WHITE = "\033[1;37m"
ANSI_BOLD_CYAN = "\033[1;36m"
ANSI_BOLD_RED = "\033[1;31m"
ANSI_CYAN = "\033[0;36m"


def color_enabled() -> bool:
    """Whether ANSI colors should be emitted to stdout.

    Colors are only safe on an interactive terminal. When stdout is piped or
    redirected (``jm-wallet info --extended > file`` / ``| less`` / CI logs),
    raw escape codes corrupt the output and break downstream parsing, so they
    are suppressed. The ``NO_COLOR`` convention (https://no-color.org) is also
    honored. This mirrors the TTY guards already used elsewhere in the CLI
    (e.g. the freeze manager and the interactive UTXO selector).
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    return sys.stdout.isatty()


def colorize(text: str, code: str) -> str:
    """Wrap ``text`` in an ANSI ``code`` when colors are enabled, else return it unchanged."""
    if not color_enabled():
        return text
    return f"{code}{text}{ANSI_RESET}"
