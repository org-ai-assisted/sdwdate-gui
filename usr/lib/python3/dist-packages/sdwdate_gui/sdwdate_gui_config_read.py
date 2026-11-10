#!/usr/bin/python3 -Bsu

## Copyright (C) 2025 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
Allows reading sdwdate-gui config values from Bash scripts.
"""

import sys
import traceback
from typing import NoReturn, Any

from .sdwdate_gui_shared import (
    ConfigData,
    parse_config_files,
)


def main() -> NoReturn:
    """
    Main function.
    """

    if len(sys.argv) != 2:
        sys.exit(2)

    ## Minor abuse of defaults_dict, but it conveniently enumerates all
    ## possible config options, and will continue to do so most likely, so
    ## this should be fine.
    if not sys.argv[1] in ConfigData.defaults_dict:
        print(
            f"ERROR: Unrecognized configuration option '{sys.argv[1]}'!",
            file=sys.stderr,
        )
        sys.exit(1)
    try:
        parse_config_files()
    except Exception:
        print(
            "ERROR: Configuration file parsing failed!",
            file=sys.stderr,
        )
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    config_val: Any = ConfigData.conf_dict[sys.argv[1]]
    if isinstance(config_val, bool):
        ## Kicksecure's Bash scripts use 'true' and 'false' for booleans, but
        ## Python uses 'True' and 'False' as the string representations of
        ## booleans. Translate to Bash-script-style.
        print(str(config_val).lower())
    else:
        print(config_val)
    sys.exit(0)
