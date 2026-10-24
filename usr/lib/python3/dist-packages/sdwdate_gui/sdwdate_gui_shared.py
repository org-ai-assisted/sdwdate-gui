#!/usr/bin/python3 -Bsu

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught

"""
Code shared between sdwdate_gui_client and sdwdate_gui_server.
"""

from typing import Any
import schema  # type: ignore

from strict_config_parser import strict_config_parser


# pylint: disable=too-few-public-methods
class ConfigData:
    """
    Configuration data for sdwdate-gui.
    """

    conf_dir_list: list[str] = [
        "/etc/sdwdate-gui.d",
        "/usr/local/etc/sdwdate-gui.d",
    ]
    conf_schema: schema.Schema = schema.Schema(
        {
            schema.Optional("disable"): bool,
            schema.Optional("run_server_in_qubes"): bool,
            schema.Optional("gateway"): str,
        },
    )
    defaults_dict: dict[str, Any] = {
        "disable": False,
        "run_server_in_qubes": False,
        "gateway": "sys-whonix",
    }
    conf_dict: dict[str, Any] = {}


## Maximum size of a single IPC message body (the bytes after the two-byte
## length prefix). We could technically have messages as large as 64 KiB, but
## no reasonable message should be even close to 4 KiB.
MAX_MSG_SIZE: int = 4096


def check_bytes_printable(buf: bytes | memoryview) -> bool:
    """
    Checks if all bytes in the provided buffer are printable ASCII or space.
    """

    for byte in buf:
        if byte < 0x20 or byte > 0x7E:
            return False

    return True


def parse_ipc_buf(sock_buf: bytes) -> tuple[bytes, list[list[str]]]:
    """
    Splits an IPC buffer into a number of string lists, each representing an
    IPC command and its arguments. Each message is prefixed by its length,
    given as a 2-byte unsigned big endian integer. All message bytes must be
    printable ASCII or space.
    """

    msg_scan_pos: int = 0
    sock_buf_len: int = len(sock_buf)
    sock_buf_view: memoryview = memoryview(sock_buf)
    out_msg_list: list[list[str]] = []

    while True:
        if sock_buf_len - msg_scan_pos < 2:
            return (sock_buf[msg_scan_pos:], out_msg_list)

        msg_len: int = int.from_bytes(
            sock_buf_view[msg_scan_pos : (msg_scan_pos + 2)],
            byteorder="big",
            signed=False,
        )
        if msg_len > MAX_MSG_SIZE:
            raise ValueError("Message length too long")
        if msg_len == 0:
            raise ValueError("Empty message in buffer")

        if sock_buf_len - (msg_scan_pos + 2) < msg_len:
            return (sock_buf[msg_scan_pos:], out_msg_list)

        msg_buf: memoryview = sock_buf_view[
            msg_scan_pos + 2 : (msg_len + msg_scan_pos + 2)
        ]
        msg_scan_pos += msg_len + 2

        if not check_bytes_printable(msg_buf):
            raise ValueError("Invalid bytes in command")
        msg_string: str = str(msg_buf, encoding="ascii")
        msg_parts: list[str] = msg_string.split(" ")
        assert len(msg_parts) >= 1
        out_msg_list.append(msg_parts)


def parse_config_files() -> None:
    """
    Parses config files for sdwdate-gui, modifying the ConfigData class to
    reflect the correct configuration state.
    """

    ConfigData.conf_dict = strict_config_parser.parse_config_files(
        conf_item_list=ConfigData.conf_dir_list,
        conf_schema=ConfigData.conf_schema,
        defaults_dict=ConfigData.defaults_dict,
    )


## Debugging.
if __name__ == "__main__":
    parse_config_files()
    for k, v in ConfigData.conf_dict.items():
        print(f"  {k}: {v}")
