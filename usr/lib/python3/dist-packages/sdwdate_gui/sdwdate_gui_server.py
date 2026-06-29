#!/usr/bin/python3 -su

## Copyright (C) 2015 - 2025 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

# pylint: disable=no-name-in-module,broad-exception-caught,too-many-lines,duplicate-code

"""
The server component of sdwdate-gui. Presents a graphical interface for
sdwdate to the user. Expects to be connected to by one or more
sdwdate_gui_client instances which provide data about sdwdate to the server
component and runs tasks at the server component's request.
"""

import os
import sys
import signal
import re
import functools
import logging

from enum import Enum
from typing import NoReturn, Pattern, Callable
from types import FrameType
from pathlib import Path

from PyQt5.QtCore import (
    pyqtSignal,
    Qt,
    QObject,
    QTimer,
)
from PyQt5.QtGui import (
    QIcon,
    QCursor,
)
from PyQt5.QtWidgets import (
    QMenu,
    QAction,
    QSystemTrayIcon,
    QApplication,
    QDialog,
    QWidget,
    QLabel,
    QPushButton,
    QGridLayout,
)
from PyQt5.QtNetwork import (
    QLocalSocket,
    QLocalServer,
)

from sanitize_string.sanitize_string_lib import sanitize_string

from .sdwdate_gui_shared import (
    ConfigData,
    MAX_MSG_SIZE,
    check_bytes_printable,
    parse_ipc_command,
    parse_config_files,
)


## Reasonable maximum lengths for untrusted strings shown in the GUI. A VM
## name under Qubes OS is at most 31 characters; the non-Qubes self-reported
## name is capped at 255. sdwdate messages are already limited to 4096 bytes,
## but that is far more than is useful in a status window.
MAX_QUBES_NAME_LEN: int = 31
MAX_DISPLAY_NAME_LEN: int = 255
MAX_DISPLAY_MSG_LEN: int = 2048

## Bound how many clients may be connected at once, and how long a client may
## stay connected without completing its handshake (providing a name), so a
## misbehaving or hostile client cannot exhaust memory or file descriptors
## with a flood of connections or idle half-open ones. The limit is far above
## any realistic number of VMs for desktop use.
MAX_CLIENTS: int = 64
HANDSHAKE_TIMEOUT_MS: int = 30000


def sanitize_for_richtext(untrusted: str, max_length: int) -> str:
    """
    Remove Unicode and HTML from an untrusted string and truncate it to a
    maximum length.
    """

    return sanitize_string(untrusted)[:max_length]


class SdwdateStatus(Enum):
    """
    Status of the sdwdate process running on a client system.
    """

    SUCCESS = 0
    BUSY = 1
    ERROR = 2
    UNKNOWN = 0xFF


class TorStatus(Enum):
    """
    Status of the Tor process running on a client system, if Tor is present on
    the client.
    """

    RUNNING = 0
    STOPPED = 1
    DISABLED = 2
    DISABLED_RUNNING = 3
    ABSENT = 0xFE
    UNKNOWN = 0xFF


class MessageType(Enum):
    """
    Used to specify which status SdwdateTrayIcon.show_status_msg should
    display to the user.
    """

    SDWDATE = 0
    TOR = 1
    DISCONNECTED = 2


def running_in_qubes_os() -> bool:
    """
    Detects if the server is running on Qubes OS. The behavior when getting
    the client's name has to be somewhat different on Qubes OS, so we need to
    adjust for that use case.
    """

    if Path("/usr/share/qubes/marker-vm").is_file():
        return True

    return False


# pylint: disable=too-many-instance-attributes
class SdwdateGuiClient(QObject):
    """
    An object representing a sdwdate-gui client. Each client object acts as a
    two-way RPC channel, allowing the server to call certain functions in the
    client and vice versa.

    Each message is sent as a length-prefixed packet. Each length prefix is a
    two-byte, big-endian integer specifying the number of bytes in the
    message. The messages then consist of a string, with space-separated
    words. The first word is the name of the function being called, subsequent
    strings are arguments. Functions do not "return" any values.

    The following functions are provided by the server and can be called by
    the client:
    - set_client_name <name>
    - set_sdwdate_status [success|busy|error] [message]
    - set_tor_status [running|stopped|disabled|disabled_running|absent]

    The following functions are provided by the client and can be called by
    the server:
    - open_tor_control_panel
    - open_sdwdate_log
    - restart_sdwdate
    - stop_sdwdate
    - suppress_client_reconnect
    """

    clientDisconnected: pyqtSignal = pyqtSignal()
    clientNameChanged: pyqtSignal = pyqtSignal()
    sdwdateStatusChanged: pyqtSignal = pyqtSignal()
    torStatusChanged: pyqtSignal = pyqtSignal()

    def __init__(
        self, client_socket: QLocalSocket, parent: QObject | None = None
    ) -> None:
        """
        Creates a new SdwdateGuiClient object from a socket.
        """
        QObject.__init__(self, parent)
        self.client_socket: QLocalSocket = client_socket
        self.client_socket.setParent(self)
        self.client_name: str | None = None
        self.client_name_set: bool = False
        self.sdwdate_status: SdwdateStatus = SdwdateStatus.UNKNOWN
        self.sdwdate_msg: str | None = None
        self.tor_status: TorStatus = TorStatus.UNKNOWN
        self.qubes_header_parsed: bool = False
        self.present_in_menu: bool = False
        self.kick_in_progress: bool = False

        self.__sock_buf: bytes = b""

        self.client_socket.readyRead.connect(self.__handle_incoming_data)
        self.client_socket.disconnected.connect(self.clientDisconnected.emit)

        ## Kick a client that connects but never completes its handshake by
        ## providing a name, so half-open / idle connections cannot
        ## accumulate. The timer is stopped as soon as the name is set.
        self.handshake_timer: QTimer = QTimer(self)
        self.handshake_timer.setSingleShot(True)
        self.handshake_timer.timeout.connect(self.__handshake_timeout)
        self.clientNameChanged.connect(self.handshake_timer.stop)
        self.handshake_timer.start(HANDSHAKE_TIMEOUT_MS)

    def __handshake_timeout(self) -> None:
        """
        Kick a still-connected client that never set its name in time.
        """

        if self.client_name_set:
            return
        if self.client_socket.state() != QLocalSocket.ConnectedState:
            return
        logging.warning(
            "Kicking client '%s' for not completing its handshake in time",
            self.client_name_or_unknown(),
        )
        self.kick_client()

    def client_name_or_unknown(self) -> str:
        """
        Returns the client name if set, otherwise returns "Unknown".
        """

        if self.client_name is not None:
            return self.client_name

        return "Unknown"

    def kick_client(self) -> None:
        """
        Forcibly disconnects the client from the server. Used when a client
        sends invalid data to the server as a security measure.
        """

        ## Guard against re-entrancy. On Qubes OS this calls
        ## suppress_client_reconnect(), which sends an RPC; if that send hits
        ## a write error, __generic_rpc_call() calls kick_client() again,
        ## which would recurse indefinitely.
        if self.kick_in_progress:
            return
        self.kick_in_progress = True

        if running_in_qubes_os():
            ## Under Qubes OS, the client will automatically reconnect if the
            ## server disconnects it. Suggest to the client that it not do
            ## that. Assuming the cause of client misbehavior is simply a bug,
            ## this should help prevent endless reconnect loops. Note that the
            ## client may disregard this; we cannot assume the client won't
            ## try to reconnect after receiving this.
            self.suppress_client_reconnect()

        ## Disconnect the "disconnected" signal from the
        ## "clientDisconnected.emit" function, so that we don't end up
        ## triggering clientDisconnected twice. The similar naming of the
        ## "disconnected" signal and "disconnect" method is a coincidence, the
        ## "disconnect" method has nothing to do with disconnecting a socket
        ## connection.
        self.client_socket.disconnected.disconnect()

        self.client_socket.disconnectFromServer()
        self.clientDisconnected.emit()

    ## SOCKET MANAGEMENT
    def __parse_qubes_data(self) -> bool:
        """
        Gets the client name from the qrexec connection header if possible.
        """

        qrexec_header_bytes: bytes | None = None
        for idx, byte in enumerate(self.__sock_buf):
            if byte == 0:
                qrexec_header_bytes = self.__sock_buf[:idx]
                self.__sock_buf = self.__sock_buf[idx + 1 :]
                break

        if qrexec_header_bytes is None:
            if len(self.__sock_buf) > 4096:
                logging.warning(
                    "Kicking client '%s' for sending too much data in qrexec "
                    "header",
                    self.client_name_or_unknown(),
                )
                self.kick_client()
            return False

        if not check_bytes_printable(qrexec_header_bytes):
            logging.warning(
                "Kicking client '%s' for sending invalid bytes in qrexec "
                "header",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        self.qubes_header_parsed = True

        qrexec_header: str = qrexec_header_bytes.decode("ascii")
        qrexec_header_parts = qrexec_header.split(" ")
        if len(qrexec_header_parts) < 2:
            return True

        ## Don't set the client name directly in this function,
        ## __set_client_name is designed to handle the qrexec case too.
        header_name: str = qrexec_header_parts[1]
        self.__set_client_name(header_name)

        return True

    # pylint: disable=too-many-return-statements
    def __try_parse_commands(self) -> None:
        """
        Tries to run any commands in the buffer.
        """

        while len(self.__sock_buf) >= 2:
            function_name: str | None
            msg_parts: list[str] | None
            try:
                preproc_sock_buf_len: int = len(self.__sock_buf)
                self.__sock_buf, function_name, msg_parts = parse_ipc_command(
                    self.__sock_buf
                )
                postproc_sock_buf_len: int = len(self.__sock_buf)
                if preproc_sock_buf_len == postproc_sock_buf_len:
                    ## If the buffer didn't shrink, that means that we've only
                    ## received part of a message. Break so that we can receive
                    ## the rest of it later on.
                    break
                if function_name is None:
                    continue
                assert function_name is not None
                assert msg_parts is not None
            except ValueError:
                logging.warning(
                    "Kicking client '%s' for sending invalid bytes in "
                    "command buffer",
                    self.client_name_or_unknown(),
                )
                self.kick_client()
                return

            match function_name:
                case "set_client_name":
                    if len(msg_parts) != 1:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_client_name' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_client_name(msg_parts[0]):
                        return
                case "set_sdwdate_status":
                    if len(msg_parts) != 2:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_sdwdate_status' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_sdwdate_status(
                        msg_parts[0], msg_parts[1]
                    ):
                        return
                case "set_tor_status":
                    if len(msg_parts) != 1:
                        logging.warning(
                            "Kicking client '%s' for sending incorrect "
                            "number of arguments for 'set_tor_status' "
                            "call",
                            self.client_name_or_unknown(),
                        )
                        self.kick_client()
                        return
                    if not self.__set_tor_status(msg_parts[0]):
                        return
                case _:
                    self.kick_client()
                    return

    def __handle_incoming_data(self) -> None:
        """
        Reads incoming data from the client into a buffer, parsing and running
        commands from the data.
        """

        ## mypy doesn't seem to know that QByteArray.data() returns a
        ## "bytes" value
        self.__sock_buf += self.client_socket.readAll().data()  # type: ignore

        if not self.qubes_header_parsed:
            if not self.__parse_qubes_data():
                return

        self.__try_parse_commands()

    ## CLIENT-TO-SERVER RPC CALLS
    def __set_client_name(self, client_name: str) -> bool:
        """
        RPC call from client to server. Sets the client's name on the
        server side.

        IMPORTANT: On non-Qubes systems, this data MUST be provided by the
        client itself, while on Qubes OS, this data MUST be provided by the
        qrexec subsystem. NOT provided by the client. If a client never
        sends a client name, the client will never appear in the GUI on
        non-Qubes systems, while if the client always sends a client name,
        the server will forcibly disconnect it under Qubes OS.
        """

        if self.client_name_set:
            ## Client is attempting to change its name after already providing
            ## it once, kick it
            logging.warning(
                "Kicking client '%s' for attempting to change its name to "
                "'%s'",
                self.client_name_or_unknown(),
                client_name,
            )
            self.kick_client()
            return False

        if running_in_qubes_os():
            ## Name rules taken from Qubes OS
            ## (qubes-core-admin/qubes/vm/__init__.py)
            if (
                ## Name must be shorter than 32 characters
                len(client_name) > 31
                ## Name must consist of alphanumeric characters, numbers, underscores,
                ## dots, and hyphens, and the first character must be an alphabetic
                ## character
                or re.match(r"\A[a-zA-Z][a-zA-Z0-9_.-]*\Z", client_name) is None
                ## Name cannot be "Domain-0", "none", or "default"
                or client_name in ("Domain-0", "none", "default")
                ## Name cannot end in "-dm"
                or client_name.endswith("-dm")
            ):
                logging.warning(
                    "Kicking client '%s' for attempting to set invalid name '%s'",
                    self.client_name_or_unknown(),
                    client_name,
                )
                self.kick_client()
                return False
        else:
            ## Less restrictive set of rules for outside of Qubes OS
            ## Name must be shorter than 256 characters
            if len(client_name) > 255:
                logging.warning(
                    "Kicking client '%s' for attempting to set invalid name '%s'",
                    self.client_name_or_unknown(),
                    client_name,
                )
                self.kick_client()
                return False

        ## It's theoretically possible for a client name to be "unsafe"
        ## without being malicious (what if the hostname contains Unicode?),
        ## so fix unsafe names instead of rejecting them.
        safe_name: str = sanitize_for_richtext(
            client_name, MAX_DISPLAY_NAME_LEN
        )

        self.client_name = safe_name
        self.client_name_set = True
        self.clientNameChanged.emit()
        return True

    @staticmethod
    def __octal_decode(octal_match: re.Match[str]) -> str:
        """
        Decodes an octal escape in an sdwdate status string.
        """

        octal_str: str = octal_match.group().strip("\\")
        octal_int: int = int(octal_str, 8)
        if (octal_int < 0x20 or octal_int > 0x7E) and octal_int != 0x0A:
            raise ValueError(f"Unsafe octal escape '{octal_str}'")
        real_char: str = chr(octal_int)
        return real_char

    def __set_sdwdate_status(
        self, sdwdate_status_str: str, sdwdate_msg_str: str
    ) -> bool:
        """
        RPC call from client to server. Updates the sdwdate status shown by
        the server.
        """

        if not self.client_name_set:
            logging.warning(
                "Kicking client '%s' for attempting to set sdwdate status "
                "before setting name",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        match sdwdate_status_str:
            case "success":
                self.sdwdate_status = SdwdateStatus.SUCCESS
            case "busy":
                self.sdwdate_status = SdwdateStatus.BUSY
            case "error":
                self.sdwdate_status = SdwdateStatus.ERROR
            case _:
                logging.warning(
                    "Kicking client '%s' for attempting to set an invalid "
                    "status of '%s'",
                    self.client_name_or_unknown(),
                    sdwdate_status_str,
                )
                self.kick_client()
                return False

        ## Decode octal escapes. We used to do this by getting a set of all
        ## escapes, then iterating through them and replacing each one, but
        ## this could cause non-deterministic behavior and was inefficient.
        ## Now we offload most of the work to Python's regex engine, which
        ## processes everything in a single left-to-right pass.
        decode_re: Pattern[str] = re.compile(r"\\\d{3}")
        try:
            sdwdate_msg_str = decode_re.sub(
                self.__octal_decode, sdwdate_msg_str
            )
        except Exception as e:
            logging.warning(
                "Kicking client '%s' for sending invalid or unsafe octal "
                "escape in sdwdate status message '%s'",
                self.client_name_or_unknown(),
                sdwdate_msg_str,
                exc_info=e,
            )
            self.kick_client()
            return False

        self.sdwdate_msg = sdwdate_msg_str

        self.sdwdateStatusChanged.emit()
        return True

    def __set_tor_status(self, tor_status_str: str) -> bool:
        """
        RPC call from client to server. Updates the sdwdate status shown by
        the server.
        """

        if not self.client_name_set:
            logging.warning(
                "Kicking client '%s' for attempting to set tor status "
                "before setting name",
                self.client_name_or_unknown(),
            )
            self.kick_client()
            return False

        match tor_status_str:
            case "running":
                self.tor_status = TorStatus.RUNNING
            case "stopped":
                self.tor_status = TorStatus.STOPPED
            case "disabled":
                self.tor_status = TorStatus.DISABLED
            case "disabled_running":
                self.tor_status = TorStatus.DISABLED_RUNNING
            case "absent":
                self.tor_status = TorStatus.ABSENT
            case _:
                logging.warning(
                    "Kicking client '%s' for attempting to set an invalid "
                    "Tor status of '%s'",
                    self.client_name_or_unknown(),
                    tor_status_str,
                )
                self.kick_client()
                return False

        self.torStatusChanged.emit()
        return True

    ## SERVER-TO-CLIENT RPC CALLS
    def __generic_rpc_call(self, msg_bytes: bytes) -> None:
        """
        Sends an RPC call from the server to the client, following the wire
        format documented for this object.
        """

        msg_len: int = len(msg_bytes)
        if msg_len > MAX_MSG_SIZE:
            ## We already reject overly large messages on the receiving end,
            ## try to not send them either.
            logging.critical("Server tried to send an oversized IPC message!")
            sys.exit(1)
        msg_buf: bytes = (
            msg_len.to_bytes(2, byteorder="big", signed=False) + msg_bytes
        )
        msg_len += 2
        while msg_len > 0:
            if self.client_socket.state() != QLocalSocket.ConnectedState:
                return
            bytes_written: int = self.client_socket.write(
                msg_buf[len(msg_buf) - msg_len :]
            )
            if bytes_written < 0:
                ## write() returns -1 on error. 0 is a theoretically possible
                ## return value depending on how Qt (both current and future
                ## versions) implements write() internally, so do not bail out
                ## when 0 is returned. This has a chance of causing us to
                ## busy-wait, but that shouldn't happen unless there is a bug
                ## in Qt or PyQt.
                self.kick_client()
                return
            msg_len -= bytes_written

    def open_tor_control_panel(self) -> None:
        """
        RPC call from server to client. Opens Tor control panel on the
        client machine.
        """

        if self.tor_status in (TorStatus.ABSENT, TorStatus.UNKNOWN):
            return

        self.__generic_rpc_call(b"open_tor_control_panel")

    def open_sdwdate_log(self) -> None:
        """
        RPC call from server to client. Opens a terminal displaying the
        sdwdate logs on the client machine.
        """

        self.__generic_rpc_call(b"open_sdwdate_log")

    def restart_sdwdate(self) -> None:
        """
        RPC call from server to client. Restarts sdwdate on the client
        machine.
        """

        self.__generic_rpc_call(b"restart_sdwdate")

    def stop_sdwdate(self) -> None:
        """
        RPC call from server to client. Stops sdwdate on the client machine.
        """

        self.__generic_rpc_call(b"stop_sdwdate")

    def suppress_client_reconnect(self) -> None:
        """
        RPC call from server to client. Suggests to the client that it not
        restart itself after being disconnected from the server. This is
        strictly advisory, the server must NOT depend on the client obeying
        this suggestion.
        """

        self.__generic_rpc_call(b"suppress_client_reconnect")


# pylint: disable=too-few-public-methods
class SdwdateGuiFrame(QDialog):
    """
    A window displaying sdwdate or tor status based on information provided by
    a client.
    """

    def __init__(
        self,
        text: str,
        icon: QIcon,
        parent: QWidget | None = None,
    ) -> None:
        """
        Constructs the window object. You can immediately move the window
        to the desired location and then show it, no further initialization is
        needed.
        """

        QDialog.__init__(self, parent)
        self.setWindowTitle("Time Synchronization Monitor")
        self.setMinimumWidth(200)

        icon_widget: QLabel = QLabel(self)
        icon_widget.setTextFormat(Qt.TextFormat.PlainText)
        icon_widget.setAlignment(Qt.AlignRight)
        icon_widget.setPixmap(icon.pixmap(64, 64))

        text_widget: QLabel = QLabel(self)
        text_widget.setTextFormat(Qt.TextFormat.PlainText)
        text_widget.setTextInteractionFlags(
            Qt.LinksAccessibleByMouse | Qt.TextSelectableByMouse
        )
        text_widget.setAlignment(Qt.AlignTop)
        text_widget.setText(text)

        close_button: QPushButton = QPushButton("Close", self)
        close_button.setMaximumWidth(50)
        close_button.clicked.connect(self.quiet_close)

        frame_content: QGridLayout = QGridLayout(self)
        frame_content.addWidget(icon_widget, 0, 0, 1, 1)
        frame_content.addWidget(text_widget, 0, 1, 1, 2)
        frame_content.addWidget(close_button, 1, 1, 1, 2)

    def quiet_close(self) -> None:
        """
        Close the window and return nothing.
        """

        self.close()


class SdwdateTrayIcon(QSystemTrayIcon):
    """
    The core GUI of sdwdate-gui. Displays a system tray icon with a context
    menu, providing info about sdwdate and Tor status and allowing
    configuring certain aspects of both services on the client side.
    """

    def __init__(
        self,
        parent: QObject | None = None,
        listener: "SdwdateGuiListener | None" = None,
    ):
        """
        Initializes the tray icon.

        If 'listener' is provided, the tray adopts that already-running
        SdwdateGuiListener (its IPC socket is already up) instead of
        creating one. This lets the server bring the listener up promptly
        at startup while deferring tray-icon construction until a system
        tray host appears, without delaying the socket.
        """

        QSystemTrayIcon.__init__(self, parent)

        self.title: str = "Time Synchronization Monitor"

        self.client_list: list[SdwdateGuiClient] = []

        self.clicked_once: bool = False
        self.pos_x: int = 0
        self.pos_y: int = 0
        self.msg_window: SdwdateGuiFrame | None = None
        self.msg_window_client: str | None = None
        self.msg_window_type: MessageType | None = None

        self.icon_path: str = "/usr/share/sdwdate-gui/icons/"
        self.error_icon: QIcon = QIcon(self.icon_path + "error.png")
        self.tor_icon_list: list[QIcon] = [
            QIcon(self.icon_path + "tor-ok.png"),
            self.error_icon,
            self.error_icon,
            QIcon(self.icon_path + "tor-warning.png"),
        ]
        self.sdwdate_icon_list: list[QIcon] = [
            QIcon(self.icon_path + "sdwdate-success.png"),
            QIcon(self.icon_path + "sdwdate-wait.png"),
            QIcon(self.icon_path + "sdwdate-stopped.png"),
        ]
        self.advanced_settings_icon: QIcon = QIcon(
            self.icon_path + "advancedsettings.ico"
        )
        self.sdwdate_log_icon: QIcon = QIcon(self.icon_path + "sdwdate-log.png")
        self.restart_sdwdate_icon: QIcon = QIcon(
            self.icon_path + "restart-sdwdate.png"
        )
        self.stop_sdwdate_icon: QIcon = QIcon(
            self.icon_path + "stop-sdwdate.png"
        )
        self.application_exit_icon: QIcon = QIcon(
            self.icon_path + "application-exit.png"
        )
        self.setIcon(self.sdwdate_icon_list[SdwdateStatus.BUSY.value])
        self.setToolTip("Time Synchronization Monitor \nRight-click for menu.")

        self.menu: QMenu = QMenu()
        self.menu_client_list: list[SdwdateGuiClient] = []
        self.menu_action_list: list[QAction] = []
        self.menu_regen_pending: bool = False
        self.regen_menu()
        self.menu.aboutToShow.connect(self.handle_menu_show)
        self.setContextMenu(self.menu)
        self.activated.connect(self.show_menu)

        if listener is None:
            self.listener: SdwdateGuiListener = SdwdateGuiListener(self)
        else:
            self.listener = listener
            self.listener.setParent(self)
        self.listener.newClient.connect(self.accept_client)

    def show_disconnected_msg(
        self,
        client: SdwdateGuiClient,
    ) -> None:
        """
        Shows a message to the user indicating that the client they are
        attempting to interact with is disconnected.
        """

        if not self.clicked_once:
            self.pos_x = QCursor.pos().x() - 50
            self.pos_y = QCursor.pos().y() - 50
            self.clicked_once = True

        msg_window: SdwdateGuiFrame = SdwdateGuiFrame(
            f"Client '{client.client_name}' is no longer connected.",
            self.error_icon,
        )
        if self.msg_window is not None and self.msg_window.isVisible():
            self.msg_window.close()
        if self.msg_window is not None:
            self.msg_window.deleteLater()

        self.msg_window = msg_window
        self.msg_window_type = MessageType.DISCONNECTED
        self.msg_window_client = client.client_name
        self.msg_window.move(self.pos_x, self.pos_y)
        self.msg_window.show()

    def show_status_msg(
        self,
        message_type: MessageType,
        client: SdwdateGuiClient,
    ) -> None:
        """
        Shows a status window for the specified client, showing either the
        sdwdate or the Tor state depending on the value of `message_type`.
        """

        if not client.client_socket.state() == QLocalSocket.ConnectedState:
            self.show_disconnected_msg(client)
            return

        if not self.clicked_once:
            self.pos_x = QCursor.pos().x() - 50
            self.pos_y = QCursor.pos().y() - 50
            self.clicked_once = True

        msg_window: SdwdateGuiFrame | None

        if message_type == MessageType.SDWDATE:
            if client.sdwdate_msg is None:
                return
            safe_msg: str = sanitize_for_richtext(
                client.sdwdate_msg, MAX_DISPLAY_MSG_LEN
            )
            if running_in_qubes_os():
                msg_window = SdwdateGuiFrame(
                    "Last message from sdwdate on "
                    f"{client.client_name}:\n\n{safe_msg}",
                    self.sdwdate_icon_list[client.sdwdate_status.value],
                )
            else:
                msg_window = SdwdateGuiFrame(
                    f"Last message from sdwdate:\n\n{safe_msg}",
                    self.sdwdate_icon_list[client.sdwdate_status.value],
                )
        else:  # message_type == MessageType.TOR
            msg_text: str
            match client.tor_status:
                case TorStatus.RUNNING:
                    msg_text = "Tor is running."
                case TorStatus.DISABLED:
                    msg_text = """\
Tor is disabled. Therefore you most likely
can not connect to the internet.

Run "Anon Connection Wizard" from the menu."""
                case TorStatus.STOPPED:
                    msg_text = """\
Tor is not running.

You have to fix this error, before you can use Tor.
Please restart Tor after fixing this error.

Start Menu -> System -> Restart Tor GUI
or in Terminal:
sudo service tor@default restart

"""
                case TorStatus.DISABLED_RUNNING:
                    msg_text = """\
Tor is running but is disabled.

A line "DisableNetwork 1" exists in torrc.
Run "Anon Connection Wizard" from the menu
to connect to or configure the Tor network."""
                case _:
                    logging.warning(
                        "'show_status_msg' called with 'message_type' == "
                        "'MessageType.TOR', but Tor status is 'ABSENT' or "
                        "'UNKNOWN'!"
                    )
                    return

            if running_in_qubes_os():
                msg_window = SdwdateGuiFrame(
                    f"Tor status on {client.client_name}:\n\n{msg_text}",
                    self.tor_icon_list[client.tor_status.value],
                )
            else:
                msg_window = SdwdateGuiFrame(
                    f"Tor status:\n\n{msg_text}",
                    self.tor_icon_list[client.tor_status.value],
                )

        if self.msg_window is not None and self.msg_window.isVisible():
            self.msg_window.close()
        if self.msg_window is not None:
            self.msg_window.deleteLater()

        self.msg_window = msg_window
        self.msg_window_type = message_type
        self.msg_window_client = client.client_name
        self.msg_window.move(self.pos_x, self.pos_y)
        self.msg_window.show()

    def run_client_method(
        self, client: SdwdateGuiClient, client_method: Callable[[], None]
    ) -> None:
        """
        Opens the Tor Control Panel for an sdwdate-gui-client instance if the
        client is still connected.
        """

        if not client.client_socket.state() == QLocalSocket.ConnectedState:
            self.show_disconnected_msg(client)
            return
        client_method()

    # pylint: disable=too-many-statements, too-many-branches
    def regen_menu(self, force_regen: bool = False) -> None:
        """
        Regenerates the context menu for the tray icon.
        """

        if self.menu.isVisible() and not force_regen:
            ## Avoid mutating menu actions while the menu popup is on screen.
            ## Queue a refresh to run when the popup opens next.
            self.menu_regen_pending = True
            return

        self.menu_regen_pending = False
        for old_action in self.menu_action_list:
            old_action.deleteLater()
        self.menu_action_list.clear()
        self.menu.clear()
        for old_client in self.menu_client_list:
            old_client.present_in_menu = False
            if not old_client in self.client_list:
                old_client.deleteLater()
        self.menu_client_list.clear()

        clients_shown: int = 0

        for client in self.client_list:
            if client.client_name is None or (
                client.tor_status == TorStatus.UNKNOWN
                and client.sdwdate_status == SdwdateStatus.UNKNOWN
            ):
                ## Client isn't ready yet, skip it
                continue

            effective_sdwdate_status: SdwdateStatus
            if client.sdwdate_status == SdwdateStatus.UNKNOWN:
                effective_sdwdate_status = SdwdateStatus.BUSY
            else:
                effective_sdwdate_status = client.sdwdate_status

            ## Client icon is the client's sdwdate status icon, unless the
            ## client is Tor-enabled and Tor is stopped or disabled.
            ##
            ## client.tor_status will be TorStatus.ABSENT if the client is not
            ## Tor-enabled, so we don't have to explicitly check if the client
            ## is Tor-enabled or not.
            client_icon: QIcon
            if client.tor_status in (TorStatus.STOPPED, TorStatus.DISABLED):
                client_icon = self.tor_icon_list[client.tor_status.value]
            else:
                client_icon = self.sdwdate_icon_list[
                    effective_sdwdate_status.value
                ]

            ## Each client gets its own submenu, unless there's only one
            ## client.
            if len(self.client_list) > 1:
                action_menu: QMenu | None = self.menu.addMenu(
                    client_icon,
                    client.client_name,
                )
            else:
                action_menu = self.menu
            assert action_menu is not None

            ## Tor-enabled clients get two extra menu items, one for Tor
            ## status,and one to open the Tor control panel.
            if client.tor_status != TorStatus.ABSENT:
                ## ACTION: Tor status
                target_tor_status: TorStatus
                if client.tor_status in (TorStatus.ABSENT, TorStatus.UNKNOWN):
                    target_tor_status = TorStatus.STOPPED
                else:
                    target_tor_status = client.tor_status
                action: QAction = QAction(
                    self.tor_icon_list[target_tor_status.value],
                    "Show Tor status",
                    action_menu,
                )
                action.triggered.connect(
                    functools.partial(
                        self.show_status_msg, MessageType.TOR, client
                    )
                )
                action_menu.addAction(action)
                self.menu_action_list.append(action)

                ## ACTION: Tor control panel
                action = QAction(
                    self.advanced_settings_icon,
                    "Tor control panel",
                    action_menu,
                )
                action.triggered.connect(
                    functools.partial(
                        self.run_client_method,
                        client,
                        client.open_tor_control_panel,
                    )
                )
                action_menu.addAction(action)
                self.menu_action_list.append(action)
                action_menu.addSeparator()

            ## ACTION: Sdwdate status
            action = QAction(
                self.sdwdate_icon_list[effective_sdwdate_status.value],
                "Show sdwdate status",
                action_menu,
            )
            action.triggered.connect(
                functools.partial(
                    self.show_status_msg,
                    MessageType.SDWDATE,
                    client,
                )
            )
            action_menu.addAction(action)
            self.menu_action_list.append(action)
            action_menu.addSeparator()

            ## ACTION: Show sdwdate log
            action = QAction(
                self.sdwdate_log_icon,
                "Open sdwdate's log",
                action_menu,
            )
            action.triggered.connect(
                functools.partial(
                    self.run_client_method, client, client.open_sdwdate_log
                )
            )
            action_menu.addAction(action)
            self.menu_action_list.append(action)

            ## ACTION: Sdwdate restart
            action = QAction(
                self.restart_sdwdate_icon,
                "Restart sdwdate",
                action_menu,
            )
            action.triggered.connect(
                functools.partial(
                    self.run_client_method, client, client.restart_sdwdate
                )
            )
            action_menu.addAction(action)
            self.menu_action_list.append(action)

            ## ACTION: Sdwdate stop
            action = QAction(
                self.stop_sdwdate_icon,
                "Stop sdwdate",
                action_menu,
            )
            action.triggered.connect(
                functools.partial(
                    self.run_client_method, client, client.stop_sdwdate
                )
            )
            action_menu.addAction(action)
            self.menu_action_list.append(action)

            ## Prevent the client from being deleted if we still have a menu
            ## entry for it, while still ensuring we free it once safe
            client.present_in_menu = True
            self.menu_client_list.append(client)

            clients_shown += 1

        if clients_shown == 0:
            no_clients_action: QAction = QAction(
                "Waiting for sdwdate-gui client...",
                self.menu,
            )
            no_clients_action.setEnabled(False)
            self.menu.addAction(no_clients_action)
            self.menu_action_list.append(no_clients_action)
        self.menu.addSeparator()

        ## Add a button to quit the sdwdate GUI server underneath all the
        ## client entries
        action = QAction(
            self.application_exit_icon,
            "&Exit",
            self.menu,
        )
        action.triggered.connect(sys.exit)
        self.menu.addAction(action)
        self.menu_action_list.append(action)

    def handle_menu_show(self) -> None:
        """
        Runs a deferred menu regeneration when the popup is being opened,
        if necessary.
        """

        if self.menu_regen_pending:
            self.regen_menu(force_regen=True)

    def set_tray_icon(self) -> None:
        """
        Sets the system tray icon for the applet based on the status of
        connected clients.
        """

        sdwdate_status_index: int = -1
        tor_status_index: int = -1

        for client in self.client_list:
            if (
                client.sdwdate_status != SdwdateStatus.UNKNOWN
                and client.sdwdate_status.value > sdwdate_status_index
            ):
                sdwdate_status_index = client.sdwdate_status.value

            if (
                client.tor_status != TorStatus.ABSENT
                and client.tor_status != TorStatus.UNKNOWN
                and client.tor_status.value > tor_status_index
            ):
                tor_status_index = client.tor_status.value

        if tor_status_index in (
            TorStatus.STOPPED.value,
            TorStatus.DISABLED.value,
        ):
            self.setIcon(self.tor_icon_list[tor_status_index])
        elif sdwdate_status_index > -1:
            self.setIcon(self.sdwdate_icon_list[sdwdate_status_index])

        ## Continue without setting a new icon if both of these checks flunk.

    def show_menu(self, event: QSystemTrayIcon.ActivationReason) -> None:
        """
        Opens the menu on either a left-click (Trigger) or a right-click
        (Context) of the tray icon. This is skipped under Wayland, as Wayland
        does not allow us to position the popup and would display it in the
        middle of the screen instead of near the tray icon.
        """

        if QApplication.platformName() == "wayland":
            return
        if event in (
            QSystemTrayIcon.ActivationReason.Trigger,
            QSystemTrayIcon.ActivationReason.Context,
        ):
            self.menu.popup(QCursor.pos())

    def handle_client_name_change(
        self,
        sender_client: SdwdateGuiClient,
    ) -> None:
        """
        Updates the client's name. This can only be done once, if a client
        tries to update its name to the name of an existing client it will be
        kicked.
        """

        duplicate_clients: list[SdwdateGuiClient] = [
            client
            for client in self.client_list
            if client is not sender_client
            and client.client_name == sender_client.client_name
        ]
        if len(duplicate_clients) != 0:
            if running_in_qubes_os():
                ## The same VM reconnected before the server noticed the
                ## previous connection had dropped. Keep the new connection
                ## and discard the stale duplicate(s).
                for old_client in duplicate_clients:
                    old_client.kick_client()
            else:
                ## On non-Qubes systems the name is self-reported, so treat a
                ## duplicate name as an impersonation attempt and kick the
                ## newcomer.
                logging.warning(
                    "Kicking client '%s' for attempting to set a name "
                    "'%s' identical to another client's name",
                    sender_client.client_name_or_unknown(),
                    sender_client.client_name,
                )
                sender_client.kick_client()
                return

        self.regen_menu()

    def handle_state_change(
        self,
        message_type: MessageType,
        message_client: SdwdateGuiClient,
    ) -> None:
        """
        Handles sdwdate and Tor state changes in any running client.
        """

        if self.msg_window is not None and self.msg_window.isVisible():
            if (
                message_type == self.msg_window_type
                and message_client.client_name == self.msg_window_client
            ):
                self.show_status_msg(message_type, message_client)

        self.regen_menu()
        self.set_tray_icon()

    def drop_client(self, sender_client: SdwdateGuiClient) -> None:
        """
        Purges a disconnected client from the client list.
        """

        if not sender_client.present_in_menu:
            sender_client.deleteLater()

        for idx, client in enumerate(self.client_list):
            if client == sender_client:
                self.client_list.pop(idx)
                self.regen_menu()
                self.set_tray_icon()
                return

        logging.warning("Dropped client not present in client list!")

    def accept_client(self, client: SdwdateGuiClient) -> None:
        """
        Adds a new client to the client list.
        """

        if len(self.client_list) >= MAX_CLIENTS:
            logging.warning(
                "Rejecting new client; already at the %d client limit",
                MAX_CLIENTS,
            )
            client.kick_client()
            client.deleteLater()
            return

        self.client_list.append(client)
        client.clientNameChanged.connect(
            functools.partial(
                self.handle_client_name_change,
                client,
            )
        )
        client.sdwdateStatusChanged.connect(
            functools.partial(
                self.handle_state_change,
                message_type=MessageType.SDWDATE,
                message_client=client,
            )
        )
        client.torStatusChanged.connect(
            functools.partial(
                self.handle_state_change,
                message_type=MessageType.TOR,
                message_client=client,
            )
        )
        client.clientDisconnected.connect(
            functools.partial(
                self.drop_client,
                client,
            )
        )


class SdwdateGuiListener(QObject):
    """
    Listens for new client connections and creates SdwdateGuiClient objects
    for them.
    """

    newClient: pyqtSignal = pyqtSignal(SdwdateGuiClient)

    # pylint: disable=too-many-statements
    def __init__(self, parent: QObject | None = None) -> None:
        """
        Initializes a listening socket.
        """

        QObject.__init__(self, parent)

        uid_str: str = str(os.getuid())
        sdwdate_run_dir: Path = Path(f"/run/user/{uid_str}/sdwdate-gui")
        sdwdate_pid_file = sdwdate_run_dir.joinpath("server_pid")
        sdwdate_socket_file = sdwdate_run_dir.joinpath(
            "sdwdate-gui-server.socket"
        )
        try:
            sdwdate_run_dir.mkdir(
                parents=True,
                exist_ok=True,
            )
        except Exception:
            logging.critical(
                "Could not create '%s' directory!'!",
                str(sdwdate_run_dir),
            )
            sys.exit(1)

        ## This PID file mechanism is prone to race conditions. If we were
        ## trying to be highly robust, we'd want to use advisory locking via
        ## os.lockf rather than a PID file. That would probably be overkill
        ## for this applet though, as the OS will only ever try to start once
        ## instance of the server per logged-in user account, unless the
        ## end-user is intentionally trying to run multiple server instances.
        if sdwdate_pid_file.is_file():
            try:
                with open(sdwdate_pid_file, "r", encoding="utf-8") as f:
                    sdwdate_pid_str: str = f.readline().strip()
                pid_verify_re: Pattern[str] = re.compile("^[0-9]+$")
                if not pid_verify_re.match(sdwdate_pid_str):
                    logging.error(
                        "PID marker file contains non-numeric characters!",
                    )
                    sys.exit(1)
                if Path(f"/proc/{sdwdate_pid_str}").is_dir():
                    logging.error(
                        "sdwdate_gui_server is already running!",
                    )
                    sys.exit(1)
            except Exception as e:
                logging.error(
                    "Could not check for running sdwdate_gui_server!",
                    exc_info=e,
                )
                sys.exit(1)

        try:
            os.remove(sdwdate_pid_file)
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(
                "Could not erase old PID file!",
                exc_info=e,
            )
            sys.exit(1)

        try:
            with open(sdwdate_pid_file, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except Exception as e:
            logging.error(
                "Could not save PID to PID file!",
                exc_info=e,
            )
            sys.exit(1)

        try:
            os.remove(sdwdate_socket_file)
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.error(
                "Could not erase old server socket!",
                exc_info=e,
            )
            sys.exit(1)

        self.server: QLocalServer = QLocalServer(self)
        ## Restrict the IPC socket to the owning user rather than relying
        ## solely on the 0700 mode of the parent /run/user/UID directory.
        self.server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        self.server.listen(str(sdwdate_socket_file))
        self.server.newConnection.connect(self.spawn_client)

    def spawn_client(self) -> None:
        """
        Creates a new client and provides the new client to a listening
        object via a signal.
        """

        new_socket: QLocalSocket | None = self.server.nextPendingConnection()
        assert new_socket is not None
        client: SdwdateGuiClient = SdwdateGuiClient(new_socket, self)
        self.newClient.emit(client)


# pylint: disable=unused-argument
def signal_handler(sig: int, frame: FrameType | None) -> None:
    """
    Handles SIGINT and SIGTERM.
    """

    logging.info("Received SIGINT or SIGTERM, exiting.")
    sys.exit(128 + sig)


def install_tray_when_available(app: QApplication) -> QTimer:
    """
    Bring the IPC listener up now, but defer the tray icon until a system
    tray host is available.

    QSystemTrayIcon selects its backend (legacy XEmbed vs. the
    StatusNotifier / SNI D-Bus protocol) when it is constructed. If
    sdwdate-gui-server is constructed before the panel's
    StatusNotifierWatcher has registered on the session bus -- a startup
    race, e.g. in the user-sysmaint-split sysmaint session, where the tray
    host and sdwdate-gui are launched together -- Qt falls back to XEmbed,
    and an SNI-only panel (lxqt-panel, waybar) never shows the icon.
    Re-showing, or calling show() again after the host appears, does not
    recover it; only deferring construction does.

    The listener (and thus the server's IPC socket) must NOT be deferred:
    on Qubes the gateway's sdwdate-gui-qubes-proxy-helper waits only a
    bounded time for the socket before giving up, so a late or absent tray
    host must not delay it. So the listener is created immediately; clients
    that connect before the tray exists are buffered and replayed once it
    is constructed (a client completes its handshake over its own socket
    regardless, so buffering only delays its menu entry, not the protocol).

    The poll timer is parented to 'app' so it (and the tray icon kept alive
    through its callback) outlives this function; the timer is also returned
    for callers, such as the test suite, that want a direct reference.
    """

    ## Eager: the IPC socket and PID file come up now, independent of any
    ## tray host (see the Qubes proxy-helper note above).
    listener: SdwdateGuiListener = SdwdateGuiListener()
    ## Clients arriving before the tray exists are held here, then replayed.
    pending_clients: list[SdwdateGuiClient] = []
    listener.newClient.connect(pending_clients.append)

    ## A list, rather than a plain variable, so the nested callback can
    ## record the constructed tray icon without a 'nonlocal' rebind.
    tray_holder: list[SdwdateTrayIcon] = []
    poll_timer: QTimer = QTimer(app)

    def attempt() -> None:
        if tray_holder:
            return
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        ## Construct first: if this raises, nothing else has changed, so
        ## the next tick retries cleanly (clients stay buffered, timer
        ## stays running).
        tray: SdwdateTrayIcon = SdwdateTrayIcon(listener=listener)
        ## Commit before the one-time, non-idempotent buffer handoff:
        ## recording the tray and stopping the timer guarantee attempt()
        ## never runs its body twice, so the disconnect() below can never
        ## fire on an already-disconnected signal.
        tray_holder.append(tray)
        poll_timer.stop()
        ## Stop buffering and replay whatever arrived before the tray
        ## existed. No event loop runs between construction and here, so no
        ## client is missed or handled twice.
        listener.newClient.disconnect(pending_clients.append)
        for client in pending_clients:
            tray.accept_client(client)
        pending_clients.clear()
        tray.show()

    poll_timer.timeout.connect(attempt)
    poll_timer.start(500)
    ## Try immediately; the common case is a tray host already present.
    attempt()
    return poll_timer


def main() -> NoReturn:
    """
    Main function.
    """

    if os.geteuid() == 0:
        print("ERROR: Do not run with sudo / as root!")
        sys.exit(1)

    if Path("/run/qubes/this-is-templatevm").is_file():
        print("INFO: Refusing to run in a QubesOS TemplateVM.")
        sys.exit(0)

    logging.basicConfig(
        format="%(funcName)s: %(levelname)s: %(message)s", level=logging.INFO
    )

    app: QApplication = QApplication(["Sdwdate"])
    app.setQuitOnLastWindowClosed(False)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        parse_config_files()
    except Exception as e:
        logging.error("Configuration file parsing failed!", exc_info=e)
        sys.exit(1)
    assert isinstance(ConfigData.conf_dict["disable"], bool)
    assert isinstance(ConfigData.conf_dict["run_server_in_qubes"], bool)
    if ConfigData.conf_dict["disable"]:
        logging.info(
            "'disable' configuration key set to 'True', therefore exiting."
        )
        sys.exit(0)
    if running_in_qubes_os():
        if not ConfigData.conf_dict["run_server_in_qubes"]:
            logging.info(
                "Running in Qubes OS, but 'run_server_in_qubes' config is "
                "set to 'False', therefore exiting."
            )
            sys.exit(0)

    timer: QTimer = QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    install_tray_when_available(app)
    app.exec_()
    sys.exit(0)
