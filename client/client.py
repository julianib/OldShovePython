import sys
import os
import socket
import ctypes
import base64
import json
import time
import copy
import logging

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from shove_ui import Ui_MainWindow

# python -m PyQt5.uic.pyuic shove.ui -o shove_ui.py
CARDS = [
    "2c",
    "2d",
    "2h",
    "2s",
    "3c",
    "3d",
    "3h",
    "3s",
    "4c",
    "4d",
    "4h",
    "4s",
    "5c",
    "5d",
    "5h",
    "5s",
    "6c",
    "6d",
    "6h",
    "6s",
    "7c",
    "7d",
    "7h",
    "7s",
    "8c",
    "8d",
    "8h",
    "8s",
    "9c",
    "9d",
    "9h",
    "9s",
    "Ac",
    "Ad",
    "Ah",
    "As",
    # "Jb",
    "Jc",
    "Jd",
    "Jh",
    # "Jr",
    "Js",
    "Kc",
    "Kd",
    "Kh",
    "Ks",
    # "Mc",
    # "Md",
    # "Mh",
    # "Ms",
    "Qc",
    "Qd",
    "Qh",
    "Qs",
    "Tc",
    "Td",
    "Th",
    "Ts",
    # "__",
    # "_c",
    # "_d",
    # "_h",
    # "_s",
    "back",
]
CODE_ERROR = {
    "client_content_type_invalid": "Invalid content type sent",
    "client_processing_error": "Client processing error",
    "client_metadata_invalid": "Invalid metadata sent",
    "client_packet_invalid": "Invalid packet sent",
    "client_packet_maximum_size": f"Sent packet exceeds maximum size",
    ConnectionRefusedError: "Server is offline",
    ConnectionResetError: "Lost connection to server",
    "credentials_incorrect": "Invalid log-in credentials",
    "email_invalid": "E-mail must be 1-100 characters and must contain @",
    "email_taken": "E-mail is taken",
    "deck_invalid": "Uploaded deck is invalid",
    "game_running": "Can't join an ongoing game",
    "packet_creation_error": "Packet created with no content or header",
    "path_select_filter_invalid": "Path select filter invalid",
    "password_invalid": "Password must be 1-100 characters",
    "password_repeat_doesnt_match": "Passwords don't match",
    "room_already_connected": "Already connected to a room",
    # "room_description_invalid": "Room description must be max 100 characters",
    "room_full": "Room is full",
    "room_name_invalid": "Room name must be 1-16 characters and alphanumeric",
    "room_name_taken": "Room name is taken",
    "room_not_connected": "Not connected to a room",
    "room_not_found": "Room not found",
    "room_password_incorrect": "Room password is incorrect",
    "server_content_type_invalid": "Invalid content type received",
    "server_metadata_invalid": "Invalid metadata received",
    "server_packet_header_invalid": "Received packet has invalid header",
    # "server_packet_no_content": "Server packet contents are empty",
    "server_packet_maximum_size": "Received packet exceeds maximum size",
    # "server_packet_no_bytes": "Expected content bytes but did not get any",
    "server_processing_error": "Server processing error",
    "session_token_incorrect": "Incorrect session token - log-in (again)",
    "unknown": "what the FUCK went wrong THIS time",
    "upload_file_type_invalid": "Unknown upload file type",
    "username_invalid": "Username must be 1-16 characters and alphanumeric",
    "username_not_found": "User not found",
    "username_not_given": "No username was given",
    "username_taken": "Username is taken"
}

FILE_DIR = os.path.dirname(__file__)
LOGGING_DIR = f"{FILE_DIR}/logs"
LATEST_LOG_FILENAME = ".client_latest.txt"
LATEST_LOG_PATH = f"{LOGGING_DIR}/{LATEST_LOG_FILENAME}"
LOGGING_FILE_TIME_FORMAT = "%d%m%yT%H%M%S"
LOGGING_TIME_FORMAT = "%X"
LOGGING_FORMAT = "[%(asctime)s] [%(levelname)s %(lineno)s] %(message)s"
ASSETS_DIR = f"{FILE_DIR}/assets"
WARNING_FILENAME = "WARNING - FILES HERE WILL BE REMOVED"
WARNING_PATH = f"{ASSETS_DIR}/{WARNING_FILENAME}"
UI_VERSION_FILENAME = "ui_version.txt"
UI_VERSION_PATH = f"{ASSETS_DIR}/{UI_VERSION_FILENAME}"
QUIT_APPLICATION = False


# setup logging/files

if not os.path.exists(LOGGING_DIR):
    os.mkdir(LOGGING_DIR)

if os.path.exists(LATEST_LOG_PATH):  # simplify
    with open(LATEST_LOG_PATH, "r") as _f:
        time_str = _f.readline().strip()

    try:
        os.rename(LATEST_LOG_PATH, f"{LOGGING_DIR}/{time_str}.txt")

    except PermissionError:
        print("NO ACCESS TO LOGGING FILE - CLIENT ALREADY RUNNING?")

    else:
        with open(LATEST_LOG_PATH, "w") as _f:
            _f.write(time.strftime(LOGGING_FILE_TIME_FORMAT) + "\n\n")

        logging.basicConfig(filename=LATEST_LOG_PATH, format=LOGGING_FORMAT, datefmt=LOGGING_TIME_FORMAT)

else:
    logging.basicConfig(filename=LATEST_LOG_PATH, format=LOGGING_FORMAT, datefmt=LOGGING_TIME_FORMAT)


log = logging.getLogger()
log.setLevel(logging.DEBUG)

_stream_handler_console = logging.StreamHandler(sys.stdout)
_stream_handler_console.setLevel(logging.DEBUG)
_formatter = logging.Formatter(LOGGING_FORMAT)
_formatter.datefmt = LOGGING_TIME_FORMAT
_stream_handler_console.setFormatter(_formatter)

log.addHandler(_stream_handler_console)
log.info("Logging ready")

if not os.path.exists(ASSETS_DIR):
    os.mkdir(ASSETS_DIR)
    log.debug("Assets dir created")

if not os.path.exists(WARNING_PATH):
    with open(WARNING_PATH, "w"):
        pass
    log.debug("Assets warning file created")

if not os.path.exists(UI_VERSION_PATH):
    with open(UI_VERSION_PATH, "w") as _f:
        _f.write("UPDATE")
    log.debug(f"{UI_VERSION_FILENAME} created (\"UPDATE\")")

with open(UI_VERSION_PATH, "r") as _f:
    UI_VERSION_STR = _f.readline()

log.info(f"UI version: {UI_VERSION_STR}")


# b64str

def b64str_to_bytes(b64str) -> bytes or None:
    if not b64str:
        log.critical("b64str is air")
        return

    return base64.b64decode(b64str.encode())


def b64str_to_pixmap(b64str) -> QPixmap or None:
    if not b64str:
        log.critical("b64str is air")
        return

    return bytes_to_pixmap(b64str_to_bytes(b64str))


def bytes_to_b64str(file_bytes) -> str:
    return base64.b64encode(file_bytes).decode()


def bytes_to_pixmap(file_bytes) -> QPixmap or None:
    if not file_bytes:
        log.critical("file_bytes is air")
        return

    pixmap = QPixmap()
    pixmap.loadFromData(file_bytes)

    return pixmap


def select_path_dialog(select_filter) -> os.PathLike:
    options = QFileDialog.Options()
    caption = f"Choose {select_filter}..."

    if select_filter == "image":
        # options |= QFileDialog.DontConfirmOverwrite
        path, _filter = QFileDialog().getOpenFileName(
            None,
            caption,
            filter="Images (*.png *.jpg)",
            options=options
        )

        return path

    elif select_filter == "directory":
        options |= QFileDialog.ShowDirsOnly
        path = QFileDialog().getExistingDirectory(
            None,
            caption,
            options=options
        )

        return path

    else:
        raise Error("path_select_filter_invalid")


def get_b64str_object(file_type, path):
    if file_type == "deck":
        deck_b64str = {}
        for card in CARDS:
            with open(f"{path}/{card}.png", "rb") as f:
                b64str = bytes_to_b64str(f.read())

            deck_b64str[card] = b64str

        return deck_b64str

    elif file_type in ["avatar", "background", "table"]:
        with open(path, "rb") as f:
            b64str = bytes_to_b64str(f.read())

        return b64str

    else:
        raise Error("upload_file_type_invalid")


# errors & dialogs

class Error(BaseException):
    def __init__(self, code):
        self.__str__ = code


def error_dialog(exc_info_or_code):
    dialog = QMessageBox()
    dialog.setWindowTitle("Error!")
    dialog.setIcon(QMessageBox.Critical)

    object_type = type(exc_info_or_code)
    if object_type == str:  # code
        try:
            error = CODE_ERROR[exc_info_or_code]

        except KeyError:
            error = CODE_ERROR["unknown"] + f" ({exc_info_or_code})"

    elif object_type == tuple:  # exc_info
        exc_type, value, _ = exc_info_or_code

        try:
            error = CODE_ERROR[str(value)]

        except KeyError:
            try:
                error = CODE_ERROR[exc_type]

            except KeyError:
                error = CODE_ERROR["unknown"] + f" ({exc_type.__name__}: {value})"

    else:
        log.critical(f"Unknown type for error dialog: {object_type}")
        return

    dialog.setText(error)
    log.debug(f"Showing error dialog ({error})")
    dialog.exec_()


def dropped_connection_dialog(exc_info_or_code):
    dialog = QMessageBox()
    dialog.setWindowTitle("Connection lost!")
    dialog.setIcon(QMessageBox.Critical)
    reconnect_button = dialog.addButton("Reconnect", QMessageBox.YesRole)
    dialog.addButton("Quit", QMessageBox.NoRole)

    object_type = type(exc_info_or_code)
    if object_type == str:  # code
        try:
            error = CODE_ERROR[exc_info_or_code]

        except KeyError:
            error = CODE_ERROR["unknown"] + f" ({exc_info_or_code})"

    elif object_type == tuple:  # exc_info
        exc_type, value, _ = exc_info_or_code

        try:
            error = CODE_ERROR[str(value)]

        except KeyError:
            try:
                error = CODE_ERROR[exc_type]

            except KeyError:
                error = CODE_ERROR["unknown"] + f" ({exc_type.__name__}: {value})"

    else:
        log.critical(f"Unknown type for dropped connection dialog: {object_type}")
        return

    dialog.setText(error)
    log.debug(f"Showing dropped connection dialog ({error})")
    dialog.exec_()

    if dialog.clickedButton() == reconnect_button:
        log.debug("Reconnect was clicked")
        global QUIT_APPLICATION
        QUIT_APPLICATION = False

    else:
        log.debug("Reconnect was not clicked")


# classes

class Packet:
    header_part_size = 8
    header_size = header_part_size * 2
    packet_size_max = 10485760

    def __init__(self, content=None, header_bytes=None):
        # log.debug("Packet initializing")
        if content:  # send packet
            self.id = 0
            self.content = content
            content_str = json.dumps(self.content)
            self.size = len(content_str)
            self.header_size_zfill = str(self.size).zfill(Packet.header_part_size)
            self.header_id_zfill = str(self.id).zfill(Packet.header_part_size)
            self.header = self.header_size_zfill + self.header_id_zfill
            self.encoded = self.header.encode() + content_str.encode()

        elif header_bytes:  # receive packet
            self.header = header_bytes.decode()
            self.header_size_zfill = self.header[:Packet.header_part_size]
            self.header_id_zfill = self.header[Packet.header_part_size:]

            try:
                self.size, self.id = int(self.header_size_zfill),\
                                     int(self.header_id_zfill)

            except ValueError as ex:
                raise Error("server_packet_header_invalid") from ex

            if self.size > Packet.packet_size_max:
                raise Error("server_packet_maximum_size")

            self.bytes = b""
            self.bytes_left = 0
            self.update_bytes(bytes_expected=False)

        else:
            raise Error("packet_creation_error")

    def __str__(self):
        return str(self.id)

    def get_formatted(self):
        content = copy.deepcopy(self.content)
        for key, value in content.items():
            if type(value) == list:
                dicts_in_list = [d for d in content[key] if type(d) == dict]
                for i, dict_in_list in enumerate(dicts_in_list):
                    for key2, value2 in dict_in_list.items():
                        for filter_keyword in ["b64str"]:
                            if filter_keyword in key2:
                                content[key][i][key2] = "<filtered>"

            for filter_keyword in ["b64str"]:
                if filter_keyword in key:
                    content[key] = "<filtered>"

        return f"{self.header_size_zfill}|{self.header_id_zfill} {str(content)}"

    def update_bytes(self, add_bytes=None, bytes_expected=True):
        if add_bytes:
            self.bytes += add_bytes

        elif bytes_expected and not self.bytes:
            raise Error("server_packet_no_bytes")  # otherwise finished receiving

        # log.debug(f"P/{self} Total bytes: {len(self.bytes)}/{self.size}")
        self.bytes_left = self.size - len(self.bytes)

    def decon(self):
        # log.debug(f"P/{self} Deconning...")
        content_str = self.bytes.decode()
        content = json.loads(content_str)
        self.content = content
        # log.debug(f"P/{self} Deconned")


class NeThread(QThread):
    connecting = pyqtSignal()
    exception = pyqtSignal(tuple, bool, bool)
    connected = pyqtSignal()
    packet_complete = pyqtSignal(Packet)

    def __init__(self, ui):
        QThread.__init__(self)
        log.debug("NeThread initializing...")
        self.ui = ui
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.hostname = ui.hostname
        self.host_port = ui.host_port
        self.connecting.connect(self.ui.on_connecting)
        self.connected.connect(self.ui.on_connected)
        self.exception.connect(self.ui.exception)
        self.packet_complete.connect(self.ui.on_packet_complete)
        log.debug("NeThread initialized, starting...")
        self.start()

    def __del__(self):
        self.wait()

    def stop(self):
        self.terminate()
        if self.socket is not None:
            self.socket.close()
            self.socket = None

        log.debug("NeThread stopped")

    def run(self):
        log.debug("NeThread started")
        self.connecting.emit()

        try:  # connect
            self.socket.connect((self.hostname, self.host_port))

        except BaseException as ex:
            if type(ex) == ConnectionRefusedError:
                self.exception.emit(sys.exc_info(), False, True)

            else:
                self.exception.emit(sys.exc_info(), True, True)

        else:
            self.connected.emit()
            log.debug("NeThread receive loop started")

            while True:  # receive loop
                if self.socket is None:
                    log.warning("Inconsistency in receive loop: loop didn't break, returning")
                    return

                try:
                    header_bytes = self.socket.recv(Packet.header_size)

                except BaseException as ex:
                    if type(ex) == ConnectionResetError:
                        self.exception.emit(sys.exc_info(), False, True)

                    else:
                        self.exception.emit(sys.exc_info(), True, True)

                    return

                try:
                    packet = Packet(header_bytes=header_bytes)

                    while packet.bytes_left:
                        packet.update_bytes(self.socket.recv(packet.bytes_left))

                    packet.decon()

                except BaseException as ex:
                    if type(ex) in [Error, json.JSONDecodeError]:
                        self.exception.emit(sys.exc_info(), False, False)

                    else:
                        self.exception.emit(sys.exc_info(), True, False)

                    continue

                # log.debug("NeThread emitting completed packet...")
                self.packet_complete.emit(packet)

        # self.stop() ?


class Shove(Ui_MainWindow):
    hostname = "localhost"
    host_port = 2000

    checked_update_since_startup = False

    username = None
    session_token = None

    room_name = None
    room_country = None
    room_description = None
    username_avatar = {}
    username_deck = {}
    username_seat = {}
    username_game_status = {}
    username_profile_status = {}
    username_slot_card = {}
    community_slot_card = {}

    lookup_rooms_page = 1
    lookup_rooms_reversed = False
    lookup_users_page = 1

    chat_toggle_global = False

    def __init__(self):
        log.debug("Shove initializing...")
        self.nethr = None
        app = QApplication(sys.argv)
        self.connect()
        self.MainWindow = QMainWindow(flags=Qt.WindowFlags())
        self.setupUi(self.MainWindow)
        log.debug("Starting app main loop...")
        app.exec_()

    def __init_post_update(self):
        log.info("Update check complete")
        # log.debug("Starting init post update")
        self.protected_icon = QIcon(f"{ASSETS_DIR}/protected.png")
        self.window_icon = QIcon(f"{ASSETS_DIR}/window_icon.png")
        self.dealer_button_pixmap = QPixmap(f"{ASSETS_DIR}/dealer_button.png")
        self.hostname = self.leConnectHostname.text()
        self.host_port = int(self.sbConnectHostPort.value())

        self.red_button_css = "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, " \
                              "stop:0 rgba(180, 0, 0, 210), stop:1 rgba(255, 255, 255, 255))"
        self.green_button_css = "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, " \
                                "stop:0 rgba(0, 255, 0, 210), stop:1 rgba(255, 255, 255, 255))"
        self.red_label_css = "color: rgb(170, 0, 0)"
        self.green_label_css = "color: rgb(0, 170, 0)"
        self.official_brush = QBrush(QColor(0, 255, 255, 64))
        self.not_full_brush = QBrush(QColor(0, 255, 0, 64))
        self.full_brush = QBrush(QColor(255, 0, 0, 64))
        self.official_brush.setStyle(Qt.SolidPattern)
        self.full_brush.setStyle(Qt.SolidPattern)
        self.not_full_brush.setStyle(Qt.SolidPattern)

        self.leChatInput.returnPressed.connect(self.btnSendMessage.click)
        self.leLoginName.returnPressed.connect(self.btnLogIn.click)
        self.leLoginPassword.returnPressed.connect(self.btnLogIn.click)
        self.leJoinRoomName.returnPressed.connect(self.btnJoinRoom.click)
        self.leJoinRoomPassword.returnPressed.connect(self.btnJoinRoom.click)
        self.leRegisterEmail.returnPressed.connect(self.btnRegister.click)
        self.leRegisterName.returnPressed.connect(self.btnRegister.click)
        self.leRegisterPassword.returnPressed.connect(self.btnRegister.click)
        self.leRegisterRepeatPassword.returnPressed.connect(self.btnRegister.click)
        self.leSearchRoom.returnPressed.connect(self.btnRefreshRooms.click)
        self.leUserLookup.returnPressed.connect(self.btnUserLookup.click)

        self.btnConnect.clicked.connect(self.ui_connect)
        self.btnDisconnect.clicked.connect(self.ui_disconnect)
        self.btnNextRooms.clicked.connect(self.ui_next_rooms_page)
        self.btnNextUsersPage.clicked.connect(self.ui_next_users_page)
        self.btnPrevRooms.clicked.connect(self.ui_prev_rooms_page)
        self.btnNextUsersPage.clicked.connect(self.ui_prev_users_page)
        self.btnSendMessage.clicked.connect(self.ui_send_message)
        self.btnToggleRoomSorting.clicked.connect(self.ui_toggle_room_sorting)
        self.btnUploadAvatarFile.clicked.connect(self.ui_upload_avatar)
        self.btnUploadBackgroundFile.clicked.connect(self.ui_upload_background)
        self.btnUploadDeckDirectory.clicked.connect(self.ui_upload_deck)
        self.btnUploadTableFile.clicked.connect(self.ui_upload_table)
        self.lwUserLookup.itemSelectionChanged.connect(self.ui_lwi_users_selection_changed)
        self.twRooms.itemClicked.connect(self.ui_twi_room_clicked)
        self.twRooms.itemDoubleClicked.connect(self.ui_twi_room_double_clicked)
        self.btnCreateRoom.clicked.connect(self.ui_create_room)
        self.btnJoinRoom.clicked.connect(self.ui_join_room)
        self.btnLeaveRoom.clicked.connect(self.ui_leave_room)
        self.btnLogIn.clicked.connect(self.ui_log_in)
        self.btnRefreshRooms.clicked.connect(self.ui_lookup_rooms)
        self.btnRegister.clicked.connect(self.ui_register)
        self.btnUserLookup.clicked.connect(self.ui_lookup_users)

        self.tabwMain.setCurrentIndex(3)  # game 0, rooms 1, community 2, log in 3, settings 4
        self.tabwSettings.setCurrentIndex(1)  # general 0, account 1, chat 2, audio 3, game 4, room 5
        self.MainWindow.setWindowIcon(self.window_icon)
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("")  # set icon in taskbar
        self.lwChat.clear()
        self.twRooms.clear()
        self.lwUserLookup.clear()
        self.tbRoomInfo.clear()
        self.lblGpotsize.clear()
        self.rbSortRoomsByName.setChecked(True)
        self.btnSendMessage.setAutoDefault(True)
        self.cbRegisterWithoutEmail.setChecked(True)

        log.info("Showing UI")
        self.MainWindow.show()
        # log.debug("Initialized")

    def get(self, attribute):
        return self.__getattribute__(attribute)

    def exception(self, exc_info, critical=False, disconnect=False):
        exc_type, value, _ = exc_info

        if critical:
            log.critical(f"UNHANDLED EXCEPTION CAUGHT: {exc_type.__name__}", exc_info=exc_info)

        else:
            log.error(f"{exc_type.__name__}: {value}", exc_info=exc_info)

        if disconnect:
            self.MainWindow.close()
            self.drop_connection()
            dropped_connection_dialog(exc_info)

        else:
            error_dialog(exc_info)

    # network

    def connect(self):
        log.debug("Attempting to connect...")
        self.nethr = NeThread(self)

    def on_connecting(self):
        log.info("Connecting...")
        self.btnConnect.setEnabled(False)
        self.btnDisconnect.setEnabled(False)

    def on_connected(self):  # fix
        log.info("Connected!")
        self.MainWindow.raise_()
        self.MainWindow.setWindowTitle("Shove - Connected")
        self.btnConnect.setEnabled(False)
        self.btnDisconnect.setEnabled(True)

        if not self.checked_update_since_startup:
            self.check_update()
            self.checked_update_since_startup = True

    def drop_connection(self):
        log.debug("Dropping connection")
        self.nethr.stop()
        self.MainWindow.setWindowTitle("Shove - Disconnected")
        self.btnConnect.setEnabled(True)
        self.btnDisconnect.setEnabled(False)

    def send_content(self, c_type, **key_value):
        content = {
            "type": c_type
        }

        content.update(key_value)
        packet = Packet(content)
        log.debug(f"P/{packet.id} Sending... {packet.get_formatted()}")

        if self.nethr.socket is None:
            log.debug("Socket is None, cancelling send_content")
            return

        try:
            self.nethr.socket.send(packet.encoded)

        except BaseException as ex:
            if type(ex) == ConnectionResetError:
                self.exception(sys.exc_info(), False)

            else:
                self.exception(sys.exc_info(), True)

            return

        # log.debug(f"P/{packet.id} Sent")

    # ui events

    def ui_connect(self):
        self.connect()

    def ui_disconnect(self):
        self.drop_connection()

    def ui_twi_room_double_clicked(self):
        self.ui_join_room()

    def ui_twi_room_clicked(self, twi: QTreeWidgetItem):
        room_name = twi.text(0)
        self.leJoinRoomName.setText(room_name)

    def ui_next_users_page(self):
        self.lookup_users_page += 1
        self.lookup_users(self.leUserLookup.placeholderText())

    def ui_prev_users_page(self):
        self.lookup_users_page -= 1
        self.lookup_users(self.leUserLookup.placeholderText())

    def ui_lwi_users_selection_changed(self):
        selected = self.lwUserLookup.selectedItems()

        if not selected:
            return

        lwi = selected[0]
        username = lwi.text()
        self.get_user_status(["lookup"], username)
        self.get_user_files(["avatar"], ["lookup"], username)

    def ui_toggle_room_sorting(self):
        self.lookup_rooms_reversed = not self.lookup_rooms_reversed
        self.btnToggleRoomSorting.setText("/\\" if self.lookup_rooms_reversed else "\\/")
        self.lookup_rooms()

    def ui_prev_rooms_page(self):
        self.lookup_rooms_page -= 1
        self.lookup_rooms()

    def ui_next_rooms_page(self):
        self.lookup_rooms_page += 1
        self.lookup_rooms()

    def ui_send_message(self):
        message = self.leChatInput.text()
        message_split = message.split()
        split_len = len(message_split)
        self.leChatInput.clear()

        if not message:
            return

        if message.startswith("/"):
            if message_split[0] == "/g":
                if split_len > 1:
                    self.send_message(" ".join(message_split[1:]), ["global"])

                else:
                    self.chat_toggle_global = not self.chat_toggle_global
                    self.append_chat("Toggled global chatting")

            elif message_split[0] == "/leaveroom":
                self.ui_leave_room()

            elif message_split[0] == "/pm" and split_len > 2:
                self.send_message(" ".join(message_split[2:]), ["private"], to_user=message_split[1])

            else:
                self.append_chat(f"Unknown command. /g <msg>, /leaveroom, /pm <user> <msg>")

        else:
            if self.room_name:
                self.send_message(message, ["room"])

            else:
                self.send_message(message, ["global"])

    def ui_upload_avatar(self):
        self.upload("image", "avatar")

    def ui_upload_background(self):
        self.upload("image", "background")

    def ui_upload_deck(self):
        self.upload("directory", "deck")

    def ui_upload_table(self):
        self.upload("image", "table")

    def ui_log_in(self):
        self.send_content(
            "log_in",
            username=self.leLoginName.text(),
            password=self.leLoginPassword.text()
        )

    def ui_register(self):
        self.send_content(
            "register",
            username=self.leRegisterName.text(),
            password=self.leRegisterPassword.text(),
            repeat_password=self.leRegisterRepeatPassword.text(),
            email=self.leRegisterEmail.text(),
            register_without_email=self.cbRegisterWithoutEmail.isChecked()
        )

    def ui_create_room(self):
        self.send_content(
            "join_room",
            metadata=["create_room"],
            room_name=self.leJoinRoomName.text(),
            session_token=self.session_token
        )

    def ui_join_room(self):
        self.send_content(
            "join_room",
            metadata=["join_room"],
            room_name=self.leJoinRoomName.text(),
            password=self.leJoinRoomPassword.text(),
            session_token=self.session_token
        )

    def ui_leave_room(self):
        self.send_content(
            "leave_room",
            session_token=self.session_token
        )

    def ui_lookup_users(self):
        username = self.leUserLookup.text()
        self.leUserLookup.setPlaceholderText(username)
        self.leUserLookup.clear()
        self.lookup_users(username)

    def ui_lookup_rooms(self):
        self.lookup_rooms()

    # general ui

    def append_chat(self, o):
        log.info(f"[CHAT] {o}")
        self.lwChat.addItem(str(o))
        self.lwChat.scrollToBottom()

    def logged_in(self):
        self.MainWindow.setWindowTitle(f"Shove - Logged in as {self.username}")
        self.tabwMain.setCurrentIndex(1)
        self.lookup_rooms()
        self.get_user_files(["avatar", "deck", "background", "table"], ["log_in"], self.username)
        self.get_user_status(["log_in"], self.username)

    def update_profile_status(self):
        status = self.username_profile_status[self.username]
        games_played = status["games_played"]
        in_room_name = status["in_room_name"]
        is_online = status["is_online"]

        if in_room_name:
            status = f"Room: {in_room_name}"

        elif is_online:
            status = "Online"

        else:
            status = "Offline"

        status_str = f"""<b>{self.username}</b><br>
        <b>{status}</b><br>
        <br>
        Games played: {games_played}
        """

        self.tbUserProfileStatus.setText(status_str)

    # lookup ui

    def update_lookup_status(self, username):
        status = self.username_profile_status[username]
        games_played = status["games_played"]
        in_room_name = status["in_room_name"]
        is_online = status["is_online"]

        if in_room_name:
            status = f"Room: {in_room_name}"

        elif is_online:
            status = "Online"

        else:
            status = "Offline"

        status_str = f"""<b>{username}</b><br>
        <b>{status}</b><br>
        <br>
        Games played: {games_played}
        """

        self.tbUserLookupStatus.setText(status_str)

    def lookup_users(self, username):
        self.send_content(
            "lookup_users",
            username=username,
            page=self.lookup_users_page
        )

    def looked_up_users(self, users, total_users, page, total_pages):
        self.lookup_users_page = page
        self.lblUsersPage.setText(f"Page {page}/{total_pages} ({total_users} users total)")
        self.btnNextUsersPage.setEnabled(self.lookup_users_page < total_pages)
        self.btnPrevUsersPage.setEnabled(self.lookup_users_page > 1)
        self.lwUserLookup.clear()

        for username in users:
            self.lwUserLookup.addItem(username)

        self.lwUserLookup.setCurrentRow(0)

    def lookup_rooms(self):
        if self.rbSortRoomsByPlayers.isChecked():
            sort_key = "player_count"

        else:
            sort_key = "room_name"

        self.send_content(
            "lookup_rooms",
            page=self.lookup_rooms_page,
            hide_full=self.cbHideFullRooms.isChecked(),
            hide_empty=self.cbHideEmptyRooms.isChecked(),
            hide_protected=self.cbHideProtectedRooms.isChecked(),
            show_only_official=self.cbShowOnlyOfficialRooms.isChecked(),
            search_string=self.leSearchRoom.text(),
            sort_key=sort_key,
            sort_reversed=self.lookup_rooms_reversed
        )

    def looked_up_rooms(self, rooms, total_rooms, page, filtered_pages, sort_key):
        columns: list = ["room_name", "description", "player_count", "country"]
        column_index = columns.index(sort_key)
        self.lookup_rooms_page = page
        self.twRooms.clear()
        self.lblRoomsPage.setText(f"Page {page}/{filtered_pages} ({total_rooms} rooms total)")
        self.btnNextRooms.setEnabled(page < filtered_pages)
        self.btnPrevRooms.setEnabled(page > 1)
        sort_order = Qt.DescendingOrder if self.lookup_rooms_reversed else Qt.AscendingOrder
        self.twRooms.sortItems(column_index, sort_order)

        for room in rooms:
            row_item = QTreeWidgetItem(self.twRooms)
            row_item.setText(0, room["room_name"])

            if room["protected"]:
                row_item.setIcon(0, self.protected_icon)

            if room["official"]:
                row_item.setBackground(0, self.official_brush)

            row_item.setText(1, room["description"])
            player_count = room["player_count"]
            max_players = room["max_players"]
            row_item.setText(2, f"{player_count}/{max_players}")

            if player_count < max_players:
                row_item.setBackground(2, self.not_full_brush)

            else:
                row_item.setBackground(2, self.full_brush)

            row_item.setText(3, room["country"])

    # game ui

    def update_game_avatar(self, username):
        seat = self.username_seat[username]
        self.get(f"lblGs{seat}a").setPixmap(self.username_avatar[username])
        self.get(f"lblGs{seat}a").setFrameStyle(QFrame.Panel)
        self.get(f"lblGs{seat}a").setFrameShadow(QFrame.Raised)
        self.get(f"lblGs{seat}a").setLineWidth(3)

    def update_game_community_slot_card(self):
        slot_card = self.community_slot_card

        for slot in [1, 2, 3, 4, 5]:
            card = slot_card[str(slot)]

            if card is None:
                self.get(f"lblGc{slot}").clear()
                del slot_card[str(slot)]
                continue

            pixmap = self.username_deck[self.username][card]
            self.get(f"lblGc{slot}").setPixmap(pixmap)

        cards_joint = ", ".join(slot_card.values())
        self.append_chat(f"Community cards: {cards_joint}")

    def update_game_status(self, username):
        seat = self.username_seat[username]
        status = self.username_game_status[username]
        total_chips = status["total_chips"]
        current_bet = status["current_bet"]
        slot_card = status["slot_card"]
        self.username_slot_card[username] = slot_card

        status_str = f"""<b>{username}</b><br>
        {total_chips} chips
        """

        self.get(f"lblGs{seat}b").setText(str(current_bet))
        self.get(f"lblGs{seat}a").setToolTip(status_str)

        for slot in [1, 2]:
            card = slot_card[str(slot)]

            if card is None:
                self.get(f"lblGs{seat}c{slot}").clear()
                continue

            pixmap = self.username_deck[username][card]
            self.get(f"lblGs{seat}c{slot}").setPixmap(pixmap)

    def update_room_info(self):
        info_lines = [
            f"Room: {self.room_name}",
            f"Players: {len(self.username_seat)}",
            f"Country: {self.room_country}",
            f"Description: {self.room_description}"
        ]

        info_formatted = "<br>".join(info_lines)
        self.tbRoomInfo.setText(info_formatted)

    def clear_seat(self, seat):
        self.get(f"lblGs{seat}a").setToolTip(None)
        self.get(f"lblGs{seat}a").clear()
        self.get(f"lblGs{seat}a").setFrameStyle(QFrame.NoFrame)
        self.get(f"lblGs{seat}b").clear()
        self.get(f"lblGs{seat}c1").clear()
        self.get(f"lblGs{seat}c2").clear()

    def you_joined_room(self):
        # tekst weghalen van ui
        for seat in range(1, 11):
            self.clear_seat(seat)

        for username in self.username_seat.keys():
            self.player_joined_table(username)

        self.get_game_info()
        self.tabwMain.setCurrentIndex(0)
        self.tbRoomInfo.clear()
        self.lblGpotsize.clear()
        self.get_room_info()

    def you_left_room(self):
        for username in self.username_seat.keys():
            self.player_left_table(username)

        self.room_name = None
        self.room_description = None
        self.tbRoomInfo.clear()
        self.lblGpotsize.clear()
        self.tabwMain.setCurrentIndex(1)

    def user_joined_room(self, username):
        self.player_joined_table(username)

    def user_left_room(self, username):
        self.player_left_table(username)

    def player_joined_table(self, username):
        self.get_user_files(["avatar", "deck"], ["game"], username)
        self.get_user_status(["game"], username)

    def player_left_table(self, username):
        if username != self.username:
            del self.username_avatar[username]
            del self.username_deck[username]
            del self.username_seat[username]
            del self.username_slot_card[username]
            del self.username_game_status[username]

        seat = self.username_seat[username]
        self.clear_seat(seat)

    # packet creation and passing

    def check_update(self):
        log.info("Checking for updates...")
        self.send_content("check_update")

    def get_assets(self, assets):
        self.send_content(
            "get_assets",
            assets=assets
        )

    def upload(self, select_filter, file_type):
        try:
            path = select_path_dialog(select_filter)
            if not path:
                return

            b64str_object = get_b64str_object(file_type, path)

        except BaseException as ex:
            if type(ex) == Error:
                self.exception(sys.exc_info())

            else:
                self.exception(sys.exc_info(), True)

            return

        else:
            self.send_content(
                "upload",
                file_type=file_type,
                b64str_object=b64str_object,
                session_token=self.session_token
            )

    def send_message(self, message, metadata=None, to_user=None):
        self.send_content(
            "send_message",
            message=message,
            metadata=metadata,
            to_user=to_user,
            session_token=self.session_token
        )

    def get_room_info(self):
        self.send_content(
            "get_room_info",
            session_token=self.session_token
        )

    def get_game_info(self):
        self.send_content(
            "get_game_info",
            session_token=self.session_token
        )

    def get_user_files(self, file_types, metadata, username):
        self.send_content(
            "get_user_files",
            file_types=file_types,
            metadata=metadata,
            username=username
        )

    def get_user_status(self, metadata, username):
        self.send_content(
            "get_user_status",
            metadata=metadata,
            username=username
        )

    # packet processing

    def on_packet_complete(self, packet: Packet):
        log.debug(f"P/{packet} Processing... {packet.get_formatted()}")

        try:
            self.process_content(packet.content)

        except BaseException as ex:
            if type(ex) == Error:
                self.exception(sys.exc_info())

            else:
                self.exception(sys.exc_info(), True)

        # log.debug(f"P/{packet} Processed")

    def process_content(self, c):
        c_type = c["type"]

        if c_type == "error":
            code = c["code"]
            log.info(f"Received error code from server: {code}")
            error_dialog(code)
            return

        if c_type == "checked_update":
            assets = c["assets"]
            ui_version = c["ui_version"]
            ui_version_str = str(ui_version)

            local_assets = [filename for filename in os.listdir(ASSETS_DIR)
                            if os.path.isfile(f"{ASSETS_DIR}/{filename}")]
            missing_assets = [asset for asset in assets
                              if asset not in local_assets]
            dont_remove = [WARNING_FILENAME, UI_VERSION_FILENAME]
            unnecessary_assets = [local_asset for local_asset in local_assets
                                  if local_asset not in assets
                                  and local_asset not in dont_remove]

            for unnecessary_asset in unnecessary_assets:
                os.remove(f"{ASSETS_DIR}/{unnecessary_asset}")
                log.warning(f"Removed unused asset {unnecessary_asset}")

            if ui_version_str != UI_VERSION_STR:
                missing_assets.append("shove.ui")
                with open(UI_VERSION_PATH, "w") as f:
                    f.write(ui_version_str)

            if missing_assets:
                log.info(f"Missing assets: {missing_assets}")
                self.get_assets(missing_assets)

            else:
                self.__init_post_update()

            return

        if c_type == "got_assets":
            log.debug("Got assets")
            files: list = c["files"]
            downloaded_ui = False
            for file in files:
                b64str = file["b64str"]
                file_bytes = b64str_to_bytes(b64str)
                filename = file["filename"]
                path = f"{ASSETS_DIR}/{filename}"

                with open(path, "wb") as f:
                    f.write(file_bytes)

                if filename == "shove.ui":
                    downloaded_ui = True

            if downloaded_ui:  # convert, restart
                log.debug("Converting downloaded UI to .py...")
                os.system(
                    f"python -m PyQt5.uic.pyuic \"{ASSETS_DIR}/shove.ui\" -o \"{FILE_DIR}/shove_ui.py\""
                )  # -x")
                log.info("Updated, restarting...")
                os.system(f"{sys.executable} {FILE_DIR}")
                sys.exit()

            self.__init_post_update()

            return

        if c_type == "logged_in":
            metadata = c["metadata"]
            self.session_token = c["session_token"]
            self.username = c["username"]
            self.logged_in()

            if "log_in" in metadata:
                self.leLoginName.clear()
                self.leLoginPassword.clear()
                log.info("Log in OK")
                return

            if "register" in metadata:
                self.leRegisterPassword.clear()
                self.leRegisterName.clear()
                self.leRegisterRepeatPassword.clear()
                self.leRegisterEmail.clear()
                log.info("Register OK")
                return

            raise Error("server_metadata_invalid")

        if c_type == "got_user_files":
            files = c["files"]
            username = c["username"]
            metadata = c["metadata"]

            for file in files:
                file_type = file["file_type"]

                if file_type == "deck":
                    deck_b64str = file["deck_b64str"]

                    deck = {}
                    for card, b64str in deck_b64str.items():
                        deck[card] = b64str_to_pixmap(b64str)

                    self.username_deck[username] = deck

                    log.debug(f"Got user {username} deck OK")
                    continue

                pixmap = b64str_to_pixmap(file["b64str"])

                if not pixmap:
                    raise Error("server_packet_invalid")

                if file_type == "avatar":
                    if "game" in metadata:
                        self.username_avatar[username] = pixmap
                        self.update_game_avatar(username)

                    elif "lookup" in metadata:
                        self.lblUserLookupAvatar.setPixmap(pixmap)

                    elif "log_in" in metadata:
                        self.lblUserProfileAvatar.setPixmap(pixmap)

                    else:
                        raise Error("server_metadata_invalid")

                elif file_type == "background":
                    if "log_in" in metadata:
                        self.lblGbg.setPixmap(pixmap)

                    else:
                        raise Error("server_metadata_invalid")

                elif file_type == "table":
                    if "log_in" in metadata:
                        self.lblGtable.setPixmap(pixmap)

                    else:
                        raise Error("server_metadata_invalid")

                log.debug(f"Got user {username} {file_type} OK")

            return

        if c_type == "got_user_status":
            username = c["username"]
            metadata = c["metadata"]
            status = c["status"]

            if "lookup" in metadata:
                self.username_profile_status[username] = status
                self.update_lookup_status(username)
                log.debug(f"Got user {username} lookup status OK")

            elif "log_in" in metadata:
                self.username_profile_status[username] = status
                self.update_profile_status()
                log.debug(f"Got profile status OK")

            elif "game" in metadata:
                self.username_game_status[username] = status
                self.update_game_status(username)
                log.debug(f"Got user {username} game status OK")

            else:
                raise Error("server_metadata_invalid")

            return

        if c_type == "room_update":
            metadata = c["metadata"]

            if "user_joined" in metadata:
                username = c["username"]
                self.username_seat = c["username_seat"]

                if username == self.username:
                    self.room_name = c["room_name"]
                    self.room_description = c["description"]
                    self.you_joined_room()

                    if "join_room" in metadata:
                        self.append_chat(f"Joined room {self.room_name}!")

                    elif "create_room" in metadata:
                        self.append_chat(f"Created room {self.room_name}!")

                    else:
                        raise Error("server_metadata_invalid")

                else:
                    self.append_chat(f"{username} joined")
                    self.user_joined_room(username)

            elif "user_left" in metadata:
                username = c["username"]

                if username == self.username:
                    self.append_chat(f"Left room {self.room_name}")
                    self.you_left_room()

                else:
                    self.append_chat(f"{username} left")
                    self.user_left_room(username)

            else:
                raise Error("server_metadata_invalid")

            return

        if c_type == "got_room_info":
            self.room_name = c["room_name"]
            self.room_description = c["description"]
            self.room_country = c["country"]
            self.update_room_info()

            return

        if c_type == "looked_up_rooms":
            sort_key = c["sort_key"]
            rooms = c["rooms"]
            filtered_pages = c["filtered_pages"]
            total_rooms = c["total_rooms"]
            page = c["page"]

            self.looked_up_rooms(rooms, total_rooms, page, filtered_pages, sort_key)

            return

        if c_type == "receive_message":
            message = c["message"]
            metadata = c["metadata"]
            # timestamp = time.strftime("%X")

            if "from_user" in metadata:
                author = c["author"]
                rank_prefix = c["rank_prefix"]
                if rank_prefix:
                    rank_prefix_formatted = f"[{rank_prefix}]"

                else:
                    rank_prefix_formatted = ""

                if "global" in metadata:
                    prefix = "G"

                elif "room" in metadata:
                    prefix = "R"

                elif "private" in metadata:
                    prefix = "@"

                else:
                    raise Error("server_metadata_invalid")

                self.append_chat(f"[{prefix}] {rank_prefix_formatted}{author}: {message}")

            elif "from_server" in metadata:
                if "global" in metadata:
                    prefix = "G"

                elif "room" in metadata:
                    prefix = "R"

                elif "private" in metadata:
                    prefix = "@"

                else:
                    raise Error("server_metadata_invalid")

                self.append_chat(f"[{prefix}] [SERVER]: {message}")

            elif "from_game" in metadata:
                self.append_chat(f"[GAME]: {message}")

            else:
                raise Error("server_metadata_invalid")

            return

        if c_type == "looked_up_users":
            users = c["users"]
            page = c["page"]
            filtered_pages = c["filtered_pages"]
            total_users = c["total_users"]

            self.looked_up_users(users, total_users, page, filtered_pages)

            return

        if c_type == "user_update":
            metadata = c["metadata"]

            if "friend_online" in metadata:
                username = c["username"]

                self.append_chat(f"{username} is online")

            else:
                raise Error("server_metadata_invalid")

            return

        if c_type == "uploaded":
            upload_type = c["upload_type"]
            log.info(f"Uploaded {upload_type} OK")

            return

        if c_type == "game_update":
            metadata = c["metadata"]

            if "starting" in metadata:
                self.append_chat("starting")

            elif "started" in metadata:
                self.append_chat("[GAME] Game started!")

            elif "dealt_cards" in metadata:
                self.append_chat(f"[GAME] Cards have been dealt!")
                self.send_content(
                    "get_user_status",
                    metadata=["game"],
                    username=self.username,
                    session_token=self.session_token
                )

            elif "betting_round" in metadata:
                self.append_chat("BETTING ROUND!")

            elif "next_stage" in metadata:
                self.get_game_info()

            elif "hand_winners" in metadata:
                winners = c["winners"]
                winning_rank = c["winning_rank"]
                winners_joint = ", ".join(winners)
                self.append_chat(f"[GAME] {winners_joint} won with a {winning_rank}!")

            elif "ending" in metadata:
                self.append_chat("ending")

            elif "ended" in metadata:
                self.append_chat("[GAME] Game ended!")

            else:
                raise Error("server_metadata_invalid")

            return

        if c_type == "got_game_info":
            stage = c["stage"]
            pot = c["pot"]
            community_slot_card = c["community_slot_card"]

            self.append_chat(f"[GAME] Game stage: {stage}")
            self.community_slot_card = community_slot_card
            self.update_game_community_slot_card()
            self.lblGpotsize.setText(f"Pot: {pot}")

            return

        log.critical(f"Invalid content type: {c_type}")
        raise Error("server_content_type_invalid")


while not QUIT_APPLICATION:
    log.debug(f"(Re)starting application...")
    QUIT_APPLICATION = True
    Shove()

log.debug("Quit application")
