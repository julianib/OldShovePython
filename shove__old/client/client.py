import sys
import os
import socket
from datetime import datetime
from inspect import currentframe, getframeinfo
import ctypes

from PyQt5.QtCore import *
from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from shove_ui import Ui_MainWindow
from utils import *


_gfi = getframeinfo
_cf = currentframe

debug(f"[TEST] {_gfi(_cf()).lineno}")


HOSTNAME = "localhost"


def bytes_to_b64str(file_bytes):
    file_b64bytes = base64.b64encode(file_bytes)
    file_b64str = file_b64bytes.decode()

    return file_b64str


def b64str_to_bytes(file_b64str, do_debug=True):
    if do_debug:
        debug_file("Converting to bytes...")
    file_b64bytes = file_b64str.encode()
    file_bytes = base64.b64decode(file_b64bytes)

    return file_bytes


def b64str_to_pixmap(img_b64str):
    debug_file("Converting to pixmap...")
    img_bytes = b64str_to_bytes(img_b64str, do_debug=False)
    pixmap = QPixmap()
    pixmap.loadFromData(img_bytes)

    return pixmap


class SocketThread(QThread):
    connecting = pyqtSignal()
    connection_failed = pyqtSignal(str)
    connected = pyqtSignal()
    do_process_packet = pyqtSignal(dict)

    def __init__(self, manager):
        QThread.__init__(self)
        self.manager = manager

    def __del__(self):
        self.wait()

    def receive(self):
        debug_socket("Now receiving packets...")

        while True:
            if not self.manager.socket:
                self.connection_failed.emit("Couldn't receive packet header: no socket set")
                break

            try:
                header_str = self.manager.socket.recv(7).decode()
                header = int(header_str)

            except ConnectionResetError as ex:
                self.connection_failed.emit(f"ConnectionResetError on recv: {ex}")
                self.manager.socket = None
                break

            except socket.error as ex:
                self.connection_failed.emit(f"socket.error on recv: {ex}")
                self.manager.socket = None
                break

            except ValueError as ex:
                debug_socket(f"ValueError on recv: {ex} (ignoring packet)")
                continue

            except Exception as ex:
                self.connection_failed.emit(f"Unhandled exception on recv: {ex}")
                self.manager.socket = None
                raise

            debug_socket(f"Receiving packet with length {header}...")
            p_bytes = b""
            while len(p_bytes) < header:
                recv_bytes = self.manager.socket.recv(header - len(p_bytes))
                if not recv_bytes:
                    break  # received all bytes

                p_bytes += recv_bytes
                debug_socket(f"Received packet bytes: {len(p_bytes)}/{header}")

            if not p_bytes:
                self.connection_failed.emit(f"Connection lost: empty packet")
                self.manager.socket = None
                break

            try:
                p = decon_packet(p_bytes)

            except json.JSONDecodeError as ex:
                debug_packet(f"json.JSONDecodeError on decon: {ex} (ignoring packet)")
                continue

            if not p:
                debug_packet("Empty packet received (ignoring packet)")
                continue

            self.do_process_packet.emit(p)

    def run(self):
        debug_socket("Creating socket manager")
        self.manager.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connecting.emit()

        try:
            self.manager.socket.connect((HOSTNAME, 2000))

        except ConnectionRefusedError:
            self.connection_failed.emit("connection refused")
            self.manager.socket = None

        else:
            self.connected.emit()

            self.receive()


class SocketManager:
    socket = None

    def __init__(self, ui):
        self.ui = ui
        self.thread = SocketThread(manager=self)
        self.thread.do_process_packet.connect(self.ui.process_packet)
        self.thread.connecting.connect(self.ui.connecting)
        self.thread.connection_failed.connect(self.ui.connection_failed)
        self.thread.connected.connect(self.ui.connected)

    def start_thread(self):
        self.thread.start()

    def kill(self):
        self.thread.terminate()
        self.socket.close()
        self.ui.sock_ma = None

    def send(self, p: dict):
        p_str = json.dumps(p)
        p_len = len(p_str)
        header = f"{p_len:07d}"

        mod_p = p.copy()
        for k in p.keys():
            if "b64str" in k:
                mod_p[k] = "<b64str filtered>"

        debug_socket(f"Sending packet: {mod_p}")

        if not self.socket:
            debug_socket(f"Could not send packet: no socket set")
            self.ui.connection_failed("no socket set")
            return

        try:
            self.socket.send(header.encode() + p_str.encode())  # new_thread(self.socket.send, args=(json.dumps(p).encode(),))

        except ConnectionResetError as ex:
            debug_socket(f"ConnectionResetError: {ex}")
            self.ui.connection_failed("connection reset")
            self.socket = None

        else:
            debug_socket(f"Sent packet")


class ShoveUi(Ui_MainWindow):
    sock_ma = None

    username = None
    card_back_pixmap = None
    card_front_pixmap_dict = None
    table_pixmap = None
    background_pixmap = None
    session_token = None

    room = {}
    current_room_page = 1
    sort_rooms_reversed = False

    current_find_users_page = 1

    def __init__(self):
        abs_python_file = sys.argv[0]
        abs_dir = os.path.dirname(abs_python_file)
        self.assets_dir = f"{abs_dir}/assets"
        if not os.path.exists(self.assets_dir):
            os.mkdir(self.assets_dir)
            debug("Asset dir created")

        if not os.path.exists(f"{self.assets_dir}/ui_version.txt"):
            with open(f"{self.assets_dir}/ui_version.txt", "w") as f:
                f.write("0")

            debug("ui_version.txt created")

        debug("Connecting client...")
        self.connect()

    def _init_post_update(self):
        _app = QApplication(sys.argv)
        self.MainWindow = QMainWindow(flags=Qt.WindowFlags())
        self.setupUi(self.MainWindow)

        self.password_icon = QIcon(f"{self.assets_dir}/password_icon.png")
        self.window_icon = QIcon(f"{self.assets_dir}/window_icon.png")
        self.MainWindow.setWindowIcon(self.window_icon)
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(u'mycompany.myproduct.subproduct.version')  # set icon in taskbar
        self.dealer_button_pixmap = QPixmap(f"{self.assets_dir}/password_icon.png")

        self.red_button_css = "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 rgba(180, 0, 0, 210), stop:1 rgba(255, 255, 255, 255))"
        self.green_button_css = "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 rgba(0, 255, 0, 210), stop:1 rgba(255, 255, 255, 255))"
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
        self.leSearchUser.returnPressed.connect(self.btnSearchUser.click)
        self.btnConnect.clicked.connect(self.connect)
        self.btnCreateRoom.clicked.connect(self.sp_create_room)
        self.btnDisconnect.clicked.connect(self.disconnect)
        self.btnJoinRoom.clicked.connect(self.sp_join_room)
        self.btnLeaveRoom.clicked.connect(self.sp_leave_room)
        self.btnLogIn.clicked.connect(self.sp_log_in)
        self.btnNextRooms.clicked.connect(self.ue_next_rooms)
        self.btnNextUsers.clicked.connect(self.ue_next_users)
        self.btnPrevRooms.clicked.connect(self.ue_prev_rooms)
        self.btnPrevUsers.clicked.connect(self.ue_prev_users)
        self.btnRefreshRooms.clicked.connect(self.sp_get_rooms)
        self.btnRegister.clicked.connect(self.sp_register)
        self.btnSearchUser.clicked.connect(self.sp_search_user)
        self.btnSendMessage.clicked.connect(self.process_send_message)
        self.btnToggleRoomSorting.clicked.connect(self.ue_toggle_room_sorting)
        self.btnUploadAvatarFile.clicked.connect(self.upload_avatar_file)
        self.btnUploadBackgroundFile.clicked.connect(self.upload_background_file)
        self.btnUploadCardBackFile.clicked.connect(self.upload_card_back_file)
        # self.btnUploadCardDeckFolder.clicked.connect(self.upload_card_deck_folder)
        self.btnUploadTableFile.clicked.connect(self.upload_table_file)
        self.lwFindUsers.itemSelectionChanged.connect(self.ue_found_username_selection_changed)
        self.twRooms.itemClicked.connect(self.ue_room_item_clicked)
        self.twRooms.itemDoubleClicked.connect(self.ue_room_item_double_clicked)

        self.tabwMain.setCurrentIndex(3)  # game 0 rooms 1 community 2 log_in 3 settings 4
        self.tabwSettings.setCurrentIndex(1)  # general 0 account 1 chat 2 audio 3 game 4 room 5
        self.lwChat.clear()
        self.lwPlayerList.clear()
        self.twRooms.clear()
        self.lwFindUsers.clear()
        self.tbRoomInfo.clear()
        self.lblGpotsize.clear()
        self.rbSortRoomsByName.setChecked(True)
        self.btnDisconnect.setEnabled(False)
        self.btnSendMessage.setAutoDefault(True)
        self.cbRegisterWithoutEmail.setChecked(True)

        debug("Set up UI")
        self.MainWindow.show()

        debug("Starting client main loop")
        _app.exec_()

    def error_dialog(self, error):
        self.sock_ma.send({"type": "client_error", "error": error})
        debug(f"Displaying error dialog: {error}")
        dialog = QMessageBox()
        dialog.setIcon(QMessageBox.Critical)
        dialog.setText("An error occured")
        dialog.setInformativeText(error)
        dialog.setWindowTitle("Error")
        dialog.exec_()

    def append_chat(self, message):
        log(f"[CHAT] {message}")
        self.lwChat.addItem(message)
        self.lwChat.scrollToBottom()

    def connect(self):
        self.sock_ma = SocketManager(ui=self)
        self.sock_ma.start_thread()
        debug_thread("Started socket thread")

    def disconnect(self):
        self.sock_ma.kill()
        debug_thread("Stopped socket thread")
        self.connection_failed("disconnected")

    def connecting(self):
        debug_socket("Connecting...")
        self.btnConnect.setEnabled(False)
        self.btnDisconnect.setEnabled(False)

    def connection_failed(self, reason):
        debug_socket(f"Connection failed: {reason}")
        self.btnConnect.setEnabled(True)
        self.btnDisconnect.setEnabled(False)

    def connected(self):
        debug_socket("Connected!")
        self.btnConnect.setEnabled(False)
        self.btnDisconnect.setEnabled(True)

        p = {
            "type": "update_check"
        }

        self.sock_ma.send(p)

    def sp_log_in(self):
        username = self.leLoginName.text()
        password = self.leLoginPassword.text()

        p = {
            "type": "log_in",
            "username": username,
            "password": password
        }

        self.sock_ma.send(p)

    def sp_register(self):
        username = self.leRegisterName.text()
        password = self.leRegisterPassword.text()
        repeat_password = self.leRegisterRepeatPassword.text()
        email = self.leRegisterEmail.text()
        register_without_email = self.cbRegisterWithoutEmail.isChecked()

        p = {
            "type": "register",
            "username": username,
            "password": password,
            "repeat_password": repeat_password,
            "email": email,
            "register_without_email": register_without_email
        }

        self.sock_ma.send(p)

    def sp_create_room(self):
        room_name = self.leJoinRoomName.text()

        p = {
            "type": "create_room",
            "room_name": room_name,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def ue_room_item_double_clicked(self, obj: QTreeWidgetItem):
        room_name = obj.text(0)
        self.leJoinRoomName.setText(room_name)
        self.sp_join_room()

    def ue_room_item_clicked(self, obj: QTreeWidgetItem):
        room_name = obj.text(0)
        self.leJoinRoomName.setText(room_name)

    def sp_join_room(self):
        room_name = self.leJoinRoomName.text()
        password = self.leJoinRoomPassword.text()

        if self.cbJoinRoomSpectator.isChecked():
            user_role = "spectator"
        else:
            user_role = "player"

        p = {
            "type": "join_room",
            "room_name": room_name,
            "password": password,
            "user_role": user_role,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def sp_leave_room(self):
        p = {
            "type": "leave_room",
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def ue_next_users(self):
        self.current_find_users_page += 1
        self.sp_search_user()

    def ue_prev_users(self):
        self.current_find_users_page -= 1
        self.sp_search_user()

    def sp_search_user(self):
        username_query = self.leSearchUser.text()
        self.leSearchUser.setPlaceholderText(username_query)
        self.leSearchUser.clear()

        p = {
            "type": "search_user",
            "username_query": username_query,
            "page_number": self.current_find_users_page
        }

        self.sock_ma.send(p)

    def ue_found_username_selection_changed(self):
        selected = self.lwFindUsers.selectedItems()
        if not selected:
            return

        obj = selected[0]
        username = obj.text()
        self.sp_get_user_stats("community", username=username)
        self.sp_get_user_avatar("community", username=username)

    def sp_get_user_stats(self, request_origin, username=None):
        p = {
            "type": "user_stats",
            "request_origin": request_origin,
            "username": username,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def sp_get_user_avatar(self, request_origin, username=None):
        p = {
            "type": "user_avatar",
            "request_origin": request_origin,
            "username": username,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def sp_get_user_card_back(self, request_origin, username=None):
        p = {
            "type": "user_card_back",
            "request_origin": request_origin,
            "username": username,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def sp_get_user_card(self, request_origin, card_code, card_number, username=None):
        p = {
            "type": "user_card",
            "card_code": card_code,
            "request_origin": request_origin,
            "card_number": card_number,
            "username": username,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def ue_toggle_room_sorting(self):
        if self.sort_rooms_reversed:
            self.btnToggleRoomSorting.setText("\\/")
        else:
            self.btnToggleRoomSorting.setText("/\\")

        self.sort_rooms_reversed = not self.sort_rooms_reversed
        self.sp_get_rooms()

    def ue_prev_rooms(self):
        self.current_room_page -= 1
        self.sp_get_rooms()

    def ue_next_rooms(self):
        self.current_room_page += 1
        self.sp_get_rooms()

    def sp_get_rooms(self):
        if self.rbSortRoomsByName.isChecked():
            sort_key = "room_name"
        elif self.rbSortRoomsByPlayers.isChecked():
            sort_key = "player_count"
        else:
            sort_key = "spectator_count"

        p = {
            "type": "get_rooms",
            "page_number": self.current_room_page,
            "hide_full": self.cbHideFullRooms.isChecked(),
            "hide_empty": self.cbHideEmptyRooms.isChecked(),
            "hide_password_protected": self.cbHidePasswordProtectedRooms.isChecked(),
            "hide_non_official": self.cbHideNonOfficialRooms.isChecked(),
            "search_string": self.leSearchRoom.text(),
            "sort_key": sort_key,
            "sort_reversed": self.sort_rooms_reversed
        }

        self.sock_ma.send(p)

    def process_send_message(self):
        message_raw = self.leChatInput.text()
        message_split = message_raw.split()
        self.leChatInput.clear()

        if not message_raw:
            return

        if not message_raw.startswith("/"):
            if self.room:
                self.sp_send_message(message_raw, "room")
            else:
                self.sp_send_message(message_raw, "global")

            return

        if message_split[0] in ["/g", "/global"]:
            self.sp_send_message(" ".join(message_split[1:]), "global")
            return

        if message_split[0] in ["/r", "/room"]:
            self.sp_send_message(" ".join(message_split[1:]), "room")
            return

        if message_split[0] in ["/leaveroom"]:
            self.sp_leave_room()
            return

        self.append_chat(f"Unknown command. /g, /r, /leaveroom")

    def sp_send_message(self, message, message_type):
        p = {
            "type": "send_message",
            "message": message,
            "message_type": message_type,
            "send_date": str(datetime.now()),
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def upload_avatar_file(self):
        path = self.choose_path("image")
        self.process_file_and_upload("avatar", path)

    def upload_background_file(self):
        pass

    def upload_card_back_file(self):
        pass

    def upload_card_images(self):
        pass

    def upload_table_file(self):
        pass

    def choose_path(self, select_what):
        options = QFileDialog.Options()
        options |= QFileDialog.DontConfirmOverwrite
        if select_what == "image":
            image_path = QFileDialog.getOpenFileName(QFileDialog(), f"Choose {select_what}...", f"{self.assets_dir}/images", "Images (*.png *.jpg)", options=options)[0]

            return image_path

        elif select_what == "directory":
            folder_path = QFileDialog.getExistingDirectory(QFileDialog(), f"Choose {select_what}...", f"{self.assets_dir}/images", options=options)

            return folder_path

        else:
            self.error_dialog("Invalid choose_path parameter (client bug)")

    def process_file_and_upload(self, purpose, path):
        if purpose not in ["avatar", "background", "card_back", "card", "table"]:
            self.error_dialog("Invalid image purpose (client bug)")
            return

        if os.path.isdir(path):
            if purpose == "card":
                for file_in_dir in os.listdir(path):
                    filename = file_in_dir.lower()
                    if os.path.isfile(filename):
                        with open(path, "rb") as f:
                            file_bytes = f.read()

                        b64file_str = bytes_to_b64str(file_bytes)
                        metadata = filename[:2]
                        self.sp_upload_file(b64file_str, purpose, metadata=metadata)

            else:
                self.error_dialog("Not to choose directory, but file (client bug)")

        elif os.path.isfile(path):
            with open(path, "rb") as f:
                file_bytes = f.read()

            b64file_str = bytes_to_b64str(file_bytes)
            self.sp_upload_file(b64file_str, purpose)

        else:
            self.error_dialog("No file/folder selected")

    def sp_upload_file(self, file_b64str, purpose, metadata=None):
        p = {
            "type": f"upload_file",
            "file_b64str": file_b64str,
            "purpose": purpose,
            "metadata": metadata,
            "session_token": self.session_token
        }

        self.sock_ma.send(p)

    def process_packet(self, p):
        debug_packet("Processing...")
        self._process_packet(p)
        debug_packet("Processed")

    def _process_packet(self, p):
        p_type = p["type"]

        if p_type == "error":
            e = p["error"]
            debug(f"Error packet: {e}")
            self.error_dialog(e)
            return

        if p_type == "update_check":
            assets = p["assets"]
            version = p["version"]
            version_str = str(version)

            local_assets = [filename for filename in os.listdir(self.assets_dir) if os.path.isfile(f"{self.assets_dir}/{filename}")]
            missing_assets = [asset for asset in assets if asset not in local_assets]

            with open(f"{self.assets_dir}/ui_version.txt", "r+") as f:
                local_version_str = f.readline()
                f.seek(0)
                f.write(version_str)

            if version_str != local_version_str:
                missing_assets.append("shove.ui")

            if missing_assets:
                p = {
                    "type": "download_assets",
                    "assets": missing_assets
                }

                self.sock_ma.send(p)

            else:
                self._init_post_update()

        if p_type == "downloaded_assets":
            files = p["files"]

            downloaded_ui = False
            for file in files:
                file_b64str = file["file_b64str"]
                file_bytes = b64str_to_bytes(file_b64str)
                asset = file["asset"]
                path = f"{self.assets_dir}/{asset}"

                with open(path, "wb") as f:
                    f.write(file_bytes)

                if asset == "shove.ui":
                    downloaded_ui = True

            if downloaded_ui:
                debug("Downloaded ui, converting to .py")
                os.system(f"python -m PyQt5.uic.pyuic C:/Users/Julian/Dropbox/py/shove/client/assets/shove.ui -o C:/Users/Julian/Dropbox/py/shove/client/shove_ui.py -x")
                debug("Converted ui! Restarting the client")
                os.system(f"{sys.executable} {sys.argv[0]}")
                sys.exit()

            self._init_post_update()

        if p_type == "user_data":
            data_type = p["data_type"]
            request_origin = p["request_origin"]
            username = p["username"]

            if data_type == "profile":
                games_played = str(p["games_played"])
                total_chips = str(p["total_chips"])
                avatar_b64str = p["avatar_b64str"]
                avatar_pixmap = b64str_to_pixmap(avatar_b64str)

                if request_origin == "game":
                    seat = str(p["seat"])
                    current_bet = str(p["current_bet"])

                    self.__getattribute__(f"lblGs{seat}a").setPixmap(avatar_pixmap)
                    self.__getattribute__(f"lblGs{seat}n").setText(username)
                    self.__getattribute__(f"lblGs{seat}b").setText(current_bet)
                    self.__getattribute__(f"lblGs{seat}tc").setText(total_chips)

                    self.__getattribute__(f"lblGs{seat}n").setToolTip(f"<b>{username}</b><br>Total chips: {total_chips}")
                    self.__getattribute__(f"lblGs{seat}a").setToolTip(f"<b>{username}</b><br>Total chips: {total_chips}")

                elif request_origin == "found_user":
                    status = p["status"]
                    self.tbFoundUserDetails.setText(f"<b>{username}</b><br>{status}<br><br>Total chips: {total_chips}<br>Games played: {games_played}")
                    self.lblFoundUserAvatar.setPixmap(avatar_pixmap)

                elif request_origin == "self":
                    self.lblCommunityUserPicture.setPixmap(avatar_pixmap)

            elif data_type == "card_back":
                card_back_b64str = p["card_back_b64str"]
                card_back_pixmap = b64str_to_pixmap(card_back_b64str)

                if request_origin == "game":
                    seat = p["seat"]
                    card_slots = p["card_slots"]

                    for card_slot in card_slots:
                        self.__getattribute__(f"lblGs{seat}c{card_slot}").setPixmap(card_back_pixmap)

                elif request_origin == "community":
                    pass

                elif request_origin == "self":
                    pass

            elif data_type == "card":
                card_b64str = p["card_b64str"]
                card_pixmap = b64str_to_pixmap(card_b64str)

                if request_origin == "game":
                    debug("d5")
                    seat = p["seat"]
                    card_number = p["card_number"]
                    self.__getattribute__(f"lblGs{seat}c{card_number}").setPixmap(card_pixmap)

                elif request_origin == "community":
                    pass

                elif request_origin == "self":
                    pass

        if p_type == "logged_in":
            caused_by = p["caused_by"]
            self.session_token = p["session_token"]
            self.username = p["username"]

            self.MainWindow.setWindowTitle(f"Shove - Logged in as {self.username}")
            self.tabwMain.setCurrentIndex(1)

            self.sp_get_rooms()

            debug_file("Downloading user files...")
            self.sock_ma.send({"type": "download_user_files", "files": ["avatar", "cards", "card_back", "background", "table"], "session_token": self.session_token, "username": self.username})

            if caused_by == "log_in":
                self.leLoginName.clear()
                self.leLoginPassword.clear()

            else:
                self.leRegisterPassword.clear()
                self.leRegisterName.clear()
                self.leRegisterRepeatPassword.clear()
                self.leRegisterEmail.clear()

            return

        if p_type == "room_update":
            update_type = p["update_type"]
            username = p["username"]
            user_role = p["user_role"]
            room_name = p["room_name"]
            new_seats_usernames: dict = p["new_seats_usernames"]

            self.lwPlayerList.clear()
            only_update_username = False
            fetch_data = True

            if update_type == "joined_room":
                if username == self.username:
                    caused_by = p["caused_by"]

                    self.tabwMain.setCurrentIndex(0)

                    self.room = {
                        "room_name": room_name,
                        "user_role": user_role,
                        "seat": None,
                        "seats_usernames": new_seats_usernames
                    }

                    if caused_by == "join":
                        self.append_chat(f"Joined room {room_name}!")

                    elif caused_by == "create":
                        self.append_chat(f"Created room {room_name}!")

                else:
                    self.room["seats_usernames"] = new_seats_usernames

                    if user_role == "player":
                        only_update_username = True

                        self.append_chat(f"Player {username} joined the room!")

                    else:
                        self.append_chat(f"Spectator {username} joined the room!")

            elif update_type == "left_room":
                if username == self.username:
                    self.room = {}
                    self.lwPlayerList.clear()
                    self.tbRoomInfo.clear()
                    self.lblGpotsize.clear()
                    self.tabwMain.setCurrentIndex(1)

                    self.append_chat(f"Left room {room_name}!")

                else:
                    self.room["seats_usernames"] = new_seats_usernames

                    if user_role == "player":
                        self.append_chat(f"Player {username} left the room!")

                    else:
                        self.append_chat(f"Spectator {username} left the room!")

            elif update_type == "role_switch":
                pass

            # update seats
            for seat in range(1, 11):
                seat_str = str(seat)
                if seat_str not in new_seats_usernames.keys():
                    self.__getattribute__(f"lblGs{seat}n").clear()
                    self.__getattribute__(f"lblGs{seat}n").setToolTip(None)
                    self.__getattribute__(f"lblGs{seat}b").clear()
                    self.__getattribute__(f"lblGs{seat}a").setToolTip(None)
                    self.__getattribute__(f"lblGs{seat}a").clear()
                    self.__getattribute__(f"lblGs{seat}c1").clear()
                    self.__getattribute__(f"lblGs{seat}c2").clear()
                    self.__getattribute__(f"lblGs{seat}tc").clear()

                else:
                    indexed_username = new_seats_usernames[seat_str]
                    self.lwPlayerList.addItem(f"[{seat}] {indexed_username}")

                    if fetch_data and not (only_update_username and not indexed_username == username):
                        self.sp_get_user_stats("game", username)
                        self.sp_get_user_avatar("game", username)
                        self.sp_get_user_card_back("game", username)

        if p_type == "room_list_update":
            sort_columns = ["room_name", "description", "player_count", "spectator_count", "country"]
            sort_key = p["sort_key"]
            sort_index = sort_columns.index(sort_key)
            rooms = p["rooms"]
            total_pages = p["total_pages"]
            total_rooms = p["total_rooms"]
            page_number = p["page_number"]
            self.current_room_page = page_number
            self.twRooms.clear()
            self.lblRoomsPage.setText(f"Page {page_number}/{total_pages} ({total_rooms} rooms total)")

            if self.current_room_page >= total_pages:
                self.btnNextRooms.setEnabled(False)

            else:
                self.btnNextRooms.setEnabled(True)

            if self.current_room_page <= 1:
                self.btnPrevRooms.setEnabled(False)

            else:
                self.btnPrevRooms.setEnabled(True)

            if self.sort_rooms_reversed:
                sort_order = Qt.DescendingOrder

            else:
                sort_order = Qt.AscendingOrder

            self.twRooms.sortItems(sort_index, sort_order)

            for i, room in enumerate(rooms):
                row_item = QTreeWidgetItem(self.twRooms)
                row_item.setText(0, room["room_name"])

                if room["has_password"]:
                    row_item.setIcon(0, self.password_icon)

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

                row_item.setText(3, str(room["spectator_count"]))
                row_item.setText(4, room["country"])

            return

        if p_type == "message":
            '''
            [#] user: hi
            [S] user: hi
            [#][A] user: hi
            [G] user: hi
            [G][SERVER] hi
            [SERVER] hi
            [GAME] Your turn!
            '''
            message = p["message"]
            author_type = p["author_type"]
            # is_global = p["is_global"]
            # client_send_date = p["client_send_date"]
            # server_send_date = p["server_send_date"]
            # receive_date = str(datetime.now())

            if author_type == "user":
                author = p["author"]
                prefix = p["prefix"]

                self.append_chat(f"{prefix} {author}: {message}")

            elif author_type == "server":
                self.append_chat(f"[SERVER] {message}")

            elif author_type == "game":
                self.append_chat(f"[GAME] {message}")

            return

        if p_type == "user_list_update":
            usernames = p["usernames"]
            self.lwFindUsers.clear()
            page_number = p["page_number"]
            self.current_find_users_page = page_number
            total_pages = p["total_pages"]
            total_users = p["total_users"]
            self.lblUsersPage.setText(f"Page {page_number}/{total_pages} ({total_users} users total)")

            if self.current_find_users_page >= total_pages:
                self.btnNextUsers.setEnabled(False)

            else:
                self.btnNextUsers.setEnabled(True)

            if self.current_find_users_page <= 1:
                self.btnPrevUsers.setEnabled(False)

            else:
                self.btnPrevUsers.setEnabled(True)

            for i, username in enumerate(usernames):
                self.lwFindUsers.addItem(username)

            self.lwFindUsers.setCurrentRow(0)

            return

        # TODO fix
        if p_type == "user_card_success":
            request_origin = p["request_origin"]
            # username = p["username"]

            if request_origin == "game":
                debug("d5")
                seat = p["seat"]
                card_number = p["card_number"]
                self.__getattribute__(f"lblGs{seat}c{card_number}").setPixmap(card_pixmap)

            elif request_origin == "community":
                pass

            else:
                self.error_dialog("Unknown request origin (server bug)")

            return

        if p_type == "upload_avatar_success":
            debug("Avatar uploaded")

            return

        # TODO fix
        if p_type == "download_cards_success":
            card_code_b64str_dict = p["card_code_b64str_dict"]
            for code, b64str in card_code_b64str_dict.items():
                self.card_front_pixmap_dict[code] = b64str_to_pixmap(b64str)

            debug("Download cards success")
            return

        # TODO fix
        if p_type == "download_card_back_success":
            card_back_b64str = p["card_back_b64str"]
            self.cards_back_pixmap = b64str_to_pixmap(card_back_b64str)

            debug("Download card back success")
            return

        # TODO fix
        if p_type == "download_background_success":
            background_b64str = p["background_b64str"]
            self.background_pixmap = b64str_to_pixmap(background_b64str)

            debug("Download background success")
            return

        # TODO fix
        if p_type == "download_table_success":
            table_b64str = p["table_b64str"]
            self.table_pixmap = b64str_to_pixmap(table_b64str)

            debug("Download table success")
            return

        if p_type == "game_update":
            update_type = p["update_type"]

            if update_type == "cards_dealt":
                cards = p["cards"]
                stage = p["stage"]

                if stage == "pot":
                    for seat, username in self.room["seats_usernames"].items():
                        if username == self.username:
                            self.__getattribute__(f"lblGs{seat}c1").setPixmap(self.card_front_pixmap_dict[cards[0]])
                            self.__getattribute__(f"lblGs{seat}c2").setPixmap(self.card_front_pixmap_dict[cards[1]])

                else:
                    for i, card in enumerate(cards):
                        self.__getattribute__(f"lblGc{i + 1}").setPixmap(self.card_front_pixmap_dict[cards[i]])

                self.append_chat(f"Cards dealt ({stage}): {' '.join(cards)}")

            elif update_type == "betting":
                stage = p["stage"]

                self.append_chat(f"Betting ({stage})")

            elif update_type == "hand_winners":
                winners = p["winners"]
                winning_rank = p["winning_rank"]

                winners_joint = ", ".join(winners)
                self.append_chat(f"[GAME] {winners_joint} won with a {winning_rank}!")

            return

        debug(f"Unknown packet received: {p}")

        return


ShoveUi()
