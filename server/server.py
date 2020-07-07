import socket
import sys
import math
import os
import random
import uuid
import json
import time
import base64
import threading
import re
import copy
import logging
from typing import List
from datetime import datetime
from enum import Enum
from inspect import isroutine, getmembers

from customdeuces import Deck, Evaluator, convert_card_to_2char

HOST_PORT = 2000
SOCKET_BACKLOG = 10
UI_VERSION = "ok"
FILE_DIR = os.path.dirname(__file__)
ASSETS_DIR = f"{FILE_DIR}/assets"
DEFAULT_USER_FILES_DIR = f"{FILE_DIR}/default_user_files"
LOGGING_DIR = f"{FILE_DIR}/logs"
LOGGING_FILE_TIME_FORMAT = "%d%m%yT%H%M%S"
LOGGING_TIME_FORMAT = "%X"
LATEST_LOG_FILENAME = ".server_latest.txt"
LOGGING_FORMAT = "[%(asctime)s] [%(threadName)s/%(levelname)s %(lineno)s] %(message)s"
LATEST_LOG_PATH = f"{LOGGING_DIR}/{LATEST_LOG_FILENAME}"
USER_FILES_DIR = f"{FILE_DIR}/user_files"
DATA_JSON = f"{USER_FILES_DIR}/data.json"

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
LOOKUP_ROOMS_MAX = 20
LOOKUP_USERS_MAX = 50
NEXT_PACKET_ID: int = None
NEXT_USER_ID: int = None

# setup logging/files

if not os.path.exists(LOGGING_DIR):
    os.mkdir(LOGGING_DIR)

if os.path.exists(LATEST_LOG_PATH):
    with open(LATEST_LOG_PATH, "r") as _f:
        time_str = _f.readline().strip()

    os.rename(LATEST_LOG_PATH, f"{LOGGING_DIR}/{time_str}.txt")

with open(LATEST_LOG_PATH, "w") as _f:
    _f.write(time.strftime(LOGGING_FILE_TIME_FORMAT) + "\n\n")

logging.basicConfig(filename=LATEST_LOG_PATH, format=LOGGING_FORMAT, datefmt=LOGGING_TIME_FORMAT)
log = logging.getLogger()
log.setLevel(logging.DEBUG)

_stream_handler_console = logging.StreamHandler(sys.stdout)
_stream_handler_console.setLevel(logging.DEBUG)
_formatter = logging.Formatter(LOGGING_FORMAT)
_formatter.datefmt = LOGGING_TIME_FORMAT
_stream_handler_console.setFormatter(_formatter)

log.addHandler(_stream_handler_console)
threading.current_thread().setName("Main thread")
log.info("Logging ready")


def start_thread(target, name=None, args: tuple = (), kwargs: dict = None, daemon=True):
    new_thread = threading.Thread(target=target, name=name or target.__name__, args=args, kwargs=kwargs, daemon=daemon)
    new_thread.start()
    return new_thread


def get_b64str(path, default=None):
    if not os.path.exists(path):
        if not os.path.exists(default):
            log.warning(f"Path and default don't exist {path}, {default}")
            return

        path = default

    with open(path, "rb") as f:
        file_bytes = f.read()

    b64str = base64.b64encode(file_bytes).decode()

    return b64str


def b64str_to_bytes(b64str):
    return base64.b64decode(b64str.encode())


# string checking

def alphanum_(string):
    return re.fullmatch(r"^\w+$", string)


def username_valid(username):
    return alphanum_(username) and 1 <= len(username) <= 16


def password_valid(password):
    return 1 <= len(password) <= 100


def email_valid(email):
    return "@" in email and 1 <= len(email) <= 100


def room_name_valid(room_name):
    return alphanum_(room_name) and 1 <= len(room_name) <= 16


def room_description_valid(room_description):
    return 1 <= len(room_description) <= 100


# storage manipulation

def read_disk_data():
    with open(DATA_JSON) as f:
        data = json.load(f)

    global NEXT_PACKET_ID, NEXT_USER_ID, USERDATA_STORAGE
    NEXT_PACKET_ID = data["next_packet_id"]
    NEXT_USER_ID = data["next_user_id"]
    USERDATA_STORAGE = data["userdata"]
    log.info("Read disk data")


def write_disk_data(stop=False):
    current_userdata = get_current_userdata()

    data = {
        "write_date": str(datetime.now()),
        "next_packet_id": NEXT_PACKET_ID,
        "next_user_id": NEXT_USER_ID,
        "userdata": current_userdata
    }

    with open(DATA_JSON, "w") as f:
        json.dump(data, f, indent=4)

    log.info(f"Wrote data to disk")

    if stop:
        log.info("Exiting...")
        sys.exit()


def get_current_userdata():
    current_userdata = []
    for entry in USERDATA_STORAGE:
        current_userdata.append(entry)
        log.debug(f"added STORAGE {entry['username']}")

    for user in USERS:
        if user.session_token:
            for entry in current_userdata:
                if user.data.username == entry["username"]:
                    current_userdata.remove(entry)
                    log.debug(f"removed USERS {user.data.username}")

            current_userdata.append(user.get_userdata())
            log.debug(f"added USERS {user.data.username}")

    log.debug("Got current userdata")
    return current_userdata


def move_to_storage(user):
    for entry in USERDATA_STORAGE:
        if user.data.username == entry["username"]:
            USERDATA_STORAGE.remove(entry)
            USERDATA_STORAGE.append(user.get_userdata())
            log.debug(f"Replaced userdata entry in STORAGE")

    USERS.remove(user)
    log.debug(f"Moved {user} to STORAGE successfully")


def increment_next_packet_id():
    global NEXT_PACKET_ID
    old = NEXT_PACKET_ID
    NEXT_PACKET_ID += 1

    return old


def increment_next_user_id():
    global NEXT_USER_ID
    old = NEXT_USER_ID
    NEXT_USER_ID += 1

    return old


class Error(BaseException):
    def __init__(self, code):
        self.__str__ = code


class Room:
    def __init__(self, room_name, **key_value):
        log.debug(f"Room initializing...")

        if Room.exists(room_name):
            raise Room.ExistsError

        self.country = ""
        self.creation_date = ""
        self.description = ""
        self.game = None
        self.max_players = 10
        self.official = False
        self.owner = ""
        self.password = ""
        self.protected = False
        self.room_name = ""

        self.username_seat = {}  # usernames
        self.users = []  # user objects

        nameless_rooms = [room for room in ROOMS if room.room_name.startswith("!")]

        self.set(
            room_name=room_name or f"!Nameless{len(nameless_rooms)}",
            creation_date=str(datetime.now())
        )

        self.game = PokerGame(self)
        self.set(**key_value)
        ROOMS.append(self)
        # log.debug(f"R/{self} Initialized")

    def __str__(self):
        return self.room_name

    def get(self, key):
        return self.__getattribute__(key)

    def set(self, **key_value):
        for key, value in key_value.items():
            if self.get(key) == value:
                log.debug(f"Key already set: {key} = {repr(value)}")

            else:
                self.__setattr__(key, value)
                log.debug(f"Set {key} = {repr(value)}")

    class ExistsError(BaseException):
        pass

    # general

    @staticmethod  # classmethod -> Room.from_matches(..)
    def matches(single, **key_value):
        matches = []
        for key, value in key_value.items():
            for room in ROOMS:
                if room.get(key) == value or (type(value) == str and room.get(key) == value.lower()):
                    matches.append(room)
                    log.debug(f"Room match #{len(matches)}: {key} = {repr(value)}")
                    if single:
                        break

            if single and matches:
                break

        if not matches:
            key_value_joint = ", ".join([f"{key} = {repr(value)}" for key, value in list(key_value.items())])
            log.debug(f"No room matches found: {key_value_joint}")

        elif single:
            return matches[0]

        return matches

    @staticmethod  # classmethod -> Room.from_match(..)
    def match(**key_value):
        return Room.matches(True, **key_value)

    @staticmethod
    def get_room(room_name):
        return Room.match(room_name=room_name)

    @staticmethod
    def create(room_name, **key_value):
        try:
            return Room(room_name, **key_value)

        except Room.ExistsError:
            log.exception(f"Failed to create room: room {room_name} already exists")
            return

    @staticmethod
    def exists(room_name):
        return Room.get_room(room_name)

    @staticmethod
    def delete_all():
        for room in ROOMS:
            for user in room.users:
                room.user_leave(user)

        ROOMS.clear()

    @staticmethod
    def delete(room_name):
        room: Room = Room.match(room_name=room_name)
        for user in room.users:
            room.user_leave(user)

        ROOMS.remove(room)

    @staticmethod
    def create_default_rooms(amount=3):
        success = 0
        i = 1
        while success < amount:
            room = Room.create(
                str(i),
                official=True
            )

            if room:
                success += 1
                room.set(description=f"Official room {room}")

            i += 1

        log.debug(f"Created {amount} default room(s)")

    @staticmethod
    def get_filtered_rooms(hide_empty, hide_full, hide_protected, search_string, show_only_official, sort_key,
                           sort_reversed):

        if sort_key == "player_count":
            sorted_rooms = sorted(ROOMS, key=lambda _: _.get_player_count(), reverse=sort_reversed)

        else:
            sorted_rooms = sorted(ROOMS, key=lambda _: _.room_name, reverse=sort_reversed)

        filtered_rooms = []
        for room in sorted_rooms:
            if not ((hide_full and room.is_full()) or
                    (hide_empty and room.is_empty()) or
                    (hide_protected and room.protected) or
                    (show_only_official and not room.official) or
                    (search_string and not (search_string in room.room_name.lower() or
                                            search_string in room.description.lower()))):

                filtered_room = {
                    "room_name": room.room_name,
                    "description": room.description,
                    "country": room.country,
                    "player_count": room.get_player_count(),
                    "official": room.official,
                    "protected": room.protected,
                    "max_players": room.max_players
                }

                filtered_rooms.append(filtered_room)

        if filtered_rooms:
            log.debug(f"Room filter matches: {len(filtered_rooms)}")
            return filtered_rooms

        log.debug("No room lookup matches")
        return []

    @staticmethod
    def in_a_room(user):
        for room in ROOMS:
            if room.in_room(user):
                log.debug(f"User {user} is in a room")
                return room

        log.debug(f"User {user} is not in a room")

    def in_room(self, user) -> bool:
        for user_in_room in self.users:
            if user_in_room == user:
                return True

        return False

    def send_content(self, c_type, **key_value):
        User.send_content_to(self.users, c_type, **key_value)

    def user_join(self, user):
        self.users.append(user)
        self.add_user_to_seat(user)
        self.game.check_start()

        log.info(f"R/{self} {user.data.username} joined")

    def user_leave(self, user):
        self.remove_user_from_seat(user)
        self.users.remove(user)
        log.debug(f"R/{self} {user.data.username} left")

    def is_empty(self) -> bool:
        return self.get_player_count() == 0

    def set_password(self, password=None):
        if password:
            self.password = password
            self.protected = True
            log.debug(f"R/{self} set password to {password}")

            return

        self.password = None
        self.protected = False
        log.debug(f"R/{self} cleared password")

    def get_empty_seats(self, single=False, randomize=True) -> list:
        taken_seats = list(self.username_seat.keys())
        empty_seats = [seat for seat in range(1, 11) if seat not in taken_seats]

        if not empty_seats:
            log.debug(f"R/{self} No empty seats")
            return []

        if randomize:
            random.shuffle(empty_seats)

        if single:
            seat = random.choice(empty_seats)
            log.debug(f"R/{self} Empty seat: {seat}")
            return seat

        log.debug(f"R/{self} Empty seats: {empty_seats}")
        return empty_seats

    def get_seat(self, of_user) -> int:
        for username, seat in self.username_seat.items():
            if username == of_user.data.username:
                return seat

    def is_full(self) -> bool:
        result = len(self.username_seat) == self.max_players
        log.debug(f"R/{self} Room full: {result}")
        return result

    def get_player_count(self) -> int:
        x = len(self.username_seat)
        log.debug(f"Room {self} has {x} players")
        return x

    def add_user_to_seat(self, user):
        seat = self.get_empty_seats(single=True)
        self.username_seat[user.data.username] = seat

        log.debug(f"R/{self} Added user {user.data.username} to seat {seat}")

    def remove_user_from_seat(self, user):
        seat = self.username_seat[user.data.username]
        del self.username_seat[user.data.username]

        log.debug(f"R/{self} removed {user.data.username} from seat {seat}")


class Data:
    def __init__(self):
        self.username = ""

        self.blocked_users = []
        self.country = ""
        self.email = ""
        self.friends = []
        self.games_played = 0
        self.games_won = 0
        self.id = 0
        self.last_logged_in = ""
        self.last_online = ""
        self.last_used_ip = ""
        self.log_ins = 0
        self.password = ""
        self.rank = ""
        self.rank_prefix = ""
        self.registration_date = ""
        self.total_chips = 0
        self.used_ips = []


class User:
    DATA_DEFAULT = dict([_ for _ in getmembers(Data(), lambda x: not isroutine(x)) if not _[0].startswith("_")])
    DATA_KEYS = list(DATA_DEFAULT.keys())
    # log.debug(f"data_default: {data_default}, data_keys: {data_keys}")

    def __init__(self, socket_pair):
        # log.debug("Initializing...")
        self.conn, self.address = socket_pair
        self.ip, self.port = self.address
        self.address_formatted = f"{self.ip}:{self.port}"
        self.data: Data = Data()
        self.session_token = None
        USERS.append(self)
        # log.debug(f"Initialized")
        log.info(f"Connected")

    def __eq__(self, other):
        if type(other) == User and self.data.username and self.data.username == other.data.username:
            return True

        return False

    def __str__(self):
        return self.data.username or self.address_formatted

    def exception(self, exc_info, critical=False, disconnect=False):
        exc_type, value, _ = exc_info

        if critical:
            logging.critical(f"UNHANDLED EXCEPTION CAUGHT: {exc_type.__name__}", exc_info=exc_info)

        else:
            logging.error(f"{exc_type.__name__}: {value}", exc_info=exc_info)

        if disconnect:
            self.disconnect()

    def get(self, key):
        return self.data.__getattribute__(key)

    def set(self, **key_value):
        """Returns new value if only 1 given"""
        for key, value in key_value.items():
            if self.get(key) == value:
                log.debug(f"Key already set: {key} = {repr(value)}")

            else:
                self.data.__setattr__(key, value)
                log.debug(f"Set {key} = {repr(value)}")

        if len(key_value) == 1:
            return list(key_value.values())[0]

    def set_userdata(self, userdata: dict):
        for key, value in userdata.items():
            if self.get(key) == value:
                log.debug(f"Userdata key already set: {key} = {repr(value)}")

            else:
                self.data.__setattr__(key, value)
                log.debug(f"Set userdata {key} = {repr(value)}")

    # network

    def receive_loop(self):  # threaded
        # log.debug(f"Receive loop started")
        while True:
            try:
                header_bytes = self.conn.recv(Packet.HEADER_SIZE)

            except BaseException as ex:
                if type(ex) == ConnectionResetError:
                    self.exception(sys.exc_info(), False, True)

                else:
                    self.exception(sys.exc_info(), True, True)

                return

            try:
                packet = Packet(header_bytes=header_bytes)
                while packet.bytes_left:
                    packet.update_bytes(self.conn.recv(packet.bytes_left))

                packet.decon()

            except BaseException:
                exc_info = sys.exc_info()
                exc_type, code, _ = exc_info

                if exc_type in [Error, json.JSONDecodeError]:
                    if exc_type == json.JSONDecodeError:
                        code = "client_packet_invalid"

                    self.exception(exc_info)

                else:
                    self.exception(exc_info, True)
                    code = "server_processing_error"

                self.send_error_code(code)

                continue

            log.debug(f"P/{packet} Processing... {packet.get_formatted()}")

            try:
                self.process_content(packet.content)

            except BaseException:
                exc_info = sys.exc_info()
                exc_type, code, traceback = exc_info

                if exc_type == Error:
                    self.exception(exc_info)

                else:
                    self.exception(exc_info, True)
                    code = "server_processing_error"

                self.send_error_code(code)

            # log.debug(f"P/{packet} Processed")

    def disconnect(self):
        self.log_out()
        move_to_storage(self)
        self.conn.close()
        log.debug(f"U/{self} disconnected")

    @staticmethod
    def send_username(username, c_type, **key_value):
        User.get_online_user(username).send_content(
            c_type,
            **key_value,
        )

    def send_content(self, c_type, **key_value):
        content = {
            "type": c_type
        }

        content.update(key_value)
        try:
            packet = Packet(content)

        except TypeError:
            log.critical(f"Packet failed to initialize when sending {c_type}: TypeError")
            return

        log.debug(f"P/{packet} Sending... {packet.get_formatted()}")

        try:
            self.conn.send(packet.encoded)

        except BaseException as ex:
            if type(ex) in [ConnectionResetError, OSError]:
                self.exception(sys.exc_info(), False, True)

            else:
                self.exception(sys.exc_info(), True, True)

            return False

        # log.debug(f"P/{packet} Sent")
        return True

    def send_error_code(self, code):
        if isinstance(code, Error):
            code = str(code)

        elif isinstance(code, BaseException):
            code = code.__class__.__name__
            logging.critical(f"send_error_code with instance of BaseException: {code}")

        self.send_content("error", code=code)

    @staticmethod
    def send_content_to(users, c_type, **key_value):
        total = len(users)
        success = 0

        for user in users:
            if user.send_content(c_type, **key_value):
                success += 1

        return success, total

    # userdata

    @staticmethod
    def matches(single, **key_value):
        matches = []
        for key, value in key_value.items():
            for user in USERS:
                if user.get(key) == value or (type(value) == str and user.get(key) == value.lower()):
                    matches.append(user.get_userdata())
                    log.debug(f"Match #{len(matches)} found in USERS: {key} = {repr(value)}")
                    if single:
                        break

            if single and matches:
                break

            for entry in USERDATA_STORAGE:
                if entry[key] == value or (type(value) == str and entry[key] == value.lower()):
                    matches.append(entry)
                    log.debug(f"Match #{len(matches) } found in USERDATA_STORAGE: {key} = {repr(value)}")
                    if single:
                        break

            if single and matches:
                break

        if not matches:
            key_value_joint = ", ".join([f"{key} = {repr(value)}" for key, value in list(key_value.items())])
            log.debug(f"No matches found: {key_value_joint}")

        elif single:
            return matches[0]

        return matches

    @staticmethod
    def match(**key_value):
        return User.matches(True, **key_value)

    @staticmethod
    def sorted_userdata_matches(sort_key, **key_value):
        return sorted(User.matches(False, **key_value), key=lambda _: _[sort_key])

    @staticmethod
    def lookup_user_query(query_username):  # None for all users
        current_userdata = get_current_userdata()
        sorted_userdata = sorted(current_userdata, key=lambda _: _["username"])
        total_usernames = len(current_userdata)

        found_usernames = []
        for entry in sorted_userdata:
            username = entry["username"]
            if query_username is None or query_username.lower() in username.lower():
                found_usernames.append(username)

        return found_usernames, total_usernames

    @staticmethod
    def get_online_user(username):
        for user in USERS:
            if user.data.username.lower() == username.lower():
                return user

        log.critical(f"get_online_user called for offline user {username}")

    def get_userdata(self) -> dict:
        userdata = {}
        for key in User.DATA_KEYS:
            userdata[key] = self.get(key)

        return userdata

    # user specific methods

    def in_room(self) -> Room or None:
        return Room.in_a_room(self)

    def in_room_name(self) -> str or None:
        if not self.in_room():
            return

        return self.in_room().room_name

    def register(self, username, password, email, log_in=False) -> str:
        log.debug(f"Registering as {username}...")
        threading.current_thread().setName(f"U/{username}")

        self.set(
            username=username,
            password=password,
            email=email,
            id=increment_next_user_id(),
            registration_date=str(datetime.now()),
            rank="User"
        )

        try:
            os.mkdir(f"{USER_FILES_DIR}/{username}")
            os.mkdir(f"{USER_FILES_DIR}/{username}/deck")

        except FileExistsError:
            log.warning(f"Username dirs in user files already exist")

        # USERDATA_STORAGE.append(self.get_userdata()) not needed as user is in USERS
        log.debug(f"Registered")
        self.set_total_chips(random.randint(1, 1000))

        if log_in:
            return self.log_in(username)

    def clear_session_token(self) -> bool:
        if not self.session_token:
            log.debug(f"Not logged in")
            return False

        self.session_token = None
        log.debug(f"Cleared session token")
        return True

    def new_session_token(self) -> str:
        self.session_token = str(uuid.uuid1())
        log.debug(f"Set new session token")
        return self.session_token

    def verify_session_token(self, session_token) -> bool:
        return self.session_token and self.session_token == session_token

    def register_used_ip(self) -> bool:
        self.set(last_used_ip=self.ip)

        if self.ip in self.data.used_ips:
            return False

        self.data.used_ips.append(self.ip)
        log.debug(f"Appended used ips")
        return True

    def log_in(self, username) -> str:
        log.debug(f"Logging in as {username}...")
        threading.current_thread().setName(f"U/{username}")
        self.set_userdata(User.match(username=username))
        self.increment_log_ins()
        self.set(last_logged_in=str(datetime.now()))
        self.register_used_ip()

        return self.new_session_token()

    def log_out(self) -> bool:
        if not self.clear_session_token():
            return False

        room = self.in_room()
        if room:
            room.user_leave(self)

        self.set(last_online=str(datetime.now()))
        log.debug(f"Logged out")
        return True

    def increment_log_ins(self):
        self.data.log_ins += 1
        log.debug(f"Incremented log ins")

    def get_rank_prefix(self) -> str or None:
        if not self.data.rank_prefix:
            return "!@#$"  # None

        return str(self.data.rank_prefix)

    def remove_total_chips(self, amount) -> int:
        new = self.data.total_chips - amount
        if new < 0:
            new = 0

        return self.set(total_chips=new)

    def set_total_chips(self, amount) -> int:
        return self.set(total_chips=amount)

    def add_total_chips(self, amount) -> int:
        return self.set(total_chips=self.data.total_chips + amount)

    def increment_games_played(self) -> int:
        return self.set(games_played=self.data.games_played + 1)

    def increment_games_won(self) -> int:
        return self.set(games_won=self.data.games_won + 1)

    # process packet content

    def process_content(self, c):
        c_type = c["type"]

        if c_type == "check_update":
            self.send_content(
                "checked_update",
                ui_version=UI_VERSION,
                assets=[asset for asset in os.listdir(ASSETS_DIR)]
            )

            return

        if c_type == "get_assets":
            assets = c["assets"]
            files = []

            for asset in assets:
                file = dict()
                file["b64str"] = get_b64str(f"{ASSETS_DIR}/{asset}")
                file["filename"] = asset
                files.append(file)

            self.send_content(
                "got_assets",
                files=files
            )

            return

        if c_type == "log_in":
            username = c["username"]
            password = c["password"]

            if not username_valid(username) or not password_valid(password) or \
                    not User.match(username=username, password=password):
                raise Error("credentials_incorrect")

            else:
                self.send_content(
                    "logged_in",
                    metadata=["log_in"],
                    username=username,
                    session_token=self.log_in(username)
                )

            return

        if c_type == "register":
            username = c["username"]
            password = c["password"]
            repeat_password = c["repeat_password"]
            register_without_email = c["register_without_email"]

            if register_without_email:
                email = None

            else:
                email = c["email"]

            if not username_valid(username):
                raise Error("username_invalid")

            if not password_valid(password):
                raise Error("password_invalid")

            if not password == repeat_password:
                raise Error("password_repeat_doesnt_match")

            if email is not None and not email_valid(email):
                raise Error("email_invalid")

            if User.match(username=username):
                raise Error("username_taken")

            if email is not None and User.match(email=email):
                raise Error("email_taken")

            self.send_content(
                "logged_in",
                metadata=["register"],
                username=username,
                session_token=self.register(username, password, email, log_in=True)
            )

            return

        if c_type == "lookup_rooms":
            page = c["page"]
            sort_key = c["sort_key"]
            filtered_rooms = Room.get_filtered_rooms(c["hide_empty"], c["hide_full"], c["hide_protected"],
                                                     c["search_string"], c["show_only_official"], sort_key,
                                                     c["sort_reversed"])

            start_index = LOOKUP_ROOMS_MAX * (page - 1)
            end_index = LOOKUP_ROOMS_MAX * page

            if start_index >= len(filtered_rooms):
                indexed_rooms = filtered_rooms[:LOOKUP_ROOMS_MAX]

            else:
                indexed_rooms = filtered_rooms[start_index:end_index]

            self.send_content(
                "looked_up_rooms",
                rooms=indexed_rooms,
                total_rooms=len(ROOMS),
                page=page or 1,
                filtered_pages=math.ceil(len(filtered_rooms) / LOOKUP_ROOMS_MAX) or 1,
                sort_key=sort_key
            )

            return

        if c_type == "lookup_users":
            page = c["page"]
            username = c["username"]

            if not username:
                username = None

            filtered_usernames, total_usernames = User.lookup_user_query(username)

            start_index = LOOKUP_USERS_MAX * (page - 1)
            end_index = LOOKUP_USERS_MAX * page

            if start_index >= len(filtered_usernames):
                indexed_usernames = filtered_usernames[:LOOKUP_USERS_MAX]

            else:
                indexed_usernames = filtered_usernames[start_index:end_index]

            self.send_content(
                "looked_up_users",
                users=indexed_usernames,
                total_users=total_usernames,
                page=page or 1,
                filtered_pages=math.ceil(len(filtered_usernames) / LOOKUP_USERS_MAX) or 1,
            )

            return

        if c_type == "get_user_status":
            username = c["username"]
            metadata = c["metadata"]

            if not username:
                raise Error("username_not_given")

            userdata = User.match(username=username)

            if not userdata:
                raise Error("username_not_found")

            user = User.get_online_user(username)

            if "lookup" in metadata or "log_in" in metadata:
                games_played = userdata["games_played"]

                if user:
                    in_room_name = user.in_room_name()
                    is_online = True

                else:
                    in_room_name = None
                    is_online = False

                status = {
                    "in_room_name": in_room_name,
                    "is_online": is_online,
                    "games_played": games_played
                }

            elif "game" in metadata:
                by_username = self.data.username

                game = user.in_room().game
                total_chips = userdata["total_chips"]
                current_bet = game.get_current_bet(username)
                slot_card = game.get_hole_slot_card(username, by_username)

                status = {
                    "total_chips": total_chips,
                    "current_bet": current_bet,
                    "slot_card": slot_card
                }

            else:
                raise Error("client_metadata_invalid")

            self.send_content(
                "got_user_status",
                username=username,
                metadata=metadata,
                status=status
            )

            return

        if c_type == "get_user_files":
            file_types = c["file_types"]
            username = c["username"]

            if not username:
                raise Error("no_username_given")

            files = []

            for file_type in file_types:
                file = {}
                if file_type == "deck":
                    deck_b64str = {}
                    for card in CARDS:
                        b64str = get_b64str(f"{USER_FILES_DIR}/{username}/deck/{card}.png",
                                            f"{DEFAULT_USER_FILES_DIR}/deck/{card}.png")
                        deck_b64str[card] = b64str

                    file["deck_b64str"] = deck_b64str

                else:
                    b64str = get_b64str(f"{USER_FILES_DIR}/{username}/{file_type}.png",
                                        f"{DEFAULT_USER_FILES_DIR}/{file_type}.png")
                    file["b64str"] = b64str

                file["file_type"] = file_type
                files.append(file)

            self.send_content(
                "got_user_files",
                username=username,
                metadata=c["metadata"],
                files=files
            )

            return

        if not self.verify_session_token(c["session_token"]):  # REQ SESSION TOKEN C_TYPES
            raise Error("session_token_incorrect")

        if c_type == "join_room":
            metadata = c["metadata"]
            room_name = c["room_name"]

            if self.in_room():
                raise Error("room_already_connected")

            room = Room.get_room(room_name)

            if "create_room" in metadata:
                if not room_name_valid(room_name):
                    raise Error("room_name_invalid")

                if room:
                    raise Error("room_name_taken")

                room = Room.create(
                    room_name,
                    owner=self.data.username,
                    description="Ok"
                )

                room.user_join(self)
                self.send_content(
                    "room_update",
                    metadata=["user_joined", "create_room"],
                    username=self.data.username,
                    room_name=room_name,
                    description=room.description,
                    username_seat=room.username_seat
                )

                room.game.check_start()

            if "join_room" in metadata:
                password = c["password"]

                if not room:
                    raise Error("room_not_found")

                if room.protected and room.password != password:
                    raise Error("room_password_incorrect")

                if room.is_full():
                    raise Error("room_full")

                if room.game.state not in \
                        [GameState.STARTING, GameState.WAITING, GameState.ENDING]:
                    raise Error("game_running")

                room.user_join(self)

                room.send_content(
                    "room_update",
                    metadata=["user_joined", "join_room"],
                    username=self.data.username,
                    room_name=room_name,
                    description=room.description,
                    username_seat=room.username_seat
                )

            return

        if c_type == "leave_room":
            room = self.in_room()

            if not room:
                raise Error("room_not_connected")

            User.send_content_to(
                room.users,
                "room_update",
                username=self.data.username,
                metadata=["user_left"]
            )

            room.user_leave(self)

            return

        if c_type == "send_message":
            message = c["message"]
            metadata = c["metadata"]

            if "global" in metadata:
                send_to = USERS
                send_metadata = ["from_user", "global"]

            elif "room" in metadata:
                room = self.in_room()

                if not room:
                    raise Error("room_not_connected")

                send_to = room.users
                send_metadata = ["from_user", "room"]

            elif "private" in metadata:
                to_user = c["to_user"]
                user = User.get_online_user(to_user)

                if not user:
                    raise Error("username_not_found")

                send_to = [self, user]
                send_metadata = ["from_user", "private"]

            else:
                raise Error("client_metadata_invalid")

            User.send_content_to(
                send_to,
                "receive_message",
                metadata=send_metadata,
                message=message,
                author=self.data.username,
                rank_prefix=self.get_rank_prefix()
            )

            return

        if c_type == "upload":
            file_type = c["file_type"]
            username = self.data.username

            if file_type == "deck":
                deck_b64str = c["b64str_object"]
                if sorted(list(deck_b64str.keys())) != CARDS:
                    raise Error("deck_invalid")

                for card, b64str in deck_b64str.items():
                    with open(f"{USER_FILES_DIR}/{username}/{card}.png", "wb") as f:
                        f.write(b64str_to_bytes(b64str))

            elif file_type in ["avatar", "background", "table"]:
                b64str = c["b64str_object"]
                with open(f"{USER_FILES_DIR}/{username}/{file_type}.png", "wb") as f:
                    f.write(b64str_to_bytes(b64str))

            else:
                raise Error("client_packet_invalid")

            self.send_content(
                "uploaded",
                file_type=file_type
            )

            return

        if c_type == "get_room_info":
            room = self.in_room()

            self.send_content(
                "got_room_info",
                room_name=room.room_name,
                description=room.description,
                country=room.country
            )

            return

        if c_type == "get_game_info":
            game = self.in_room().game
            community_slot_card = game.get_community_slot_card()

            self.send_content(
                "got_game_info",
                stage=game.state.value,
                community_slot_card=community_slot_card,
                pot=game.pot
            )

            return

        raise Error("client_content_type_invalid")


class GameState(Enum):
    WAITING = "waiting"
    STARTING = "starting"
    STARTED = "started"
    ENDING = "ending"


class BaseGame:
    def __init__(self, room: Room):
        # super(PokerGame, self).__init__(room)
        self.room = room
        self.state = GameState.WAITING
        self.min_players = 1
        self.players_in_round = []
        self.thread = None
        self.stop = False

    def __str__(self):
        return self.room.room_name

    def send_update(self, **key_value):
        self.room.send_content(
            "game_update",
            **key_value
        )

    def check_start(self, seconds=3, force=False):
        if self.state == GameState.WAITING and not self.thread:
            self.thread = start_thread(self._starting_thread, args=(seconds, force), name=f"G{self}")

        elif len(self.room.username_seat) < self.min_players:
            self.stop = True

    def _starting_thread(self, seconds, force):
        self.state = GameState.STARTING
        time_left = 0 if force else seconds

        while time_left:
            if time_left == seconds or 1 <= time_left <= 3 or time_left % 5 == 0:
                log.debug(f"Starting timer: {time_left}s left")

                self.send_update(
                    metadata=["starting"],
                    time_left=time_left
                )

            time.sleep(1)
            time_left -= 1

            if self.stop:
                self.state = GameState.WAITING
                log.debug("Stopped starting timer")
                return

        self.state = GameState.STARTED
        self.players_in_round = list(self.room.username_seat.keys())

        for player in self.players_in_round:
            User.get_online_user(player).increment_games_played()

        log.info("Game started")
        self.send_update(
            metadata=["started"]
        )

        self.start()

    def start(self):
        pass

    def end(self, winning_users=None, seconds=3, force=False):
        if winning_users:
            for user in winning_users:
                user.increment_games_won()

        start_thread(self._ending_thread, args=(seconds, force), name=f"G/{self.room}e")

    def _ending_thread(self, seconds=3, force=False):
        self.state = GameState.ENDING
        time_left = 0 if force else seconds

        while time_left:
            if time_left == seconds or 1 <= time_left <= 3 or time_left % 5 == 0:
                log.debug(f"Ending timer: {time_left}s left")

                self.send_update(
                    metadata=["ending"],
                    time_left=time_left
                )

            time.sleep(1)
            time_left -= 1

            if self.stop:
                log.debug("Stopped ending timer")
                break

        self.players_in_round.clear()

        log.info("Game ended")
        self.send_update(
            metadata=["ended"]
        )

        self.state = GameState.WAITING
        self.check_start()


class PokerGame(BaseGame):
    def __init__(self, room):
        super(PokerGame, self).__init__(room)
        self.min_players = 1
        self.username_seat = {}
        self.username_cards = {}
        self.username_cards_2char = {}
        self.username_visible_cards = {}
        self.username_current_bet = {}
        self.evaluator = Evaluator()
        self.deck = None
        self.community_cards = []
        self.community_cards_2char = []
        self.pot = 100

    class State(Enum):
        DEALING_CARDS = "dealing_cards"
        PREFLOP = "preflop"
        FLOP = "flop"
        TURN = "turn"
        RIVER = "river"
        SHOWDOWN = "showdown"

    def get_current_bet(self, username):
        try:
            return self.username_current_bet[username]

        except KeyError:
            return -1

    def get_community_slot_card(self):
        if self.state in [self.State.SHOWDOWN, self.State.RIVER, GameState.ENDING]:
            count = 5

        elif self.state in [self.State.TURN]:
            count = 4

        elif self.state in [self.State.FLOP]:
            count = 3

        else:
            count = 0

        cards = self.community_cards_2char[:count]

        slot_card = {}
        for i in range(1, 6):
            try:
                slot_card[i] = cards[i - 1]

            except IndexError:
                slot_card[i] = None

        return slot_card

    def get_hole_slot_card(self, username, by_username):
        try:
            cards = self.username_cards_2char[username]

        except KeyError:
            return {1: None, 2: None}

        own_cards = username == by_username

        slot_card = {
            1: cards[0] if self.username_visible_cards[username][0] or own_cards else "back",
            2: cards[1] if self.username_visible_cards[username][1] or own_cards else "back"
        }

        return slot_card

    def start(self):
        self.username_seat = self.room.username_seat
        for username in self.username_seat.keys():
            User.get_online_user(username).remove_total_chips(10)
            self.username_visible_cards[username] = [False, False]

        self.deck = Deck()
        self.community_cards = self.deck.draw(5)
        self.community_cards_2char = [convert_card_to_2char(card) for card in self.community_cards]
        self.deal_cards()

    def deal_cards(self):
        self.state = self.State.DEALING_CARDS
        for username, seat in self.username_seat.items():
            cards = self.deck.draw(2)
            self.username_cards[username] = cards
            cards_2char = [convert_card_to_2char(card) for card in cards]
            self.username_cards_2char[username] = cards_2char
            log.debug(f"{username}'s cards: {cards_2char}")

        self.send_update(
            metadata=["dealt_cards"]
        )

        self.next_stage()

    def betting_round(self):
        self.send_update(
            metadata=["betting_round"]
        )
        time.sleep(3)
        self.next_stage()

    def next_stage(self):
        if self.state == PokerGame.State.RIVER:
            self.state = PokerGame.State.SHOWDOWN
            self.evaluate_winner()

            return

        if self.state == PokerGame.State.DEALING_CARDS:
            self.state = PokerGame.State.PREFLOP

        elif self.state == PokerGame.State.PREFLOP:
            self.state = PokerGame.State.FLOP

        elif self.state == PokerGame.State.FLOP:
            self.state = PokerGame.State.TURN

        elif self.state == PokerGame.State.TURN:
            self.state = PokerGame.State.RIVER

        else:
            log.critical(f"Invalid PokerGame state: {self.state}")
            self.end()
            return

        self.send_update(
            metadata=["next_stage"]
        )

        time.sleep(1)
        self.betting_round()

    def evaluate_winner(self):
        best_rank = 7463
        winners = []
        for username, cards in self.username_cards.items():
            self.username_visible_cards[username] = [True, True]
            rank = self.evaluator.evaluate(cards, self.community_cards)
            if rank == best_rank:
                winners.append(username)

            elif rank < best_rank:
                winners = [username]
                best_rank = rank

        winning_rank_str = self.evaluator.class_to_string(self.evaluator.get_rank_class(best_rank))
        winning_rank_percentage = (1.0 - self.evaluator.get_five_card_rank_percentage(best_rank)) * 100.0

        winners_joint = ", ".join(winners)

        log.info(
            f"G-{self} Player(s) {winners_joint} win(s) with a {winning_rank_str} (rank: {best_rank}, "
            f"%: {winning_rank_percentage})"
        )

        self.send_update(
            metadata=["hand_winners"],
            winners=winners,
            winning_rank=winning_rank_str
        )

        winning_users = []
        for username in winners:
            user = User.get_online_user(username)
            user.add_total_chips(self.pot)
            winning_users.append(user)

        time.sleep(3)

        self.end(winning_users)


class Packet:
    HEADER_PART_SIZE = 8
    HEADER_SIZE = HEADER_PART_SIZE * 2
    PACKET_SIZE_MAX = 10485760

    def __init__(self, content=None, header_bytes=None):
        # log.debug("Packet initializing...")

        if content:  # send packet
            self.id = increment_next_packet_id()
            self.content = content
            content_str = json.dumps(self.content)
            self.size = len(content_str)
            self.header_size_zfill = str(self.size).zfill(Packet.HEADER_PART_SIZE)
            self.header_id_zfill = str(self.id).zfill(Packet.HEADER_PART_SIZE)
            self.header = self.header_size_zfill + self.header_id_zfill
            self.encoded = self.header.encode() + content_str.encode()

        elif header_bytes:  # receive packet
            self.header = header_bytes.decode()
            self.header_size_zfill = self.header[:Packet.HEADER_PART_SIZE]
            self.header_id_zfill = self.header[Packet.HEADER_PART_SIZE:]

            try:
                self.size, self.id = int(self.header_size_zfill),\
                                     int(self.header_id_zfill)

            except ValueError as ex:
                raise Error("client_packet_header_invalid") from ex

            if self.size > Packet.PACKET_SIZE_MAX:
                raise Error("client_packet_maximum_size")

            self.bytes = b""
            self.bytes_left = 0
            self.update_bytes(bytes_expected=False)

        else:
            raise Error("packet_creation_error")

        # log.debug(f"P/{self} Initialized")

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
            raise Error("client_packet_no_bytes")  # else finished receiving

        # log.debug(f"P/{self} Total bytes: {len(self.bytes)}/{self.size}")
        self.bytes_left = self.size - len(self.bytes)

    def decon(self):
        # log.debug(f"P/{self} Deconning...")
        content_str = self.bytes.decode()
        content = json.loads(content_str)
        self.content = content
        # log.debug(f"P/{self} Deconned")


class Server:
    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.bind(("", HOST_PORT))

        except OSError as ex:
            logging.error(f"Failed to bind socket to port, exiting ({ex.__class__.__name__})")
            sys.exit()

        self.socket.listen(SOCKET_BACKLOG)
        start_thread(self.accept_connection_loop, name="Accept loop")

        log.info(f"Ready on port {HOST_PORT}, type \"help\" for commands")

        while True:
            try:
                command_input()

            except IndexError:
                log.info("Commands: help, stop, save, user, room, say")

            except SystemExit:
                break

    def accept_connection_loop(self):
        while True:
            user = User(self.socket.accept())
            start_thread(user.receive_loop, name=f"U/{user}")


def command_input():
    command = input()
    log.info(command)
    cs = command.split()
    cl = len(cs)

    if cs[0] == "help":
        if cs[1] == "user":
            log.info(
                "list\n"
                "message <user> <message...>"
            )

        elif cs[1] == "room":
            log.info(
                "set <room_name> <key> <value>\n"
                "create <room_name>\n"
                "delete <room_name>\n"
                "list\n"
                "message <room> <message...>"
            )

        else:
            log.info("Commands: help, stop, save, user, room, say")

    if cs[0] == "stop":
        write_disk_data(stop=True)

    if cs[0] == "save":
        write_disk_data()

    if cs[0] == "user":
        if cs[1] == "list":
            log.info(f"Users ({len(USERS)}):\n" +
                     ("\n".join([str(user) for user in USERS])))

        if cl >= 4 and cs[1] == "message":
            username = cs[2]
            user = User.get_online_user(username)
            if user:
                user.send_content(
                    "receive_message",
                    message=" ".join(cs[3:]),
                    metadata=["from_server", "private"]
                )

            elif User.match(username=username):
                log.info("User is offline")

            else:
                log.info("User doesn't exist")

    if cs[0] == "room":
        if cl == 3 and cs[1] == "create":
            Room.create(
                cs[2],
                official=True
            )

        elif cl >= 4 and cs[1] == "set":
            room: Room = Room.get_room(cs[2])
            if room:
                key = cs[3]
                if key == "password":
                    if cl == 4:
                        password = None

                    else:
                        password = cs[4]

                    room.set(
                        has_password=password or False,
                        password=password
                    )

                elif key in ["max_players"]:  # ints
                    room.set(
                        key=int(cs[4])
                    )

                else:  # if key in room.data_keys, set key=cs[4]
                    log.info("Invalid room key")

            else:
                log.info("Room not found")

        elif cl == 3 and cs[1] == "delete":
            if Room.exists(cs[2]):
                Room.delete(cs[2])

            else:
                log.info("Room not found")

        elif cl >= 4 and cs[1] == "message":
            room = Room.get_room(cs[2])
            if room:
                User.send_content_to(
                    room.users,
                    "receive_message",
                    message=" ".join(cs[3:]),
                    metadata=["from_server", "room"]
                )

            else:
                log.info("Room not found")

        elif cl == 2 and cs[1] == "list":
            log.info(f"Rooms ({len(ROOMS)}):\n" +
                     ("\n".join([str(room) for room in ROOMS])))

    if cs[0] == "say":
        User.send_content_to(
            USERS,
            "receive_message",
            message=" ".join(cs[1:]),
            metadata=["from_server", "global"]
        )


USERS: List[User] = []
USERDATA_STORAGE = []
ROOMS: List[Room] = []
read_disk_data()
Room.create_default_rooms(5)

Server()
