import socket
import sys
import math
import os
from datetime import datetime
import random
from enum import Enum
import uuid
from inspect import isroutine, getmembers, getframeinfo, currentframe

from utils import *
from error_message import *

from customdeuces import Deck, Evaluator, convert_card_to_2char

_gfi = getframeinfo
_cf = currentframe

debug(f"[test msg] {_gfi(_cf()).lineno}")


PORT = 2000
SOCKET_BACKLOG = 10
RECV_BYTES_MAX = 1048576

CLIENTS = []
USERS = []
ROOMS = []


PACKETS_PROCESSED = get_data()["processed_packets"]


def inc_packets_processed():
    global PACKETS_PROCESSED
    PACKETS_PROCESSED += 1

    return PACKETS_PROCESSED


def save_data(stop=False):
    all_userdata = []
    for user in USERS:
        to_append_userdata = {}
        for k in USERDATA_KEYS:
            to_append_userdata[k] = user.__getattribute__(k)
        all_userdata.append(to_append_userdata)

    data = {
        "write_date": str(datetime.now()),
        "processed_packets": PACKETS_PROCESSED,
        "next_user_id": User.get_next_user_id(),
        "users": all_userdata
    }

    with open(DATA_PATH, "w") as f:
        json.dump(data, f, indent=2)

    log(f"Saved data")

    if stop:
        sys.exit()


def error_packet(error):
    return {"type": "error", "error": error}


class Client:
    def __init__(self, conn, addr):
        self.conn = conn
        self.addr = addr
        self.from_ip = addr[0]
        self.from_port = addr[1]
        self.addr_format = f"{self.from_ip}:{self.from_port}"
        self.session_token = None
        self.debug(f"Connected")

    def debug(self, o):
        debug(o, debug_suffix=f"/CLIENT/{self.addr_format}")

    def disconnect(self):
        for client in CLIENTS:
            if client.conn == self.conn:
                if client.session_token:
                    User.get_from_session_token(client.session_token).log_out()

                CLIENTS.remove(client)
                self.debug(f"Disconnected successfully")

                return

    def send(self, sp):
        Client.send_to_clients([self], sp)

    @staticmethod
    def send_to_clients(client_list, sp):
        sp_str = json.dumps(sp)
        total = len(client_list)
        success = 0
        sp_len = len(sp_str)
        header = f"{sp_len:07d}"

        for client in client_list:
            try:
                client.conn.send(header.encode() + sp_str.encode())

            except ConnectionResetError as ex:
                debug_client(f"ConnectionResetError: {ex}")
                client.disconnect()

            else:
                success += 1
                debug_client(f"Sent packet, len: {sp_len}")

        return success, total

    @staticmethod
    def send_all_clients(sp):
        Client.send_to_clients(CLIENTS, sp)

    def handler(self):
        self.debug(f"Awaiting data...")

        while True:
            try:
                header_str = self.conn.recv(7).decode()
                header = int(header_str)

            except ConnectionResetError as ex:
                self.debug(f"ConnectionResetError: {ex}")
                self.disconnect()
                break

            except socket.error as ex:
                self.debug(f"socket.error: {ex}")
                break

            except ValueError as ex:
                self.debug(f"ValueError: {ex} (ignoring packet)")
                continue

            '''
            except Exception as ex:
                self.debug(f"Unhandled exception when receiving packet header: {ex}")
                break
            '''

            self.debug(f"Receiving packet with length {header}...")

            if header > RECV_BYTES_MAX:
                self.debug(f"Header exceeds RECV_BYTES_MAX ({RECV_BYTES_MAX}) (ignoring packet)")
                continue

            p_bytes = b""
            while len(p_bytes) < header:
                recv_bytes = self.conn.recv(header - len(p_bytes))
                if not recv_bytes:
                    break  # received all bytes

                p_bytes += recv_bytes
                self.debug(f"Received packet bytes: {len(p_bytes)}/{header}")

            if not p_bytes:
                self.debug(f"Connection lost: empty packet")
                self.disconnect()
                break

            packet_num = inc_packets_processed()
            self.debug(f"Received packet #{packet_num}")

            try:
                p = decon_packet(p_bytes)

            except json.JSONDecodeError as ex:
                self.debug(f"json.JSONDecodeError: {ex} (ignoring packet)")
                continue

            if not p:
                self.debug("Packet somehow empty (ignoring packet)")
                continue

            sp = process_packet(self, p)

            if sp:
                mod_sp = sp.copy()
                for k in sp.keys():
                    if "b64str" in k:
                        mod_sp[k] = "<b64str filtered>"

                self.send(sp)

            self.debug(f"Processed packet #{packet_num}, sp: {mod_sp}")


def process_server_command(cs):
    cl = len(cs)
    if cl == 0:
        print("invalid command")
        return False

    if cs[0] in ["?", "help"]:
        print("Commands: stop, save, users, user, rooms, room, sayr, say")
        return True

    if cs[0] in ["q", "quit", "exit", "stop"]:
        save_data(stop=True)
        return True

    if cs[0] in ["save", "savedata"]:
        save_data()
        return True

    if cs[0] in ["user", "users"]:
        print("Users:")
        for user in USERS:
            print(f"{user.username}: (regdate: {user.register_date}, session: {user.session_token})")

        return True

    if cs[0] in ["room", "rooms"]:
        if cl == 1:
            print("room set <room_name> <key> <value>/delete <room_name>/list")
            return False

        if cl == 3 and cs[1] in ["create", "add"]:
            Room.create(cs[2], {"official": True})
            return True

        if cl == 5 and cs[1] in ["set", "setting", "option"]:
            if Room.exists(cs[2]):
                room = Room.get_room(cs[2])
                if cs[3] in ["room_name", "description", "owner", "country", "password", "max_players"]:
                    if cs[3] in ["password"]:
                        room.set_m({"has_password": True, "password": cs[4]})
                        return True

                    if cs[3] in ["max_players"]:
                        room.set("max_players", int(cs[4]))
                        return True

                    room.set(cs[3], cs[4])
                    return True

                print("invalid room key")
                return False

            print("room not found")
            return False

        if cl == 3 and cs[1] in ["remove", "delete"]:
            if Room.exists(cs[2]):
                Room.delete(cs[2])
                return True

            print("room not found")
            return False

        if cl == 2 and cs[1] in ["list", "show"]:
            print(f"{len(ROOMS)} rooms total,", ", ".join([f"{room.room_name}: [{', '.join(room.players)}]" for room in ROOMS]))
            return True

    if cs[0] in ["say", "message", "msg"]:
        if cl == 1:
            print("say <message>")
            return False

        Client.send_to_clients(CLIENTS, {"type": "server_global_message", "message": " ".join(cs[1:]), "server_send_date": str(datetime.now())})

        return True

    if cs[0] in ["sayr", "sayroom", "msgroom", "messageroom"]:
        if cl < 3:
            print("sayr <room> <message>")
            return False

        room = Room.get_room(cs[1])

        if not room:
            print("invalid room")
            return False

        room.send_to_room({"type": "server_room_message", "message": " ".join(cs[2:]), "server_send_date": str(datetime.now())})

        return True

    print("Invalid command")
    return False


class Server:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rooms = []

    def __init__(self):
        try:
            self.sock.bind(("", PORT))

        except OSError as ex:
            log(f"Failed to bind socket: {ex}")
            sys.exit()

        self.sock.listen(SOCKET_BACKLOG)

        port = self.sock.getsockname()[1]
        new_thread(self.accept_client_loop)

        log(f"Server ready on port {port}, type help for commands")

        while True:
            command = input()
            cs = command.split()
            if process_server_command(cs):
                log("Command OK")

    def accept_client_loop(self):
        while True:
            conn, addr = self.sock.accept()
            client = Client(conn, addr)

            CLIENTS.append(client)
            new_thread(client.handler)


def process_packet(client: Client, p: dict):
    debug_packet("Processing...")
    try:
        p_type = p["type"]

    except KeyError:
        return {"error": err_packet_invalid}

    if p_type == "log_in":
        username = p["username"]
        password = p["password"]

        if not User.exists(username):
            return error_packet(err_username_not_found)

        user = User.get_from_username(username)

        if not user.password == password:
            return error_packet(err_password_incorrect)

        session_token = user.log_in(client.from_ip)
        client.session_token = session_token

        return {
            "type": "log_in_success",
            "username": username,
            "session_token": session_token
        }

    if p_type == "request_cards":
        # session_token = p["session_token"]
        # user = User.get_from_session_token(session_token)

        card_code_b64str_dict = {}

        for filename in os.listdir("client_defaults/card"):
            card_code = filename.split(".")[0]

            card_code_b64str_dict[card_code] = get_b64str(f"client_defaults/card/{filename}")

        return {
            "type": "request_cards_success",
            "card_code_b64str_dict": card_code_b64str_dict
        }

    if p_type == "register":
        username = p["username"]
        password = p["password"]
        email = p["email"]
        repeat_password = p["repeat_password"]
        register_without_email = p["register_without_email"]

        if not valid_username_length(username):
            return error_packet(err_username_length_invalid)

        if not valid_username_characters(username):
            return error_packet(err_username_characters_invalid)

        if not valid_password_length(password):
            return error_packet(err_password_length_invalid)

        if not passwords_match(password, repeat_password):
            return error_packet(err_passwords_dont_match)

        if not valid_email(email) and not register_without_email:
            return error_packet(err_email_invalid)

        if User.exists(username):
            return error_packet(err_username_taken)

        if register_without_email:
            email = None

        elif User.email_is_taken(email):
            return error_packet(err_email_taken)

        user = User.register(username, password, email)
        user.set_total_chips(random.randint(1, 1000))
        session_token = user.log_in(client.from_ip)
        client.session_token = session_token

        return {
            "type": "register_success",
            "username": username,
            "session_token": session_token
        }

    if p_type == "join_room":
        room_name = p["room_name"]
        password = p["password"]
        user_role = p["user_role"]
        session_token = p["session_token"]
        user = User.verify_session_token(session_token)
        room = Room.get_room(room_name)

        if not user:
            return error_packet(err_session_invalid)

        if not Room.exists(room_name):
            return error_packet(err_room_not_found)

        if Room.user_is_in_room(user):
            return error_packet(err_room_already_connected)

        if user_role == "player" and room.all_seats_taken():
            return error_packet(err_room_full)

        if room.has_password and room.password != password:
            return error_packet(err_room_password_incorrect)

        if not (room.game.state == GameState.STARTING or room.game.state == GameState.WAITING):
            user_role = "spectator"

        room.user_join(user, user_role)

        room_sp = {
            "type": "user_joined_room",
            "username": user.username,
            "user_role": user_role,
            "seats_usernames": room.get_seats_usernames()
        }

        room.send_to_clients(room_sp)

        return {
            "type": "join_room_success",
            "user_role": user_role,
            "room_name": room_name,
            "seats_usernames": room.get_seats_usernames()
        }

    if p_type == "create_room":
        room_name = p["room_name"]
        session_token = p["session_token"]
        user = User.verify_session_token(session_token)

        if not user:
            return error_packet(err_session_invalid)

        if Room.exists(room_name):
            return error_packet(err_room_name_taken)

        if Room.user_is_in_room(user):
            return error_packet(err_room_already_connected)

        room = Room.create(room_name, {"owner": user.username})
        user_role = "player"
        room.user_join(user, user_role)

        return {
            "type": "create_room_success",
            "user_role": user_role,
            "room_name": room_name,
            "seats_usernames": room.get_seats_usernames()
        }

    if p_type == "leave_room":
        session_token = p["session_token"]
        user: User = User.verify_session_token(session_token)

        if not user:
            return error_packet(err_session_invalid)

        if not Room.user_is_in_room(user):
            return error_packet(err_room_not_connected)

        room: Room = Room.get_room(user.in_room_name)

        if user in room.spectators:
            user_role = "spectator"
            seat = None

        else:
            user_role = "player"
            seat = int(room.get_seat(user))

        room.user_leave(user)

        room_sp = {
            "type": "user_left_room",
            "username": user.username,
            "user_role": user_role,
            "seat": seat,
            "seats_usernames": room.get_seats_usernames()
        }

        room.send_to_clients(room_sp)

        return {
            "type": "leave_room_success",
            "room_name": room.room_name
        }

    if p_type == "get_rooms":
        page_number = p["page_number"]

        if not page_number:
            page_number = 1

        filtered_rooms = Room.get_filtered_rooms(p)

        start_index = ROOM_GET_MAX_COUNT * (page_number - 1)
        end_index = ROOM_GET_MAX_COUNT * page_number

        indexed_rooms = filtered_rooms[start_index:end_index]
        if not indexed_rooms:
            indexed_rooms = filtered_rooms[:ROOM_GET_MAX_COUNT]
            page_number = 1

        return {
            "type": "get_rooms_success",
            "rooms": indexed_rooms,
            "sort_key": p["sort_key"],
            "page_number": page_number,
            "total_pages": math.ceil(len(filtered_rooms) / ROOM_GET_MAX_COUNT) or 1,
            "total_filtered_rooms": len(filtered_rooms),
            "total_rooms": len(ROOMS)
        }

    if p_type == "send_message":
        session_token = p["session_token"]
        message_type = p["message_type"]
        message = p["message"]

        if not message:
            return err_packet_invalid(err_message_empty)

        from_user = User.get_from_session_token(session_token)

        if not from_user:
            return error_packet(err_session_invalid)

        if message_type == "global":
            global_sp = {
                "type": "user_message",
                "message_type": "global",
                "username": from_user.username,
                "message": p["message"],
                "client_send_date": p["send_date"],
                "server_send_date": str(datetime.now())
            }

            Client.send_all_clients(global_sp)

            return {
                "type": "send_message_success"
            }

        if message_type == "room":
            room_name = from_user.in_room_name
            if not room_name:
                return error_packet(err_room_not_connected)

            room = Room.get_room(room_name)

            room_sp = {
                "type": "user_message",
                "message_type": "room",
                "username": from_user.username,
                "message": p["message"],
                "client_send_date": p["send_date"],
                "server_send_date": str(datetime.now())
            }

            room.send_to_clients(room_sp)

            return {
                "type": "send_message_success"
            }

        else:
            return error_packet(err_packet_invalid)

    if p_type == "search_user":
        page_number = p["page_number"]
        username_query = p["username_query"]

        if not page_number:
            page_number = 1

        filtered_usernames = User.find_matching_usernames(username_query)

        start_index = USER_GET_MAX_COUNT * (page_number - 1)
        end_index = USER_GET_MAX_COUNT * page_number

        indexed_users = filtered_usernames[start_index:end_index]

        if not indexed_users:
            indexed_users = indexed_users[:USER_GET_MAX_COUNT]
            page_number = 1

        return {
            "type": "search_user_success",
            "usernames": indexed_users,
            "page_number": page_number,
            "total_pages": math.ceil(len(filtered_usernames) / USER_GET_MAX_COUNT) or 1,
            "total_filtered_users": len(filtered_usernames),
            "total_users": len(USERS)
        }

    if p_type == "user_stats":
        username = p["username"]
        # session_token = p["session_token"]

        user = User.get_from_username(username)
        total_chips = user.total_chips
        games_played = user.games_played
        room = Room.get_room(user.in_room_name)

        if room:
            seat = room.get_seat(user)
        else:
            seat = None

        return {
            "type": "user_stats_success",
            "request_origin": p["request_origin"],
            "username": user.username,
            "games_played": games_played,
            "total_chips": total_chips,
            "seat": seat,
            "current_bet": 0
        }

    if p_type == "user_avatar":
        request_origin = p["request_origin"]
        username = p["username"]

        if request_origin in ["game", "community"]:
            user = User.get_from_username(username)
            avatar_b64str = get_b64str(f"userdata/{username}/avatar.png", "client_defaults/avatar.png")

            if request_origin == "game":
                room = Room.get_room(user.in_room_name)

                if room:
                    seat = room.get_seat(user)
                else:
                    seat = None

                return {
                    "type": "user_avatar_success",
                    "request_origin": "game",
                    "avatar_b64str": avatar_b64str,
                    "seat": seat,
                }

            if request_origin == "community":
                return {
                    "type": "user_avatar_success",
                    "request_origin": "community",
                    "avatar_b64str": avatar_b64str,
                }

        if request_origin == "profile":
            session_token = p["session_token"]
            user = User.get_from_session_token(session_token)

            avatar_b64str = get_b64str(f"userdata/{user.username}/avatar.png", "client_defaults/avatar.png")

            return {
                "type": "user_avatar_success",
                "request_origin": "profile",
                "avatar_b64str": avatar_b64str,
            }

    if p_type == "user_card_back":
        username = p["username"]
        # session_token = p["session_token"]

        user = User.get_from_username(username)
        room = Room.get_room(user.in_room_name)

        if room:
            seat = room.get_seat(user)
        else:
            seat = None

        card_back_b64str = get_b64str(f"userdata/{username}/card_back.png", "client_defaults/card_back.png")

        return {
            "type": "user_card_back_success",
            "request_origin": p["request_origin"],
            "username": user.username,
            "card_back_b64str": card_back_b64str,
            "seat": seat,
        }

    if p_type == "user_card":
        username = p["username"]
        # session_token = p["session_token"]

        user = User.get_from_username(username)
        room = Room.get_room(user.in_room_name)

        if room:
            seat = room.get_seat(user)
        else:
            seat = None

        card_code = p["card_code"]
        card_b64str = get_b64str(f"userdata/{username}/card/{card_code}.png", f"client_defaults/card/{card_code}.png")

        return {
            "type": "user_card_success",
            "request_origin": p["request_origin"],
            "username": user.username,
            "card_b64str": card_b64str,
            "card_code": card_code,
            "card_number": p["card_number"],
            "seat": seat,
        }

    if p_type == "upload_file":
        file_b64str = p["file_b64str"]
        file_b64bytes = file_b64str.encode()
        file_bytes = base64.b64decode(file_b64bytes)
        purpose = p["purpose"]
        # metadata = p["metadata"]
        session_token = p["session_token"]
        from_user = User.get_from_session_token(session_token)
        from_username = from_user.username

        if purpose == "avatar":
            if not os.path.exists(f"userdata/{from_username}"):
                os.mkdir(f"userdata/{from_username}")

            with open(f"userdata/{from_username}/avatar.png", "wb") as f:
                f.write(file_bytes)

            return {
                "type": f"upload_{purpose}_success"
            }

    if p_type == "request_file":
        filename = p["filename"]

        file_b64str = get_b64str(f"{filename}")

        return {
            "type": "request_file_success",
            "filename": filename,
            "file_b64str": file_b64str
        }

    if p_type == "client_error":
        error = p["error"]
        debug(f"Client received error: {error}")

        return

    return error_packet(err_packet_invalid)


class UserdataVariables:
    username = None

    country = None
    email = None
    friends_added = []
    games_played = 0
    in_room = False
    in_room_name = None
    is_online = False
    last_ip = None
    last_logged_in = None
    last_online = None
    logged_in_amount = 0
    password = None
    register_date = None
    session_token = None
    session_token_date = None
    total_chips = 0
    total_chips_won = 0
    used_ips = []
    user_id = None
    users_blocked = []


class User(UserdataVariables):
    NEXT_USER_ID = None

    def __init__(self, userdata: dict = None):
        if userdata:
            self.set_m(userdata)

        USERS.append(self)
        self.debug(f"Initialized")

    def debug(self, o):
        debug(o, debug_suffix=f"/USER/{self.username}")

    @staticmethod
    def _load_userdata_from_disk():
        data = get_data()

        User.NEXT_USER_ID = data["next_user_id"]

        for userdata in data["users"]:
            User(userdata)

    @staticmethod
    def get_from_username(username):
        for user in USERS:
            if user.username == username:
                user.debug(f"Got user")
                return user

    @staticmethod
    def get_from_session_token(session_token):
        if session_token:
            for user in USERS:
                if user.session_token == session_token:
                    user.debug(f"Got user")
                    return user

    def get(self, k):
        return self.__getattribute__(k)

    def set(self, k, v):
        self.__setattr__(k, v)

    def set_m(self, k_v: dict):
        for k, value in k_v.items():
            self.__setattr__(k, value)

    @staticmethod
    def user_key_value_match(k, value):
        for user in USERS:
            if user.__getattribute__(k) == value:
                user.debug(f"k/v match (k: {k}, v: {value})")
                return user

    @staticmethod
    def exists(username):
        found_user = User.user_key_value_match("username", username)

        if found_user:
            found_user.debug(f"Exists")
            return True

        debug(f"User {username} does not exist")
        return False

    @staticmethod
    def email_is_taken(email):
        if User.user_key_value_match("email", email):
            return True

        return False

    @staticmethod
    def increment_next_user_id(inc_value=1):
        old_value = User.NEXT_USER_ID
        User.NEXT_USER_ID += inc_value

        debug(f"Incremented nuid: old {old_value} new {User.NEXT_USER_ID}")
        return old_value

    @staticmethod
    def get_next_user_id():
        return User.NEXT_USER_ID

    @staticmethod
    def register(username, password, email=None):
        user_id = User.increment_next_user_id()

        new_user = User()

        update = {
            "username": username,
            "password": password,
            "user_id": user_id,
            "email": email,
            "register_date": str(datetime.now()),
        }

        new_user.set_m(update)

        new_user.debug(f"Registered")

        return new_user

    def reset_session_token(self):
        k_v = {
            "session_token": None,
            "session_token_date": None,
        }

        self.set_m(k_v)

    @staticmethod
    def verify_session_token(session_token):
        user = User.get_from_session_token(session_token)

        if not user:
            debug(f"Could not verify session token {session_token}")

            return

        user.debug(f"Verified session token {session_token}")

        return user

    def set_new_session_token(self):
        session_token = str(uuid.uuid1())

        k_v = {
            "session_token": session_token,
            "session_token_date": str(datetime.now())
        }

        self.set_m(k_v)

        self.debug(f"Set session")

        return session_token

    def add_used_ip(self, ip: str):
        self.last_ip = ip

        if ip not in self.used_ips:
            self.used_ips.append(ip)

        else:
            self.debug(f"IP {ip} already used")

            return

        self.debug(f"Added used IP {ip}")

    @staticmethod
    def find_matching_usernames(query_username):
        sorted_usernames = sorted(USERS, key=lambda u: u.get("username"))
        found_usernames = []
        for user in sorted_usernames:
            if query_username in user.username:
                found_usernames.append(user.username)

        return found_usernames

    def log_in(self, from_ip: str=None):
        self.reset_session_token()
        self.set_new_session_token()
        self.increment_log_in_amount()

        k_v = {
            "is_online": True,
            "last_logged_in": str(datetime.now())
        }
        self.set_m(k_v)

        if from_ip:
            self.add_used_ip(from_ip)

        self.debug(f"Logged in")

        return self.session_token

    def log_out(self):
        if self.in_room:
            Room.get_room(self.in_room_name).user_leave(self)

        self.reset_session_token()

        k_v = {
            "is_online": False,
            "last_online": str(datetime.now())
        }
        self.set_m(k_v)

        self.debug(f"Logged out")

    def increment_log_in_amount(self, amount=1):
        self.logged_in_amount += amount

        self.debug(f"Set log in amount of user {self.username} to {self.logged_in_amount}")

        return self.logged_in_amount

    @staticmethod
    def session_token_in_room(session_token, room_name):
        user = User.get_from_session_token(session_token)
        result = user.in_room_name == room_name

        if result:
            user.debug(f"In room {room_name}")
            return True

        user.debug(f"Not in a room")
        return False

    def remove_total_chips(self, amount):
        self.total_chips -= amount

        if self.total_chips < 0:
            self.total_chips = 0

        self.debug(f"Removed {amount} chips")

        return self.total_chips

    def set_total_chips(self, amount):
        self.total_chips = amount

        self.debug(f"Set chips to {amount}")

    def add_total_chips(self, amount):
        self.total_chips += amount
        self.debug(f"Added {amount} chips")

        return self.total_chips

    def inc_games_played(self, amount=1):
        self.games_played += amount

        self.debug(f"Incremented games played")

    def send_to_client(self, sd: dict):
        self.debug(f"Sending packet to user: {sd}")

        for client in CLIENTS:
            if client.session_token == self.session_token:
                client.send(sd)

        self.debug(f"Sent packet")


class RoomVariables:
    room_name = None

    country = None
    creation_date = None
    description = None
    has_password = False
    max_players = 10
    official = False
    owner = None
    password = None
    player_count = 0
    seats_players = {}
    game = None
    spectator_count = 0
    spectators = []
    sessions = []


class Room(RoomVariables):
    def __init__(self, room_name, k_v: dict = None):
        if not room_name:
            raise Exception(f"Attempted to create room without name")

        if Room.exists(room_name):
            raise Exception(f"Room name taken")

        k_v.update({
            "game": Game(self),
            "creation_date": str(datetime.now())
        })

        self.room_name = room_name
        self.set_m(k_v)
        ROOMS.append(self)

        self.debug(f"Initialized")

    def debug(self, o):
        debug(o, debug_suffix=f"/ROOM/{self.room_name}")

    def get(self, k):
        return self.__getattribute__(k)

    def set(self, k, v):
        self.__setattr__(k, v)

    def set_m(self, k_v: dict):
        for k, v in k_v.items():
            self.__setattr__(k, v)

    @staticmethod
    def get_room(room_name):
        for room in ROOMS:
            if room.room_name == room_name:
                return room

    @staticmethod
    def room_key_value_match(k, value):
        for room in ROOMS:
            if room.__getattribute__(k) == value:
                return room

    @staticmethod
    def exists(room_name):
        if Room.room_key_value_match("room_name", room_name):
            return True

        return False

    @staticmethod
    def create(room_name, k_v: dict = None):
        return Room(room_name, k_v)

    @staticmethod
    def delete_all_rooms():
        ROOMS.clear()

    @staticmethod
    def delete(room_name):
        for room in ROOMS:
            if room.room_name == room_name:
                ROOMS.remove(room)

    @staticmethod
    def create_default_rooms(amount=3):
        failed = 0
        success = 0
        while failed + success + 1 <= amount:
            room_num = failed + success + 1
            if Room.create(f"{room_num}", {"official": True, "description": f"Official room {room_num}"}):
                success += 1
                continue

            failed += 1

        debug(f"Created {success}/{amount} default room(s)")

    @staticmethod
    def get_filtered_rooms(p):
        hide_full = p["hide_full"]
        hide_empty = p["hide_empty"]
        hide_password_protected = p["hide_password_protected"]
        hide_non_official = p["hide_non_official"]
        sort_reversed = p["sort_reversed"]
        sort_key = p["sort_key"]
        search_string = p["search_string"]
        search_string.lower()

        sorted_rooms = sorted(ROOMS, key=lambda r: r.get(sort_key), reverse=sort_reversed)
        filtered_rooms = []

        found = 0
        for room in sorted_rooms:
            if not ((room.all_seats_taken() and hide_full) or
                    (room.is_empty() and hide_empty) or
                    (room.has_password and hide_password_protected) or
                    (not room.official and hide_non_official) or
                    (search_string and not (search_string in room.room_name.lower() or
                                            search_string in room.description.lower()))):

                to_append = {
                    "room_name": room.room_name,
                    "description": room.description,
                    "country": room.country,
                    "player_count": room.player_count,
                    "spectator_count": room.spectator_count,
                    "official": room.official,
                    "has_password": room.has_password,
                    "max_players": room.max_players
                }

                filtered_rooms.append(to_append)
                room.debug(f"Room {room.room_name} matched criteria")

                found += 1

        return filtered_rooms

    @staticmethod
    def user_is_in_room(user):
        for room in ROOMS:
            for s in room.sessions:
                if s == user.session_token:
                    room.debug(f"User {user.username} is in room")
                    return True

        debug(f"User {user.username} is not in a room")
        return False

    def user_join(self, user, user_role):
        self.sessions.append(user.session_token)
        user.in_room_name = self.room_name
        user.in_room = True

        if user_role == "player" and (self.game.state == GameState.WAITING or self.game.state == GameState.STARTING):
            self.assign_seat(user)

        else:  # elif user_role == "spectator":
            self.add_to_spectators(user)

        self.game.starting_timer()

        log(f"User {user.username} joined room {self.room_name} as {user_role}")

    def user_leave(self, user):
        self.sessions.remove(user.session_token)
        user.in_room_name = None
        user.in_room = False

        if user in self.seats_players.values():
            self.remove_user_from_seat(user)

        elif user in self.spectators:
            self.remove_from_spectators(user)

        else:
            raise Exception(f"User {user.username} has no known role in room {self.room_name}?")

        self.debug(f"User {user.username} left")

    def is_empty(self):
        return self.player_count == 0

    def get_seats_usernames(self):
        seats_usernames = {}
        for seat, user in self.seats_players.items():
            seats_usernames[str(seat)] = user.username

        return seats_usernames

    def set_password(self, password=None):
        if password:
            self.password = password
            self.has_password = True
            self.debug(f"Set password to {password}")

            return

        self.password = None
        self.has_password = False
        self.debug(f"Reset password")

    def add_to_spectators(self, user):
        self.spectators.append(user)
        self.spectator_count = len(self.spectators)
        self.debug(f"Added {user.username} to spectators")

    def remove_from_spectators(self, user):
        self.spectators.remove(user)
        self.spectator_count = len(self.spectators)
        self.debug(f"Removed {user.username} from spectators")

    def get_empty_seats(self, single=False, randomize=True):
        taken_seats = list(self.seats_players.keys())
        seats = [i for i in range(1, self.max_players + 1) if i not in taken_seats]

        if randomize:
            random.shuffle(seats)

        if not seats:
            self.debug("No empty seats")
            return []

        if single:
            self.debug(f"Empty seat: {seats[0]}")
            return seats[0]

        self.debug(f"Empty seats: {seats}")
        return seats

    def get_seat(self, user):
        for seat, seated in self.seats_players.items():
            if seated.username == user.username:
                return seat

    def all_seats_taken(self):
        result = len(self.seats_players) == self.max_players
        self.debug(f"All seats taken: {result}")
        return result

    def assign_seat(self, user):
        seat = self.get_empty_seats(single=True)
        if not seat:
            self.debug(f"Failed to assign seat to {user.username}: all seats taken")
            return

        self.seats_players[seat] = user
        self.player_count = len(self.seats_players)

        self.debug(f"Assigned seat {seat} to {user.username}")

    def remove_user_from_seat(self, user):
        seat = self.get_seat(user)

        self.debug(f"Removed {user.username} from seat {seat}")
        del self.seats_players[seat]

    def send_to_clients(self, sd: dict):
        self.debug(f"Sending packet to users: {sd}")

        success, total = Client.send_to_clients(
            [client for client in CLIENTS if User.session_token_in_room(client.session_token, self.room_name)], sd
        )

        self.debug(f"Sent packet to {success}/{total} users")


class GameState(Enum):
    WAITING = 1
    STARTING = 2
    DEALING_CARDS = 3
    PREFLOP = 4
    FLOP = 5
    TURN = 6
    RIVER = 7
    SHOWDOWN = 8


class Game:
    def __init__(self, room):
        self.room = room
        self.state = GameState.WAITING
        self.starting_timer_running = False
        self.min_players = 1
        self.seats_players_in_hand = {}
        self.players_cards = {}
        self.evaluator = Evaluator()
        self.deck = None
        self.board = []
        self.board_2char = []

        self.debug("Initialized")

    def debug(self, o):
        debug(o, debug_suffix=f"/GAME/{self.room.room_name}")

    def starting_timer(self):
        if self.state == GameState.WAITING and not self.starting_timer_running:
            if self.room.player_count < self.min_players:
                self.debug(f"Waiting for {self.min_players - self.room.player_count} more player(s) to join...")
            else:
                self.debug(f"Starting timer")
                self.state = GameState.STARTING
                new_thread(self.starting_timer_thread)

    def starting_timer_thread(self, seconds=3):
        time_left = seconds
        self.starting_timer_running = True

        while time_left > 0:
            if self.room.player_count < self.min_players:
                self.debug("2 players required! stopping waiting timer")
                self.starting_timer_running = False
                return

            if time_left == seconds or 1 <= time_left <= 3 or time_left % 5 == 0:
                self.debug(f"Starting timer: {time_left}s left")
                self.room.send_to_clients({"type": "game_message", "message": f"Game starting in {time_left}s"})

            time_left -= 1
            time.sleep(1)

        self.starting_timer_running = False
        self.debug(f"Starting timer ended")

        self.prepare_start()

    def prepare_start(self):
        self.debug(f"Preparing game...")
        self.state = GameState.DEALING_CARDS
        self.seats_players_in_hand = self.room.seats_players
        self.debug(self.seats_players_in_hand)
        self.start()

    def start(self):
        self.debug(f"Started game")
        self.room.send_to_clients({"type": "game_message", "message": f"Game started!"})
        self.deck = Deck()
        self.board = self.deck.draw(5)
        self.board_2char = [convert_card_to_2char(card) for card in self.board]
        self.deal_cards()

    def deal_cards(self):
        self.state = GameState.DEALING_CARDS
        for seat, user in self.seats_players_in_hand.items():
            cards = self.deck.draw(2)
            self.players_cards[user] = cards
            cards_2char = [convert_card_to_2char(card) for card in cards]
            self.debug(cards_2char)

            user.send_to_client({"type": "cards_dealt", "cards": cards_2char})

        self.preflop()

    def preflop(self):
        self.state = GameState.PREFLOP

        self.room.send_to_clients({"type": "preflop_betting"})

        self.flop()

    def flop(self):
        self.state = GameState.FLOP

        self.room.send_to_clients({"type": "flop_dealt", "cards": self.board_2char[:3]})

        self.turn()

    def turn(self):
        self.state = GameState.TURN

        self.room.send_to_clients({"type": "turn_dealt", "cards": self.board_2char[:4]})

        self.river()

    def river(self):
        self.state = GameState.RIVER

        self.room.send_to_clients({"type": "river_dealt", "cards": self.board_2char})

        self.evaluate_winner()

    def evaluate_winner(self):
        best_rank = 7463
        winners = []
        for user, cards in self.players_cards.items():
            rank = self.evaluator.evaluate(cards, self.board)
            if rank == best_rank:
                winners.append(user.username)
            elif rank < best_rank:
                winners = [user.username]
                best_rank = rank

        wr_str = self.evaluator.class_to_string(self.evaluator.get_rank_class(best_rank))
        w_percentage = (1.0 - self.evaluator.get_five_card_rank_percentage(best_rank)) * 100.0

        winners_joint = ", ".join(winners)

        print(f"Player {winners_joint} wins with a {wr_str} (score: {best_rank}, pct: {w_percentage})")

        self.room.send_to_clients({"type": "hand_winners", "winners": winners_joint, "winning_rank": wr_str})


USERDATA_KEYS = [_k[0] for _k in getmembers(UserdataVariables, lambda x: not isroutine(x)) if not _k[0].startswith("_")]

User._load_userdata_from_disk()
Room.create_default_rooms(5)
Server()
