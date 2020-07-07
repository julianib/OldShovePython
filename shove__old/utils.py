import time
import threading
import json
import base64

DEBUG = True
DEBUG_CLIENT = True
DEBUG_SOCKET = True
DEBUG_FILE = True
DEBUG_THREAD = True
DEBUG_PACKET = True
USERNAME_LENGTH_MIN = 1
USERNAME_LENGTH_MAX = 16
PASSWORD_LENGTH_MIN = 1
PASSWORD_LENGTH_MAX = 64
EMAIL_LENGTH_MIN = 2
EMAIL_LENGTH_MAX = 64
ROOM_NAME_LENGTH_MIN = 1
ROOM_NAME_LENGTH_MAX = 16
ROOM_DESCRIPTION_LENGTH_MIN = 0
ROOM_DESCRIPTION_LENGTH_MAX = 64
ROOM_GET_MAX_COUNT = 20
USER_GET_MAX_COUNT = 50

VALID_USERNAME_CHARACTERS = "0123456789abcdefghijklmnopqrstuvwxyz_"
VALID_ROOM_NAME_CHARACTERS = VALID_USERNAME_CHARACTERS
VALID_ROOM_DESCRIPTION_CHARACTERS = VALID_ROOM_NAME_CHARACTERS + "~!@#$%€^&*()-_=+[]{};:\|,<.>/?"


DATA_PATH = "userdata/data.json"


def get_data():
    with open(DATA_PATH) as f:
        return json.load(f)


def get_b64str(path, missing=None):
    if path.startswith(".") or "c:" in path.lower():
        debug_file(f"Prevented potential data breach: {path}")
        return

    try:
        with open(path, "rb") as f:
            file_bytes = f.read()

        debug_file(f"Found {path}")

    except FileNotFoundError:
        if not missing:
            raise

        with open(missing, "rb") as f:
            file_bytes = f.read()

        debug_file(f"Didn't find {path}, using missing option")

    file_b64bytes = base64.b64encode(file_bytes)
    file_b64str = file_b64bytes.decode()

    debug_file(f"Got {path} b64str")

    return file_b64str


def set_data(data):
    with open(DATA_PATH, "w") as f:
        json.dump(data, f, indent=2)


def debug(o, debug_suffix=""):
    log(o, log_type=f"DEBUG{debug_suffix}")  # TODO print_lock zodat het niet tript, ook in andere .py's


def debug_socket(o):
    if DEBUG_SOCKET:
        debug(o, debug_suffix="/SOCKET")


def debug_client(o):
    if DEBUG_SOCKET:
        debug(o, debug_suffix="/CLIENT")


def debug_file(o):
    if DEBUG_FILE:
        debug(o, debug_suffix="/FILE")


def debug_thread(o):
    if DEBUG_THREAD:
        debug(o, debug_suffix="/THREAD")


def debug_packet(o):
    if DEBUG_PACKET:
        debug(o, debug_suffix="/PACKET")


def log(o, log_type="LOG"):
    time_str = time.strftime("%X")  # %x %X -> date & time
    print(f"[{time_str}] [{log_type}] {o}")


def new_thread(target, args: tuple=(), kwargs: dict=None, daemon=True):
    nt = threading.Thread(target=target, args=args, kwargs=kwargs)
    nt.daemon = daemon
    nt.start()
    debug_thread(f"Created thread for target \"{target.__name__}\"")

    return nt


def decon_packet(p_bytes: bytes):
    debug_packet(f"Deconning...")
    p_str = p_bytes.decode()
    try:
        p: dict = json.loads(p_str)

    except json.JSONDecodeError:
        raise

    mod_p = p.copy()
    for k in p.keys():
        if "b64str" in k:
            mod_p[k] = "<b64str filtered>"

    debug_packet(f"Deconned: {mod_p}")

    return p


def valid_username_length(username):
    return USERNAME_LENGTH_MIN <= len(username) <= USERNAME_LENGTH_MAX


def valid_username_characters(username):
    for char in username.lower():
        if char not in VALID_USERNAME_CHARACTERS:
            return False

    return True


def valid_password_length(password):
    return PASSWORD_LENGTH_MIN <= len(password) <= PASSWORD_LENGTH_MAX


def passwords_match(password, repeat_password):
    return password == repeat_password


def valid_email(email):
    return "@" in email and "." in email and EMAIL_LENGTH_MIN <= len(email) <= EMAIL_LENGTH_MAX


def valid_room_name_length(room_name):
    return ROOM_NAME_LENGTH_MIN <= len(room_name) <= ROOM_NAME_LENGTH_MAX


def valid_room_name_characters(room_name):
    for char in room_name.lower():
        if char not in VALID_ROOM_NAME_CHARACTERS:
            return False

    return True


def valid_room_description_length(room_description):
    return ROOM_DESCRIPTION_LENGTH_MIN <= len(room_description) <= ROOM_DESCRIPTION_LENGTH_MAX


def valid_room_description_characters(room_description):
    for char in room_description.lower():
        if char not in VALID_ROOM_DESCRIPTION_CHARACTERS:
            return False

    return True
