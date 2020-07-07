from utils import PASSWORD_LENGTH_MAX, PASSWORD_LENGTH_MIN, USERNAME_LENGTH_MAX, USERNAME_LENGTH_MIN

err = "An unknown error occured"

err_email_invalid = "E-mail invalid"
err_email_taken = "E-mail is taken"

err_packet_invalid = "Invalid packet sent (client or server bug)"

err_password_length_invalid = f"Password has to be {PASSWORD_LENGTH_MIN}-{PASSWORD_LENGTH_MAX} characters in length"
err_password_incorrect = "Password is incorrect"
err_passwords_dont_match = "Passwords don't match"

err_message_empty = "Empty message received (client bug)"

err_room_not_found = "Room not found"
err_room_already_connected = "Already connected to a room"
err_room_full = "Room is full"
err_room_name_taken = "Room name is taken"
err_room_not_connected = "Not connected to a room"
err_room_password_incorrect = "Room password is incorrect"

err_session_invalid = "Invalid session (try relogging)"

err_username_characters_invalid = "Username can only have the characters A-z, 0-9 and _"
err_username_length_invalid = f"Username has to be {USERNAME_LENGTH_MIN}-{USERNAME_LENGTH_MAX} characters in length"
err_username_not_found = "User not found"
err_username_taken = "Username is taken"
