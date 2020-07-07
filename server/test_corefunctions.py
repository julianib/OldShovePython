import random
from customdeuces import *
from enum import Enum

"""
ALLES OUTDATED -->>>> GEBRUIK DISCORD BOT
"""

ROOMS = []
FIRST_BUTTON_SEAT = 1
FIRST_MOVER_ACTIONS = ["check", "bet", "fold"]
AFTER_FIRST_BET_ACTIONS = ["call", "raise", "fold"]
BIG_BLIND_NO_RAISE_ACTIONS = ["check", "raise", "fold"]
BIG_BLIND_AFTER_RAISE_ACTIONS = ["call", "raise", "fold"]
ACTION_TYPES = enumerate(["CHECK", "CALL", "BET", "RAISE", "FOLD"])


class ActionType(Enum):
    CHECK = "check"
    CALL = "call"
    BET = "bet"
    RAISE = "raise"
    FOLD = "fold"

    def __eq__(self, other):
        return other == self.value


class User:
    def __init__(self, name):
        self.name = name
        self.room = None

    def __eq__(self, other):
        if self.name == other.name:
            return True

    def send(self, obj):
        print(f"USER LOG [{self.name}] > {obj}")


class Player(User):
    def __init__(self, name):
        super(Player, self).__init__(name)
        self.seat = None
        self.chips = 1000
        self.chips_put = 0
        self.is_allin = False
        self.aii = 0  # all-in investment (for side-pots)
        self.has_folded = False

    def send(self, obj):
        print(f"USER LOG [{self.name}/seat {self.seat}/{self.chips} chips] > {obj}")

    def put_chips(self, amount):
        if self.chips > amount:
            self.chips_put = amount
            self.chips -= amount
            self.send(f"You put {amount} chips")

        if self.chips <= amount:
            self.is_allin = True
            self.aii = self.chips + self.chips_put
            chips_copy = self.chips
            self.chips = 0
            self.send(f"You put {chips_copy} chips (ALL-IN)")

    def earn_chips(self, amount):
        return self, amount  #


class Spectator(User):
    def __init__(self, name):
        super(Spectator, self).__init__(name)


class Action:
    def __init__(self, player, type_, amount=None):
        self.player = player
        self.type = type_
        self.amount = amount


class Room:
    def __init__(self, room_name, host_name):
        for room in ROOMS:
            if room.room_name == room_name:
                raise Exception(f"Room name taken: {room_name}")
        self.room_name = room_name
        self.host_name = host_name
        self.players_incl_new = {}
        self.players = {}
        self.seat_hands = {}
        self.spectators = []
        self.hands_dealt = 0
        self.button_seat = 0
        self.small_blind_seat = 0
        self.big_blind_seat = 0
        self.small_blind = 5
        self.big_blind = 10
        self.current_bet = 0
        self.current_action_seat = 0
        self.pot = 0
        self.deck = []
        self.board = []

        ROOMS.append(self)
        self.send(f"{host_name} hosted room {room_name}")

    @staticmethod
    def get(room_name):
        for room in ROOMS:
            if room.room_name == room_name:
                return room

    @staticmethod
    def create(room_name, host_name):
        return Room(room_name, host_name)

    def send(self, obj):
        print(f"ROOM LOG [{self.room_name}] > {obj}")

    def get_user(self, user_name):
        for seat, existing_user in self.players_incl_new.items():
            if user_name == existing_user.name:
                return existing_user

        for existing_user in self.spectators:
            if user_name == existing_user.name:
                return existing_user

    def get_empty_seats(self, incl_new_players):
        empty_seats = list(range(1, 5))
        if incl_new_players:
            for seat, player_name in self.players_incl_new.items():
                empty_seats.remove(seat)
        else:
            for seat, player_name in self.players.items():
                empty_seats.remove(seat)

        sorted(empty_seats)
        return empty_seats

    def get_taken_seats(self, incl_new_players):
        taken_seats = []
        if incl_new_players:
            for seat, player_name in self.players_incl_new.items():
                taken_seats.append(seat)
        else:
            for seat, player_name in self.players.items():
                taken_seats.append(seat)

        taken_seats_sorted = sorted(taken_seats)
        return taken_seats_sorted

    def player_join(self, player_name):
        if self.get_user(player_name):
            raise Exception(f"Player already in room {self.room_name}")

        empty_seats = self.get_empty_seats(True)
        if not len(empty_seats):
            raise Exception(f"No seats left in room {self.room_name}")

        random_seat = random.choice(empty_seats)
        player = Player(player_name)
        player.seat = random_seat
        self.players_incl_new[random_seat] = player
        self.send(f"Player {player.name} joined room {self.room_name} in seat {random_seat}")
        return True

    def player_leave(self, player_name):
        if player_name:
            return False
        return self, player_name

    def spectator_join(self, spectator):
        if self.get_user(spectator):
            raise Exception(f"Spectator already in room {self.room_name}")
        self.send(f"Spectator {spectator} joined room {self.room_name}")

        self.spectators.append(spectator)
        return True

    def move_button(self):
        if not self.button_seat:
            taken_seats = self.get_taken_seats(False)
            self.button_seat = min(taken_seats)
            new_button_seat_index = taken_seats.index(self.button_seat)
        else:
            taken_seats = self.get_taken_seats(False)
            current_button_seat_index = taken_seats.index(self.button_seat)
            new_button_seat_index = current_button_seat_index + 1
            if new_button_seat_index == len(taken_seats):
                self.button_seat = taken_seats[0]
                new_button_seat_index = 0
            else:
                self.button_seat = taken_seats[new_button_seat_index]

        if len(taken_seats) == 2:
            self.small_blind_seat = taken_seats[new_button_seat_index]
            if new_button_seat_index == 1:
                self.big_blind_seat = taken_seats[new_button_seat_index]
            else:
                self.big_blind_seat = taken_seats[new_button_seat_index + 1]
        else:
            if new_button_seat_index + 1 == len(taken_seats):
                self.small_blind_seat = taken_seats[0]
                self.big_blind_seat = taken_seats[1]
            elif new_button_seat_index + 2 == len(taken_seats):
                self.small_blind_seat = taken_seats[-1]
                self.big_blind_seat = taken_seats[0]
            else:
                self.small_blind_seat = taken_seats[new_button_seat_index + 1]
                self.big_blind_seat = taken_seats[new_button_seat_index + 2]

        self.send(f"Set button seat to {self.button_seat} (SB: {self.small_blind_seat}, BB: {self.big_blind_seat})")

        return self.button_seat

    def next_hand(self):
        self.players = self.players_incl_new
        self.hands_dealt += 1
        self.send(f"{'=' * 10} Starting hand {self.hands_dealt} {'=' * 10}")
        if len(self.players) == 1:
            raise Exception(f"Only 1 player in room {self.room_name}")

        self.move_button()
        if len(self.players) == 2:
            self.players[self.button_seat].send("You are the dealer (and small blind)")
            self.players[self.big_blind_seat].send("You are the big blind")
        else:
            self.players[self.button_seat].send("You are the dealer")
            self.players[self.small_blind_seat].send("You are the small blind")
            self.players[self.big_blind_seat].send("You are the big blind")

        self.deck = Deck()
        self.board = self.deck.draw(5)
        pretty_board_cards = []
        for i in range(len(self.board)):
            pretty_board_cards.append(Card.int_to_pretty_str(self.board[i]))
        board_cards_str = " ".join(pretty_board_cards)
        self.send(f"The board is {board_cards_str}")

        for seat, player in self.players.items():
            hand = self.deck.draw(2)
            self.seat_hands[seat] = hand
            cards_str = f"{Card.int_to_pretty_str(hand[0])} {Card.int_to_pretty_str(hand[1])}"
            player.send(f"Your cards are {cards_str}")

        self.post_blinds()
        self.preflop()

    def post_blinds(self):
        self.players[self.small_blind_seat].put_chips(self.small_blind)
        self.players[self.big_blind_seat].put_chips(self.big_blind)
        self.current_bet = self.big_blind

    def collect_chips(self):
        for seat, player in self.players.items():
            self.pot += player.chips_put
            player.put_chips = 0

    def get_next_action_seat(self):
        print("finding next actionable seat")
        unfolded_players = self.get_unfolded_players()
        if len(unfolded_players) == 1:
            return None

        not_allin_players = self.get_not_allin_players()
        actionable_players = [player for player in not_allin_players if player in unfolded_players]

        taken_seats = self.get_taken_seats(False)
        if not self.current_action_seat:
            current_seat_index = taken_seats.index(self.big_blind_seat)
        else:
            current_seat_index = taken_seats.index(self.current_action_seat)

        print(f"current seat: {taken_seats[current_seat_index]}")

        players_checked = 0
        new_seat_index = current_seat_index
        while True:
            players_checked += 1
            if players_checked == len(actionable_players):
                return None

            new_seat_index += 1
            if new_seat_index == len(taken_seats):
                new_seat_index = 0

            new_action_player = self.players[taken_seats[new_seat_index]]
            print(f"checking player {new_action_player.name} in seat {taken_seats[new_seat_index]}, {new_action_player.chips} chips, put: {new_action_player.chips_put}")

            if not new_action_player.has_folded and not new_action_player.is_allin:
                print("player ok!")
                break

        return taken_seats[new_seat_index]

    def get_unfolded_players(self):
        return [player for seat, player in self.players.items() if not player.has_folded]

    def get_not_allin_players(self):
        return [player for seat, player in self.players.items() if not player.is_allin]

    def wait_for_player_action(self, player, first_mover_action, preflop):  # timeout=10
        ok = False
        while not ok:
            # player.send(f"Action ({', '.join(FIRST_BET_ACTIONS)}): ")
            if first_mover_action:
                action_full = input(f"Action ({', '.join(FIRST_MOVER_ACTIONS)}): ")
            elif preflop and self.current_action_seat == self.big_blind_seat and self.current_bet != player.put_chips:
                action_full = input(f"Action ({', '.join(BIG_BLIND_AFTER_RAISE_ACTIONS)}): ")
            elif preflop and self.current_action_seat == self.big_blind_seat:
                action_full = input(f"Action ({', '.join(BIG_BLIND_NO_RAISE_ACTIONS)}): ")
            else:
                action_full = input(f"Action ({', '.join(AFTER_FIRST_BET_ACTIONS)}): ")

            action_split = action_full.split()
            action_type = action_split[0]

            if first_mover_action and action_type not in FIRST_MOVER_ACTIONS:
                print("1")
                player.send("Invalid action!")
                continue

            elif not first_mover_action and not preflop and action_type not in AFTER_FIRST_BET_ACTIONS:
                print("2")
                player.send("Invalid action!")
                continue

            if preflop and self.current_action_seat == self.big_blind_seat and self.current_bet != player.chips_put and action_type not in BIG_BLIND_AFTER_RAISE_ACTIONS:
                print("3")
                player.send("Invalid action!")
                continue

            elif preflop and self.current_action_seat == self.big_blind_seat and self.current_bet == player.chips_put and action_type not in BIG_BLIND_NO_RAISE_ACTIONS:
                print("4")
                player.send("Invalid action!")
                continue

            if len(action_split) > 1:
                action_amount = int(action_split[1])
                if action_amount > player.chips:
                    player.send("Not enough chips!")
                    continue
                if action_type == ActionType.RAISE and action_amount == self.current_bet:
                    player.send("Can't raise equal to current bet!")
                    continue
                return Action(player, action_type, action_amount)
            else:
                return Action(player, action_type)

    def preflop(self):
        ready_for_flop = False
        self.current_action_seat = self.get_next_action_seat()
        self.current_bet = self.big_blind

        while not ready_for_flop:
            # check if all players bet same, etc. (ready for next street)
            # break
            current_action_player = self.players[self.current_action_seat]
            to_call_amount = self.current_bet - current_action_player.chips_put
            current_action_player.send(f"Action on you! (TO CALL: {to_call_amount})")
            action = self.wait_for_player_action(current_action_player, first_mover_action=False, preflop=True)
            if action.type == ActionType.CALL:
                current_action_player.put_chips(self.current_bet - current_action_player.chips_put)
                self.send(f"{current_action_player.name} calls {to_call_amount}")
                self.current_action_seat = self.get_next_action_seat()

            elif action.type == ActionType.RAISE:
                self.current_bet = current_action_player.chips_put + action.amount
                current_action_player.put_chips(action.amount)
                if current_action_player.is_allin:
                    self.send(f"{current_action_player.name} raises to {action.amount} (ALL-IN)")
                else:
                    self.send(f"{current_action_player.name} raises to {action.amount}")

                self.current_action_seat = self.get_next_action_seat()

            elif action.type == ActionType.FOLD:
                folded_player = self.players[self.current_action_seat]
                folded_player.has_folded = True
                self.send(f"{current_action_player.name} folds")
                self.current_action_seat = self.get_next_action_seat()

            elif action.type == ActionType.CHECK:
                self.send(f"{current_action_player.name} checks")
                self.current_action_seat = self.get_next_action_seat()

            else:
                raise Exception("Invalid action type received somehow")

            if self.current_action_seat:
                continue

            unfolded_players = self.get_unfolded_players()
            if len(unfolded_players) == 1:
                # 1 player left that didnt fold
                winning_player = self.get_unfolded_players()[0]
                winnings = self.pot
                for player in self.players:
                    winnings += player.current_bet

                winning_player.earn_chips(winnings)
                self.send("Hand ended")

            else:
                self.collect_chips()


print("Import holdem OK")
