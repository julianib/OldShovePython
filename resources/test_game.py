from enum import Enum
from datetime import datetime, timedelta

from poker import Deck, Player
from pot import PotManager, best_possible_hand
from user import *

from server import send_to_room
from utils import *


class GameState(Enum):
    NO_GAME = 1
    WAITING = 2
    NO_HANDS = 3
    HANDS_DEALT = 4
    FLOP_DEALT = 5
    TURN_DEALT = 6
    RIVER_DEALT = 7


class Game:
    settings = {"current_blind": 5, "buy_in": 500, "double_delay": 30, "starting_blind": 5}
    blind = 0
    state = GameState.NO_GAME
    players = []
    in_hand = []
    dealer_index = 0
    first_bettor = 0
    cur_deck: Deck = None
    shared_cards = []
    pot = PotManager()
    turn_index = -1
    last_double: datetime = None

    def __init__(self, room_name):
        self.room_name = room_name
        self.new_game()

    def new_game(self):
        self.blind = 0
        self.state = GameState.NO_GAME
        self.players = []
        self.in_hand = []
        self.dealer_index = 0
        self.first_bettor = 0
        self.cur_deck: Deck = None
        self.shared_cards = []
        self.pot = PotManager()
        self.turn_index = -1
        self.last_double: datetime = None

    def add_player(self, user: User):
        self.state = GameState.WAITING

        if self.is_playing(user):
            return False

        self.players.append(Player(user))

        if len(self.players) >= 2:
            self.start()

        return True

    def is_playing(self, user: User):
        for player in self.players:
            if player.user == user:
                return True

        return False

    def leave_hand(self, to_remove: Player):
        for i, player in enumerate(self.in_hand):
            if player == to_remove:
                index = 1
                break

        else:
            return

        self.in_hand.remove(to_remove)

        if index < self.first_bettor:
            self.first_bettor -= 1

        if self.first_bettor >= len(self.in_hand):
            self.first_bettor = 0

        if self.turn_index >= len(self.in_hand):
            self.turn_index = 0

    def status_between_rounds(self):
        messages = []
        for player in self.players:
            messages.append(f"{player.name} has {player.chips} chips")
        messages.append(f"{self.dealer.name} is the dealer")

        return messages

    def next_dealer(self):
        self.dealer_index = (self.dealer_index + 1) % len(self.players)

    @property
    def dealer(self):
        return self.players[self.dealer_index]

    @property
    def cur_bet(self):
        return self.pot.cur_bet

    @property
    def current_player(self):
        return self.in_hand[self.turn_index]

    def start(self):
        self.state = GameState.NO_HANDS
        self.dealer_index = 0
        for player in self.players:
            player.chips = self.settings["buy_in"]

        self.blind = self.settings["starting_blind"]

        self.deal_hands()

        return ["-- Game started"] + self.status_between_rounds()

    def deal_hands(self):
        self.cur_deck = Deck()

        self.shared_cards = []

        self.in_hand = []
        for player in self.players:
            player.cards = (self.cur_deck.draw(), self.cur_deck.draw())
            player.cur_bet = 0
            player.placed_bet = False
            self.in_hand.append(player)

        self.state = GameState.HANDS_DEALT
        messages = ["-- Cards dealt"]

        self.pot.new_hand(self.players)

        if self.blind > 0:
            messages += self.pay_blinds()

        self.turn_index -= 1

        return messages + self.next_turn()

    def pay_blinds(self):
        messages = []
        now = datetime.now()

        if self.settings["double_delay"] == 0:
            self.last_double = None

        elif self.last_double is None:
            self.last_double = datetime.now()

        elif (now - self.last_double) > timedelta(minutes=self.settings["double_delay"]):
            messages.append("Blinds are being doubled")
            self.settings["current_blind"] *= 2
            self.last_double = now

        self.blind = self.settings["current_blind"]

        if len(self.players) > 2:
            sb_player = self.players[(self.dealer_index + 1)] % len(self.in_hand)
            bb_player = self.players[(self.dealer_index + 2)] % len(self.in_hand)
            self.turn_index = (self.dealer_index + 3) % len(self.in_hand)
            self.first_bettor = (self.dealer_index + 1) % len(self.in_hand)  # TODO confirm error in github code: self.players

        else:  # heads-up
            sb_player = self.players[self.dealer_index]
            bb_player = self.players[self.dealer_index - 1]
            self.turn_index = self.dealer_index
            self.first_bettor = self.dealer_index - 1

        messages.append(f"{sb_player.name} paid SB")
        if self.pot.pay_blind(sb_player, self.blind):
            messages.append(f"{sb_player.name} is all-in!")
            self.leave_hand(sb_player)

        messages.append(f"{bb_player.name} paid BB")
        if self.pot.pay_blind(bb_player, self.blind * 2):
            messages.append(f"{bb_player.name} is all-in!")
            self.leave_hand(bb_player)

        return messages

    def options_message(self):
        messages = [f"It's {self.current_player}'s turn, they have {self.current_player.chips} chips",
                    f"The pot is {self.pot.value}"]

        if self.pot.cur_bet > 0:
            messages.append([f"Bet to meet: {self.pot.cur_bet} and you(?) bet {self.current_player.cur_bet}"])

        else:
            messages += f"Bet to meet {self.cur_bet}"

        if self.current_player.cur_bet == self.cur_bet:
            messages += "You can check, raise or fold"
        elif self.current_player.max_bet > self.cur_bet:
            messages += "You can call, raise or fold"
        else:
            messages += "You can go all-in or fold"

        return messages

    def next_round(self):
        messages = []

        if self.state == GameState.HANDS_DEALT:
            messages += "-- Dealing the flop:"
            self.shared_cards.append([self.cur_deck.draw(), self.cur_deck.draw(), self.cur_deck.draw()])
            self.state = GameState.FLOP_DEALT

        elif self.state == GameState.FLOP_DEALT:
            messages += "-- Dealing the turn:"
            self.shared_cards += self.cur_deck.draw()
            self.state = GameState.TURN_DEALT

        elif self.state == GameState.TURN_DEALT:
            messages += "-- Dealing the river:"
            self.shared_cards += self.cur_deck.draw()
            self.state = GameState.RIVER_DEALT

        elif self.state == GameState.RIVER_DEALT:
            return self.showdown()

        messages.append(" ".join(str(card) for card in self.shared_cards))
        self.pot.next_round()
        self.turn_index = self.first_bettor

        return messages + self.options_message()

    def next_turn(self):
        if self.pot.round_over():
            if self.pot.betting_over():
                return self.showdown()

            else:
                return self.next_round()

        else:
            self.turn_index = (self.turn_index + 1) % len(self.in_hand)
            return self.options_message()

    def showdown(self):
        while len(self.shared_cards) < 5:
            self.shared_cards.append(self.cur_deck.draw())

        messages = ["-- Showdown"]

        for player in self.pot.in_pot():
            messages += f"{player.name} shows {player.cards[0]} {player.cards[1]}"

        winners = self.pot.get_winners(self.shared_cards)
        for winner, winnings in sorted(winners.items(), key=lambda k_v: k_v[1]):
            hand_name = str(best_possible_hand(self.shared_cards, winner.cards))
            messages += f"{winner.name} wins {winnings} chips with a {hand_name}"
            winner.chips += winnings

        i = 0
        while i < len(self.players):
            player = self.players[i]
            if player.chips > 0:
                i += 1
                continue

            messages += f"{player.name} has knocked out of the game"
            self.players.pop(i)
            if len(self.players) == 1:
                messages += f"{self.players[0].name} wins!"

                self.state = GameState.NO_GAME
                return messages

            if i <= self.dealer_index:
                self.dealer_index -= 1

        self.state = GameState.NO_HANDS
        self.next_dealer()
        messages += self.status_between_rounds()

        return messages

    def check(self):
        self.current_player.placed_bet = True
        return [f"{self.current_player.name} checks"] + self.next_turn()

    def raise_bet(self, amount):
        self.pot.handle_raise(self.current_player, amount)
        messages = [f"{self.current_player.name} raises with {amount}"]
        if self.current_player.chips == 0:
            messages += f"{self.current_player.name} is all-in"
            self.leave_hand(self.current_player)
            self.turn_index -= 1

        return messages + self.next_turn()

    def call(self):
        self.pot.handle_call(self.current_player)
        messages = [f"{self.current_player.name} calls"]

        if self.current_player.chips == 0:
            messages.append(f"{self.current_player.name} is all-in!")
            self.leave_hand(self.current_player)
            self.turn_index -= 1

        return messages + self.next_turn()

    def all_in(self):
        if self.pot.cur_bet > self.current_player.max_bet:
            return self.call()

        return self.raise_bet(self.current_player.max_bet - self.cur_bet)

    def fold(self):
        messages = [f"{self.current_player.name} folds"]
        self.pot.handle_fold(self.current_player)
        self.leave_hand(self.current_player)

        if len(self.pot.in_pot()) == 1:
            winner = self.pot.in_pot()[0]
            messages += f"{winner.name} wins {self.pot.value} chips"
            winner.chips += self.pot.value
            self.state = GameState.NO_HANDS
            self.next_dealer()

            return messages + self.status_between_rounds()

        if self.pot.betting_over():
            return self.showdown()

        self.turn_index -= 1
        return messages + self.next_turn()

    def send_hands(self):
        sd = {
            "type": "pokermsg",
            "content": "{player.cards[0]} {player.cards[1]}"
        }

        new_thread(send_to_room, (self.room_name, sd))
