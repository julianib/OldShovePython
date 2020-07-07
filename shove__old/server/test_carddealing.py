from test_corefunctions import *
from customdeuces import *

"""
ALLES OUTDATED ->> GEBRUIK DISCORD BOT
"""

room = Room(1, "p1")
player1 = Player("p1")
player2 = Player("p2")
player3 = Player("p3")

evaluator = Evaluator()

amount = 200
current_hand = 0

current_hand += 1
print(f"== Hand {current_hand} started ==")
deck = Deck()
board = deck.draw(5)
player1_hand = deck.draw(2)
player2_hand = deck.draw(2)
player3_hand = deck.draw(2)

print("Board:")
Card.print_pretty_cards(board[:3])
Card.print_pretty_cards(board[:4])
Card.print_pretty_cards(board)

print("One's cards:")
Card.print_pretty_cards(player1_hand)
print(player1_hand)
print(Card.get_rank_char(player1_hand[0]))
print(Card.get_suit_int(player1_hand[0]))
print("Two's cards:")
Card.print_pretty_cards(player2_hand)
print("Three's cards:")
Card.print_pretty_cards(player3_hand)

players = {
    "One": player1_hand,
    "Two": player2_hand,
    "Three": player3_hand,
}

best_rank = 7463
winners = []
for name, hand in players.items():
    rank = evaluator.evaluate(hand, board)
    if rank == best_rank:
        winners.append(name)
    elif rank < best_rank:
        winners = [name]
        best_rank = rank

wcstr = evaluator.class_to_string(evaluator.get_rank_class(best_rank))
wpercentage = (1.0 - evaluator.get_five_card_rank_percentage(best_rank)) * 100.0

if len(winners) == 1:
    print(f"Player {winners[0]} wins with a {wcstr} (score: {best_rank}, pct: {wpercentage})")
else:
    print(f"Players {', '.join([x for x in winners])} win with a {wcstr} (score: {best_rank}, pct: {wpercentage})")

input()
