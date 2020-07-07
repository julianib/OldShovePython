from test_corefunctions import *
from customdeuces import *

"""
ALLES OUTDATED ->>>> GEBRUIK DISCORD BOT
[r] room settings


connect to server


join room
    - player ([r] room password)
    take random empty seat
    wait till next hand
    [r] forced big blind
    hand start:
        dealer button moves
        deal cards
        iterate streets:
            iterate users:
                action on user (bet/raise/call/fold)
                next user if not all in
                all in? -> all_in_investment = x
                if a winner, take x*(unfolded players) from side pot + main pot
                rest of side pot goes to winner #2
            after each bet, check if each player put down same amount or folded
            next street
        sort winners (side pots) check side pots explained.png 
        if players with chips left > 1, next hand
    

    - [r] spectator
"""

room = Room("room1", "alpha")

joining_players = ["alpha", "beta", "gamma", "delta"]
joining_spectators = ["omega"]

for pn in joining_players:
    room.player_join(pn)

for sn in joining_spectators:
    room.spectator_join(sn)

room.next_hand()
