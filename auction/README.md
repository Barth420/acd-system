# DTCL Season 4 – Player Auction

Live, rule-based auction for the men's (17 teams) and women's (5 teams) leagues.
No dependencies – just Node 18+.

```bash
cd auction
ADMIN_PASSWORD=choose-one node server.js      # PORT=3000 by default
```

* Everyone: `http://<host>:3000/` – live wheel, current player + photo, bids, what is left in each set, team rosters.
* Auctioneer: `http://<host>:3000/admin` – same page plus controls (password prompt). `Space` spins the wheel.
* If `ADMIN_PASSWORD` is not set, one is generated and printed on start (kept in `runtime/`).
* State is saved to `runtime/state.json`, so a restart resumes the auction.

## Flow
1. Pick the set to draw from (Platinum → Gold → Silver → Bronze, then Unsold) and spin. The server picks the player at random; every screen animates to the same result.
2. Photo, category, base price appear. Click a team tile to place its bid (opening bid = base, then +increment). Teams that can't bid are greyed with the reason; each eligible team shows its max bid.
3. **Sold** assigns the player and price to the leading team; **Unsold** parks the player for the Unsold round; **Back to wheel** ignores the draw. Sales can be undone from the Teams tab or with *Undo last sale*.

## Rules enforced
* Men: Platinum 2 (base ₹5L), Gold 2 (₹3L), Silver 3 (₹2L), Bronze 3 (₹1L) = 10 players; extra Bronze allowed up to the max squad (12) while purse remains.
* A team can only bid if, after paying, it can still afford the base price of every mandatory slot it has left.
* Players already tagged with a team in the sheet are *Retained*: they cost ₹0 and count towards that team's category quotas.
* Women: only 5 Platinum / 10 Gold / 10 Silver exist, so defaults are 1-2-2-5 (10 players). Change anything under **Rules & purse**.
* Default purse: ₹50L men, ₹40L women (editable).

## Data
`python3 -I scripts/build_data.py MEN.xlsx WOMEN.xlsx` regenerates `data/players.json`. Phone numbers, DD numbers and t-shirt sizes are not copied. Five men without a category/points in the sheet are left out.
