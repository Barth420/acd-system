"""Build data/players.json from the two registration sheets.

usage: python3 -I scripts/build_data.py MEN.xlsx WOMEN.xlsx

Phone numbers, DD numbers and t-shirt sizes are deliberately NOT copied over -
the auction page is public, so only what is needed on screen goes in.
"""
import json, re, sys, os
import openpyxl

MEN_TEAMS = [  # (id, display name, short, sheet spelling)
    ("aarisa", "Aarisa Solitaires", "AAR", "AARISA SOLITAIR"),
    ("amam", "Amam Legends", "AML", "AMAM LEGENDS"),
    ("boundry", "Boundry Breakers", "BBR", "BOUNDRY BRAKERS"),
    ("box", "Box Blasters", "BXB", "BOX BLASTERS"),
    ("diamstar", "Diamstar Dominators", "DDM", "DIAMSTAR DOMINATORS"),
    ("maverick", "Maverick Striker", "MAV", "MAVERICK STRIKER"),
    ("regent", "Regent Rafters", "RGR", "REGENT RAFTERS"),
    ("rm", "RM Titans", "RMT", "R.M.TITANS"),
    ("royale", "Royale Titans", "ROY", "ROYALE TITANS"),
    ("rs", "RS Titans", "RST", "R.S.TITANS"),
    ("shadow", "Shadow Strikers", "SHD", "SHADOW STRIKERS"),
    ("shah", "Shah Strikers", "SHS", "SHAH STRIKERS"),
    ("avengers", "Turf Avengers", "TAV", "TURF AVENGERS"),
    ("mafias", "Turf Mafias", "TMF", "TURF MAFIA"),
    ("van", "Van Warriors", "VAN", "VAN WARRIORS"),
    ("vk", "VK Brothers", "VKB", "VK BROTHERS"),
    ("yoddhas", "Yoddhas", "YOD", "YODDHAS"),
]
WOMEN_TEAMS = [
    ("runmachines", "Run Machines", "RUN", None),
    ("doshi", "Doshi Divas", "DOS", None),
    ("omdiam", "Om Diam", "OMD", None),
    ("ys1", "Youth Star 1", "YS1", None),
    ("ys2", "Youth Star 2", "YS2", None),
]
CATS = {"PLATINIUM": "PLATINUM", "PLATINUM": "PLATINUM", "GOLD": "GOLD",
        "SILVER": "SILVER", "BRONZE": "BRONZE"}


def title(name):
    return " ".join(w.capitalize() for w in name.split())


def short(name):
    p = title(name).split()
    return p[0] if len(p) == 1 else f"{p[0]} {p[-1]}"


def role(v):
    v = (v or "").replace(" ", "").upper()
    return {"ALLROUNDER": "All-rounder", "BATSMAN": "Batter", "BOWLER": "Bowler",
            "WICKETKEEPER": "Wicketkeeper"}.get(v, "All-rounder")


def load(path, prefix, teams):
    ws = openpyxl.load_workbook(path).active
    hdr = [c.value for c in ws[1]]
    ix = {h: i for i, h in enumerate(hdr) if h}
    by_sheet = {t[3]: t[0] for t in teams if t[3]}
    players, skipped = [], []
    for row in ws.iter_rows(min_row=2):
        name = row[ix["MEMBER_NAME"]].value
        if not name:
            continue
        name = " ".join(name.split())
        cat = CATS.get((row[ix["CATEGORY"]].value or "").strip().upper())
        if not cat:
            skipped.append(title(name))
            continue
        cell = row[ix["PHOTO"]]
        photo = cell.hyperlink.target if cell.hyperlink else None
        team = row[ix["TEAM"]].value if "TEAM" in ix else None
        players.append({
            "id": f"{prefix}{row[ix['NO']].value}",
            "name": title(name), "short": short(name), "cat": cat,
            "pts": float(row[ix["POINT"]].value or 0),
            "role": role(row[ix["I AM A"]].value),
            "photo": photo,
            "pre": by_sheet[team.strip()] if team else None,
        })
    return players, skipped


def main(men_x, women_x, out):
    data = {}
    for key, path, pre, teams in (("men", men_x, "m", MEN_TEAMS), ("women", women_x, "w", WOMEN_TEAMS)):
        players, skipped = load(path, pre, teams)
        data[key] = {
            "teams": [{"id": t[0], "name": t[1], "short": t[2]} for t in teams],
            "players": players,
        }
        print(key, len(players), "players;", sum(1 for p in players if p["pre"]),
              "pre-assigned; skipped (no category):", skipped)
    with open(out, "w") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"))


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    main(sys.argv[1], sys.argv[2], os.path.join(here, "..", "data", "players.json"))
