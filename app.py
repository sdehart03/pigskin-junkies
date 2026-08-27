import hashlib
import hmac
import html
import csv
import os
import secrets
import sqlite3
import urllib.parse
from io import StringIO
from datetime import datetime, timedelta
from http import cookies
from pathlib import Path
from wsgiref.simple_server import make_server
from zoneinfo import ZoneInfo


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PIGSKIN_JUNKIES_DB_PATH", str(BASE_DIR / "pigskin_junkies.db")))
STATIC_DIR = BASE_DIR / "static"
SECRET_KEY = os.environ.get("PIGSKIN_JUNKIES_SECRET", "change-this-before-production")
HOST = os.environ.get("PIGSKIN_JUNKIES_HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8001"))
COOKIE_SECURE = os.environ.get("PIGSKIN_JUNKIES_COOKIE_SECURE", "0") == "1"
CONTEST_TIME_ZONE = ZoneInfo("America/New_York")

# Searchable suggestions for the weekly game builder. Commissioners can still type a
# custom team name for FCS, neutral-site, or future realignment matchups.
NCAA_TEAMS = (
    "Air Force", "Akron", "Alabama", "Appalachian State", "Arizona", "Arizona State", "Arkansas", "Arkansas State",
    "Army", "Auburn", "Ball State", "Baylor", "Boise State", "Boston College", "Bowling Green", "Buffalo",
    "BYU", "California", "Central Michigan", "Charlotte", "Cincinnati", "Clemson", "Coastal Carolina", "Colorado",
    "Colorado State", "Connecticut", "Duke", "East Carolina", "Eastern Michigan", "Florida", "Florida Atlantic",
    "Florida International", "Florida State", "Fresno State", "Georgia", "Georgia Southern", "Georgia State",
    "Georgia Tech", "Hawaii", "Houston", "Illinois", "Indiana", "Iowa", "Iowa State", "Jacksonville State",
    "James Madison", "Kansas", "Kansas State", "Kennesaw State", "Kent State", "Kentucky", "Liberty", "Louisiana",
    "Louisiana Tech", "Louisiana-Monroe", "Louisville", "LSU", "Marshall", "Maryland", "Memphis", "Miami (FL)",
    "Miami (OH)", "Michigan", "Michigan State", "Middle Tennessee", "Minnesota", "Mississippi State", "Missouri",
    "Missouri State", "Navy", "NC State", "Nebraska", "Nevada", "New Mexico", "New Mexico State", "North Carolina",
    "North Texas", "Northern Illinois", "Northwestern", "Notre Dame", "Ohio", "Ohio State", "Oklahoma", "Oklahoma State",
    "Old Dominion", "Ole Miss", "Oregon", "Oregon State", "Penn State", "Pittsburgh", "Purdue", "Rice", "Rutgers",
    "Sam Houston", "San Diego State", "San Jose State", "SMU", "South Alabama", "South Carolina", "South Florida",
    "Southern Mississippi", "Stanford", "Syracuse", "TCU", "Temple", "Tennessee", "Texas", "Texas A&M", "Texas State",
    "Texas Tech", "Toledo", "Troy", "Tulane", "Tulsa", "UAB", "UCF", "UCLA", "UConn", "ULM", "UMass", "UNLV",
    "USC", "UTEP", "UTSA", "Utah", "Utah State", "Vanderbilt", "Virginia", "Virginia Tech", "Wake Forest",
    "Washington", "Washington State", "West Virginia", "Western Kentucky", "Western Michigan", "Wisconsin", "Wyoming"
)


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def now_iso():
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M")


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"{salt}${digest.hex()}"


def verify_password(password, stored):
    salt, digest = stored.split("$", 1)
    return hmac.compare_digest(hash_password(password, salt), stored)


def sign_session(account_id):
    payload = str(account_id)
    sig = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def unsign_session(value):
    try:
        payload, sig = value.rsplit("|", 1)
    except ValueError:
        return None
    expected = hmac.new(SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if hmac.compare_digest(sig, expected):
        return payload
    return None


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        PRAGMA foreign_keys = ON;

        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_commissioner INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            display_name TEXT NOT NULL,
            FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS weeks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            slug TEXT NOT NULL UNIQUE,
            label TEXT NOT NULL,
            lock_time TEXT NOT NULL,
            is_current INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS tiebreakers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_id INTEGER NOT NULL,
            position INTEGER NOT NULL,
            prompt TEXT NOT NULL,
            FOREIGN KEY (week_id) REFERENCES weeks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_id INTEGER NOT NULL,
            code TEXT NOT NULL,
            away_team TEXT NOT NULL,
            home_team TEXT NOT NULL,
            kickoff TEXT NOT NULL,
            site_note TEXT NOT NULL DEFAULT '',
            spread_text TEXT NOT NULL,
            display_order INTEGER NOT NULL DEFAULT 0,
            winner TEXT,
            score_away INTEGER NOT NULL DEFAULT 0,
            score_home INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (week_id) REFERENCES weeks(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS picks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            week_id INTEGER NOT NULL,
            entry_id INTEGER NOT NULL,
            submitted_at TEXT NOT NULL,
            tiebreaker_1 INTEGER,
            tiebreaker_2 INTEGER,
            tiebreaker_3 INTEGER,
            UNIQUE (week_id, entry_id),
            FOREIGN KEY (week_id) REFERENCES weeks(id) ON DELETE CASCADE,
            FOREIGN KEY (entry_id) REFERENCES entries(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS pick_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pick_id INTEGER NOT NULL,
            game_id INTEGER NOT NULL,
            selected_team TEXT NOT NULL,
            UNIQUE (pick_id, game_id),
            FOREIGN KEY (pick_id) REFERENCES picks(id) ON DELETE CASCADE,
            FOREIGN KEY (game_id) REFERENCES games(id) ON DELETE CASCADE
        );
        """
    )
    ensure_schema(conn)

    existing = conn.execute("SELECT COUNT(*) AS count FROM accounts").fetchone()["count"]
    if existing == 0:
        seed_database(conn)
        ensure_schema(conn)
    conn.commit()
    conn.close()


def ensure_schema(conn):
    columns = [row["name"] for row in conn.execute("PRAGMA table_info(games)").fetchall()]
    if "site_note" not in columns:
        conn.execute("ALTER TABLE games ADD COLUMN site_note TEXT NOT NULL DEFAULT ''")
    if "display_order" not in columns:
        conn.execute("ALTER TABLE games ADD COLUMN display_order INTEGER NOT NULL DEFAULT 0")
    for week in conn.execute("SELECT DISTINCT week_id FROM games").fetchall():
        unordered = conn.execute(
            "SELECT COUNT(*) AS count FROM games WHERE week_id = ? AND display_order = 0",
            (week["week_id"],),
        ).fetchone()["count"]
        if unordered:
            game_ids = [row["id"] for row in conn.execute(
                "SELECT id FROM games WHERE week_id = ? ORDER BY id", (week["week_id"],)
            ).fetchall()]
            set_game_order(conn, week["week_id"], game_ids)


def seed_database(conn):
    accounts = [
        ("Scott", "scott@pigskin-junkies.com", "pigskin12", 1),
        ("Alex", "alex@pigskin-junkies.com", "pigskin34", 1),
        ("Jamie", "jamie@pigskin-junkies.com", "pigskin56", 0),
        ("Morgan", "morgan@pigskin-junkies.com", "pigskin78", 0),
        ("Taylor", "taylor@pigskin-junkies.com", "pigskin90", 0),
        ("Casey", "casey@pigskin-junkies.com", "pigskin11", 0),
    ]
    account_ids = {}
    for name, email, password, is_commissioner in accounts:
        cur = conn.execute(
            "INSERT INTO accounts (name, email, password_hash, is_commissioner) VALUES (?, ?, ?, ?)",
            (name, email, hash_password(password), is_commissioner),
        )
        account_ids[email] = cur.lastrowid

    entries = [
        (account_ids["scott@pigskin-junkies.com"], "Scott Entry 1"),
        (account_ids["scott@pigskin-junkies.com"], "Scott Entry 2"),
        (account_ids["alex@pigskin-junkies.com"], "Alex Entry 1"),
        (account_ids["alex@pigskin-junkies.com"], "Alex Entry 2"),
        (account_ids["jamie@pigskin-junkies.com"], "Jamie"),
        (account_ids["morgan@pigskin-junkies.com"], "Morgan"),
        (account_ids["taylor@pigskin-junkies.com"], "Taylor"),
        (account_ids["casey@pigskin-junkies.com"], "Casey"),
    ]
    entry_ids = {}
    for account_id, display_name in entries:
        cur = conn.execute(
            "INSERT INTO entries (account_id, display_name) VALUES (?, ?)",
            (account_id, display_name),
        )
        entry_ids[display_name] = cur.lastrowid

    weeks = [
        ("kickoff-week", "Kickoff Week", "2026-08-22T12:00", 0),
        ("week-1", "Week 1", "2026-08-29T12:00", 1),
    ]
    week_ids = {}
    for slug, label, lock_time, is_current in weeks:
        cur = conn.execute(
            "INSERT INTO weeks (slug, label, lock_time, is_current) VALUES (?, ?, ?, ?)",
            (slug, label, lock_time, is_current),
        )
        week_ids[slug] = cur.lastrowid

    for position, prompt in enumerate(
        [
            "SMU vs Florida State total points",
            "Louisville vs Ole Miss total points",
            "Washington State vs Washington total points",
        ],
        start=1,
    ):
        conn.execute(
            "INSERT INTO tiebreakers (week_id, position, prompt) VALUES (?, ?, ?)",
            (week_ids["week-1"], position, prompt),
        )
    for position, prompt in enumerate(
        ["Total points game 1", "Total points game 2", "Total points game 3"],
        start=1,
    ):
        conn.execute(
            "INSERT INTO tiebreakers (week_id, position, prompt) VALUES (?, ?, ?)",
            (week_ids["kickoff-week"], position, prompt),
        )

    kickoff_games = [
        ("Game 01", "Team A", "Team B", "Sat Aug 22 12:00 PM", "", "Team B -3.5", "Team B", 20, 24),
        ("Game 02", "Team C", "Team D", "Sat Aug 22 3:30 PM", "", "Team D -1.5", "Team C", 28, 24),
    ]
    week1_games = [
        ("Game 01", "North Carolina", "Tcu", "Sat Aug 29 12:00 PM", "Dublin, Ireland", "Tcu -7.5", "Tcu", 24, 34),
        ("Game 02", "N.C. State", "VIRGINIA", "Sat Aug 29 3:30 PM", "", "VIRGINIA -5.5", "VIRGINIA", 17, 24),
        ("Game 03", "Colorado", "GEORGIA TECH", "Thu Sep 3 8:00 PM", "", "GEORGIA TECH -7.5", "Colorado", 27, 21),
        ("Game 04", "Toledo", "MICHIGAN STATE", "Fri Sep 4 8:00 PM", "", "MICHIGAN STATE -10.5", "MICHIGAN STATE", 16, 28),
        ("Game 05", "Miami", "STANFORD", "Fri Sep 4 9:00 PM", "", "Miami -23.5", "Miami", 35, 13),
        ("Game 06", "Fresno State", "USC", "Fri Sep 4 9:00 PM", "", "USC -22.5", "USC", 20, 42),
        ("Game 07", "East Carolina", "ALABAMA", "Sat Sep 5 12:00 PM", "", "ALABAMA -28.5", "ALABAMA", 10, 38),
        ("Game 08", "Oregon State", "HOUSTON", "Sat Sep 5 12:00 PM", "", "HOUSTON -20.5", "HOUSTON", 14, 30),
        ("Game 09", "North Texas", "INDIANA", "Sat Sep 5 12:00 PM", "", "INDIANA -40.5", "INDIANA", 10, 41),
        ("Game 10", "Boston College", "CINCINNATI", "Sat Sep 5 3:30 PM", "", "CINCINNATI -7.5", "Boston College", 27, 21),
        ("Game 11", "Boise State", "OREGON", "Sat Sep 5 3:30 PM", "", "OREGON -24.5", "OREGON", 17, 38),
        ("Game 12", "Baylor", "AUBURN", "Sat Sep 5 3:30 PM", "", "AUBURN -7.5", "AUBURN", 21, 30),
        ("Game 13", "Missouri State", "TEXAS A&M", "Sat Sep 5 7:00 PM", "", "TEXAS A&M -39.5", "TEXAS A&M", 7, 45),
        ("Game 14", "Clemson", "LSU", "Sat Sep 5 7:30 PM", "", "LSU -9.5", "Clemson", 31, 28),
        ("Game 15", "Western Michigan", "MICHIGAN", "Sat Sep 5 7:30 PM", "", "MICHIGAN -26.5", "MICHIGAN", 9, 34),
        ("Game 16", "Ucla", "CALIFORNIA", "Sat Sep 5 10:30 PM", "", "Ucla -1.5", "CALIFORNIA", 20, 24),
        ("Game 17", "Washington State", "WASHINGTON", "Sun Sep 6 4:00 PM", "APPLE CUP", "WASHINGTON -22.5", "WASHINGTON", 13, 35),
        ("Game 18", "Louisville", "OLE MISS", "Sun Sep 6 4:00 PM", "Nashville, TN", "OLE MISS -6.5", "OLE MISS", 17, 26),
        ("Game 19", "Notre Dame", "Wisconsin", "Sun Sep 6 7:30 PM", "Green Bay, WI", "Notre Dame -20.5", "Notre Dame", 33, 14),
        ("Game 20", "Smu", "FLORIDA STATE", "Mon Sep 7 7:30 PM", "", "Smu -1.5", "FLORIDA STATE", 24, 27),
    ]

    game_ids = {}
    for week_slug, games in (("kickoff-week", kickoff_games), ("week-1", week1_games)):
        for code, away, home, kickoff, site_note, spread, winner, score_away, score_home in games:
            cur = conn.execute(
                """
                INSERT INTO games
                    (week_id, code, away_team, home_team, kickoff, site_note, spread_text, winner, score_away, score_home)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (week_ids[week_slug], code, away, home, kickoff, site_note, spread, winner, score_away, score_home),
            )
            game_ids[(week_slug, code)] = cur.lastrowid

    kickoff_picks = {
        "Scott Entry 1": {"Game 01": "Team B", "Game 02": "Team C", "tb": [44, 47, 0]},
        "Scott Entry 2": {"Game 01": "Team A", "Game 02": "Team C", "tb": [42, 45, 0]},
        "Alex Entry 1": {"Game 01": "Team B", "Game 02": "Team D", "tb": [45, 52, 0]},
        "Alex Entry 2": {"Game 01": "Team B", "Game 02": "Team C", "tb": [43, 49, 0]},
        "Jamie": {"Game 01": "Team A", "Game 02": "Team C", "tb": [41, 49, 0]},
        "Morgan": {"Game 01": "Team B", "Game 02": "Team C", "tb": [46, 48, 0]},
        "Taylor": {"Game 01": "Team B", "Game 02": "Team C", "tb": [40, 46, 0]},
        "Casey": {"Game 01": "Team A", "Game 02": "Team D", "tb": [43, 44, 0]},
    }

    week1_picks = {
        "Scott Entry 1": {
            "Game 01": "TCU", "Game 02": "Virginia", "Game 03": "Colorado", "Game 04": "Michigan State",
            "Game 05": "Miami", "Game 06": "USC", "Game 07": "Alabama", "Game 08": "Houston",
            "Game 09": "Indiana", "Game 10": "Boston College", "Game 11": "Oregon", "Game 12": "Auburn",
            "Game 13": "Texas A&M", "Game 14": "Clemson", "Game 15": "Michigan", "Game 16": "California",
            "Game 17": "Washington", "Game 18": "Ole Miss", "Game 19": "Notre Dame", "Game 20": "Florida State",
            "tb": [58, 43, 48],
        },
        "Scott Entry 2": {
            "Game 01": "North Carolina", "Game 02": "Virginia", "Game 03": "Colorado", "Game 04": "Michigan State",
            "Game 05": "Miami", "Game 06": "USC", "Game 07": "Alabama", "Game 08": "Oregon State",
            "Game 09": "Indiana", "Game 10": "Cincinnati", "Game 11": "Oregon", "Game 12": "Auburn",
            "Game 13": "Texas A&M", "Game 14": "LSU", "Game 15": "Michigan", "Game 16": "California",
            "Game 17": "Washington", "Game 18": "Ole Miss", "Game 19": "Notre Dame", "Game 20": "Florida State",
            "tb": [55, 40, 46],
        },
        "Alex Entry 1": {
            "Game 01": "TCU", "Game 02": "NC State", "Game 03": "Colorado", "Game 04": "Michigan State",
            "Game 05": "Miami", "Game 06": "USC", "Game 07": "Alabama", "Game 08": "Houston",
            "Game 09": "Indiana", "Game 10": "Cincinnati", "Game 11": "Oregon", "Game 12": "Auburn",
            "Game 13": "Texas A&M", "Game 14": "LSU", "Game 15": "Michigan", "Game 16": "UCLA",
            "Game 17": "Washington", "Game 18": "Ole Miss", "Game 19": "Notre Dame", "Game 20": "Florida State",
            "tb": [54, 50, 45],
        },
        "Alex Entry 2": {
            "Game 01": "TCU", "Game 02": "Virginia", "Game 03": "Georgia Tech", "Game 04": "Michigan State",
            "Game 05": "Miami", "Game 06": "USC", "Game 07": "Alabama", "Game 08": "Houston",
            "Game 09": "Indiana", "Game 10": "Boston College", "Game 11": "Oregon", "Game 12": "Baylor",
            "Game 13": "Texas A&M", "Game 14": "Clemson", "Game 15": "Michigan", "Game 16": "California",
            "Game 17": "Washington", "Game 18": "Louisville", "Game 19": "Notre Dame", "Game 20": "Florida State",
            "tb": [51, 44, 52],
        },
        "Jamie": {
            "Game 01": "North Carolina", "Game 02": "Virginia", "Game 03": "Georgia Tech", "Game 04": "Michigan State",
            "Game 05": "Miami", "Game 06": "USC", "Game 07": "Alabama", "Game 08": "Houston",
            "Game 09": "Indiana", "Game 10": "Boston College", "Game 11": "Oregon", "Game 12": "Baylor",
            "Game 13": "Texas A&M", "Game 14": "Clemson", "Game 15": "Michigan", "Game 16": "California",
            "Game 17": "Washington", "Game 18": "Louisville", "Game 19": "Notre Dame", "Game 20": "Florida State",
            "tb": [50, 45, 49],
        },
        "Morgan": {
            "Game 01": "TCU", "Game 02": "Virginia", "Game 03": "Colorado", "Game 04": "Toledo",
            "Game 05": "Miami", "Game 06": "Fresno State", "Game 07": "Alabama", "Game 08": "Houston",
            "Game 09": "Indiana", "Game 10": "Cincinnati", "Game 11": "Oregon", "Game 12": "Auburn",
            "Game 13": "Texas A&M", "Game 14": "LSU", "Game 15": "Michigan", "Game 16": "California",
            "Game 17": "Washington", "Game 18": "Ole Miss", "Game 19": "Wisconsin", "Game 20": "SMU",
            "tb": [47, 41, 50],
        },
    }

    insert_pick_set(conn, week_ids["kickoff-week"], kickoff_picks, entry_ids, game_ids, "kickoff-week")
    insert_pick_set(conn, week_ids["week-1"], week1_picks, entry_ids, game_ids, "week-1")


def insert_pick_set(conn, week_id, pick_map, entry_ids, game_ids, week_slug):
    for display_name, payload in pick_map.items():
        cur = conn.execute(
            """
            INSERT INTO picks (week_id, entry_id, submitted_at, tiebreaker_1, tiebreaker_2, tiebreaker_3)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (week_id, entry_ids[display_name], now_iso(), payload["tb"][0], payload["tb"][1], payload["tb"][2]),
        )
        pick_id = cur.lastrowid
        for game_code, team in payload.items():
            if game_code == "tb":
                continue
            conn.execute(
                "INSERT INTO pick_items (pick_id, game_id, selected_team) VALUES (?, ?, ?)",
                (pick_id, game_ids[(week_slug, game_code)], team),
            )


def sync_reference_weeks(conn):
    week = conn.execute("SELECT id FROM weeks WHERE slug = 'week-1'").fetchone()
    if not week:
        return
    week1_reference = {
        "Game 01": ("North Carolina", "Tcu", "Sat Aug 29 12:00 PM", "Dublin, Ireland", "Tcu -7.5"),
        "Game 02": ("N.C. State", "VIRGINIA", "Sat Aug 29 3:30 PM", "", "VIRGINIA -5.5"),
        "Game 03": ("Colorado", "GEORGIA TECH", "Thu Sep 3 8:00 PM", "", "GEORGIA TECH -7.5"),
        "Game 04": ("Toledo", "MICHIGAN STATE", "Fri Sep 4 8:00 PM", "", "MICHIGAN STATE -10.5"),
        "Game 05": ("Miami", "STANFORD", "Fri Sep 4 9:00 PM", "", "Miami -23.5"),
        "Game 06": ("Fresno State", "USC", "Fri Sep 4 9:00 PM", "", "USC -22.5"),
        "Game 07": ("East Carolina", "ALABAMA", "Sat Sep 5 12:00 PM", "", "ALABAMA -28.5"),
        "Game 08": ("Oregon State", "HOUSTON", "Sat Sep 5 12:00 PM", "", "HOUSTON -20.5"),
        "Game 09": ("North Texas", "INDIANA", "Sat Sep 5 12:00 PM", "", "INDIANA -40.5"),
        "Game 10": ("Boston College", "CINCINNATI", "Sat Sep 5 3:30 PM", "", "CINCINNATI -7.5"),
        "Game 11": ("Boise State", "OREGON", "Sat Sep 5 3:30 PM", "", "OREGON -24.5"),
        "Game 12": ("Baylor", "AUBURN", "Sat Sep 5 3:30 PM", "", "AUBURN -7.5"),
        "Game 13": ("Missouri State", "TEXAS A&M", "Sat Sep 5 7:00 PM", "", "TEXAS A&M -39.5"),
        "Game 14": ("Clemson", "LSU", "Sat Sep 5 7:30 PM", "", "LSU -9.5"),
        "Game 15": ("Western Michigan", "MICHIGAN", "Sat Sep 5 7:30 PM", "", "MICHIGAN -26.5"),
        "Game 16": ("Ucla", "CALIFORNIA", "Sat Sep 5 10:30 PM", "", "Ucla -1.5"),
        "Game 17": ("Washington State", "WASHINGTON", "Sun Sep 6 4:00 PM", "APPLE CUP", "WASHINGTON -22.5"),
        "Game 18": ("Louisville", "OLE MISS", "Sun Sep 6 4:00 PM", "Nashville, TN", "OLE MISS -6.5"),
        "Game 19": ("Notre Dame", "Wisconsin", "Sun Sep 6 7:30 PM", "Green Bay, WI", "Notre Dame -20.5"),
        "Game 20": ("Smu", "FLORIDA STATE", "Mon Sep 7 7:30 PM", "", "Smu -1.5"),
    }
    for code, values in week1_reference.items():
        conn.execute(
            """
            UPDATE games
            SET away_team = ?, home_team = ?, kickoff = ?, site_note = ?, spread_text = ?
            WHERE week_id = ? AND code = ?
            """,
            (*values, week["id"], code),
        )


def parse_cookies(environ):
    jar = cookies.SimpleCookie()
    if environ.get("HTTP_COOKIE"):
        jar.load(environ["HTTP_COOKIE"])
    return jar


def get_current_account(environ, conn):
    jar = parse_cookies(environ)
    morsel = jar.get("pigskin_session")
    if not morsel:
        return None
    account_id = unsign_session(morsel.value)
    if not account_id:
        return None
    return conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()


def get_active_entry_id(environ, conn, account):
    jar = parse_cookies(environ)
    requested = jar.get("pigskin_entry")
    if requested:
        value = requested.value
        valid = conn.execute(
            "SELECT id FROM entries WHERE id = ? AND account_id = ?",
            (value, account["id"]),
        ).fetchone()
        if valid:
            return int(value)
    entry = conn.execute(
        "SELECT id FROM entries WHERE account_id = ? ORDER BY id LIMIT 1",
        (account["id"],),
    ).fetchone()
    return entry["id"] if entry else None


def read_post_data(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or "0")
    except ValueError:
        length = 0
    raw = environ["wsgi.input"].read(length).decode("utf-8")
    parsed = urllib.parse.parse_qs(raw, keep_blank_values=True)
    return {key: values[-1] for key, values in parsed.items()}


def redirect(start_response, location, headers=None):
    headers = headers or []
    start_response("302 Found", [("Location", location), *headers])
    return [b""]


def cookie_header(name, value, max_age=None):
    parts = [f"{name}={value}", "Path=/", "HttpOnly", "SameSite=Lax"]
    if COOKIE_SECURE:
      parts.append("Secure")
    if max_age is not None:
      parts.append(f"Max-Age={max_age}")
    return ("Set-Cookie", "; ".join(parts))


def html_response(start_response, body, status="200 OK", headers=None):
    payload = body.encode("utf-8")
    base_headers = [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(payload)))]
    start_response(status, base_headers + (headers or []))
    return [payload]


def text_response(start_response, body, content_type="text/plain; charset=utf-8", status="200 OK"):
    payload = body.encode("utf-8")
    start_response(status, [("Content-Type", content_type), ("Content-Length", str(len(payload)))])
    return [payload]


def serve_static(start_response, filename):
    path = STATIC_DIR / filename
    if not path.exists():
        return text_response(start_response, "Not found", status="404 Not Found")
    content = path.read_bytes()
    mime = "text/css; charset=utf-8" if path.suffix == ".css" else "application/octet-stream"
    start_response("200 OK", [("Content-Type", mime), ("Content-Length", str(len(content)))])
    return [content]


def fetch_current_week(conn):
    week = conn.execute("SELECT * FROM weeks WHERE is_current = 1 LIMIT 1").fetchone()
    if week:
        return week
    return conn.execute("SELECT * FROM weeks ORDER BY id DESC LIMIT 1").fetchone()


def fetch_week(conn, week_id):
    try:
        return conn.execute("SELECT * FROM weeks WHERE id = ?", (int(week_id),)).fetchone()
    except (TypeError, ValueError):
        return None


def form_week(conn, form):
    return fetch_week(conn, form.get("week_id")) or fetch_current_week(conn)


def commissioner_week_url(form):
    week = form.get("week_id", "")
    return f"/commissioner/weekly?week_id={urllib.parse.quote(str(week))}" if fetch_week_id(week) else "/commissioner/weekly"


def fetch_week_id(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def fetch_week_tiebreakers(conn, week_id):
    return conn.execute(
        "SELECT * FROM tiebreakers WHERE week_id = ? ORDER BY position",
        (week_id,),
    ).fetchall()


def fetch_week_games(conn, week_id):
    return conn.execute(
        "SELECT * FROM games WHERE week_id = ? ORDER BY display_order, id",
        (week_id,),
    ).fetchall()


def is_locked(week):
    return datetime.fromisoformat(week["lock_time"]) <= contest_now()


def contest_now():
    return datetime.now(CONTEST_TIME_ZONE).replace(tzinfo=None)


def game_kickoff(game):
    kickoff = game["kickoff"]
    try:
        return datetime.fromisoformat(kickoff)
    except ValueError:
        for pattern in ("%a %b %d %I:%M %p",):
            try:
                return datetime.strptime(kickoff, pattern).replace(year=contest_now().year)
            except ValueError:
                pass
    return None


def is_game_locked(game):
    kickoff = game_kickoff(game)
    return contest_now() >= kickoff.replace(second=0, microsecond=0) - timedelta(minutes=1) if kickoff else is_locked_for_legacy_game(game)


def has_game_started(game):
    kickoff = game_kickoff(game)
    return contest_now() >= kickoff if kickoff else is_locked_for_legacy_game(game)


def is_locked_for_legacy_game(game):
    return True


def locked_game_count(games):
    return sum(1 for game in games if is_game_locked(game))


def game_lock_label(game):
    kickoff = game_kickoff(game)
    if not kickoff:
        return "Lock time unavailable"
    return (kickoff - timedelta(minutes=1)).strftime("%a %b %-d at %-I:%M %p")


def game_meta(game):
    kickoff = game["kickoff"]
    try:
        kickoff = datetime.fromisoformat(kickoff).strftime("%a %b %-d %-I:%M %p")
    except ValueError:
        pass
    parts = [kickoff]
    if game["site_note"]:
        parts.append(game["site_note"])
    parts.append(game["spread_text"])
    return " | ".join(part for part in parts if part)


def line_values(spread_text, away_team, home_team):
    if spread_text == "Pick 'em":
        return "none", ""
    try:
        favorite, spread = spread_text.rsplit(" -", 1)
        float(spread)
    except (ValueError, AttributeError):
        return "none", ""
    if favorite == away_team:
        return "away", spread
    if favorite == home_team:
        return "home", spread
    return "none", ""


def kickoff_input_value(game):
    """Format kickoff values for the browser's date-and-time input when possible."""
    kickoff = game_kickoff(game)
    return kickoff.strftime("%Y-%m-%dT%H:%M") if kickoff else game["kickoff"]


def fetch_account_entries(conn, account_id):
    return conn.execute(
        "SELECT * FROM entries WHERE account_id = ? ORDER BY id",
        (account_id,),
    ).fetchall()


def fetch_accounts_with_entries(conn):
    accounts = conn.execute("SELECT * FROM accounts ORDER BY is_commissioner DESC, name, id").fetchall()
    payload = []
    for account in accounts:
        payload.append(
            {
                "account": account,
                "entries": fetch_account_entries(conn, account["id"]),
            }
        )
    return payload


def fetch_all_weeks(conn):
    return conn.execute("SELECT * FROM weeks ORDER BY id DESC").fetchall()


def fetch_pick_bundle(conn, week_id, entry_id):
    pick = conn.execute(
        "SELECT * FROM picks WHERE week_id = ? AND entry_id = ?",
        (week_id, entry_id),
    ).fetchone()
    selections = {}
    if pick:
        for row in conn.execute(
            "SELECT game_id, selected_team FROM pick_items WHERE pick_id = ?",
            (pick["id"],),
        ).fetchall():
            selections[row["game_id"]] = row["selected_team"]
    return pick, selections


def tiebreaker_value(pick, position):
    if not pick:
        return ""
    return pick[f"tiebreaker_{position}"]


def fetch_all_entries(conn):
    return conn.execute(
        """
        SELECT e.*, a.name AS account_name
        FROM entries e
        JOIN accounts a ON a.id = e.account_id
        ORDER BY e.id
        """
    ).fetchall()


def compute_week_results(conn, week_id):
    games = fetch_week_games(conn, week_id)
    entries = fetch_all_entries(conn)
    pick_rows = conn.execute(
        """
        SELECT p.*, e.display_name
        FROM picks p
        JOIN entries e ON e.id = p.entry_id
        WHERE p.week_id = ?
        """,
        (week_id,),
    ).fetchall()
    picks_by_entry = {row["entry_id"]: row for row in pick_rows}
    item_rows = conn.execute(
        """
        SELECT p.entry_id, pi.game_id, pi.selected_team
        FROM pick_items pi
        JOIN picks p ON p.id = pi.pick_id
        WHERE p.week_id = ?
        """,
        (week_id,),
    ).fetchall()
    selections = {}
    for row in item_rows:
        selections.setdefault(row["entry_id"], {})[row["game_id"]] = row["selected_team"]
    tb_game = next((game for game in games if game["code"] == "Game 20"), games[0] if games else None)
    actual_total = (tb_game["score_away"] + tb_game["score_home"]) if tb_game else 0
    results = []
    for entry in entries:
        pick = picks_by_entry.get(entry["id"])
        if not pick:
            results.append(
                {
                    "entry_id": entry["id"],
                    "display_name": entry["display_name"],
                    "submitted": False,
                    "wins": 0,
                    "total_games": len(games),
                    "tb_gap": 9999,
                    "submitted_at": None,
                }
            )
            continue
        wins = 0
        for game in games:
            if has_game_started(game) and selections.get(entry["id"], {}).get(game["id"]) == game["winner"]:
                wins += 1
        results.append(
            {
                "entry_id": entry["id"],
                "display_name": entry["display_name"],
                "submitted": True,
                "wins": wins,
                "total_games": len(games),
                "tb_gap": abs(actual_total - int(pick["tiebreaker_1"] or 0)),
                "submitted_at": pick["submitted_at"],
            }
        )
    results.sort(key=lambda item: (-item["wins"], item["tb_gap"], item["display_name"].lower()))
    for index, result in enumerate(results, start=1):
        result["rank"] = index
    return results


def compute_previous_rank(conn, current_week_id, entry_id):
    week = conn.execute(
        "SELECT * FROM weeks WHERE id < ? ORDER BY id DESC LIMIT 1",
        (current_week_id,),
    ).fetchone()
    if not week:
        return None
    prior = compute_week_results(conn, week["id"])
    match = next((row for row in prior if row["entry_id"] == entry_id), None)
    return match["rank"] if match else None


def compute_season_results(conn):
    weeks = conn.execute("SELECT * FROM weeks ORDER BY id").fetchall()
    entries = fetch_all_entries(conn)
    per_week = {week["id"]: compute_week_results(conn, week["id"]) for week in weeks}
    standings = []
    for entry in entries:
        row = {"entry_id": entry["id"], "display_name": entry["display_name"], "weekly": [], "total": 0}
        for week in weeks:
            result = next((item for item in per_week[week["id"]] if item["entry_id"] == entry["id"]), None)
            wins = result["wins"] if result and result["submitted"] else None
            if wins is not None:
                row["total"] += wins
            row["weekly"].append({"label": week["label"], "wins": wins})
        standings.append(row)
    standings.sort(key=lambda item: (-item["total"], item["display_name"].lower()))
    for index, item in enumerate(standings, start=1):
        item["rank"] = index
    return standings


def build_nav(active):
    links = [
        ("Home", "/"),
        ("Commissioner", "/commissioner"),
        ("Submit Picks", "/picks"),
        ("Leaderboards", "/leaderboard"),
        ("Pick Trends", "/trends"),
    ]
    return "".join(
        f'<a class="main-nav__link{" is-active" if href == active else ""}" href="{href}">{label}</a>'
        for label, href in links
    )


def build_auth_controls(account):
    if not account:
        return '<a class="auth-chip" href="/login">Sign In</a>'
    badge = "Commissioner" if account["is_commissioner"] else "Participant"
    return (
        '<div class="auth-chip">'
        f'<span><span class="auth-chip__name">{esc(account["name"])}</span> · {badge}</span>'
        '<a class="button button--ghost button--small" href="/account/password">Change password</a>'
        '<a class="button button--ghost button--small" href="/logout">Log Out</a>'
        "</div>"
    )


def render_layout(title, body, active, account):
    return f"""<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{esc(title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com" />
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=Source+Sans+3:wght@400;600;700&display=swap" rel="stylesheet" />
    <link rel="stylesheet" href="/static/styles.css" />
  </head>
  <body>
    <div class="site-shell">
      <header class="site-header">
        <a class="brand" href="/">
          <span class="brand__mark">PJ</span>
          <span><strong>Pigskin Junkies</strong><small>College Football Pick'em Contest</small></span>
        </a>
        <nav class="main-nav">{build_nav(active)}</nav>
        <div class="auth-controls">{build_auth_controls(account)}</div>
      </header>
      <main class="page-shell page-shell--single">{body}</main>
    </div>
  </body>
</html>"""


def render_home(conn, account):
    week = fetch_current_week(conn)
    results = compute_week_results(conn, week["id"])
    hero_cards = [
        ("Entries submitted", f'{sum(1 for item in results if item["submitted"])}/{len(results)}'),
        ("Picks", "Game-by-game locks"),
        ("Leader", f'{results[0]["display_name"]} · {results[0]["wins"]} pts' if results else "Not set"),
    ]
    hero = "".join(
        f'<div class="hero__summary-item"><div class="summary-row"><span>{esc(label)}</span><strong>{esc(value)}</strong></div></div>'
        for label, value in hero_cards
    )
    top_three = "".join(
        f'<a class="leader-card" href="/player?entry_id={item["entry_id"]}&week_id={week["id"]}"><strong>#{item["rank"]} {esc(item["display_name"])}</strong><span>{item["wins"]}/{item["total_games"]} correct</span></a>'
        for item in results[:3]
    )
    body = f"""
      <section class="hero">
        <div class="hero__copy">
          <p class="eyebrow">College football pick'em</p>
          <h1>{esc(week["label"])} is on the board.</h1>
          <p class="hero__lede">Make your selections, follow the board, and see where the field leans.</p>
          <div class="hero__actions">
            <a class="button button--primary" href="/picks">Make picks</a>
            <a class="button button--ghost" href="/leaderboard">View standings</a>
          </div>
        </div>
        <aside class="hero__card">
          <p class="hero__card-label">{esc(week["label"])} snapshot</p>
          <div class="hero__summary">{hero}</div>
        </aside>
      </section>

      <section class="panel">
        <div class="section-heading">
          <div><p class="section-label">Contest pulse</p><h2>Current leaders</h2></div>
          <a class="button button--ghost button--small" href="/leaderboard">Full standings</a>
        </div>
        <div class="leader-grid">{top_three}</div>
      </section>
    """
    return render_layout("Pigskin Junkies | Home", body, "/", account)


def render_login(conn, account, error="", next_page=""):
    if account:
        target = "/commissioner" if next_page == "commissioner" and account["is_commissioner"] else "/picks"
        cta = "Go to commissioner page" if target == "/commissioner" else "Go to your picks"
        body = f"""
        <section class="page-hero"><div><p class="eyebrow">Participant access</p><h1>Sign in to make your picks</h1></div></section>
        <section class="auth-layout">
          <article class="panel">
            <div class="empty-state">
              <div class="account-banner"><div><strong>{esc(account["name"])}</strong><div class="helper-copy">{esc(account["email"])}</div></div><span class="pill">Signed in</span></div>
              <a class="button button--primary" href="{target}">{cta}</a>
            </div>
          </article>
        </section>
        """
        return render_layout("Pigskin Junkies | Sign In", body, "", account)

    callout = "Sign in with a commissioner account to manage games, scores, and standings." if next_page == "commissioner" else "Sign in to load and save only your own contest entries."
    error_html = f'<div class="alert alert--error">{esc(error)}</div>' if error else ""
    hidden = f'<input type="hidden" name="next" value="{esc(next_page)}" />' if next_page else ""
    body = f"""
      <section class="page-hero page-hero--compact"><div><p class="eyebrow">Pigskin Junkies</p><h1>Sign in to make your picks</h1></div></section>
      <section class="auth-layout auth-layout--narrow">
        <article class="panel">
          {error_html}
          <form class="form-card" method="post" action="/login">
            {hidden}
            <label>Email<input type="email" name="email" autocomplete="username" placeholder="you@example.com" required /></label>
            <label>Password<input type="password" name="password" autocomplete="current-password" placeholder="Enter your contest password" required /></label>
            <div class="helper-copy">{esc(callout)}</div>
            <div class="pick-actions"><button class="button button--primary" type="submit">Sign in</button></div>
          </form>
        </article>
      </section>
    """
    return render_layout("Pigskin Junkies | Sign In", body, "", account)


def render_change_password(account, error="", message=""):
    error_html = f'<div class="alert alert--error">{esc(error)}</div>' if error else ""
    message_html = f'<div class="alert alert--success">{esc(message)}</div>' if message else ""
    body = f"""
      <section class="page-hero"><div><p class="eyebrow">Account security</p><h1>Change your password</h1></div></section>
      <section class="auth-layout">
        <article class="panel">
          <p class="section-label">Private account details</p>
          <h2>Choose a password only you know</h2>
          {error_html}
          {message_html}
          <form class="form-card" method="post" action="/account/password">
            <label>Current password<input type="password" name="current_password" autocomplete="current-password" required /></label>
            <label>New password<input type="password" name="new_password" autocomplete="new-password" minlength="8" required /></label>
            <label>Confirm new password<input type="password" name="confirm_password" autocomplete="new-password" minlength="8" required /></label>
            <div class="callout">Use at least 8 characters. After you save it, commissioners cannot view your new password.</div>
            <div class="pick-actions"><button class="button button--primary" type="submit">Save new password</button></div>
          </form>
        </article>
        <article class="panel">
          <p class="section-label">Your login</p>
          <h2>Keep your entry secure</h2>
          <div class="stack">
            <div class="summary-card"><strong>{esc(account["name"])}</strong><span>{esc(account["email"])}</span></div>
            <div class="summary-card"><strong>Temporary passwords</strong><span>Replace the password given to you by a commissioner as soon as you sign in.</span></div>
          </div>
        </article>
      </section>
    """
    return render_layout("Pigskin Junkies | Change Password", body, "", account)


def render_delete_account_confirmation(account, target):
    body = f"""
      <section class="page-hero"><div><p class="eyebrow">Account removal</p><h1>Delete {esc(target["name"])}?</h1></div></section>
      <section class="auth-layout">
        <article class="panel">
          <p class="section-label">Confirmation required</p>
          <h2>This action cannot be undone</h2>
          <div class="alert alert--error">Deleting this account will permanently remove its entries and all submitted picks.</div>
          <div class="summary-card"><strong>{esc(target["name"])}</strong><span>{esc(target["email"])}</span></div>
          <form class="pick-actions" method="post" action="/commissioner/account/delete">
            <input type="hidden" name="account_id" value="{target["id"]}" />
            <input type="hidden" name="confirm_delete" value="yes" />
            <button class="button button--danger" type="submit">Yes, permanently delete this account</button>
            <a class="button button--ghost" href="/commissioner/participants">Cancel and keep account</a>
          </form>
        </article>
      </section>
    """
    return render_layout("Pigskin Junkies | Confirm Account Deletion", body, "/commissioner", account)


def render_commissioner(conn, account, section="dashboard", week_id=None):
    if not account:
        return None, redirect  # sentinel handled by caller
    if not account["is_commissioner"]:
        body = """
          <section class="page-hero"><div><p class="eyebrow">Commissioner view</p><h1>Weekly setup and score control</h1></div></section>
          <section class="panel">
            <div class="empty-state">
              <div class="callout">This page is reserved for commissioner accounts.</div>
              <a class="button button--primary" href="/picks">Go to your picks</a>
            </div>
          </section>
        """
        return render_layout("Pigskin Junkies | Commissioner", body, "/commissioner", account), None

    week = fetch_week(conn, week_id) or fetch_current_week(conn)
    tiebreakers = fetch_week_tiebreakers(conn, week["id"])
    games = fetch_week_games(conn, week["id"])
    results = compute_week_results(conn, week["id"])
    accounts_with_entries = fetch_accounts_with_entries(conn)
    weeks = fetch_all_weeks(conn)
    submitted_count = sum(1 for item in results if item["submitted"])
    missing = [item for item in results if not item["submitted"]]
    missing_html = "".join(
        f'<div class="missing-player"><strong>{esc(item["display_name"])}</strong><span>Waiting on entry</span></div>'
        for item in missing
    ) or '<div class="missing-player"><strong>Everyone is in</strong><span>No follow-up needed</span></div>'
    game_rows = []
    for game in games:
        favorite_side, spread_value = line_values(game["spread_text"], game["away_team"], game["home_team"])
        winner_select = (
            f'<select form="commissioner-save-form" name="winner_{game["id"]}">'
            f'<option value="" {"selected" if not game["winner"] else ""}>No result yet</option>'
            f'<option value="{esc(game["away_team"])}" {"selected" if game["winner"] == game["away_team"] else ""}>{esc(game["away_team"])}</option>'
            f'<option value="{esc(game["home_team"])}" {"selected" if game["winner"] == game["home_team"] else ""}>{esc(game["home_team"])}</option>'
            "</select>"
        )
        game_rows.append(
            "<tr>"
            f"<td>{esc(game['code'])}</td>"
            f"<td><strong>{esc(game['away_team'])}</strong> at <strong>{esc(game['home_team'])}</strong></td>"
            f"<td>{esc(game_meta(game))}</td>"
            f"<td>{esc(game['spread_text'])}</td>"
            f"<td>{winner_select}</td>"
            f'<td><div class="summary-row"><input form="commissioner-save-form" class="score-input" type="number" min="0" aria-label="{esc(game["away_team"])} final score" name="score_away_{game["id"]}" value="{game["score_away"]}" /><input form="commissioner-save-form" class="score-input" type="number" min="0" aria-label="{esc(game["home_team"])} final score" name="score_home_{game["id"]}" value="{game["score_home"]}" /></div></td>'
            f'''<td><div class="game-row-actions"><a class="button button--ghost button--small" href="/commissioner/game/{game["id"]}/edit">Edit</a>
              <form method="post" action="/commissioner/game/move/{game["id"]}"><button class="button button--ghost button--small" type="submit" name="direction" value="earlier" {"disabled" if game == games[0] else ""}>Up</button></form>
              <form method="post" action="/commissioner/game/move/{game["id"]}"><button class="button button--ghost button--small" type="submit" name="direction" value="later" {"disabled" if game == games[-1] else ""}>Down</button></form>
            </div></td>'''
            "</tr>"
        )
    account_rows = []
    for item in accounts_with_entries:
        managed = item["account"]
        entries_html = "".join(
            f'<div class="entry-pill">{esc(entry["display_name"])}</div>'
            for entry in item["entries"]
        ) or '<div class="entry-pill">No entries</div>'
        account_rows.append(
            f"""
            <tr>
              <td>{esc(managed["name"])}</td>
              <td>{esc(managed["email"])}</td>
              <td>{'Commissioner' if managed["is_commissioner"] else 'Participant'}</td>
              <td><div class="entry-pill-wrap">{entries_html}</div></td>
              <td>
                <details class="manage-details">
                  <summary>Manage account</summary>
                  <form class="inline-form" method="post" action="/commissioner/account/update">
                    <input type="hidden" name="account_id" value="{managed["id"]}" />
                    <label>Name<input type="text" name="name" value="{esc(managed["name"])}" required /></label>
                    <label>Email<input type="email" name="email" value="{esc(managed["email"])}" required /></label>
                    <label>New password<input type="text" name="password" placeholder="Leave blank to keep current" /></label>
                    <label class="checkbox-row"><input type="checkbox" name="is_commissioner" value="1" {'checked' if managed["is_commissioner"] else ''} /> Commissioner</label>
                    <button class="button button--ghost button--small" type="submit">Save account</button>
                  </form>
                  <form class="inline-form inline-form--compact" method="post" action="/commissioner/entry/add">
                    <input type="hidden" name="account_id" value="{managed["id"]}" />
                    <label>New entry name<input type="text" name="display_name" placeholder="Add another entry" required /></label>
                    <button class="button button--ghost button--small" type="submit">Add entry</button>
                  </form>
                  <form class="inline-form inline-form--compact" method="post" action="/commissioner/account/delete">
                    <input type="hidden" name="account_id" value="{managed["id"]}" />
                    <button class="button button--danger button--small" type="submit" {'disabled title="You cannot delete the account you are currently using."' if managed["id"] == account["id"] else ''}>Delete account</button>
                  </form>
                </details>
              </td>
            </tr>
            """
        )
    week_rows = []
    for listed_week in weeks:
        week_rows.append(
            "<tr>"
            f"<td>{esc(listed_week['label'])}</td>"
            f"<td>{esc(listed_week['slug'])}</td>"
            f"<td>{esc(listed_week['lock_time'])}</td>"
            f"<td>{'Current' if listed_week['is_current'] else ''}</td>"
            "</tr>"
        )
    next_game_number = len(games) + 1
    team_datalist = '<datalist id="ncaa-team-options">' + ''.join(
        f'<option value="{esc(team)}"></option>' for team in NCAA_TEAMS
    ) + "</datalist>"
    weekly_section = f"""
      <section class="dashboard-grid commissioner-weekly-grid">
        <article class="panel">
          <div class="section-heading"><div><p class="section-label">Weekly setup</p><h2>Week settings and results</h2></div></div>
          <form id="commissioner-save-form" class="form-card" method="post" action="/commissioner/save">
            <input type="hidden" name="week_id" value="{week['id']}" />
            <div class="form-row">
              <label>Week label<input type="text" name="week_label" value="{esc(week['label'])}" /></label>
              <label>Lock time<input type="datetime-local" name="lock_time" value="{esc(week['lock_time'])}" /></label>
            </div>
            <div class="form-row">
              {''.join(f'<label>Tiebreaker {tb["position"]}<input type="text" name="tb_{tb["position"]}" value="{esc(tb["prompt"])}" /></label>' for tb in tiebreakers)}
            </div>
          </form>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Game</th><th>Matchup</th><th>Kickoff</th><th>Spread</th><th>Winner</th><th>Final score</th><th>Manage</th></tr></thead>
              <tbody>{''.join(game_rows)}</tbody>
            </table>
          </div>
          <button form="commissioner-save-form" class="button button--primary" type="submit">Save contest updates</button>
        </article>
        <article class="panel">
          <p class="section-label">Operations</p><h2>Who still needs to pick?</h2>
          <div class="stack compact-stack">{missing_html}</div>
        </article>
      </section>
      <section class="panel game-builder-panel">
        <div class="section-heading"><div><p class="section-label">Game builder</p><h2>Add a matchup to {esc(week['label'])}</h2></div><span class="badge">Next: Game {next_game_number:02d}</span></div>
        <div class="callout">Choose from the NCAA team suggestions or type any custom team name. The favorite and spread become the exact text participants see on their pick card.</div>
        {team_datalist}
        <form class="form-card game-builder-grid" method="post" action="/commissioner/game/add">
          <input type="hidden" name="week_id" value="{week['id']}" />
          <label>Away team<input list="ncaa-team-options" name="away_team" placeholder="Start typing a team" required /></label>
          <label>Home team<input list="ncaa-team-options" name="home_team" placeholder="Start typing a team" required /></label>
          <label>Kickoff<input type="datetime-local" name="kickoff" required /></label>
          <label>Location or note<input type="text" name="site_note" placeholder="Example: Atlanta, GA or neutral site" /></label>
          <label>Favorite
            <select name="favorite_side"><option value="away">Away team</option><option value="home" selected>Home team</option><option value="none">Pick 'em</option></select>
          </label>
          <label>Favorite by<input type="number" min="0" step="0.5" name="spread" placeholder="Example: 3.5" /></label>
          <div class="pick-actions"><button class="button button--primary" type="submit">Add Game {next_game_number:02d}</button></div>
        </form>
      </section>
    """

    participants_section = f"""
      <section class="panel">
        <div class="section-heading"><div><p class="section-label">Accounts and entries</p><h2>Participant management</h2></div></div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Entries</th><th>Manage</th></tr></thead>
            <tbody>{''.join(account_rows)}</tbody>
          </table>
        </div>
        <details class="commissioner-disclosure panel-subsection">
          <summary>Add participant</summary>
          <form class="form-card" method="post" action="/commissioner/account/add">
            <div class="form-row">
              <label>Name<input type="text" name="name" required /></label>
              <label>Email<input type="email" name="email" required /></label>
            </div>
            <div class="form-row">
              <label>Password<input type="text" name="password" required /></label>
              <label>Primary entry name<input type="text" name="entry_one" required /></label>
            </div>
            <div class="form-row">
              <label>Optional second entry<input type="text" name="entry_two" /></label>
              <label class="checkbox-row"><input type="checkbox" name="is_commissioner" value="1" /> Commissioner account</label>
            </div>
            <button class="button button--primary" type="submit">Create account</button>
          </form>
        </details>
        <details class="commissioner-disclosure panel-subsection">
          <summary>Import participant list</summary>
          <form class="form-card" method="post" action="/commissioner/account/import">
            <div class="callout">Use columns: <code>name,email,password,entry_one,entry_two,is_commissioner</code>. Leave <code>entry_two</code> blank for single-entry participants.</div>
            <label>CSV data
              <textarea name="csv_data" rows="10" class="input-textarea" placeholder="name,email,password,entry_one,entry_two,is_commissioner&#10;Jane,jane@example.com,temp-pass,Jane Entry 1,Jane Entry 2,false"></textarea>
            </label>
            <button class="button button--ghost" type="submit">Import accounts</button>
          </form>
        </details>
      </section>
    """

    weeks_section = f"""
      <section class="panel">
        <div class="section-heading"><div><p class="section-label">Week management</p><h2>Current and upcoming weeks</h2></div></div>
        <form class="form-card" method="post" action="/commissioner/week/select">
          <label>Current week
            <select name="week_id">
              {''.join(f'<option value="{listed_week["id"]}" {"selected" if listed_week["id"] == week["id"] else ""}>{esc(listed_week["label"])}</option>' for listed_week in weeks)}
            </select>
          </label>
          <button class="button button--ghost" type="submit">Make current week</button>
        </form>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Week</th><th>Slug</th><th>Lock time</th><th>Status</th></tr></thead>
            <tbody>{''.join(week_rows)}</tbody>
          </table>
        </div>
        <div class="section-heading panel-subsection"><div><p class="section-label">New week</p><h2>Start the next slate</h2></div></div>
        <form id="new-week" class="form-card" method="post" action="/commissioner/week/add">
          <div class="form-row">
            <label>Week label<input type="text" name="label" placeholder="Week 2" required /></label>
            <label>Slug<input type="text" name="slug" placeholder="week-2" required /></label>
          </div>
          <label>Lock time<input type="datetime-local" name="lock_time" required /></label>
          <div class="callout">New weeks begin with a blank game slate and become the active week automatically. Add the new matchups from Weekly Setup.</div>
          <label class="checkbox-row"><input type="checkbox" name="keep_current" value="1" /> Keep the current week active while I build this one for later</label>
          <button class="button button--primary" type="submit">Create new week</button>
        </form>
      </section>
    """

    workspace_nav = """
      <nav class="commissioner-workspace-nav" aria-label="Commissioner workspaces">
        <a class="button button--ghost button--small" href="/commissioner">Overview</a>
        <a class="button button--ghost button--small" href="/commissioner/weekly">Weekly setup</a>
        <a class="button button--ghost button--small" href="/commissioner/participants">Participants</a>
        <a class="button button--ghost button--small" href="/commissioner/weeks">Weeks</a>
      </nav>
    """

    if section == "weekly":
        body = f"""
          <section class="page-hero"><div><p class="eyebrow">Commissioner workspace</p><h1>{esc(week['label'])} setup</h1></div><div class="page-hero__actions"><span class="pill">{submitted_count} of {len(results)} entries received</span><span class="pill pill--accent">{len(games) - locked_game_count(games)} games still open</span></div></section>
          {workspace_nav}
          <form class="week-switcher" method="get" action="/commissioner/weekly">
            <label>Build or review a week
              <select name="week_id">
                {''.join(f'<option value="{listed_week["id"]}" {"selected" if listed_week["id"] == week["id"] else ""}>{esc(listed_week["label"])}{" (current)" if listed_week["is_current"] else ""}</option>' for listed_week in weeks)}
              </select>
            </label>
            <button class="button button--primary button--small" type="submit">Open week</button>
            <span>This only changes the commissioner workspace. It does not change the public contest week.</span>
          </form>
          {weekly_section}
        """
    elif section == "participants":
        body = f"""
          <section class="page-hero"><div><p class="eyebrow">Commissioner workspace</p><h1>Participants and entries</h1></div><div class="page-hero__actions"><span class="pill">{len(accounts_with_entries)} accounts</span></div></section>
          {workspace_nav}{participants_section}
        """
    elif section == "weeks":
        body = f"""
          <section class="page-hero"><div><p class="eyebrow">Commissioner workspace</p><h1>Contest weeks</h1></div><div class="page-hero__actions"><span class="pill">{len(weeks)} weeks configured</span></div></section>
          {workspace_nav}{weeks_section}
        """
    else:
        body = f"""
      <section class="page-hero">
        <div><p class="eyebrow">Commissioner view</p><h1>Contest control center</h1></div>
        <div class="page-hero__actions">
          <span class="pill">{submitted_count} of {len(results)} entries received</span>
          <span class="pill pill--accent">{len(games) - locked_game_count(games)} games still open</span>
        </div>
      </section>
      <section class="commissioner-hub">
        <a class="commissioner-hub__card" href="/commissioner/weekly"><p class="section-label">Weekly setup</p><h2>{esc(week['label'])}</h2><span>Update lock time, tiebreakers, game results, and follow up on missing picks.</span><strong>Open weekly setup</strong></a>
        <a class="commissioner-hub__card" href="/commissioner/participants"><p class="section-label">Participants</p><h2>{len(accounts_with_entries)} accounts</h2><span>Create, update, and organize participant accounts and their entries.</span><strong>Manage participants</strong></a>
        <a class="commissioner-hub__card" href="/commissioner/weeks"><p class="section-label">Weeks</p><h2>{len(weeks)} configured</h2><span>Switch the active contest week or create the next one when ready.</span><strong>Manage weeks</strong></a>
      </section>
    """
    return render_layout("Pigskin Junkies | Commissioner", body, "/commissioner", account), None


def render_game_editor(conn, account, game_id):
    game = conn.execute(
        """SELECT games.*, weeks.label AS week_label
           FROM games JOIN weeks ON weeks.id = games.week_id
           WHERE games.id = ?""",
        (game_id,),
    ).fetchone()
    if not game:
        body = """
          <section class="panel empty-state">
            <h1>Game not found</h1>
            <a class="button button--primary" href="/commissioner/weekly">Return to weekly setup</a>
          </section>
        """
        return render_layout("Pigskin Junkies | Game not found", body, "/commissioner", account)

    favorite_side, spread_value = line_values(game["spread_text"], game["away_team"], game["home_team"])
    kickoff_value = kickoff_input_value(game)
    ordered_games = fetch_week_games(conn, game["week_id"])
    game_position = next(index for index, listed_game in enumerate(ordered_games, start=1) if listed_game["id"] == game["id"])
    team_datalist = '<datalist id="ncaa-team-options">' + ''.join(
        f'<option value="{esc(team)}"></option>' for team in NCAA_TEAMS
    ) + "</datalist>"
    body = f"""
      <section class="page-hero game-editor-hero">
        <div><p class="eyebrow">{esc(game['week_label'])} | {esc(game['code'])}</p><h1>Edit matchup</h1><p class="hero__lede">Update the game details participants see on their pick card.</p></div>
        <a class="button button--ghost" href="/commissioner/weekly?week_id={game['week_id']}">Back to weekly setup</a>
      </section>
      <section class="panel game-editor-panel">
        <div class="game-editor-matchup"><span class="game-editor-matchup__team">{esc(game['away_team'])}</span><span class="game-editor-matchup__at">at</span><span class="game-editor-matchup__team">{esc(game['home_team'])}</span></div>
        <div class="game-editor-meta"><span>{esc(game_meta(game))}</span><span>Game locks one minute before kickoff.</span></div>
        {team_datalist}
        <form class="game-editor-form" method="post" action="/commissioner/game/update/{game['id']}">
          <fieldset class="game-editor-group"><legend>Matchup</legend><div class="game-editor-grid game-editor-grid--teams">
            <label>Away team<input list="ncaa-team-options" name="away_team" value="{esc(game['away_team'])}" required /></label>
            <label>Home team<input list="ncaa-team-options" name="home_team" value="{esc(game['home_team'])}" required /></label>
          </div></fieldset>
          <fieldset class="game-editor-group"><legend>Kickoff and location</legend><div class="game-editor-grid">
            <label>Kickoff<input type="datetime-local" name="kickoff" value="{esc(kickoff_value)}" required /></label>
            <label>Location or note<input type="text" name="site_note" value="{esc(game['site_note'])}" placeholder="Example: Atlanta, GA or neutral site" /></label>
          </div></fieldset>
          <fieldset class="game-editor-group"><legend>Point spread</legend><div class="game-editor-grid">
            <label>Favorite<select name="favorite_side"><option value="away" {"selected" if favorite_side == "away" else ""}>Away team</option><option value="home" {"selected" if favorite_side == "home" else ""}>Home team</option><option value="none" {"selected" if favorite_side == "none" else ""}>Pick 'em</option></select></label>
            <label>Favorite by<input type="number" min="0" step="0.5" name="spread" value="{esc(spread_value)}" placeholder="Example: 3.5" /></label>
          </div></fieldset>
          <fieldset class="game-editor-group"><legend>Card order</legend><div class="game-editor-grid">
            <label>Place this game as
              <select name="position">{''.join(f'<option value="{position}" {"selected" if position == game_position else ""}>Game {position:02d}</option>' for position in range(1, len(ordered_games) + 1))}</select>
            </label>
            <div class="game-editor-help">The rest of the card will renumber automatically when you save.</div>
          </div></fieldset>
          <div class="game-editor-actions"><a class="button button--ghost" href="/commissioner/weekly?week_id={game['week_id']}">Cancel</a><button class="button button--primary" type="submit">Save game changes</button></div>
        </form>
      </section>
    """
    return render_layout(f"Pigskin Junkies | Edit {game['code']}", body, "/commissioner", account)


def movement_text(current_rank, previous_rank):
    if not previous_rank:
        return "New this week"
    if current_rank < previous_rank:
        return "Moving up"
    if current_rank > previous_rank:
        return "Moved down"
    return "Holding position"


def render_picks(conn, account, message="", active_entry_id=None):
    week = fetch_current_week(conn)
    if not account:
        body = """
          <section class="page-hero"><div><p class="eyebrow">Participant view</p><h1>Submit your Pigskin Junkies picks</h1></div></section>
          <section class="panel">
            <div class="empty-state">
              <div class="callout">Sign in first so the site knows exactly which picks belong to you.</div>
              <a class="button button--primary" href="/login">Go to sign in</a>
            </div>
          </section>
        """
        return render_layout("Pigskin Junkies | Submit Picks", body, "/picks", account)

    entries = fetch_account_entries(conn, account["id"])
    active_entry_id = active_entry_id or get_active_entry_id_from_query_or_default(entries)
    active_entry = next((entry for entry in entries if entry["id"] == active_entry_id), entries[0] if entries else None)
    pick, selections = fetch_pick_bundle(conn, week["id"], active_entry["id"])
    tiebreakers = fetch_week_tiebreakers(conn, week["id"])
    games = fetch_week_games(conn, week["id"])
    cards = []
    for game in games:
        game_locked = is_game_locked(game)
        options = []
        if game_locked:
            locked_pick = selections.get(game["id"])
            options.append(
                f'<div class="pick-lock-notice"><strong>{esc(locked_pick) if locked_pick else "No pick submitted"}</strong><span>This game locked at {esc(game_lock_label(game))}.</span></div>'
            )
        else:
            for team in (game["away_team"], game["home_team"]):
                checked = "checked" if selections.get(game["id"]) == team else ""
                options.append(
                    f'<label class="pick-option"><input type="radio" name="pick_{game["id"]}" value="{esc(team)}" {checked} required /><span>{esc(team)}</span></label>'
                )
        cards.append(
            f'<fieldset class="pick-game-card {"pick-game-card--locked" if game_locked else ""}"><legend>{esc(game["code"])}: {esc(game["away_team"])} at {esc(game["home_team"])}</legend><div class="pick-game-card__meta">{esc(game_meta(game))}</div><div class="pick-options">{"".join(options)}</div></fieldset>'
        )
    entry_select = ""
    if len(entries) > 1:
        entry_select = (
            '<div class="form-row"><label>Entry<select name="entry_id">'
            + "".join(
                f'<option value="{entry["id"]}" {"selected" if entry["id"] == active_entry["id"] else ""}>{esc(entry["display_name"])}</option>'
                for entry in entries
            )
            + "</select></label></div>"
        )
    notice = f'<div class="alert alert--success">{esc(message)}</div>' if message else ""
    body = f"""
      <section class="page-hero">
        <div><p class="eyebrow">Participant view</p><h1>Submit your Pigskin Junkies picks</h1></div>
        <div class="page-hero__actions"><span class="badge">{esc(week["label"])}</span><span class="pill pill--accent">{len(games) - locked_game_count(games)} game locks remaining</span></div>
      </section>
      <section class="panel">
        {notice}
        <form class="pick-form" method="post" action="/picks">
          <div class="form-row">
            <div class="account-banner"><div><strong>{esc(account["name"])}</strong><div class="helper-copy">{esc(account["email"])}</div></div><span class="pill">{len(entries)} entries linked</span></div>
            <div class="callout">Each game locks one minute before its own kickoff. Your picks stay private from everyone else until that game begins.</div>
          </div>
          {entry_select}
          <div class="pick-game-grid">{''.join(cards)}</div>
          <div class="form-row">
            {''.join(f'<label>{esc(tb["prompt"])}<input type="number" min="0" name="tb_{tb["position"]}" value="{esc(tiebreaker_value(pick, tb["position"]))}" required /></label>' for tb in tiebreakers)}
          </div>
          <div class="pick-actions"><button class="button button--primary" type="submit">Save picks</button><span class="pill">{esc(active_entry["display_name"])} is active</span></div>
        </form>
      </section>
    """
    return render_layout("Pigskin Junkies | Submit Picks", body, "/picks", account)


def get_active_entry_id_from_query_or_default(entries):
    if not entries:
        return None
    return entries[0]["id"]


def render_leaderboard(conn, account):
    week = fetch_current_week(conn)
    results = compute_week_results(conn, week["id"])
    season = compute_season_results(conn)
    weeks = conn.execute("SELECT * FROM weeks ORDER BY id").fetchall()
    weekly_rows = []
    for item in results:
        previous = compute_previous_rank(conn, week["id"], item["entry_id"])
        weekly_rows.append(
            "<tr>"
            f"<td>#{item['rank']}</td>"
            f'<td><a class="leaderboard-link" href="/player?entry_id={item["entry_id"]}&week_id={week["id"]}">{esc(item["display_name"])}</a></td>'
            f"<td>{item['wins']}/{item['total_games']}</td>"
            f"<td>{item['tb_gap'] if item['submitted'] else '-'}</td>"
            f'<td class="status {"status--good" if item["submitted"] else "status--warn"}">{movement_text(item["rank"], previous) if item["submitted"] else "Missing picks"}</td>'
            "</tr>"
        )
    season_rows = []
    for row in season:
        season_rows.append(
            "<tr>"
            f"<td>#{row['rank']}</td>"
            f'<td><a class="leaderboard-link" href="/player?entry_id={row["entry_id"]}&week_id={week["id"]}">{esc(row["display_name"])}</a></td>'
            + "".join(f"<td>{item['wins'] if item['wins'] is not None else '-'}</td>" for item in row["weekly"])
            + f"<td><strong>{row['total']}</strong></td></tr>"
        )
    body = f"""
      <section class="page-hero">
        <div><p class="eyebrow">Participant view</p><h1>Weekly leaderboard and season standings</h1></div>
        <div class="page-hero__actions"><span class="badge">{esc(week["label"])}</span></div>
      </section>
      <section class="dashboard-grid">
        <article class="panel">
          <div class="section-heading"><div><p class="section-label">This week</p><h2>Weekly leaderboard</h2></div><span class="badge">Click a name to inspect picks</span></div>
          <div class="table-wrap"><table><thead><tr><th>Rank</th><th>Entry</th><th>Weekly points</th><th>Tiebreak gap</th><th>Status</th></tr></thead><tbody>{''.join(weekly_rows)}</tbody></table></div>
        </article>
        <article class="panel">
          <div class="section-heading"><div><p class="section-label">Whole season</p><h2>Season standings</h2></div><span class="badge">Auto-totaled</span></div>
          <div class="table-wrap"><table><thead><tr><th>Rank</th><th>Entry</th>{''.join(f'<th>{esc(item["label"])}</th>' for item in weeks)}<th>Total</th></tr></thead><tbody>{''.join(season_rows)}</tbody></table></div>
        </article>
      </section>
    """
    return render_layout("Pigskin Junkies | Leaderboards", body, "/leaderboard", account)


def render_trends(conn, account):
    week = fetch_current_week(conn)
    games = fetch_week_games(conn, week["id"])
    pick_rows = conn.execute(
        """
        SELECT g.id AS game_id, g.away_team, g.home_team, g.code, g.winner, pi.selected_team
        FROM games g
        LEFT JOIN pick_items pi ON pi.game_id = g.id
        WHERE g.week_id = ?
        ORDER BY g.id
        """,
        (week["id"],),
    ).fetchall()
    grouped = {}
    for row in pick_rows:
        grouped.setdefault(row["game_id"], {"meta": row, "counts": {}})
        if row["selected_team"]:
            grouped[row["game_id"]]["counts"][row["selected_team"]] = grouped[row["game_id"]]["counts"].get(row["selected_team"], 0) + 1
    cards = []
    for game in games:
        if not has_game_started(game):
            cards.append(
                f'''<article class="breakdown-card breakdown-card--hidden">
                  <strong>{esc(game["code"])}</strong>
                  <span>{esc(game["away_team"])} at {esc(game["home_team"])}</span>
                  <div class="pick-game-card__meta">{esc(game_meta(game))}</div>
                  <div class="pick-lock-notice"><strong>Pick trends unlock at kickoff</strong><span>Selections stay private until this game begins.</span></div>
                </article>'''
            )
            continue
        counts = grouped.get(game["id"], {"counts": {}})["counts"]
        away_count = counts.get(game["away_team"], 0)
        home_count = counts.get(game["home_team"], 0)
        total = max(away_count + home_count, 1)
        away_width = (away_count / total) * 50
        home_width = (home_count / total) * 50
        cards.append(
            f"""
            <article class="breakdown-card">
              <strong>{esc(game["code"])}</strong>
              <span>{esc(game["away_team"])} at {esc(game["home_team"])}</span>
              <div class="pick-game-card__meta">{esc(game_meta(game))}</div>
              <div class="trend-scale">
                <span>{away_count}</span>
                <div class="trend-track">
                  <span class="trend-fill trend-fill--away" style="width: {away_width:.1f}%"></span>
                  <span class="trend-fill trend-fill--home" style="width: {home_width:.1f}%"></span>
                </div>
                <span>{home_count}</span>
              </div>
              <div class="trend-labels"><span>{esc(game["away_team"])}</span><span>{esc(game["home_team"])}</span></div>
              <span class="winner-tag">Winner: {esc(game["winner"] or "TBD")}</span>
            </article>
            """
        )
    body = f"""
      <section class="page-hero">
        <div><p class="eyebrow">Participant view</p><h1>How the field leaned on each game</h1></div>
        <div class="page-hero__actions"><span class="badge">{esc(week["label"])}</span></div>
      </section>
      <section class="panel">
        <div class="section-heading"><div><p class="section-label">Pick distribution</p><h2>Weekly trends</h2></div><span class="badge">Heavier-picked side stretches farther</span></div>
        <div class="breakdown-grid">{''.join(cards)}</div>
      </section>
    """
    return render_layout("Pigskin Junkies | Pick Trends", body, "/trends", account)


def render_player(conn, account, entry_id, week_id):
    week = conn.execute("SELECT * FROM weeks WHERE id = ?", (week_id,)).fetchone() or fetch_current_week(conn)
    entry = conn.execute("SELECT * FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if not entry:
        body = '<section class="panel"><div class="callout">That entry was not found.</div></section>'
        return render_layout("Pigskin Junkies | Entry Detail", body, "/leaderboard", account)
    pick, selections = fetch_pick_bundle(conn, week["id"], entry["id"])
    games = fetch_week_games(conn, week["id"])
    tiebreakers = fetch_week_tiebreakers(conn, week["id"])
    result = next((row for row in compute_week_results(conn, week["id"]) if row["entry_id"] == entry["id"]), None)
    rows = []
    for game in games:
        visible = has_game_started(game)
        selected = selections.get(game["id"], "-") if visible else "Hidden until kickoff"
        winner = game["winner"] if visible else "Hidden until kickoff"
        correct = visible and selected == game["winner"]
        status = "Hidden" if not visible else ("No pick" if selected == "-" else ("Correct" if correct else "Miss"))
        status_class = "status--good" if correct else "status--warn"
        rows.append(
            "<tr>"
            f"<td>{esc(game['code'])}</td>"
            f"<td>{esc(game['away_team'])} at {esc(game['home_team'])}<div class=\"helper-copy\">{esc(game_meta(game))}</div></td>"
            f"<td>{esc(selected)}</td>"
            f"<td>{esc(winner or 'TBD')}</td>"
            f'<td class="status {status_class}">{status}</td>'
            "</tr>"
        )
    body = f"""
      <section class="page-hero">
        <div><p class="eyebrow">Participant detail</p><h1>{esc(entry["display_name"])} picks</h1></div>
        <div class="page-hero__actions"><a class="button button--ghost button--small" href="/leaderboard">Back to leaderboard</a></div>
      </section>
      <section class="dashboard-grid">
        <article class="panel">
          <p class="section-label">Snapshot</p><h2>Entry summary</h2>
          <div class="stack">
            <div class="summary-card"><strong>Weekly rank</strong><span>{'#' + str(result['rank']) if result else 'No rank'}</span></div>
            <div class="summary-card"><strong>Weekly points</strong><span>{f"{result['wins']}/{result['total_games']}" if result and result['submitted'] else 'No picks submitted'}</span></div>
            <div class="summary-card"><strong>Submitted</strong><span>{esc(result['submitted_at']) if result and result['submitted_at'] else 'Not submitted'}</span></div>
          </div>
        </article>
        <article class="panel">
          <p class="section-label">Tiebreakers</p><h2>Guesses</h2>
          <div class="stack">
            {''.join(f'<div class="summary-card"><strong>{esc(tb["prompt"])}</strong><span>{esc(tiebreaker_value(pick, tb["position"]) or "-")}</span></div>' for tb in tiebreakers)}
          </div>
        </article>
      </section>
      <section class="panel">
        <div class="section-heading"><div><p class="section-label">Every game</p><h2>Weekly picks</h2></div><span class="badge">{esc(week["label"])}</span></div>
        <div class="table-wrap"><table><thead><tr><th>Game</th><th>Matchup</th><th>Pick</th><th>Winner</th><th>Result</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div>
      </section>
    """
    return render_layout("Pigskin Junkies | Entry Detail", body, "/leaderboard", account)


def save_commissioner_changes(conn, form):
    week = form_week(conn, form)
    conn.execute(
        "UPDATE weeks SET label = ?, lock_time = ? WHERE id = ?",
        (form.get("week_label", week["label"]).strip() or week["label"], form.get("lock_time", week["lock_time"]), week["id"]),
    )
    for tb in fetch_week_tiebreakers(conn, week["id"]):
        conn.execute(
            "UPDATE tiebreakers SET prompt = ? WHERE id = ?",
            (form.get(f"tb_{tb['position']}", tb["prompt"]).strip() or tb["prompt"], tb["id"]),
        )
    for game in fetch_week_games(conn, week["id"]):
        conn.execute(
            "UPDATE games SET winner = ?, score_away = ?, score_home = ? WHERE id = ?",
            (
                form.get(f"winner_{game['id']}", game["winner"]) or None,
                int(form.get(f"score_away_{game['id']}", game["score_away"]) or 0),
                int(form.get(f"score_home_{game['id']}", game["score_home"]) or 0),
                game["id"],
            ),
        )
    conn.commit()


def create_account(conn, form):
    name = (form.get("name") or "").strip()
    email = (form.get("email") or "").strip().lower()
    password = (form.get("password") or "").strip()
    entry_one = (form.get("entry_one") or "").strip()
    entry_two = (form.get("entry_two") or "").strip()
    if not all([name, email, password, entry_one]):
        return
    cur = conn.execute(
        "INSERT INTO accounts (name, email, password_hash, is_commissioner) VALUES (?, ?, ?, ?)",
        (name, email, hash_password(password), 1 if form.get("is_commissioner") else 0),
    )
    account_id = cur.lastrowid
    conn.execute("INSERT INTO entries (account_id, display_name) VALUES (?, ?)", (account_id, entry_one))
    if entry_two:
        conn.execute("INSERT INTO entries (account_id, display_name) VALUES (?, ?)", (account_id, entry_two))
    conn.commit()


def import_accounts_from_csv(conn, csv_text):
    if not (csv_text or "").strip():
        return 0
    created = 0
    reader = csv.DictReader(StringIO(csv_text.strip()))
    for row in reader:
        name = (row.get("name") or "").strip()
        email = (row.get("email") or "").strip().lower()
        password = (row.get("password") or "").strip()
        entry_one = (row.get("entry_one") or "").strip()
        entry_two = (row.get("entry_two") or "").strip()
        is_commissioner = (row.get("is_commissioner") or "").strip().lower() in {"1", "true", "yes", "y"}
        if not all([name, email, password, entry_one]):
            continue
        existing = conn.execute("SELECT id FROM accounts WHERE lower(email) = lower(?)", (email,)).fetchone()
        if existing:
            continue
        cur = conn.execute(
            "INSERT INTO accounts (name, email, password_hash, is_commissioner) VALUES (?, ?, ?, ?)",
            (name, email, hash_password(password), 1 if is_commissioner else 0),
        )
        account_id = cur.lastrowid
        conn.execute("INSERT INTO entries (account_id, display_name) VALUES (?, ?)", (account_id, entry_one))
        if entry_two:
            conn.execute("INSERT INTO entries (account_id, display_name) VALUES (?, ?)", (account_id, entry_two))
        created += 1
    conn.commit()
    return created


def update_account(conn, form):
    account_id = int(form.get("account_id") or 0)
    account = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if not account:
        return
    password = (form.get("password") or "").strip()
    password_hash = hash_password(password) if password else account["password_hash"]
    conn.execute(
        "UPDATE accounts SET name = ?, email = ?, password_hash = ?, is_commissioner = ? WHERE id = ?",
        (
            (form.get("name") or account["name"]).strip() or account["name"],
            (form.get("email") or account["email"]).strip().lower() or account["email"],
            password_hash,
            1 if form.get("is_commissioner") else 0,
            account_id,
        ),
    )
    conn.commit()


def delete_account(conn, account_id, acting_account_id):
    target = conn.execute("SELECT * FROM accounts WHERE id = ?", (account_id,)).fetchone()
    if not target or target["id"] == acting_account_id:
        return False
    if target["is_commissioner"]:
        commissioner_count = conn.execute("SELECT COUNT(*) AS count FROM accounts WHERE is_commissioner = 1").fetchone()["count"]
        if commissioner_count <= 1:
            return False

    entry_rows = conn.execute("SELECT id FROM entries WHERE account_id = ?", (account_id,)).fetchall()
    for entry in entry_rows:
        pick_rows = conn.execute("SELECT id FROM picks WHERE entry_id = ?", (entry["id"],)).fetchall()
        for pick in pick_rows:
            conn.execute("DELETE FROM pick_items WHERE pick_id = ?", (pick["id"],))
        conn.execute("DELETE FROM picks WHERE entry_id = ?", (entry["id"],))
    conn.execute("DELETE FROM entries WHERE account_id = ?", (account_id,))
    conn.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
    conn.commit()
    return True


def add_entry(conn, form):
    account_id = int(form.get("account_id") or 0)
    display_name = (form.get("display_name") or "").strip()
    if not account_id or not display_name:
        return
    conn.execute("INSERT INTO entries (account_id, display_name) VALUES (?, ?)", (account_id, display_name))
    conn.commit()


def set_current_week(conn, form):
    week_id = int(form.get("week_id") or 0)
    if not week_id:
        return
    conn.execute("UPDATE weeks SET is_current = 0")
    conn.execute("UPDATE weeks SET is_current = 1 WHERE id = ?", (week_id,))
    conn.commit()


def create_week(conn, form):
    label = (form.get("label") or "").strip()
    slug = (form.get("slug") or "").strip()
    lock_time = (form.get("lock_time") or "").strip()
    if not all([label, slug, lock_time]):
        return
    make_current = form.get("keep_current") != "1"
    if make_current:
        conn.execute("UPDATE weeks SET is_current = 0")
    cur = conn.execute(
        "INSERT INTO weeks (slug, label, lock_time, is_current) VALUES (?, ?, ?, ?)",
        (slug, label, lock_time, 1 if make_current else 0),
    )
    new_week_id = cur.lastrowid
    for position in range(1, 4):
        conn.execute(
            "INSERT INTO tiebreakers (week_id, position, prompt) VALUES (?, ?, ?)",
            (new_week_id, position, f"Tiebreaker {position}"),
        )
    conn.commit()


def add_game(conn, form):
    week = form_week(conn, form)
    away_team = (form.get("away_team") or "").strip()
    home_team = (form.get("home_team") or "").strip()
    kickoff = (form.get("kickoff") or "").strip()
    site_note = (form.get("site_note") or "").strip()
    favorite_side = form.get("favorite_side") or "none"
    spread_raw = (form.get("spread") or "").strip()
    if not week or not all([away_team, home_team, kickoff]) or away_team.lower() == home_team.lower():
        return False
    try:
        spread = abs(float(spread_raw)) if spread_raw else 0
    except ValueError:
        return False
    if favorite_side == "away":
        favorite = away_team
    elif favorite_side == "home":
        favorite = home_team
    else:
        favorite = ""
    spread_text = f"{favorite} -{spread:g}" if favorite and spread else "Pick 'em"
    game_count = conn.execute("SELECT COUNT(*) AS count FROM games WHERE week_id = ?", (week["id"],)).fetchone()["count"]
    conn.execute(
        """
        INSERT INTO games (week_id, code, away_team, home_team, kickoff, site_note, spread_text, display_order, winner, score_away, score_home)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0, 0)
        """,
        (week["id"], f"Game {game_count + 1:02d}", away_team, home_team, kickoff, site_note, spread_text, game_count + 1),
    )
    conn.commit()
    return True


def update_game(conn, form, game_id):
    game = conn.execute("SELECT * FROM games WHERE id = ?", (game_id,)).fetchone()
    away_team = (form.get("away_team") or "").strip()
    home_team = (form.get("home_team") or "").strip()
    kickoff = (form.get("kickoff") or "").strip()
    site_note = (form.get("site_note") or "").strip()
    favorite_side = form.get("favorite_side") or "none"
    spread_raw = (form.get("spread") or "").strip()
    if not game or not all([away_team, home_team, kickoff]) or away_team.lower() == home_team.lower():
        return None
    try:
        spread = abs(float(spread_raw)) if spread_raw else 0
    except ValueError:
        return None
    favorite = away_team if favorite_side == "away" else home_team if favorite_side == "home" else ""
    spread_text = f"{favorite} -{spread:g}" if favorite and spread else "Pick 'em"
    conn.execute(
        "UPDATE games SET away_team = ?, home_team = ?, kickoff = ?, site_note = ?, spread_text = ? WHERE id = ?",
        (away_team, home_team, kickoff, site_note, spread_text, game_id),
    )
    ordered_game_ids = [listed_game["id"] for listed_game in fetch_week_games(conn, game["week_id"])]
    ordered_game_ids.remove(game_id)
    try:
        position = int(form.get("position") or len(ordered_game_ids) + 1)
    except ValueError:
        position = len(ordered_game_ids) + 1
    ordered_game_ids.insert(max(0, min(position - 1, len(ordered_game_ids))), game_id)
    set_game_order(conn, game["week_id"], ordered_game_ids)
    conn.commit()
    return game["week_id"]


def set_game_order(conn, week_id, ordered_game_ids):
    for position, listed_game_id in enumerate(ordered_game_ids, start=1):
        conn.execute(
            "UPDATE games SET display_order = ?, code = ? WHERE id = ? AND week_id = ?",
            (position, f"Game {position:02d}", listed_game_id, week_id),
        )


def move_game(conn, game_id, direction):
    game = conn.execute("SELECT * FROM games WHERE id = ?", (game_id,)).fetchone()
    if not game or direction not in {"earlier", "later"}:
        return None
    ordered_game_ids = [listed_game["id"] for listed_game in fetch_week_games(conn, game["week_id"])]
    current_position = ordered_game_ids.index(game_id)
    new_position = current_position - 1 if direction == "earlier" else current_position + 1
    if 0 <= new_position < len(ordered_game_ids):
        ordered_game_ids[current_position], ordered_game_ids[new_position] = ordered_game_ids[new_position], ordered_game_ids[current_position]
        set_game_order(conn, game["week_id"], ordered_game_ids)
        conn.commit()
    return game["week_id"]


def save_picks(conn, account, form):
    week = fetch_current_week(conn)
    entries = fetch_account_entries(conn, account["id"])
    entry_ids = {str(entry["id"]) for entry in entries}
    selected_entry_id = form.get("entry_id") or (str(entries[0]["id"]) if entries else None)
    if selected_entry_id not in entry_ids:
        return "That entry does not belong to the signed-in account."
    tiebreakers = fetch_week_tiebreakers(conn, week["id"])
    games = fetch_week_games(conn, week["id"])
    current = conn.execute(
        "SELECT * FROM picks WHERE week_id = ? AND entry_id = ?",
        (week["id"], selected_entry_id),
    ).fetchone()
    tb_game = next((game for game in games if game["code"] == "Game 20"), games[-1] if games else None)
    tiebreakers_locked = bool(tb_game and is_game_locked(tb_game))
    if current:
        pick_id = current["id"]
        conn.execute(
            "UPDATE picks SET submitted_at = ?, tiebreaker_1 = ?, tiebreaker_2 = ?, tiebreaker_3 = ? WHERE id = ?",
            (
                now_iso(),
                current["tiebreaker_1"] if tiebreakers_locked else int(form.get("tb_1") or 0),
                current["tiebreaker_2"] if tiebreakers_locked else int(form.get("tb_2") or 0),
                current["tiebreaker_3"] if tiebreakers_locked else int(form.get("tb_3") or 0),
                pick_id,
            ),
        )
    else:
        cur = conn.execute(
            """
            INSERT INTO picks (week_id, entry_id, submitted_at, tiebreaker_1, tiebreaker_2, tiebreaker_3)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                week["id"],
                selected_entry_id,
                now_iso(),
                int(form.get("tb_1") or 0),
                int(form.get("tb_2") or 0),
                int(form.get("tb_3") or 0),
            ),
        )
        pick_id = cur.lastrowid
    for game in games:
        if is_game_locked(game):
            continue
        selected = form.get(f"pick_{game['id']}")
        if selected not in {game["away_team"], game["home_team"]}:
            continue
        conn.execute(
            """
            INSERT INTO pick_items (pick_id, game_id, selected_team) VALUES (?, ?, ?)
            ON CONFLICT(pick_id, game_id) DO UPDATE SET selected_team = excluded.selected_team
            """,
            (pick_id, game["id"], selected),
        )
    conn.commit()
    return "Your picks have been saved."


def app(environ, start_response):
    init_db()
    conn = get_conn()
    path = environ.get("PATH_INFO", "/")
    method = environ.get("REQUEST_METHOD", "GET").upper()
    query = urllib.parse.parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=True)
    account = get_current_account(environ, conn)

    if path.startswith("/static/"):
        conn.close()
        return serve_static(start_response, path.replace("/static/", "", 1))

    if path == "/" and method == "GET":
        body = render_home(conn, account)
        conn.close()
        return html_response(start_response, body)

    if path == "/login" and method == "GET":
        next_page = query.get("next", [""])[0]
        body = render_login(conn, account, next_page=next_page)
        conn.close()
        return html_response(start_response, body)

    if path == "/login" and method == "POST":
        form = read_post_data(environ)
        next_page = form.get("next", "")
        user = conn.execute("SELECT * FROM accounts WHERE lower(email) = lower(?)", (form.get("email", "").strip(),)).fetchone()
        if not user or not verify_password(form.get("password", ""), user["password_hash"]):
            body = render_login(conn, account, error="That email/password combination did not match a participant account.", next_page=next_page)
            conn.close()
            return html_response(start_response, body, status="401 Unauthorized")
        if next_page == "commissioner" and not user["is_commissioner"]:
            body = render_login(conn, account, error="That account can sign in for picks, but it does not have commissioner access.", next_page=next_page)
            conn.close()
            return html_response(start_response, body, status="403 Forbidden")
        headers = [cookie_header("pigskin_session", sign_session(user["id"]))]
        first_entry = conn.execute("SELECT id FROM entries WHERE account_id = ? ORDER BY id LIMIT 1", (user["id"],)).fetchone()
        if first_entry:
            headers.append(cookie_header("pigskin_entry", first_entry["id"]))
        target = "/commissioner" if next_page == "commissioner" else "/picks"
        conn.close()
        return redirect(start_response, target, headers)

    if path == "/logout":
        conn.close()
        headers = [
            cookie_header("pigskin_session", "", max_age=0),
            cookie_header("pigskin_entry", "", max_age=0),
        ]
        return redirect(start_response, "/login", headers)

    if path == "/account/password" and method == "GET":
        if not account:
            conn.close()
            return redirect(start_response, "/login")
        body = render_change_password(account)
        conn.close()
        return html_response(start_response, body)

    if path == "/account/password" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login")
        form = read_post_data(environ)
        current_password = form.get("current_password", "")
        new_password = form.get("new_password", "")
        confirm_password = form.get("confirm_password", "")
        if not verify_password(current_password, account["password_hash"]):
            body = render_change_password(account, error="Your current password was not correct.")
            conn.close()
            return html_response(start_response, body, status="400 Bad Request")
        if len(new_password) < 8:
            body = render_change_password(account, error="Your new password must be at least 8 characters.")
            conn.close()
            return html_response(start_response, body, status="400 Bad Request")
        if new_password != confirm_password:
            body = render_change_password(account, error="Your new passwords did not match.")
            conn.close()
            return html_response(start_response, body, status="400 Bad Request")
        conn.execute("UPDATE accounts SET password_hash = ? WHERE id = ?", (hash_password(new_password), account["id"]))
        conn.commit()
        body = render_change_password(account, message="Your password has been updated. Only you know the new one.")
        conn.close()
        return html_response(start_response, body)

    if path == "/commissioner" and method == "GET":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        body, sentinel = render_commissioner(conn, account)
        conn.close()
        return html_response(start_response, body)

    if path.startswith("/commissioner/game/") and path.endswith("/edit") and method == "GET":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        game_id = fetch_week_id(path.removeprefix("/commissioner/game/").removesuffix("/edit").strip("/"))
        body = render_game_editor(conn, account, game_id) if game_id else render_game_editor(conn, account, -1)
        conn.close()
        return html_response(start_response, body)

    if path in {"/commissioner/weekly", "/commissioner/participants", "/commissioner/weeks"} and method == "GET":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        section = path.rsplit("/", 1)[-1]
        body, sentinel = render_commissioner(conn, account, section=section, week_id=query.get("week_id", [None])[0])
        conn.close()
        return html_response(start_response, body)

    if path == "/commissioner/save" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        save_commissioner_changes(conn, form)
        conn.close()
        return redirect(start_response, commissioner_week_url(form))

    if path == "/commissioner/game/add" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        add_game(conn, form)
        conn.close()
        return redirect(start_response, commissioner_week_url(form))

    if path.startswith("/commissioner/game/move/") and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        game_id = fetch_week_id(path.rsplit("/", 1)[-1])
        updated_week_id = move_game(conn, game_id, form.get("direction")) if game_id else None
        conn.close()
        return redirect(start_response, f"/commissioner/weekly?week_id={updated_week_id}" if updated_week_id else "/commissioner/weekly")

    if path.startswith("/commissioner/game/update/") and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        game_id = fetch_week_id(path.rsplit("/", 1)[-1])
        updated_week_id = update_game(conn, form, game_id) if game_id else None
        conn.close()
        return redirect(start_response, f"/commissioner/weekly?week_id={updated_week_id}" if updated_week_id else commissioner_week_url(form))

    if path == "/commissioner/account/add" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        create_account(conn, read_post_data(environ))
        conn.close()
        return redirect(start_response, "/commissioner/participants")

    if path == "/commissioner/account/update" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        update_account(conn, read_post_data(environ))
        conn.close()
        return redirect(start_response, "/commissioner/participants")

    if path == "/commissioner/account/delete" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        target = conn.execute("SELECT * FROM accounts WHERE id = ?", (int(form.get("account_id") or 0),)).fetchone()
        if not target or target["id"] == account["id"]:
            conn.close()
            return redirect(start_response, "/commissioner/participants")
        if form.get("confirm_delete") != "yes":
            body = render_delete_account_confirmation(account, target)
            conn.close()
            return html_response(start_response, body)
        delete_account(conn, target["id"], account["id"])
        conn.close()
        return redirect(start_response, "/commissioner/participants")

    if path == "/commissioner/account/import" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        form = read_post_data(environ)
        import_accounts_from_csv(conn, form.get("csv_data", ""))
        conn.close()
        return redirect(start_response, "/commissioner/participants")

    if path == "/commissioner/entry/add" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        add_entry(conn, read_post_data(environ))
        conn.close()
        return redirect(start_response, "/commissioner/participants")

    if path == "/commissioner/week/select" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        set_current_week(conn, read_post_data(environ))
        conn.close()
        return redirect(start_response, "/commissioner/weeks")

    if path == "/commissioner/week/add" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login?next=commissioner")
        if not account["is_commissioner"]:
            conn.close()
            return redirect(start_response, "/picks")
        create_week(conn, read_post_data(environ))
        conn.close()
        return redirect(start_response, "/commissioner/weeks")

    if path == "/picks" and method == "GET":
        if account:
            entry_override = query.get("entry_id", [""])[0]
            if entry_override:
                owned = conn.execute("SELECT id FROM entries WHERE id = ? AND account_id = ?", (entry_override, account["id"])).fetchone()
                if owned:
                    headers = [cookie_header("pigskin_entry", owned["id"])]
                    body = render_picks(conn, account, active_entry_id=owned["id"])
                    conn.close()
                    return html_response(start_response, body, headers=headers)
        body = render_picks(conn, account, active_entry_id=get_active_entry_id(environ, conn, account) if account else None)
        conn.close()
        return html_response(start_response, body)

    if path == "/picks" and method == "POST":
        if not account:
            conn.close()
            return redirect(start_response, "/login")
        form = read_post_data(environ)
        message = save_picks(conn, account, form)
        entry_id = form.get("entry_id", "")
        headers = []
        if entry_id:
            headers.append(cookie_header("pigskin_entry", entry_id))
        body = render_picks(conn, account, message=message, active_entry_id=int(entry_id) if entry_id else get_active_entry_id(environ, conn, account))
        conn.close()
        return html_response(start_response, body, headers=headers)

    if path == "/leaderboard" and method == "GET":
        body = render_leaderboard(conn, account)
        conn.close()
        return html_response(start_response, body)

    if path == "/trends" and method == "GET":
        body = render_trends(conn, account)
        conn.close()
        return html_response(start_response, body)

    if path == "/player" and method == "GET":
        entry_id = int(query.get("entry_id", ["0"])[0] or 0)
        week_id = int(query.get("week_id", [str(fetch_current_week(conn)["id"])])[0])
        body = render_player(conn, account, entry_id, week_id)
        conn.close()
        return html_response(start_response, body)

    conn.close()
    return text_response(start_response, "Not found", status="404 Not Found")


application = app


if __name__ == "__main__":
    init_db()
    print(f"Pigskin Junkies running on http://{HOST}:{PORT}")
    with make_server(HOST, PORT, app) as server:
        server.serve_forever()
