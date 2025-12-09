import sqlite3
import pandas as pd
import bcrypt
from pathlib import Path


DATA_DIR = Path("DATA")
DB_PATH = Path(__file__).parent / "DATA" / "intelligence_platform.db"

DATA_DIR.mkdir(exist_ok=True)
print("Using DB:", DB_PATH.absolute())

#Database connection
def connect_database():
    """Connect to SQLite database (creates if not exists)."""
    #conn = connect_database()
    #print(conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall())
    return sqlite3.connect(DB_PATH)

#creating tables
def create_tables(conn):
    """Create 4 tables."""
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );""")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS cyber_incidents(
            incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
            dataset_name TEXT,
            category TEXT,
            source TEXT,
            last_updated DATETIME NOT NULL,
            incident_type TEXT,
            record_count INTEGER,
            file_size_mb REAL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS it_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id TEXT UNIQUE NOT NULL,
            priority TEXT,
            status TEXT,
            category TEXT,
            subject TEXT,
            description TEXT,
            created_date TEXT,
            resolved_date TEXT,
            assigned_to TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """)

    conn.commit()
    print("✅ All tables created.")
#part 4 migration
def migrate_users():
    """"Load users from users.txt - database"""
    path = DATA_DIR / "users.txt"
    if not path.exists():
        print("<UNK> Users file not found.")
        return
    conn = connect_database()
    migrated = 0

    with open(path, "r") as file:
        for line in file:
            parts= line.strip().split(",")
            if len(parts) < 2:
                continue
            username, pw_hash = parts[0], parts[1]
            conn.execute("""INSERT OR IGNORE INTO users (username, password_hash)(VALUES(?,?)) )""",
            (username, pw_hash))
            migrated += 1
    conn.commit()
    conn.close()

    print("<UNK> {} users migrated.")

#part 5 Authentication
def register_users(username, password, role="user"):
    """Register new user."""
    conn = connect_database()

    exists = conn.execute(
        "SELECT * FROM users WHERE username = ?",(username,)#.fetchtone()
    )
    if exists:
        conn.close()
        return False,"Username already exists."

    password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    conn.execute("""INSERT INTO users (username, password_hash)(VALUES(?,?)) VALUES(?,?)""",(username, password_hash,role))
    conn.commit()
    conn.close()

    return True,"User registered successfully."

def create_cyber_incidents_table(conn):
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS cyber_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            last_updated DATETIME NOT NULL,
            incident_type TEXT,
            severity TEXT,
            status TEXT,
            description TEXT,
            reported_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()

def login_user(username, password):
    """Validate login using bcrypt."""
    conn = connect_database()

    row = conn.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    conn.close()

    if not row:
        return False, "User not found."

    stored_hash = row[0]

    if bcrypt.checkpw(password.encode(), stored_hash.encode()):
        return True, "Login successful."
    else:
        return False, "Incorrect password."



# load csv with pandas

def load_csv_to_table(csv_path, table):
    """Load any CSV into a table using pandas."""
    if not csv_path.exists():
        print(f"⚠️ CSV not found: {csv_path}")
        return 0

    df = pd.read_csv(csv_path)
    conn = connect_database()

    df.to_sql(table, conn, if_exists="append", index=False)

    conn.close()
    print(f"📥 Loaded {len(df)} rows into {table}")
    return len(df)



# CRUD operations

def insert_incident(date, incident_type, severity, status, desc, reporter):
    """Create a new incident."""
    conn = connect_database()
    cur = conn.execute("""
        INSERT INTO cyber_incidents
        (last_updated, incident_type, severity, status, description, reported_by)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (date, incident_type, severity, status, desc, reporter))
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def get_all_incidents():
    conn = connect_database()
    df = pd.read_sql_query("SELECT * FROM cyber_incidents", conn)
    conn.close()
    return df


def update_incident_status(incident_id, new_status):
    conn = connect_database()
    conn.execute("""
    UPDATE cyber_incidents
    SET status = ?
    WHERE id = ?
    """, (new_status, incident_id))

    conn.commit()
    conn.close()


def delete_incident(incident_id):
    conn = connect_database()
    conn.execute("DELETE FROM cyber_incidents WHERE id = ?", (incident_id,))
    conn.commit()
    conn.close()

# ANALYTICAL QUERIES (GROUP BY)

def incidents_by_type():
    conn = connect_database()
    df = pd.read_sql_query("""
        SELECT incident_type, COUNT(*) AS count
        FROM cyber_incidents
        GROUP BY incident_type
        ORDER BY count DESC
   """, conn)
    conn.close()
    return df

# FULL SETUP

def setup_database():
    """Creates tables, migrates users, and loads CSV files."""
    conn = connect_database()
    create_tables(conn)
    conn.close()

    print("\n👤 Migrating users...")
    migrate_users()

    print("\n📥 Loading CSV files...")
    load_csv_to_table(DATA_DIR / "cyber_incidents.csv", "cyber_incidents")
    load_csv_to_table(DATA_DIR / "datasets_metadata.csv", "datasets_metadata")
    load_csv_to_table(DATA_DIR / "it_tickets.csv", "it_tickets")

    print("\n🎉 Database setup complete!\n")



# FULL TEST

def run_demo():
    print("\n===== WEEK 8 DEMO START =====")

    setup_database()

    print("\n🔐 Registering 'alice'...")
    print(register_users("alice", "Pass123!"))

    print("\n🔐 Logging in as 'alice'...")
    print(login_user("alice", "Pass123!"))

    print("\n📝 Creating new incident...")
    incident_id = insert_incident(
        "2024-11-01", "Phishing", "High", "Open",
        "Suspicious email", "alice"
    )
    print(f"Incident #{incident_id} created.")

    print("\n📊 All incidents:")
    print(get_all_incidents())

    print("\n🔄 Updating incident...")
    update_incident_status(incident_id, "Resolved")

    print("\n🗑️ Deleting incident...")
    delete_incident(incident_id)

    print("\n===== WEEK 8 DEMO COMPLETE =====")


if __name__ == "__main__":
    run_demo()

