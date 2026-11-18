"""Ownership lives in the database predicates, including reorder writes."""
import json
import sqlite3
import threading


class Orders:
    def __init__(self, path: str = ":memory:"):
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.connection:
            self.connection.execute("CREATE TABLE IF NOT EXISTS orders "
                                    "(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, items TEXT NOT NULL)")
            self.connection.executemany("INSERT OR IGNORE INTO orders VALUES (?, ?, ?)",
                                        [(1, 1, '["notebook"]'), (2, 1, '["pen"]'), (3, 2, '["mug"]')])

    @staticmethod
    def decode(row):
        return {"id": row["id"], "user_id": row["user_id"], "items": json.loads(row["items"])}

    def list_for(self, user: int):
        with self.lock:
            return [self.decode(row) for row in self.connection.execute(
                "SELECT * FROM orders WHERE user_id = ? ORDER BY id", (user,))]

    def get_for(self, order: int, user: int):
        with self.lock:
            row = self.connection.execute("SELECT * FROM orders WHERE id = ? AND user_id = ?",
                                          (order, user)).fetchone()
            return None if row is None else self.decode(row)

    def reorder_for(self, order: int, user: int):
        with self.lock, self.connection:
            cursor = self.connection.execute(
                "INSERT INTO orders (user_id, items) SELECT user_id, items FROM orders "
                "WHERE id = ? AND user_id = ?", (order, user))
            if cursor.rowcount == 0:
                return None
            row = self.connection.execute("SELECT * FROM orders WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return self.decode(row)
