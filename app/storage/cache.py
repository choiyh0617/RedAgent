from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path


class SimpleCache:
    def __init__(self) -> None:
        self._data: dict[str, object] = {}

    def get(self, key: str):
        return self._data.get(key)

    def set(self, key: str, value: object) -> None:
        self._data[key] = value


class SQLiteJSONCache:
    def __init__(self, path: Path, *, table_name: str = "cache") -> None:
        self.path = path
        self.table_name = table_name
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def get(self, key: str):
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute(
                f"SELECT value_json, expires_at FROM {self.table_name} WHERE cache_key = ?",
                (key,),
            ).fetchone()
        finally:
            connection.close()
        if not row:
            return None
        value_json, expires_at = row
        if expires_at is not None and expires_at < time.time():
            self.delete(key)
            return None
        return json.loads(value_json)

    def set(self, key: str, value: object, *, ttl_seconds: int | None = None) -> None:
        expires_at = None if ttl_seconds is None else time.time() + ttl_seconds
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                f"INSERT OR REPLACE INTO {self.table_name}(cache_key, value_json, expires_at) VALUES (?, ?, ?)",
                (key, json.dumps(value), expires_at),
            )
            connection.commit()
        finally:
            connection.close()

    def delete(self, key: str) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(f"DELETE FROM {self.table_name} WHERE cache_key = ?", (key,))
            connection.commit()
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self.table_name} (
                    cache_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    expires_at REAL
                )
                """
            )
            connection.commit()
        finally:
            connection.close()
