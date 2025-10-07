"""Compatibility wrapper for the existing database module.

sniffer.py imports `db`, but the project implements the database in
`database.py`. This wrapper re-exports the commonly used names so the
sniffer can import `from db import insert_packets_batch` without change.
"""
from database import insert_packets_batch, insert_packet, conn, cur

__all__ = ["insert_packets_batch", "insert_packet", "conn", "cur"]
