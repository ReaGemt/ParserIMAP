import logging
import sqlite3
from datetime import datetime, timedelta
from typing import Optional, Callable

DB_PATH = 'processed_emails.db'

def with_db_connection(db_path: str = DB_PATH) -> Callable:
    """Decorator to handle database connection setup and teardown."""
    def decorator(func):
        def wrapper(*args, **kwargs):
            try:
                with sqlite3.connect(db_path) as conn:
                    conn.execute("PRAGMA journal_mode=WAL;")  # Optimize for writes
                    kwargs['conn'] = conn
                    return func(*args, **kwargs)
            except sqlite3.Error as e:
                logging.error(f"Database error in {func.__name__}: {e}")
                raise
        return wrapper
    return decorator

@with_db_connection()
def init_db(conn: sqlite3.Connection) -> None:
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_emails (
                message_id TEXT PRIMARY KEY,
                processed BOOLEAN DEFAULT 0,
                error_message TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_message_id ON processed_emails (message_id)')
        conn.commit()
    except sqlite3.Error as e:
        logging.error(f"Error initializing database: {e}")
        raise

@with_db_connection()
def is_email_processed(message_id: str, conn: sqlite3.Connection) -> bool:
    try:
        cursor = conn.cursor()
        cursor.execute('SELECT processed FROM processed_emails WHERE message_id = ?', (message_id,))
        result = cursor.fetchone()
        if result is None:
            logging.debug(f"Email {message_id} not found in database.")
            return False
        return result[0] == 1
    except sqlite3.Error as e:
        logging.error(f"Error checking email {message_id}: {e}")
        return False

@with_db_connection()
def mark_email_as_processed(
    message_id: str,
    conn: sqlite3.Connection,
    error_message: Optional[str] = None
) -> None:
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO processed_emails (message_id, processed, error_message)
            VALUES (?, ?, ?)
        ''', (message_id, error_message is None, error_message))
        conn.commit()
        logging.info(f"Email {message_id} marked as processed.")
    except sqlite3.Error as e:
        logging.error(f"Error marking email {message_id} as processed: {e}")
        raise

@with_db_connection()
def cleanup_old_records(days_to_keep: int, conn: sqlite3.Connection) -> None:
    try:
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        cutoff_date_str = cutoff_date.strftime('%Y-%m-%d %H:%M:%S')

        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM processed_emails WHERE timestamp < ?', (cutoff_date_str,))
        count_to_delete = cursor.fetchone()[0]

        if count_to_delete > 0:
            cursor.execute('DELETE FROM processed_emails WHERE timestamp < ?', (cutoff_date_str,))
            conn.commit()
            logging.info(f"Deleted {count_to_delete} records older than {days_to_keep} days.")
        else:
            logging.info("No records to delete.")
    except sqlite3.Error as e:
        logging.error(f"Error cleaning old records: {e}")
        raise
