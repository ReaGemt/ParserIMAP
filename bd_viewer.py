import logging
import sqlite3
from tabulate import tabulate

def view_all_records(db_path: str = 'processed_emails.db') -> None:
    """
    Выводит все записи из таблицы processed_emails в виде таблицы.
    """
    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM processed_emails')
            records = cursor.fetchall()

            if records:
                headers = ["Message ID", "Processed", "Error Message", "Timestamp"]
                print(tabulate(records, headers=headers, tablefmt="grid"))
            else:
                print("В таблице processed_emails нет записей.")
    except sqlite3.Error as e:
        logging.error(f"Ошибка при получении записей из базы данных: {e}")

# Пример использования:
view_all_records()