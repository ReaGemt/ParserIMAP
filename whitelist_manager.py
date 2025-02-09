import logging
import smtplib
import re
from email.message import EmailMessage
from typing import Set

WHITELIST_FILES = {
    "addresses": "whitelist_a.txt",
    "domains": "whitelist_d.txt"
}

class WhitelistManager:
    def __init__(self):
        self.whitelist_addresses = self._load_whitelist("addresses")
        self.whitelist_domains = self._load_whitelist("domains")

    def _load_whitelist(self, key: str) -> Set[str]:
        """Загружает whitelist из файла."""
        filename = WHITELIST_FILES[key]
        try:
            with open(filename, "r", encoding="utf-8") as f:
                return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
        except FileNotFoundError:
            logging.warning(f"Файл {filename} не найден. Будет создан при сохранении.")
            return set()
        except Exception as e:
            logging.error(f"Ошибка загрузки {filename}: {e}")
            return set()

    def _save_whitelist(self, key: str):
        """Сохраняет whitelist в файл."""
        filename = WHITELIST_FILES[key]
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(sorted(getattr(self, f"whitelist_{key}"))) + "\n")
            logging.info(f"Whitelist сохранён в {filename}.")
        except Exception as e:
            logging.error(f"Ошибка сохранения {filename}: {e}")

    def is_whitelisted(self, email: str) -> bool:
        """Проверяет, находится ли email в whitelist."""
        email = email.lower()
        return email in self.whitelist_addresses or email.split("@")[1] in self.whitelist_domains

    def add_entry(self, key: str, entry: str):
        """Добавляет запись в whitelist."""
        getattr(self, f"whitelist_{key}").add(entry.lower())
        self._save_whitelist(key)

    def remove_entry(self, key: str, entry: str):
        """Удаляет запись из whitelist."""
        getattr(self, f"whitelist_{key}").discard(entry.lower())
        self._save_whitelist(key)

def validate_email(email: str) -> bool:
    """Проверяет корректность email."""
    return bool(re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email))

def send_email(smtp_user, smtp_password, to_addr, subject, body):
    """Отправляет email через SMTP."""
    msg = EmailMessage()
    msg["From"] = smtp_user
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    
    try:
        with smtplib.SMTP_SSL("smtp.example.com", 465, timeout=10) as server:
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        logging.info(f"Письмо отправлено на {to_addr}")
        return True
    except smtplib.SMTPException as e:
        logging.error(f"Ошибка SMTP: {e}")
    except Exception as e:
        logging.error(f"Ошибка отправки email: {e}")
    return False