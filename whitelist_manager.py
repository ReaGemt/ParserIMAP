# whitelist_manager.py

import re
import logging
import smtplib
import time
import tkinter as tk
from email.message import EmailMessage
from socket import socket
from tkinter import messagebox, simpledialog, END
from typing import Set
import config


WHITELIST_FILE_ADDRESSES = 'whitelist_a.txt'
WHITELIST_FILE_DOMAINS = 'whitelist_d.txt'


def load_whitelist(filename: str) -> Set[str]:
    """
    Загружает whitelist из указанного файла.
    Пропускает пустые строки и строки, начинающиеся с '#'.
    Возвращает множество адресов или доменов в нижнем регистре.
    """
    whitelist = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith('#'):
                    continue
                whitelist.add(line)
    except FileNotFoundError:
        logging.warning(f"Файл {filename} не найден. Будет создан новый при сохранении.")
    except Exception as e:
        logging.error(f"Ошибка загрузки whitelist из {filename}: {e}")
    return whitelist


def load_whitelist_addresses() -> Set[str]:
    """
    Загружает whitelist email-адресов из файла.
    """
    addresses = load_whitelist(WHITELIST_FILE_ADDRESSES)
    logging.info(f"Загружено {len(addresses)} email-адресов из {WHITELIST_FILE_ADDRESSES}.")
    return addresses


def load_whitelist_domains() -> Set[str]:
    """
    Загружает whitelist доменов из файла.
    """
    domains = load_whitelist(WHITELIST_FILE_DOMAINS)
    logging.info(f"Загружено {len(domains)} доменов из {WHITELIST_FILE_DOMAINS}.")
    return domains


def save_whitelist(filename: str, whitelist: Set[str]):
    """
    Сохраняет whitelist в указанный файл.
    Каждая запись — отдельная строка.
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            for item in sorted(whitelist):
                f.write(item + '\n')
        logging.info(f"Whitelist сохранён в {filename}.")
    except Exception as e:
        logging.error(f"Ошибка сохранения whitelist в {filename}: {e}")


def save_whitelist_addresses(addresses: Set[str]):
    """
    Сохраняет whitelist email-адресов.
    """
    save_whitelist(WHITELIST_FILE_ADDRESSES, addresses)


def save_whitelist_domains(domains: Set[str]):
    """
    Сохраняет whitelist доменов.
    """
    save_whitelist(WHITELIST_FILE_DOMAINS, domains)


def is_sender_whitelisted(from_address: str, whitelist_addresses: Set[str], whitelist_domains: Set[str]) -> bool:
    """
    Проверяет, находится ли отправитель в whitelist.
    Разрешены точные адреса или домены из whitelist.
    """
    from_address = from_address.lower()
    if from_address in whitelist_addresses:
        return True
    domain = from_address.split('@')[-1]
    if domain in whitelist_domains:
        return True
    return False


def send_autoreply_not_whitelisted(mail, to_address: str, original_subject: str):
    """
    Отправляет автоответ на письмо отправителю, которого нет в whitelist.
    """
    try:
        # Проверка входных данных
        if not to_address or "@" not in to_address:
            logging.error(f"Некорректный адрес электронной почты: {to_address}")
            return False
        if not mail:
            logging.error("Объект mail не передан.")
            return False
        logging.debug(f"Начало отправки автоответа для {to_address}. Тема: {original_subject}")

        reply_subject = f"Re: {original_subject}" if original_subject else "Re: Ваше сообщение"
        reply_body = (
            "Здравствуйте!\n\n"
            "У вашей организации отсутсвует, право на получение пин и пак кодов. Ваш запрос не обработан.\n"
            "Если вы считаете, что это ошибка, обратитесь в службу поддержки.\n\n"
            "С уважением,\nАвтоматический обработчик писем."
        )
        logging.debug("Сформировано тело автоответа.")

        # Создаём письмо
        msg = EmailMessage()
        msg["From"] = config.SMTP_U
        msg["To"] = to_address
        msg["Subject"] = reply_subject
        msg.set_content(reply_body)
        logging.debug("Сообщение создано.")

        # Отправляем письмо
        success = False
        try:
            logging.debug(f"Подключение к SMTP-серверу: {config.SMTP_S}:{config.SMTP_PORT}")
            with smtplib.SMTP_SSL(config.SMTP_S, 465, timeout=10) as server:
                # server.starttls()
                logging.debug("TLS-соединение установлено.")
                server.login(config.SMTP_U, config.SMTP_P)
                logging.debug("Успешный вход в SMTP.")
                server.send_message(msg)
                success = True
                logging.info(f"Автоответ отправлен для {to_address}.")
        except Exception as e:
            logging.exception(f"Ошибка при отправке автоответа: {e}")

        # Сохранение отправленного письма
        if success and config.ENABLE_SENT_SAVE:
            try:
                from main import save_sent_email
                logging.debug(f"Сохранение автоответа для {to_address} в '{config.SENT_FOLDER}'.")
                save_success = save_sent_email(mail, msg)
                if save_success:
                    logging.info(f"Письмо сохранено в папке '{config.SENT_FOLDER}'.")
                else:
                    logging.error(f"Не удалось сохранить письмо для {to_address}.")
            except Exception as e:
                logging.exception(f"Ошибка при сохранении письма: {e}")

        return success

    except Exception as e:
        logging.exception(f"Общая ошибка при отправке автоответа для {to_address}: {e}")
        return False


def send_email(smtp_server, smtp_port, smtp_user, smtp_password, from_addr, to_addr, subject, body):
    """
    Простая функция для отправки email через SMTP.
    Возвращает True при успехе, False при ошибке.
    """
    import smtplib
    from email.mime.text import MIMEText

    try:
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From'] = from_addr
        msg['To'] = to_addr

        with smtplib.SMTP_SSL(config.SMTP_S, 465, timeout=10) as server:
            # server.starttls()  # Защищённое соединение
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Ошибка отправки email: {e}")
        return False


def open_whitelist_gui():
    """
    Открывает графический интерфейс для управления whitelist.
    Позволяет добавлять и удалять email-адреса и домены.
    """
    addresses = load_whitelist_addresses()
    domains = load_whitelist_domains()

    root = tk.Tk()
    root.title("Whitelist Manager")

    # Функции для обновления Listbox
    def refresh_listbox(lb, items):
        lb.delete(0, END)
        for item in sorted(items):
            lb.insert(END, item)

    # Функции добавления и удаления
    def add_item(items_set, listbox, item_type):
        new_item = simpledialog.askstring("Добавить", f"Введите новый {item_type}:")
        if new_item:
            new_item = new_item.strip().lower()
            if new_item in items_set:
                messagebox.showinfo("Информация", f"{item_type.capitalize()} уже в списке.")
            elif not validate_email(new_item) and item_type == "email-адрес":
                messagebox.showwarning("Неверный формат", "Введите корректный email-адрес.")
            else:
                items_set.add(new_item)
                refresh_listbox(listbox, items_set)

    def remove_selected(items_set, listbox, item_type):
        selected = listbox.curselection()
        if not selected:
            messagebox.showwarning("Предупреждение", f"Выберите {item_type} для удаления.")
            return
        for index in reversed(selected):
            item = listbox.get(index)
            if messagebox.askyesno("Подтверждение", f"Удалить {item_type} '{item}'?"):
                items_set.remove(item)
                listbox.delete(index)

    def validate_email(email: str) -> bool:
        """
        Простая проверка корректности email-адреса.
        """
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    # Создаём вкладки для адресов и доменов
    from tkinter import ttk
    tab_control = ttk.Notebook(root)

    # Вкладка для email-адресов
    tab_addresses = ttk.Frame(tab_control)
    tab_control.add(tab_addresses, text='Email-адреса')

    lb_addresses = tk.Listbox(tab_addresses, selectmode=tk.MULTIPLE, width=50, height=15)
    lb_addresses.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
    scrollbar_a = tk.Scrollbar(tab_addresses, orient="vertical")
    scrollbar_a.config(command=lb_addresses.yview)
    scrollbar_a.pack(side=tk.RIGHT, fill=tk.Y)
    lb_addresses.config(yscrollcommand=scrollbar_a.set)
    refresh_listbox(lb_addresses, addresses)

    frame_buttons_a = tk.Frame(tab_addresses)
    frame_buttons_a.pack(pady=5)

    btn_add_a = tk.Button(frame_buttons_a, text="Добавить",
                          command=lambda: add_item(addresses, lb_addresses, "email-адрес"))
    btn_add_a.pack(side=tk.LEFT, padx=5)

    btn_remove_a = tk.Button(frame_buttons_a, text="Удалить",
                             command=lambda: remove_selected(addresses, lb_addresses, "email-адрес"))
    btn_remove_a.pack(side=tk.LEFT, padx=5)

    # Вкладка для доменов
    tab_domains = ttk.Frame(tab_control)
    tab_control.add(tab_domains, text='Домены')

    lb_domains = tk.Listbox(tab_domains, selectmode=tk.MULTIPLE, width=50, height=15)
    lb_domains.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.BOTH, expand=True)
    scrollbar_d = tk.Scrollbar(tab_domains, orient="vertical")
    scrollbar_d.config(command=lb_domains.yview)
    scrollbar_d.pack(side=tk.RIGHT, fill=tk.Y)
    lb_domains.config(yscrollcommand=scrollbar_d.set)
    refresh_listbox(lb_domains, domains)

    frame_buttons_d = tk.Frame(tab_domains)
    frame_buttons_d.pack(pady=5)

    btn_add_d = tk.Button(frame_buttons_d, text="Добавить", command=lambda: add_item(domains, lb_domains, "домен"))
    btn_add_d.pack(side=tk.LEFT, padx=5)

    btn_remove_d = tk.Button(frame_buttons_d, text="Удалить",
                             command=lambda: remove_selected(domains, lb_domains, "домен"))
    btn_remove_d.pack(side=tk.LEFT, padx=5)

    # Кнопка сохранения и выхода
    def save_and_exit():
        save_whitelist_addresses(addresses)
        save_whitelist_domains(domains)
        messagebox.showinfo("Сохранено", "Whitelist успешно сохранён.")
        root.destroy()

    btn_save_exit = tk.Button(root, text="Сохранить и выйти", command=save_and_exit)
    btn_save_exit.pack(pady=10)

    tab_control.pack(expand=1, fill="both")
    root.mainloop()


def send_reply_no_attachment(to_address: str, original_subject: str, mail):
    """
    Отправляет автоответное письмо, информирующее о том, что вложение отсутствует,
    и сохраняет отправленное письмо в папке отправленных.
    """
    MAX_RETRIES = 3  # Максимальное количество попыток
    RETRY_DELAY = 5  # Задержка между попытками (в секундах)
    SMTP_TIMEOUT = 30  # Увеличенный тайм-аут для SMTP (в секундах)

    # Лог входных данных
    logging.debug(f"Отправка автоответа для {to_address}. Тема: {original_subject}")

    reply_subject = f"Re: {original_subject}" if original_subject else "Re: Ваше сообщение"
    reply_body = (
        "Здравствуйте!\n\n"
        "Мы получили ваше письмо с темой \"{subject}\", однако во вложении отсутствует необходимый файл.\n"
        "Пожалуйста, убедитесь, что вы прикрепили нужное вложение, и отправьте письмо повторно.\n\n"
        "С уважением,\nАвтоматический обработчик писем."
    ).format(subject=original_subject)

    # Создание письма
    msg = EmailMessage()
    msg["From"] = config.SMTP_U
    msg["To"] = to_address
    msg["Subject"] = reply_subject
    msg.set_content(reply_body)

    logging.debug("Сообщение создано успешно.")

    # Отправка автоответа с повторными попытками
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            logging.debug(f"Попытка {attempt}: Подключение к SMTP-серверу: {config.SMTP_S}:{config.SMTP_PORT}")

            if config.SMTP_PORT == 465:
                # Используем SMTP_SSL для порта 465
                with smtplib.SMTP_SSL(config.SMTP_S, config.SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                    server.login(config.SMTP_U, config.SMTP_P)
                    server.send_message(msg)
            else:
                # Используем обычный SMTP с STARTTLS для других портов
                with smtplib.SMTP(config.SMTP_S, config.SMTP_PORT, timeout=SMTP_TIMEOUT) as server:
                    server.starttls()
                    server.login(config.SMTP_U, config.SMTP_P)
                    server.send_message(msg)

            logging.info(f"Письмо успешно отправлено на {to_address}.")
            success = True
            break  # Успешно отправлено, выходим из цикла

        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, socket.timeout) as e:
            logging.error(f"Попытка {attempt}: Ошибка SMTP: {e}")
            if attempt < MAX_RETRIES:
                logging.info(f"Повторная попытка через {RETRY_DELAY} секунд.")
                time.sleep(RETRY_DELAY)
            else:
                logging.error(f"Не удалось отправить письмо после {MAX_RETRIES} попыток.")
                success = False
        except Exception as e:
            logging.exception(f"Попытка {attempt}: Непредвиденная ошибка: {e}")
            success = False
            break  # Прерываем цикл при непредвиденной ошибке

    # Сохранение в "Sent"
    if success and config.ENABLE_SENT_SAVE:
        try:
            # Убедитесь, что save_sent_email доступна без циклического импорта
            from main import save_sent_email
            save_success = save_sent_email(mail, msg)
            if save_success:
                logging.info(f"Письмо сохранено в папке '{config.SENT_FOLDER}'.")
            else:
                logging.error(f"Не удалось сохранить письмо в папке '{config.SENT_FOLDER}'.")
        except Exception as e:
            logging.exception(f"Ошибка при сохранении письма: {e}")

    return success

