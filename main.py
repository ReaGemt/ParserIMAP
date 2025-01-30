# Импорт необходимых модулей
import imaplib
import io
import logging  # Логирование событий и ошибок
import os  # Взаимодействие с операционной системой (файловая система)
import re  # Регулярные выражения для поиска и замены в строках
import signal  # Обработка системных сигналов (например, для корректного завершения программы)
import smtplib  # Отправка электронной почты через SMTP-сервер
import socket
import ssl
import sys  # Доступ к системным параметрам и функциям интерпретатора Python
import time  # Работа с временем (задержки, отметки времени)
from datetime import datetime
from email.header import decode_header, make_header  # Декодирование MIME-заголовков электронных писем
from email.message import EmailMessage  # Создание и обработка сообщений электронной почты
from email.parser import BytesParser  # Парсер для обработки байтового содержимого электронных писем
from email.utils import parseaddr
from logging.handlers import RotatingFileHandler  # Обработчик логирования с ротацией файлов
from threading import Lock  # Создание блокировок для потоков (для потокобезопасности)
from urllib.parse import quote  # Кодирование строк для использования в URL

import pandas as pd  # Работа с данными в формате таблиц (DataFrame)
import requests  # Отправка HTTP-запросов
import schedule  # Планирование периодических задач
from PyPDF2 import PdfReader, PdfWriter
from bs4 import BeautifulSoup  # Парсинг и извлечение данных из HTML-кода
from rapidfuzz import fuzz
from reportlab.lib.pagesizes import letter
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from requests.adapters import HTTPAdapter  # Адаптер для HTTP-запросов с возможностью повторных попыток
from urllib3.util.retry import Retry  # Настройка политики повторных попыток для HTTP-запросов

import config  # Локальный модуль с конфигурацией (должен быть создан отдельно)
from bd_utill import cleanup_old_records, init_db, is_email_processed, mark_email_as_processed
from ocr_utill import process_pdf, process_pdf_attachment
from patterns import patterns_body  # Модуль с регулярными выражениями (должен быть создан отдельно)
from whitelist_manager import (
    load_whitelist_addresses,
    load_whitelist_domains,
    is_sender_whitelisted,
    send_autoreply_not_whitelisted, send_reply_no_attachment
)

# Загружаем whitelist при старте
WHITELIST_ADDRESSES = load_whitelist_addresses()
WHITELIST_DOMAINS = load_whitelist_domains()


def create_ssl_context():
    context = ssl.create_default_context()
    # Если сервер использует самоподписанный сертификат, добавьте его
    # context.load_verify_locations('path/to/certificate.pem')
    return context


# Определяем функцию decode_folder_name на уровне модуля
def decode_folder_name(folder):
    try:
        parts = folder.split(' "/" ')
        if len(parts) == 2:
            folder_name = parts[1].strip('"')
            # Корректно декодируем из модифицированной UTF-7
            decoded_string = folder_name.encode('ascii').decode('utf-7')
            return decoded_string
        return folder
    except Exception as e:
        logging.warning(f"Не удалось декодировать имя папки: {e}")
        return folder


# Настройка логирования
def setup_logging():
    try:
        # Создаем обработчик для записи логов в файл с ротацией
        handler = RotatingFileHandler(
            config.LOG_FILE,  # Путь к файлу логов из конфигурации
            maxBytes=5 * 1024 * 1024,  # Максимальный размер файла логов (5 МБ)
            backupCount=5,  # Количество резервных копий лог-файлов
            encoding='utf-8'  # Кодировка файла логов
        )
        handler.setLevel(config.LOG_LEVEL)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)

        # Создаем обработчик для вывода логов в консоль
        console_handler = logging.StreamHandler()
        console_handler.setLevel(config.LOG_LEVEL)
        console_handler.setFormatter(formatter)

        # Настраиваем логгеры
        logger = logging.getLogger()
        logger.setLevel(config.LOG_LEVEL)
        logger.addHandler(handler)
        logger.addHandler(console_handler)

        logging.info("Логирование настроено успешно.")

    except Exception as e:
        print(f"Ошибка при настройке логирования: {e}")


# Вызываем функцию настройки логирования при запуске программы
setup_logging()


# Обработчик сигналов для корректного завершения программы
def signal_handler(signum, frame):
    logging.info('Получен сигнал завершения. Программа остановлена.')
    sys.exit(0)  # Завершаем программу с кодом 0


# Назначаем обработчики для сигналов SIGINT (Ctrl+C) и SIGTERM
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Создаем блокировку для работы с Excel-файлом (чтобы избежать одновременного доступа из разных потоков)
excel_lock = Lock()


# Создание сессии для HTTP-запросов с повторными попытками
def create_session():
    session = requests.Session()  # Создаем сессию requests
    # Настраиваем стратегию повторных попыток для HTTP-запросов
    retry_strategy = Retry(
        total=5,  # Общее количество попыток
        backoff_factor=1,  # Фактор задержки между попытками (удвоение задержки)
        status_forcelist=[500, 502, 503, 504],  # Список HTTP-статусов, при которых будут повторяться запросы
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]  # Методы HTTP, для которых применимы повторные попытки
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)  # Создаем адаптер с указанной стратегией повторов
    session.mount('http://', adapter)  # Применяем адаптер для HTTP
    session.mount('https://', adapter)  # Применяем адаптер для HTTPS
    return session  # Возвращаем настроенную сессию


# Создаем глобальную сессию для использования в программе
session = create_session()

# Хранилище обработанных писем по Message-ID, чтобы избежать повторной обработки
processed_emails = set()


# Функция декодирования MIME-заголовков (например, темы письма или адреса отправителя)
def decode_mime_header_value(header_value):
    if header_value:
        try:
            # Декодируем заголовок, учитывая возможные кодировки
            decoded_header = str(make_header(decode_header(header_value)))
            return decoded_header  # Возвращаем декодированное значение
        except Exception as e:
            logging.error(f"Ошибка декодирования заголовка {header_value}: {e}")
            return header_value  # Если произошла ошибка, возвращаем исходное значение
    return ""


# Функция декодирования имен файлов из MIME-заголовков вложений
def decode_filename(filename):
    try:
        logging.debug(f"Декодирование имени файла: {filename}")
        decoded_filename = decode_mime_header_value(filename)  # Декодируем имя файла
        # Заменяем недопустимые символы в имени файла на подчеркивания
        decoded_filename = re.sub(r'[<>:"/\\|?*]', '_', decoded_filename)
        if not decoded_filename.strip():
            # Если после очистки имя файла пустое, генерируем имя по шаблону
            decoded_filename = f"attachment_{int(time.time())}"
            logging.debug(f"Имя файла после замены: {decoded_filename}")
        return decoded_filename
    except Exception as e:
        logging.error(f"Ошибка декодирования имени файла '{filename}': {e}")
        # Если произошла ошибка, возвращаем сгенерированное имя файла
        return f"unknown_filename_{int(time.time())}"


# Функция подключения к почтовому ящику через IMAP с SSL и настройкой папки "Sent"
def connect_to_mailbox(retries=5):
    for attempt in range(1, retries + 1):
        try:
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2  # Устанавливаем минимальную версию TLS
            mail = imaplib.IMAP4_SSL(config.IMAP_S, ssl_context=context)
            mail.login(config.IMAP_U, config.IMAP_P)
            logging.info("Подключено к почтовому серверу.")
            list_folders(mail)
            create_sent_folder_if_not_exists(mail)
            status, _ = mail.select("INBOX")
            if status != 'OK':
                logging.error('Не удалось выбрать папку "INBOX" после подключения.')
            return mail
        except (imaplib.IMAP4.error, ssl.SSLError, socket.error) as e:
            logging.error(f"Попытка {attempt}: Ошибка подключения: {e}")
            time.sleep(5)
        except Exception as e:
            logging.exception(f"Непредвиденная ошибка при подключении: {e}")
            time.sleep(5)
    logging.error("Не удалось подключиться к почтовому серверу.")
    return None


def parse_imap_list_response(folder_line):
    """
    Парсит ответ LIST IMAP-сервера и возвращает флаги, разделитель и имя папки.
    """
    try:
        # Используем регулярное выражение для парсинга
        assert isinstance(folder_line, object)
        match = re.match(r'\((?P<flags>.*?)\)\s+"(?P<separator>.)"\s+"?(?P<name>.*?)"?$', folder_line)
        if match:
            flags = match.group('flags').split()
            separator = match.group('separator')
            name = match.group('name')
            # Декодируем имя папки из модифицированной UTF-7
            decoded_name = name.encode('ascii').decode('utf-7')
            return flags, separator, decoded_name
        else:
            logging.warning(f"Не удалось разобрать строку папки: {folder_line}")
            return [], '', folder_line
    except Exception as e:
        logging.warning(f"Ошибка при разборе строки папки: {e}")
        return [], '', folder_line


# Функция создания папки "Sent", если она не существует на почтовом сервере
def create_sent_folder_if_not_exists(mail):
    try:
        status, folders = mail.list()
        if status != 'OK':
            logging.error("Не удалось получить список папок IMAP.")
            return False

        # Проверяем наличие папки с флагом \Sent
        found_sent = False
        for folder in folders:
            folder_str = folder.decode()
            flags, separator, folder_name = parse_imap_list_response(folder_str)
            logging.debug(f"Найдена папка: '{folder_name}' с флагами: {flags}")
            if '\\Sent' in flags or '\\Sent Items' in flags:
                found_sent = True
                logging.info(f"Найдена папка для отправленных: '{folder_name}'.")
                config.SENT_FOLDER = folder_name
                break

        if not found_sent and config.ALLOW_SENT_CREATION:
            # Создаём папку "Отправленные" в модифицированной UTF-7
            sent_folder_utf7 = "Отправленные".encode('utf-7').decode('ascii')
            create_status, data = mail.create(sent_folder_utf7)
            if create_status == 'OK':
                logging.info("Папка 'Отправленные' успешно создана.")
                mail.subscribe(sent_folder_utf7)
                config.SENT_FOLDER = "Отправленные"
            else:
                logging.error("Не удалось создать папку 'Отправленные'.")
                return False

        return True

    except Exception as e:
        logging.exception(f"Ошибка при проверке папки 'Sent': {e}")
        return False


# Функция вывода списка папок (для отладки)
def list_folders(mail):
    status, folders = mail.list()
    if status == 'OK':
        for folder in folders:
            folder_decoded = decode_folder_name(folder.decode())
    else:
        logging.error("Не удалось получить список папок.")


# Функция получения непрочитанных писем из папки "INBOX"
def fetch_unread_emails(mail):
    try:
        status, _ = mail.select("INBOX")  # Выбираем папку "INBOX" для работы
        if status != 'OK':
            logging.error('Не удалось выбрать папку "INBOX".')
            return []
        status, messages = mail.search(None, '(UNSEEN)')  # Ищем все непрочитанные сообщения
        if status != 'OK':
            logging.error('Ошибка поиска новых сообщений.')
            return []
        email_ids = messages[0].split()  # Получаем список идентификаторов писем
        logging.info(f"Найдено новых сообщений: {len(email_ids)}")
        return email_ids  # Возвращаем список идентификаторов
    except imaplib.IMAP4.abort as e:
        logging.error(f'IMAP abort error: {e}')
        mail = connect_to_mailbox()  # Пробуем переподключиться к почтовому ящику
        if mail:
            return fetch_unread_emails(mail)  # Повторяем попытку получения непрочитанных писем
        return []
    except Exception as e:
        logging.exception(f'Неизвестная ошибка при получении непрочитанных писем: {e}')
        return []


# Функция повторного выполнения IMAP-команд с обработкой ошибок и повторными попытками
def retry_imap_command(mail, command, *args, retries=3):
    for attempt in range(1, retries + 1):
        try:
            method = getattr(mail, command)
            logging.debug(f"Выполнение команды IMAP '{command}' с аргументами {args}. Попытка {attempt}.")
            status, data = method(*args)
            logging.debug(f"Ответ команды '{command}': статус={status}, данные={data}")
            if status == 'OK':
                return status, data
            logging.error(f"Команда {command} вернула статус: {status}")
        except (imaplib.IMAP4.abort, imaplib.IMAP4.error, ssl.SSLError, socket.error) as e:
            logging.error(f"Ошибка {type(e).__name__} при команде {command}: {e}")
            if attempt < retries:
                logging.info(f"Повторная попытка команды '{command}' через 5 секунд.")
                time.sleep(5)
                mail = connect_to_mailbox()  # Переподключаемся к серверу
                if not mail:
                    logging.error(f"Не удалось восстановить соединение при команде {command}")
                    break
            else:
                logging.exception(f"Не удалось выполнить команду {command} после {retries} попыток.")
        except Exception as e:
            logging.exception(f"Неизвестная ошибка при выполнении команды {command}: {e}")
    return None, None


# Функция для фуззи-поиска в тексте
def fuzzy_search_in_text(target_str: str, full_text: str, threshold: int = 70) -> bool:
    """
    Ищет подстроку target_str в full_text, используя fuzzy matching (rapidfuzz).
    Возвращает True, если есть слово в full_text, схожее с target_str на threshold% или выше.
    """
    if not target_str or not full_text:
        return False

    # Разбиваем текст на слова
    words = full_text.split()

    for word in words:
        score = fuzz.ratio(target_str.lower(), word.lower())
        if score >= threshold:
            return True
    return False


# Функция для извлечения фамилии из полного имени (ФИО)
def extract_surname(full_name):
    if not full_name:
        return None
    # Ищем первое слово, начинающееся с заглавной буквы, предполагая, что это фамилия
    match = re.match(r'(?P<surname>[А-ЯЁ][а-яё]+)', full_name)
    if match:
        return match.group('surname')  # Возвращаем найденную фамилию
    return None


# Функция анализа письма с вложениями
def analyze_email_with_attachments(mail, email_id, email_body):
    """Анализирует письмо с вложениями."""
    email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
    try:
        # Получаем вложения
        status, msg_data = retry_imap_command(mail, 'fetch', email_id_str, '(BODY.PEEK[])')
        if status != 'OK' or not msg_data:
            logging.error(f"Ошибка получения сообщения {email_id_str}")
            return False

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = BytesParser().parsebytes(response_part[1])
                attachments = check_attachments(msg)

                for attachment in attachments:
                    if attachment.lower().endswith('.pdf'):
                        # Обрабатываем PDF вложение
                        extracted_text = process_pdf_attachment(attachment)

                        if extracted_text:
                            # Сравниваем текст из PDF с телом письма
                            if email_body.strip() in extracted_text.strip():
                                logging.info(f"Текст из PDF совпадает с текстом в письме для {attachment}.")
                            else:
                                logging.warning(f"Текст из PDF не совпадает с текстом в письме для {attachment}.")

                        # Удаляем обработанное вложение
                        os.remove(attachment)

        return True

    except Exception as e:
        logging.exception(f"Ошибка анализа вложений для сообщения {email_id_str}: {e}")
        return False


# Функция взаимодействия с API для получения данных по карте и фамилии
def reqcard(surname: str, card: str):
    # Кодируем фамилию и номер карты для использования в URL
    encoded_surname = quote(surname)
    encoded_card = quote(card)
    # Формируем URL запроса к API
    url = f'{config.API_URL}/thg/find?Card={encoded_card}&Fam={encoded_surname}'
    logging.info(f'Выполнение запроса к URL: {url}')

    try:
        response = session.get(url, timeout=10)  # Отправляем GET-запрос к API с таймаутом 10 секунд
        logging.debug(f'Ответ от API: {response.status_code} {response.text}')
        response.raise_for_status()  # Проверяем, был ли запрос успешным
        data = response.json()  # Парсим ответ JSON

        if data and isinstance(data, list) and len(data) > 0:
            logging.debug(f"Полученные данные от API: {data[0]}")
            # Извлекаем необходимые поля из ответа API
            return data[0].get('Puk'), data[0].get('Pin'), data[0].get('CardHolderName')
        else:
            logging.warning(f'Пустой или некорректный ответ для карты {card} и фамилии {surname}.')
            return None, None, None
    except requests.exceptions.Timeout:
        logging.error('Превышено время ожидания запроса к API.')
    except requests.exceptions.ConnectionError as e:
        logging.error(f'Ошибка соединения с API: {e}')
    except Exception as e:
        logging.exception(f'Непредвиденная ошибка при запросе к API: {e}')
    return None, None, None  # Возвращаем None, если запрос не успешен


# Функция для добавления данных в Excel-файл
def append_to_excel(data, file_path=config.XLSX_FILE):
    with excel_lock:  # Используем блокировку для потокобезопасности
        try:
            new_data_df = pd.DataFrame(data, dtype=str)  # Создаем DataFrame из переданных данных
            new_data_df.columns = new_data_df.columns.str.strip()  # Удаляем пробелы из названий столбцов
            new_data_df.rename(columns={'Карта': 'Номер карты'}, inplace=True)  # Переименовываем столбец
            # Очищаем номера карт от пробелов и приводим к верхнему регистру
            new_data_df['Номер карты'] = new_data_df['Номер карты'].str.replace(r'\s+', '', regex=True).str.upper()
            if os.path.exists(file_path):
                # Если файл существует, читаем существующие данные
                existing_df = pd.read_excel(file_path, dtype=str)
                existing_df.columns = existing_df.columns.str.strip()
                existing_df.rename(columns={'Карта': 'Номер карты'}, inplace=True)
                existing_df['Номер карты'] = existing_df['Номер карты'].str.replace(r'\s+', '', regex=True).str.upper()
                # Объединяем новые и существующие данные, удаляя дубликаты по "Номеру карты"
                combined_df = pd.concat([existing_df, new_data_df], ignore_index=True)
                combined_df.drop_duplicates(subset=['Номер карты'], inplace=True)
                # Записываем объединенные данные обратно в файл
                with pd.ExcelWriter(file_path, engine='openpyxl', mode='w') as writer:
                    combined_df.to_excel(writer, index=False)
                logging.info(f'Данные успешно обновлены в файле {file_path}')
            else:
                # Если файл не существует, создаем новый файл с данными
                with pd.ExcelWriter(file_path, engine='openpyxl', mode='w') as writer:
                    new_data_df.to_excel(writer, index=False)
                logging.info(f'Файл {file_path} создан с данными.')
        except (PermissionError, FileNotFoundError) as e:
            logging.error(f'Ошибка при записи в Excel файл: {e}')
        except Exception as e:
            logging.exception(f'Непредвиденная ошибка при записи в Excel файл: {e}')


# Функция сохранения отправленного письма в папку "Sent"
def save_sent_email(mail, msg):
    if not config.ENABLE_SENT_SAVE:
        logging.info("Сохранение отправленных писем отключено.")
        return False

    try:
        raw_message = msg.as_bytes()
        logging.debug(f"Сформировано сырье сообщения для сохранения в папке '{config.SENT_FOLDER}'.")

        # Логи для параметров команды append
        flags = '\\Seen'  # Флаг для сохранения как прочитанное
        internal_date = imaplib.Time2Internaldate(time.time())
        logging.debug(f"Флаги: {flags}, Внутренняя дата: {internal_date}")

        # Отправка команды APPEND с повторными попытками
        status, data = retry_imap_command(
            mail,
            'append',
            f'"{config.SENT_FOLDER}"',
            flags,
            internal_date,
            raw_message
        )

        logging.debug(f"Ответ на APPEND: статус={status}, данные={data}")

        if status == 'OK':
            logging.info(f"Письмо успешно сохранено в папке '{config.SENT_FOLDER}'.")
            return True
        else:
            logging.error(f"Не удалось сохранить письмо. Статус: {status}, данные: {data}.")
            return False
    except Exception as e:
        logging.exception(f"Ошибка при сохранении письма в папку '{config.SENT_FOLDER}': {e}")
        return False


# Регистрация шрифта с поддержкой латиницы
pdfmetrics.registerFont(TTFont('DejaVuSans-Bold', 'DejaVuSans-Bold.ttf'))


def generate_pdf_response(template_path, card, fio, pin, puk, output_path=None):
    """
    Заполняет заранее подготовленный PDF-шаблон и сохраняет его.

    :param template_path: Путь к PDF-шаблону.
    :param card: Номер карты.
    :param fio: ФИО пользователя.
    :param pin: PIN-код.
    :param puk: PUK-код.
    :param output_path: Путь к созданному PDF-файлу. Если не задан, формируется автоматически.
    :return: Путь к созданному PDF-файлу.
    """
    try:
        if output_path is None:
            output_path = f"response_{card}.pdf"

        # Читаем шаблон
        reader = PdfReader(template_path)
        writer = PdfWriter()

        # Создаем временный PDF с текстом
        packet = io.BytesIO()
        c = canvas.Canvas(packet, pagesize=letter)

        # Устанавливаем шрифт с поддержкой латиницы
        c.setFont("DejaVuSans-Bold", 10)

        # Добавляем текст на PDF (координаты нужно подгонять под шаблон)
        c.drawString(350, 680, f"{card}")
        c.drawString(350, 700, f"{fio}")
        c.drawString(250, 480, f"PIN - {pin}")
        c.drawString(250, 460, f"PUK - {puk}")

        c.save()
        packet.seek(0)

        # Читаем заполненный текстовый слой
        text_layer = PdfReader(packet)

        # Обрабатываем страницы шаблона
        for i, page in enumerate(reader.pages):
            if i == 0:  # Добавляем текст только на первую страницу
                page.merge_page(text_layer.pages[0])
            writer.add_page(page)

        # Сохраняем результат
        with open(output_path, "wb") as output_file:
            writer.write(output_file)

        return output_path
    except Exception as e:
        logging.error(f"Ошибка при генерации PDF: {e}")
        return None


def send_reply_with_template(
        to_address, subject, body, pdf_path, mail, in_reply_to=None, references=None, email_id=None
) -> bool:
    """
    Отправляет ответное письмо с вложением PDF и удаляет файл после отправки.

    :param to_address: Адрес получателя.
    :param subject: Тема письма.
    :param body: Тело письма.
    :param pdf_path: Путь к PDF-файлу для вложения.
    :param mail: Объект IMAP-соединения (если нужен).
    :param in_reply_to: ID оригинального письма (строка без символов новой строки).
    :param references: Ссылки на оригинальные письма (строка без символов новой строки).
    :param email_id: ID письма (если нужно).
    :return: True при успешной отправке, False иначе.
    """
    # Валидация входных данных
    if not all([to_address, subject, body, pdf_path]):
        logging.error("Необходимо указать to_address, subject, body и pdf_path.")
        return False

    msg = EmailMessage()
    msg["From"] = config.SMTP_U
    msg["To"] = to_address
    msg["Subject"] = subject

    if in_reply_to:
        msg["In-Reply-To"] = in_reply_to.replace("\n", "").replace("\r", "").strip()
    if references:
        msg["References"] = references.replace("\n", "").replace("\r", "").strip()

    msg.set_content(body)

    # Проверка существования и доступности PDF-файла
    if not os.path.exists(pdf_path):
        logging.error(f"PDF-файл {pdf_path} не найден.")
        return False
    if not os.access(pdf_path, os.R_OK):
        logging.error(f"PDF-файл {pdf_path} недоступен для чтения.")
        return False

    try:
        with open(pdf_path, "rb") as pdf_file:
            pdf_data = pdf_file.read()
            msg.add_attachment(
                pdf_data,
                maintype="application",
                subtype="pdf",
                filename=os.path.basename(pdf_path),
            )
        logging.info(f"Вложение {pdf_path} добавлено к письму.")
        logging.info(f"Размер вложения: {len(pdf_data)} байт.")
    except Exception as e:
        logging.error(f"Не удалось прикрепить PDF {pdf_path}: {e}")
        logging.error(f"Тип ошибки: {type(e).__name__}")
        return False

    MAX_RETRIES = 3
    RETRY_DELAY = 5  # секунд

    logging.info(f"Письмо готово к отправке на {to_address}. Тема: {subject}")

    for attempt in range(MAX_RETRIES):
        try:
            if config.SMTP_PORT == 465:
                with smtplib.SMTP_SSL(config.SMTP_S, config.SMTP_PORT) as server:
                    server.login(config.SMTP_U, config.SMTP_P)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(config.SMTP_S, config.SMTP_PORT, timeout=10) as server:
                    server.starttls()
                    server.login(config.SMTP_U, config.SMTP_P)
                    server.send_message(msg)
            logging.info(f"Письмо с шаблоном отправлено на {to_address}")
            # Сохранение отправленного письма
            if config.ENABLE_SENT_SAVE:
                save_success = save_sent_email(mail, msg)
                if save_success:
                    logging.info(f"Отправленное письмо сохранено в папке '{config.SENT_FOLDER}'.")
                else:
                    logging.error(f"Не удалось сохранить отправленное письмо в папку '{config.SENT_FOLDER}'.")
            break  # Успешно отправлено, выходим из цикла
        except Exception as e:
            logging.error(f"Попытка {attempt + 1} не удалась: {e}")
            if attempt < MAX_RETRIES - 1:
                logging.info(f"Повторная попытка через {RETRY_DELAY} секунд. "
                             f"Осталось попыток: {MAX_RETRIES - attempt - 1}")
                time.sleep(RETRY_DELAY)
            else:
                logging.exception(f"Ошибка при отправке письма после {MAX_RETRIES} попыток.")
                if email_id:
                    email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
                    unmark_as_seen(mail, email_id_str)
                return False

    # Удаление PDF-файла после успешной отправки
    if os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
            logging.info(f"Сгенерированный PDF '{pdf_path}' успешно удалён.")
        except Exception as e:
            logging.error(f"Не удалось удалить файл '{pdf_path}': {e}")

    return True


# Функция для пометки письма как непрочитанного
def unmark_as_seen(mail, email_id):
    email_id = email_id.decode() if isinstance(email_id, bytes) else email_id
    try:
        status_select, _ = mail.select("INBOX")  # Выбираем папку "INBOX" в режиме чтения и записи
        if status_select != 'OK':
            logging.error('Не удалось выбрать папку "INBOX" в режиме чтения и записи.')
            return
        # Снимаем флаг \Seen у письма
        status, _ = retry_imap_command(mail, 'store', email_id, '-FLAGS', r'(\Seen)')
        if status == 'OK':
            logging.info(f"Письмо {email_id} помечено как непрочитанное.")
        else:
            logging.error(f"Не удалось пометить письмо {email_id} как непрочитанное. Статус: {status}")
    except Exception as e:
        logging.exception(f"Ошибка при снятии метки с письма {email_id}: {e}")


# Функция для пометки письма как прочитанного
def mark_email_as_seen(mail, email_id):
    email_id = email_id.decode() if isinstance(email_id, bytes) else email_id
    try:
        # Устанавливаем флаг \Seen у письма
        status, _ = retry_imap_command(mail, 'store', email_id, '+FLAGS', '\\Seen')
        if status == 'OK':
            logging.info(f"Письмо {email_id} помечено как прочитанное.")
        else:
            logging.error(f"Не удалось пометить письмо {email_id} как прочитанное.")
    except Exception as e:
        logging.exception(f"Ошибка при пометке письма {email_id} как прочитанного: {e}")


def process_entry(
        entry,
        from_address,
        mail,
        original_subject,
        in_reply_to,
        references,
        email_id,
        pdf_path=None  # <-- Если есть реальный путь к PDF-вложению
):
    logging.debug(f'Начинается обработка записи: {entry}')
    name = entry.get('ФИО')
    card = entry.get('Карта')

    # Удаляем возможно лишние данные из ФИО
    if name:
        name = re.sub(r'\s*тел.*$', '', name, flags=re.IGNORECASE).strip()

    # Извлекаем фамилию
    surname = extract_surname(name) if name else ''
    if surname:
        logging.debug(f'Извлеченная фамилия: {surname}')
    else:
        logging.warning(f'ФИО отсутствует для карты: {card}')
        # Пропускаем дальнейшую обработку и помечаем письмо как непрочитанное
        email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
        unmark_as_seen(mail, email_id_str)
        return False  # Прерываем обработку

    # Добавляем префикс 'RUD' к номеру карты, если его нет
    if not card.startswith('RUD'):
        card = f'RUD{card}'
        logging.info(f'Добавлен префикс RUD к карте: {card}')

    # --- Открываем PDF (если есть) и запускаем OCR ---
    if pdf_path and os.path.exists(pdf_path):
        try:
            logging.info(f"Открываем для OCR реальное вложение: {pdf_path}")
            extracted_text_list = process_pdf(pdf_path)  # Например, список строк
        except Exception as e:
            logging.error(f"Ошибка при обработке PDF {pdf_path}: {e}")
            # Помечаем письмо как непрочитанное
            email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
            unmark_as_seen(mail, email_id_str)
            return False  # Прерываем обработку
    else:
        logging.warning("PDF-вложение отсутствует.")
        # Отправляем автоответное письмо о том, что вложение отсутствует
        success = send_reply_no_attachment(
            to_address=from_address,
            original_subject=original_subject,
            mail=mail
        )
        if success:
            logging.info(f"Уведомление об отсутствии вложения отправлено на {from_address}.")
            # Помечаем письмо как прочитанное, так как уведомление отправлено
            email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
            mark_email_as_seen(mail, email_id_str)
            return True  # Уведомление отправлено, письмо обработано
        else:
            logging.error(f"Не удалось отправить уведомление об отсутствии вложения на {from_address}.")
            return False  # Письмо остаётся непрочитанным

    # Склеиваем OCR-результат в одну строку для удобства
    extracted_text_combined = " ".join(extracted_text_list)

    # --- Фаззи-поиск фамилии и карты в тексте PDF ---
    found_surname = fuzzy_search_in_text(surname, extracted_text_combined, threshold=config.FUZZY_THRESHOLD)
    found_card = fuzzy_search_in_text(card, extracted_text_combined, threshold=config.FUZZY_THRESHOLD)

    if found_surname and found_card:
        logging.info(f"Фамилия '{surname}' и карта '{card}' найдены в PDF (порог >= {config.FUZZY_THRESHOLD}%).")

        # Запрос к API (reqcard) для получения PIN/PUK
        try:
            puk, pin, cardholder = reqcard(surname, card)
            if puk and pin and cardholder:
                # Генерируем PDF-ответ из ШАБЛОНА (template.pdf)
                pdf_path_out = generate_pdf_response(
                    template_path=config.PDF_TEMPLATE_PATH,
                    card=card,
                    fio=name if name else "Не указано",
                    pin=pin,
                    puk=puk,
                    output_path=f"response_{card}.pdf",
                )

                if pdf_path_out:
                    # Отправляем письмо с вложением
                    success = send_reply_with_template(
                        to_address=from_address,
                        subject="Re: " + original_subject,
                        body=(
                            f"Ответ по вашему запросу\n\n"
                            f"{card}\n"
                            f"{name},\n\n"
                            f"Прикреплен PDF с данными для карты {card}.\n\n"
                            f"Пожалуйста, проверьте вложение."
                        ),
                        pdf_path=pdf_path_out,
                        mail=mail,
                        in_reply_to=in_reply_to,
                        references=references,
                        email_id=email_id,
                    )
                    if success:
                        logging.info(f"Ответ с вложением отправлен для карты {card}")
                        return True  # Ответ с вложением отправлен, письмо обработано
                    else:
                        logging.info(f"Не удалось отправить письмо для карты {card}.")
                        return False  # Письмо остаётся непрочитанным
                else:
                    logging.error(f"Ошибка при создании PDF для карты {card}.")
                    return False  # Письмо остаётся непрочитанным
            else:
                # Если API вернул None, сохраняем для ручного разбора
                data = {
                    'ФИО': name if name else 'Не указано',
                    'Номер карты': card,
                    'email': from_address
                }
                append_to_excel([data])
                logging.info(f'Данные добавлены в Excel для карты {card}')
                return False  # Письмо остаётся непрочитанным для ручного разбора
        except Exception as e:
            logging.error(f"Ошибка при запросе к API для карты {card}: {e}")
            # Помечаем письмо как непрочитанное
            email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
            unmark_as_seen(mail, email_id_str)
            return False  # Прерываем обработку
    else:
        logging.info(f"Фамилия '{surname}' и/или карта '{card}' не найдены (порог >= {config.FUZZY_THRESHOLD}%).")
        return False  # Письмо остаётся непрочитанным

def clean_text(text):
    text = text.replace('\xa0', ' ')  # Удаление неразрывных пробелов
    text = re.sub(r'\s+', ' ', text).strip()  # Удаление лишних пробелов
    return text


# Функция анализа тела письма и поиска необходимых данных
def analyze_body(
        body,
        from_address,
        mail,
        original_subject,
        in_reply_to,
        references,
        email_id,
        pdf_path=None
):
    """
    Анализирует тело письма, ищет ФИО и номер карты по регулярным выражениям.
    Если данные найдены, вызывает process_entry, передавая путь к PDF.
    """

    any_successful = False  # Флаг, показывающий, удалось ли обработать хотя бы одну карту
    processed_cards = set()  # Чтобы не обрабатывать одну и ту же карту несколько раз
    body = body.replace('\xa0', ' ')  # Заменяем неразрывные пробелы на обычные

    # Разбиваем тело письма на строки
    lines = body.splitlines()
    logging.debug(f"Начало анализа тела письма. Количество строк: {len(lines)}")

    # Переменные для текущего ФИО и текущей карты
    name = None
    card = None

    # Набор фраз, которые пропускаем как "стоп-слова"
    stop_words = set(config.STOP_WORD)

    # Перебираем каждую строку письма
    for line in lines:
        line = line.strip()
        logging.debug(f"Обработка строки: {line}")
        if not line:
            continue  # Пустая строка — пропускаем

        lower_line = line.lower()
        if lower_line in stop_words:
            logging.debug(f"Строка '{line}' является стоп-словом. Пропускаем.")
            continue

        # Проверяем регулярные выражения из patterns_body (каждая может вернуть имя/карту и т.д.)
        for pattern in patterns_body:
            match = pattern.search(line)
            if match:
                match_dict = match.groupdict()
                logging.debug(f"Найдено совпадение: {match_dict}")

                # Ищем карту
                if 'card' in match_dict and match_dict['card']:
                    card = match_dict['card']
                    # Убираем пробелы и дефисы, переводим в UPPER
                    card = re.sub(r'[\s\-]', '', card).upper()
                    # Проверяем, что номер карты соответствует формату RUDXXXXXXXXXXXXX
                    if not re.match(r'^RUD\d{13,}$', card):
                        logging.debug(f"Номер карты '{card}' не соответствует формату. Пропускаем.")
                        continue
                    logging.debug(f"Найден номер карты: {card}")

                # Ищем ФИО (или имя)
                if 'name' in match_dict and match_dict['name']:
                    potential_name = match_dict['name']
                    # Убираем лишние символы (запятые, точки и т.д.)
                    potential_name = re.sub(r'[.,;]', '', potential_name).strip()
                    # Проверяем, не является ли имя стоп-словом
                    if potential_name.lower() in stop_words:
                        logging.debug(f"Найденное имя '{potential_name}' является стоп-словом. Пропускаем.")
                        continue
                    name = potential_name
                    logging.debug(f"Найдено имя: {name}")

                # Если мы нашли карту, и её ещё не обрабатывали
                if card and card not in processed_cards:
                    # Проверяем, не является ли карта дубликатом
                    if is_email_processed(card):  # Предположим, что у вас есть такая функция
                        logging.debug(f"Карта '{card}' уже обработана ранее. Пропускаем.")
                        continue

                    # Указываем производителя по умолчанию
                    entry = {
                        'ФИО': name,
                        'Карта': card,
                    }

                    logging.info(f'Найдены данные: ФИО: {name}, Карта: {card}')

                    # Вызываем process_entry, передавая pdf_path
                    try:
                        success = process_entry(
                            entry,
                            from_address,
                            mail,
                            original_subject,
                            in_reply_to,
                            references,
                            email_id,
                            pdf_path=pdf_path  # <-- Важная передача пути к PDF
                        )
                    except Exception as e:
                        logging.error(f"Ошибка при обработке записи: {e}")
                        success = False

                    if success:
                        any_successful = True
                    processed_cards.add(card)  # Чтобы не обрабатывать карту второй раз

                    # Сбрасываем переменные, чтобы при следующем нахождении обрабатывать новую пару
                    name = None
                    card = None

                # Выйти из цикла по паттернам, если нашли совпадение в этой строке
                break

    if not any_successful:
        logging.debug('Совпадения по регулярным выражениям не найдены или обработка неуспешна.')

    return any_successful


# Функция анализа письма
def analyze_email(mail, email_id):
    email_id_str = email_id.decode() if isinstance(email_id, bytes) else email_id
    try:
        # Проверяем, не обрабатывали ли мы это письмо раньше
        if is_email_processed(email_id_str):
            logging.info(f"Письмо {email_id_str} уже числится как обработанное в БД. Пропускаем.")
            return

        status, msg_data = retry_imap_command(mail, 'fetch', email_id_str, '(BODY.PEEK[])')
        if status != 'OK' or not msg_data:
            logging.error(f'Ошибка получения сообщения {email_id_str}')
            mark_email_as_processed(message_id=email_id_str, error_message="Fetch error")
            return

        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = BytesParser().parsebytes(response_part[1])
                subject = decode_mime_header_value(msg["Subject"])
                from_full = decode_mime_header_value(msg.get("From"))
                _, from_address = parseaddr(from_full)
                from_address = from_address.lower()
                date_ = msg.get("Date")
                message_id = msg.get("Message-ID")
                references = msg.get("References", "")
                in_reply_to = msg.get("In-Reply-To", message_id)

                if not message_id:
                    message_id = email_id_str

                logging.info(f"Сообщение: {email_id_str} | Тема: {subject} | От: {from_address} | Дата: {date_}")

                if is_email_processed(message_id):
                    logging.info(f"Письмо {message_id} уже числится как обработанное. Пропускаем.")
                    continue

                if not is_sender_whitelisted(from_address, WHITELIST_ADDRESSES, WHITELIST_DOMAINS):
                    logging.info(f"Отправитель '{from_address}' НЕ в whitelist. "
                                 f"Отправляем автоответ и пропускаем письмо.")
                    send_autoreply_not_whitelisted(mail=mail, to_address=from_address, original_subject=subject)
                    mark_email_as_processed(message_id=message_id)
                    continue

                body = get_email_body(msg)
                attachments = check_attachments(msg)
                pdf_path = None
                for attach_path in attachments:
                    if attach_path.lower().endswith('.pdf'):
                        pdf_path = attach_path
                        logging.info(f"Найден PDF-вложение: {pdf_path}")
                        break

                if body:
                    logging.debug(f"Тело письма:\n{body}")
                else:
                    logging.debug("Тело письма пустое.")

                body_data_found = analyze_body(
                    body,
                    from_address=from_address,
                    mail=mail,
                    original_subject=subject,
                    in_reply_to=in_reply_to,
                    references=references,
                    email_id=email_id,
                    pdf_path=pdf_path
                )

                if body_data_found:
                    logging.debug('Данные из тела письма успешно обработаны.')
                    mark_email_as_seen(mail, email_id_str)
                    mark_email_as_processed(message_id=message_id)
                else:
                    logging.info(f"Не удалось полностью обработать письмо {email_id_str}.")
                    mark_email_as_processed(message_id=message_id, error_message=None)

    except Exception as e:
        logging.exception(f'Ошибка анализа сообщения {email_id_str}: {e}')
        mark_email_as_processed(message_id=email_id_str, error_message=str(e))
        unmark_as_seen(mail, email_id_str)


# Функция извлечения тела письма в текстовом формате
def get_email_body(msg):
    try:
        body = None
        if msg.is_multipart():
            # Если письмо состоит из нескольких частей (multipart)
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))
                if content_type == "text/plain" and "attachment" not in content_disposition:
                    # Извлекаем текстовую часть без вложений
                    charset = part.get_content_charset() or 'utf-8'
                    body = part.get_payload(decode=True).decode(charset, errors='replace')
                    logging.debug("Извлечено тело письма в формате text/plain.")
                    break
                elif content_type == "text/html" and "attachment" not in content_disposition:
                    # Извлекаем HTML-часть и преобразуем в текст
                    charset = part.get_content_charset() or 'utf-8'
                    html_body = part.get_payload(decode=True).decode(charset, errors='replace')
                    soup = BeautifulSoup(html_body, 'html.parser')
                    body = soup.get_text(separator='\n')
                    logging.debug("Извлечено текстовое содержимое из тела письма в формате text/html.")
        else:
            # Если письмо состоит из одной части
            content_type = msg.get_content_type()
            if content_type == "text/plain":
                charset = msg.get_content_charset() or 'utf-8'
                body = msg.get_payload(decode=True).decode(charset, errors='replace')
                logging.debug("Извлечено тело письма в формате text/plain.")
            elif content_type == "text/html":
                charset = msg.get_content_charset() or 'utf-8'
                html_body = msg.get_payload(decode=True).decode(charset, errors='replace')
                soup = BeautifulSoup(html_body, 'html.parser')
                body = soup.get_text(separator='\n')
                logging.debug("Извлечено текстовое содержимое из тела письма в формате text/html.")

        if body:
            body = body.replace('\xa0', ' ')  # Заменяем неразрывные пробелы на обычные
            return body  # Возвращаем извлеченное тело письма
        else:
            logging.debug("Не удалось извлечь тело письма.")
            return ""
    except Exception as e:
        logging.error(f'Ошибка извлечения тела письма: {e}')
        return ""


# Функция проверки наличия вложений в письме
def check_attachments(msg):
    attachments = []
    try:
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    decoded_filename = decode_filename(filename)  # Декодируем и очищаем имя файла
                    logging.info(f"Вложение найдено и декодировано: {decoded_filename}")

                    # Сохраняем вложение на диск
                    filepath = save_attachment(part, decoded_filename)
                    if filepath:
                        # Добавляем в итоговый список ТОЛЬКО полный путь
                        attachments.append(filepath)
    except Exception as e:
        logging.error(f"Ошибка обработки вложений: {e}")
    return attachments


# Функция сохранения вложений на диск
def save_attachment(part, filename, save_dir='attachments'):
    os.makedirs(save_dir, exist_ok=True)  # Создаем директорию для вложений, если ее нет
    try:
        filepath = os.path.join(save_dir, filename)  # Формируем полный путь к файлу
        with open(filepath, "wb") as f:
            f.write(part.get_payload(decode=True))  # Записываем содержимое вложения в файл
        logging.info(f'Вложение сохранено: {filepath}')
        return filepath
    except Exception as e:
        logging.error(f'Не удалось сохранить вложение {filename}: {e}')
        return None


# Функция обработки всех непрочитанных писем
def process_emails():
    """
    Основная функция для обработки писем.
    """
    # Подключаемся к почтовому серверу через единую функцию
    mail = connect_to_mailbox()
    if not mail:
        logging.error("Не удалось подключиться к почтовому серверу.")
        return

    # Получаем список новых писем
    try:
        message_ids = fetch_unread_emails(mail)
        logging.info(f"Найдено {len(message_ids)} новых писем для обработки.")

        for msg_id in message_ids:
            try:
                logging.debug(f"Начало обработки письма с ID: {msg_id}")
                analyze_email(mail, msg_id)
                logging.debug(f"Завершена обработка письма с ID: {msg_id}")
            except Exception as e:
                logging.exception(f"Ошибка при обработке письма {msg_id}: {e}")
                # Продолжаем обработку следующего письма, даже если текущее вызвало ошибку
                continue

    except Exception as e:
        logging.exception(f"Ошибка при получении писем: {e}")

    finally:
        try:
            logging.debug("Завершение работы с почтовым сервером.")
            mail.logout()
            logging.info("Успешно отключились от почтового сервера.")
        except Exception as e:
            logging.warning(f"Ошибка при отключении от почтового сервера: {e}")


# Функция для определения, ночное ли сейчас время
def is_night_time():
    now = datetime.now().time()  # Получаем текущее время
    return now >= config.NIGHT_START or now < config.NIGHT_END
    # noinspection PyUnreachableCode
    logging.info(f'Текущее время: {now}. NIGHT_START: {config.NIGHT_START}, NIGHT_END: {config.NIGHT_END}')
    if is_night_time():
        logging.info("Режим: Ночь")
    else:
        logging.info("Режим: День")


# Основная функция программы
def main():
    # Запускаем первичную обработку (при старте)
    process_emails()

    # Функция для планирования проверки с учетом времени суток
    def schedule_email_check():
        if is_night_time():
            interval = config.NIGHT_CHECK_INTERVAL
        else:
            interval = config.DAY_CHECK_INTERVAL

        logging.info(f"Планируем проверку почты каждые {interval} минут.")
        schedule.every(interval).minutes.do(process_emails)

    # 1) Один раз при старте
    schedule_email_check()

    # 2) Каждые N часов
    schedule.every().hour.do(schedule_email_check)

    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Завершение работы программы пользователем.")
        sys.exit(0)


if __name__ == "__main__":
    init_db()  # Инициализация базы данных
    cleanup_old_records(days_to_keep=30)  # Очистка старых записей
    main()
