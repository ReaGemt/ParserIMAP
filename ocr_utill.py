#ocr_utill.py
import logging
import os
import tempfile
from collections import Counter

import cv2
import numpy as np
import pytesseract
from PIL import Image, ImageEnhance
from easyocr import Reader as EasyOCRReader
from paddleocr import PaddleOCR
from pdf2image import convert_from_path
from transformers import VisionEncoderDecoderModel, TrOCRProcessor


# --------------------------------------------------------------------
# Глобальные/общие OCR-объекты (инициализируются один раз)
# --------------------------------------------------------------------
try:
    logging.debug("Инициализация EasyOCR...")
    easyocr_reader = EasyOCRReader(['ru', 'en'])
    logging.debug("EasyOCR инициализирован.")

    logging.debug("Инициализация PaddleOCR...")
    paddle_ocr = PaddleOCR(use_angle_cls=True, lang='ru', use_gpu=False)
    logging.debug("PaddleOCR инициализирован.")

    logging.debug("Инициализация TrOCR-моделей...")
    processor = TrOCRProcessor.from_pretrained("microsoft/trocr-base-stage1")
    model = VisionEncoderDecoderModel.from_pretrained("microsoft/trocr-base-stage1")
    logging.debug("TrOCR-модели инициализированы.")

except Exception as e:
    logging.error(f"Ошибка при инициализации OCR: {e}")
    easyocr_reader = None
    paddle_ocr = None
    processor = None
    model = None


# --------------------------------------------------------------------
# Функции предобработки и OCR
# --------------------------------------------------------------------

def preprocess_image(image: Image.Image) -> Image.Image:
    """
    Предобрабатывает изображение для OCR:
    1) Увеличивает контраст
    2) Переводит в Ч/Б (grayscale)
    3) Удаляет шумы с помощью медианного фильтра
    :param image: PIL-изображение
    :return: Обработанное PIL-изображение
    """
    try:
        enhancer = ImageEnhance.Contrast(image)
        image = enhancer.enhance(2.0)
        image = image.convert('RGB')

        img_np = np.array(image)
        img_np = cv2.medianBlur(img_np, 3)

        return Image.fromarray(img_np)
    except Exception as e:
        logging.error(f"Ошибка при предобработке изображения: {e}")
        return image  # Возвращаем исходное изображение, чтобы не потерять данные


def extract_text_tesseract(image: Image.Image) -> str:
    """
    Извлекает текст с помощью Tesseract.
    """
    try:
        text = pytesseract.image_to_string(image, lang='rus+eng')
        return text
    except Exception as e:
        logging.error(f"Ошибка Tesseract OCR: {e}")
        return ""


def extract_text_easyocr(image, reader: EasyOCRReader) -> str:
    """
    Извлекает текст с помощью EasyOCR.
    """
    try:
        if isinstance(image, str):
            result = reader.readtext(image, detail=0)
        else:
            img_np = np.array(image)
            result = reader.readtext(img_np, detail=0)
        return " ".join(result)
    except Exception as e:
        logging.error(f"Ошибка EasyOCR: {e}")
        return ""


def extract_text_paddleocr(image_path, ocr: PaddleOCR) -> str:
    """
    Извлекает текст с помощью PaddleOCR (нужно передавать путь).
    """
    try:
        result = ocr.ocr(image_path)
        if not result or not result[0]:
            return ""
        text = "\n".join([line[1][0] for line in result[0]])
        return text
    except Exception as e:
        logging.error(f"Ошибка PaddleOCR: {e}")
        return ""


def extract_text_trocr(image, trocr_processor, trocr_model):
    """
    Извлекает текст с помощью TrOCR (VisionEncoderDecoderModel).
    :param image: PIL.Image
    :param trocr_processor: TrOCRProcessor
    :param trocr_model: VisionEncoderDecoderModel
    """
    try:
        logging.debug("Начало обработки TrOCR.")
        inputs = trocr_processor(image, return_tensors="pt")
        pixel_values = inputs.pixel_values
        generated_ids = trocr_model.generate(pixel_values)
        text = trocr_processor.batch_decode(generated_ids, skip_special_tokens=True)[0]
        logging.debug(f"Результат TrOCR: {text}")
        return text
    except Exception as e:
        logging.error(f"Ошибка TrOCR: {e}")
        return ""


def combine_results(results: list[str]) -> str:
    """
    Объединяем результаты из нескольких OCR
    """
    words = " ".join(results).split()
    most_common_words = Counter(words).most_common()
    return " ".join([word for word, _ in most_common_words])


# --------------------------------------------------------------------
# Универсальная функция обработки PDF
# --------------------------------------------------------------------

def process_pdf_pages(
        pdf_path: str,
        save_output: bool = False,
        output_file: str = "output.txt"
) -> list[str]:
    """
    1) Конвертирует PDF в изображения
    2) Применяет Tesseract, EasyOCR, PaddleOCR, TrOCR
    3) Склеивает результат
    """
    if not os.path.exists(pdf_path):
        logging.error(f"Файл {pdf_path} не найден.")
        return []

    logging.info(f"Начало обработки PDF: {pdf_path}")
    pages = convert_from_path(pdf_path)
    final_text = []

    for i, page_image in enumerate(pages):
        logging.debug(f"--- Обработка страницы {i + 1} ---")

        # Предобработка
        processed_image = preprocess_image(page_image)

        # Сохраняем временный PNG для PaddleOCR
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as temp_img:
            processed_image.save(temp_img.name)
            temp_png_path = temp_img.name

        # Запускаем OCR
        text_tesseract = extract_text_tesseract(processed_image)
        text_easyocr = extract_text_easyocr(processed_image, easyocr_reader)
        text_paddleocr = extract_text_paddleocr(temp_png_path, paddle_ocr)

        # ВАЖНО: вызываем именно с тремя аргументами, как объявлено
        text_trocr = extract_text_trocr(processed_image, processor, model)

        # Удаляем временный PNG
        if os.path.exists(temp_png_path):
            os.remove(temp_png_path)

        # Объединяем
        combined_text = combine_results([
            text_tesseract,
            text_easyocr,
            text_paddleocr,
            text_trocr
        ])
        final_text.append(combined_text)

    if save_output:
        try:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(final_text))
            logging.info(f"Результат OCR сохранен в файл {output_file}.")
        except Exception as e:
            logging.error(f"Ошибка при записи в файл {output_file}: {e}")

    return final_text


# Обёртки для совместимости
def process_pdf_attachment(pdf_path: str) -> str:
    results = process_pdf_pages(pdf_path, save_output=True)
    return "\n".join(results)


def process_pdf(pdf_path: str) -> list[str]:
    return process_pdf_pages(pdf_path, save_output=True)


def compare_with_email_body(extracted_text, email_body) -> bool:
    email_body_cleaned = " ".join(email_body.split()).lower()
    extracted_text_combined = " ".join(extracted_text).lower()
    return email_body_cleaned in extracted_text_combined
