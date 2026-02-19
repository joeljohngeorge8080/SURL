import re
import pytesseract
from PIL import Image


def extract_text_from_image(image_path: str) -> str:
    """
    Extract raw text from image using OCR.
    """
    image = Image.open(image_path)
    text = pytesseract.image_to_string(image)
    return text


def extract_url_from_text(text: str) -> str | None:
    """
    Extract first valid URL-like pattern from OCR text.
    """

    # Basic URL regex
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'

    matches = re.findall(url_pattern, text)

    if matches:
        return matches[0]

    return None
