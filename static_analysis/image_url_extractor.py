import re
import pytesseract
from PIL import Image, UnidentifiedImageError

# Characters OCR commonly glues onto the end of a URL from surrounding prose.
_TRAILING_PUNCT = ".,;:!?)]}>'\""
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.I)


class UnreadableImageError(ValueError):
    """The upload is not an image Pillow can open (or is unsafely large)."""


class OcrUnavailableError(RuntimeError):
    """The tesseract binary is missing or failed on the host."""


def extract_text_from_image(image_path: str) -> str:
    """
    Extract raw text from image using OCR.
    """
    try:
        with Image.open(image_path) as image:
            return pytesseract.image_to_string(image)
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError) as e:
        if isinstance(e, pytesseract.TesseractNotFoundError):
            raise OcrUnavailableError("OCR engine is not installed") from e
        raise UnreadableImageError("The uploaded file is not a readable image") from e
    except pytesseract.TesseractError as e:
        raise OcrUnavailableError("OCR engine failed") from e


def extract_urls(text: str) -> list[str]:
    """All http(s) URLs in OCR text, trailing punctuation stripped, de-duplicated
    in the order they appear."""
    urls = (m.rstrip(_TRAILING_PUNCT) for m in _URL_RE.findall(text or ""))
    return list(dict.fromkeys(u for u in urls if "://" in u and len(u) > len("https://")))


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
