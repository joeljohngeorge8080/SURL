import logging
import sys
import json
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """Emit log records as single-line JSON for structured log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        log_obj = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        if record.exc_info:
            log_obj["exc"] = self.formatException(record.exc_info)

        # Attach any explicit extra fields without overwriting core keys
        for key, value in record.__dict__.items():
            if key not in (
                "msg", "args", "levelname", "levelno", "name", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process", "message",
            ):
                if not key.startswith("_"):
                    log_obj[key] = value

        return json.dumps(log_obj, default=str)


def setup_logger(name: str = "SURL", level: int = logging.INFO) -> logging.Logger:
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger  # Already configured — avoid duplicate handlers

    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    # Silence noisy third-party loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("playwright").setLevel(logging.WARNING)

    return logger


logger = setup_logger()
