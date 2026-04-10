from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.logger import logger
import uuid


async def global_exception_handler(request: Request, exc: Exception):
    request_id = str(uuid.uuid4())

    # Log the error — exc type only, not the full message to avoid leaking data
    logger.error({
        "event": "unhandled_exception",
        "request_id": request_id,
        "exc_type": type(exc).__name__,
        "path": str(request.url.path),
    })

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal scanning engine failure.",
            "request_id": request_id,
        },
    )
