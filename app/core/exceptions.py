from fastapi import Request
from fastapi.responses import JSONResponse
from app.core.logger import logger
import uuid


async def global_exception_handler(request: Request, exc: Exception):

    request_id = str(uuid.uuid4())

    logger.error(f"[{request_id}] Unhandled Exception: {str(exc)}")

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal scanning engine failure",
            "request_id": request_id
        }
    )
