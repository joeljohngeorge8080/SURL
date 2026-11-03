from fastapi import APIRouter, Request, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from app.api.schemas import ScanRequest, ScanResponse
from app.services.scan_orchestrator import scan_url, run_dynamic_scan, is_private_ip
from static_analysis.image_url_extractor import extract_text_from_image
from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score
import asyncio
import re
import shutil
import os
import tempfile

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
async def scan_endpoint(request: ScanRequest):
    result = await scan_url(request.url)
    return result


@router.post("/scan-selected", response_model=ScanResponse)
async def scan_selected(request: ScanRequest):
    return await scan_url(request.url)


@router.post("/scan-dynamic")
async def scan_dynamic(request: ScanRequest):
    import uuid
    from app.core.logger import logger
    try:
        return await run_dynamic_scan(request.url)
    except Exception as e:
        request_id = str(uuid.uuid4())
        logger.error({
            "event": "dynamic_scan_error",
            "request_id": request_id,
            "exc_type": type(e).__name__,
        })
        return {
            "error": "Internal scanning engine failure.",
            "request_id": request_id,
        }


@router.post("/scan-image")
async def scan_image(file: UploadFile = File(...)):

    fd, temp_path = tempfile.mkstemp(suffix=".png")

    try:
        # Save file
        with os.fdopen(fd, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # OCR (blocking — run off the event loop)
        text = await asyncio.to_thread(extract_text_from_image, temp_path)

        # Extract only http/https URLs
        urls = re.findall(r"https?://[^\s]+", text)

        # Remove duplicates
        urls = list(set(urls))

        if not urls:
            return {"error": "No valid http/https URL found in image."}

        # Preview scan for each URL
        preview_results = []

        for url in urls:
            # OCR'd URLs are attacker-controlled: never fetch internal targets
            if await asyncio.to_thread(is_private_ip, url):
                preview_results.append({
                    "url": url,
                    "preview_score": 0,
                    "preview_severity": "Blocked",
                    "preview_flags": ["Private IP addresses cannot be scanned"]
                })
                continue

            try:
                static_data = await asyncio.to_thread(run_static_analysis, url)
                score_data = calculate_risk_score(static_data)

                preview_results.append({
                    "url": url,
                    "preview_score": score_data.get("risk_score"),
                    "preview_severity": score_data.get("severity"),
                    "preview_flags": score_data.get("reasons", [])[:3]  # limit for preview
                })

            except Exception:
                preview_results.append({
                    "url": url,
                    "preview_score": 0,
                    "preview_severity": "Unknown",
                    "preview_flags": ["Preview scan failed"]
                })

        return {
            "detected_urls": preview_results
        }

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


templates = Jinja2Templates(
    directory=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")
)



@router.get("/results", response_class=HTMLResponse)
def results_page(request: Request):
    return templates.TemplateResponse(
        "results.html",
        {"request": request}
    )


@router.get("/dynamic-results", response_class=HTMLResponse)
def dynamic_results_page(request: Request):
    return templates.TemplateResponse(
        "dynamic_results.html",
        {"request": request}
    )

