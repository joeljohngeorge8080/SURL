from fastapi import APIRouter, UploadFile, File
from app.api.schemas import ScanRequest, ScanResponse
from app.services.scan_orchestrator import scan_url
from static_analysis.image_url_extractor import extract_text_from_image
from static_analysis.static_runner import run_static_analysis
from scoring_engine.score_calculator import calculate_risk_score
import re
import uuid
import shutil
import os

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_endpoint(request: ScanRequest):
    result = scan_url(request.url)
    return result


@router.post("/scan-selected")
def scan_selected(request: ScanRequest):
    return scan_url(request.url)


@router.post("/scan-image")
async def scan_image(file: UploadFile = File(...)):

    temp_path = f"temp_{uuid.uuid4()}.png"

    try:
        # Save file
        with open(temp_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # OCR
        text = extract_text_from_image(temp_path)

        # Extract only http/https URLs
        urls = re.findall(r"https?://[^\s]+", text)

        # Remove duplicates
        urls = list(set(urls))

        if not urls:
            return {"error": "No valid http/https URL found in image."}

        # Preview scan for each URL
        preview_results = []

        for url in urls:
            try:
                static_data = run_static_analysis(url)
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


from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

templates = Jinja2Templates(directory="app/templates")


@router.get("/results", response_class=HTMLResponse)
def results_page(request: Request):
    return templates.TemplateResponse(
        "results.html",
        {"request": request}
    )

