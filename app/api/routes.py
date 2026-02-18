from fastapi import APIRouter
from app.api.schemas import ScanRequest, ScanResponse
from app.services.scan_orchestrator import scan_url

router = APIRouter()


@router.post("/scan", response_model=ScanResponse)
def scan_endpoint(request: ScanRequest):
    result = scan_url(request.url)
    return result
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
