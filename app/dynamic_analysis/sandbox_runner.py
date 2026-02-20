import asyncio
from playwright.async_api import async_playwright
from urllib.parse import urlparse
import uuid
import os

from app.intelligence.redirect_intelligence import analyze_redirect_chain
from app.intelligence.keyword_intelligence import analyze_keywords
from app.intelligence.js_intelligence import analyze_javascript
from app.intelligence.correlation_engine import strict_three_layer_correlation
from app.intelligence.credential_intelligence import analyze_credentials
from app.dynamic_analysis.network_monitor import analyze_post_requests


SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


async def run_dynamic_analysis(url: str, static_results: dict = None) -> dict:

    results = {
        "redirect_chain": [],
        "redirect_intelligence": {},
        "keyword_hits": {},
        "javascript_intelligence": {},
        "credential_analysis": {},
        "screenshots": [],
        "classification": "Unknown",
        "confidence": "Low",
    }
    
    if static_results is None:
        static_results = {}

    

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            context = await browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True
            )

            page = await context.new_page()

            # -------------------------
            # NETWORK MONITORING
            # -------------------------
            network_requests = []
            collected_js = []

            async def handle_request(request):
                try:
                    headers = request.headers
                    content_length = headers.get("content-length")
                    if content_length:
                        content_length = int(content_length)
                    else:
                        content_length = 0

                    network_requests.append({
                        "method": request.method,
                        "url": request.url,
                        "content_length": content_length
                    })
                except Exception:
                    pass

            page.on("request", handle_request)

            async def capture_response(response):
                try:
                    content_type = response.headers.get("content-type", "")

                    if "javascript" in content_type.lower():
                        body = await response.text()

                        # Prevent memory explosion
                        if body and len(body) < 500_000:
                            collected_js.append(body)

                except Exception:
                    pass

            page.on("response", capture_response)

            response = await page.goto(url, wait_until="domcontentloaded"
, timeout=15000)

            if not response:
                raise Exception("Page failed to load")

            # -------------------------
            # REDIRECT EXTRACTION
            # -------------------------
            redirect_chain = []

            try:
                if response and response.request:
                    req = response.request

                    # Walk backward safely
                    while req:
                        redirect_chain.insert(0, req.url)
                        req = req.redirected_from

            except Exception:
                redirect_chain = []

            results["redirect_chain"] = redirect_chain

            redirect_analysis = analyze_redirect_chain(url, redirect_chain)
            results["redirect_intelligence"] = redirect_analysis

            # -------------------------
            # WAIT FOR FULL RENDER
            # -------------------------
            await asyncio.sleep(3)

            # -------------------------
            # PAGE TEXT EXTRACTION
            # -------------------------
            try:
                page_text = await page.inner_text("body")
            except Exception:
                page_text = ""

            keyword_hits = analyze_keywords(page_text)
            results["keyword_hits"] = keyword_hits

            # -------------------------
            # JS INTELLIGENCE
            # -------------------------
            await asyncio.sleep(2)

            combined_js_analysis = {
                "high_risk": [],
                "medium_risk": [],
                "credential_related": [],
            }

            for js_code in collected_js:
                result = analyze_javascript(js_code)
                combined_js_analysis["high_risk"].extend(result["high_risk"])
                combined_js_analysis["medium_risk"].extend(result["medium_risk"])
                combined_js_analysis["credential_related"].extend(result["credential_related"])

            for key in combined_js_analysis:
                combined_js_analysis[key] = list(set(combined_js_analysis[key]))

            if combined_js_analysis["high_risk"]:
                summary = "High-risk JavaScript patterns detected."
            elif combined_js_analysis["credential_related"]:
                summary = "Credential-handling JavaScript behavior detected."
            elif combined_js_analysis["medium_risk"]:
                summary = "Moderate dynamic behavior patterns detected."
            else:
                summary = "No suspicious script patterns detected."

            combined_js_analysis["summary"] = summary

            results["javascript_intelligence"] = combined_js_analysis
            
            # -------------------------
            # CREDENTIAL INTELLIGENCE
            # -------------------------
            credential_analysis = await analyze_credentials(page, url)
            results["credential_analysis"] = credential_analysis

            # -------------------------
            # SCREENSHOTS
            # -------------------------
            landing_shot = f"{uuid.uuid4()}_landing.png"
            landing_path = os.path.join(SCREENSHOT_DIR, landing_shot)
            await page.screenshot(path=landing_path, full_page=False)
            results["screenshots"].append(landing_shot)

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)

            scroll_shot = f"{uuid.uuid4()}_scrolled.png"
            scroll_path = os.path.join(SCREENSHOT_DIR, scroll_shot)
            await page.screenshot(path=scroll_path, full_page=True)
            results["screenshots"].append(scroll_shot)

            # -------------------------
            # NETWORK EXFILTRATION ANALYSIS
            # -------------------------
            exfiltration_results = analyze_post_requests(url, network_requests)
            results["network_exfiltration"] = exfiltration_results

            # -------------------------
            # CORRELATION ENGINE
            # -------------------------
            correlation_result = strict_three_layer_correlation(
                redirect_analysis=redirect_analysis,
                keyword_hits=keyword_hits,
                js_analysis=combined_js_analysis,
                credential_analysis=credential_analysis,
                network_exfiltration=exfiltration_results,
            )

            results["classification"] = correlation_result["classification"]
            results["confidence"] = correlation_result["confidence"]
            results["correlation_signals"] = correlation_result["signals"]


            await browser.close()

    except Exception as e:
        import traceback
        print(f"Dynamic Analysis Error: {str(e)}")
        print(f"Traceback: {traceback.format_exc()}")
        results["classification"] = "Execution Error"
        results["confidence"] = "Low"


    return results
