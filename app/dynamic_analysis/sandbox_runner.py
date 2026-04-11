import asyncio
from playwright.async_api import async_playwright
import os

from app.intelligence.redirect_intelligence import analyze_redirect_chain
from app.intelligence.keyword_intelligence import analyze_keywords
from app.intelligence.js_intelligence import analyze_javascript
from app.intelligence.correlation_engine import strict_three_layer_correlation
from app.intelligence.credential_intelligence import analyze_credentials
from app.dynamic_analysis.network_monitor import analyze_post_requests
from app.dynamic_analysis.interaction_engine import simulate_interaction
from app.dynamic_analysis.screenshots import ScreenshotSession


SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


async def run_dynamic_analysis(url: str, static_results: dict = None) -> dict:

    results = {
        "redirect_chain": [],
        "redirect_intelligence": {},
        "keyword_hits": {},
        "javascript_intelligence": {},
        "credential_analysis": {},
        "network_exfiltration": {},
        "interaction_results": {},
        # screenshots is now a list of {"label", "filename", "path"} dicts
        "screenshots": [],
        "classification": "Unknown",
        "confidence": "Low",
    }

    if static_results is None:
        static_results = {}

    browser = None

    try:
        async with async_playwright() as p:

            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage"]
            )

            context = await browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True,
                # Realistic viewport
                viewport={"width": 1280, "height": 800},
            )

            page = await context.new_page()

            # ── Network monitoring ────────────────────────────────────────
            network_requests = []
            collected_js = []

            async def handle_request(request):
                try:
                    headers = request.headers
                    content_length = headers.get("content-length")
                    content_length = int(content_length) if content_length else 0
                    network_requests.append({
                        "method": request.method,
                        "url": request.url,
                        "content_length": content_length,
                    })
                except Exception:
                    pass

            page.on("request", handle_request)

            async def capture_response(response):
                try:
                    content_type = response.headers.get("content-type", "")
                    if "javascript" in content_type.lower():
                        body = await response.text()
                        if body and len(body) < 500_000:
                            collected_js.append(body)
                except Exception:
                    pass

            page.on("response", capture_response)

            # ── Navigate to target ────────────────────────────────────────
            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=15000,
            )

            if not response:
                raise Exception("Page failed to load")

            # ── Redirect chain ────────────────────────────────────────────
            redirect_chain = []
            try:
                req = response.request if response else None
                while req:
                    if req.url not in redirect_chain:
                        redirect_chain.insert(0, req.url)
                    req = req.redirected_from
            except Exception:
                redirect_chain = []

            results["redirect_chain"] = redirect_chain
            redirect_analysis = analyze_redirect_chain(url, redirect_chain)
            results["redirect_intelligence"] = redirect_analysis

            # Allow the page to settle before interaction
            await asyncio.sleep(2)

            # ── Page text extraction ───────────────────────────────────────
            try:
                page_text = await page.inner_text("body")
            except Exception:
                page_text = ""

            keyword_hits = analyze_keywords(page_text)
            results["keyword_hits"] = keyword_hits

            # ── Credential intelligence ───────────────────────────────────
            credential_analysis = await analyze_credentials(page, url)
            results["credential_analysis"] = credential_analysis

            # ── Humanized interaction + multi-stage screenshots ───────────
            # Initialise the screenshot session — all stages captured inside
            ss = ScreenshotSession(page, SCREENSHOT_DIR)

            interaction_results = await simulate_interaction(page, ss)
            results["interaction_results"] = interaction_results

            # Aggregate labeled screenshots from the session
            results["screenshots"] = ss.screenshots

            # ── JS intelligence ───────────────────────────────────────────
            await asyncio.sleep(1)
            preliminary_exfiltration = analyze_post_requests(url, network_requests)

            combined_js_analysis = {
                "high_risk": [],
                "medium_risk": [],
                "credential_related": [],
            }

            for js_code in collected_js:
                js_result = analyze_javascript(
                    js_code,
                    credential_analysis=credential_analysis,
                    external_post_detected=preliminary_exfiltration.get(
                        "external_post_detected", False
                    ),
                )
                combined_js_analysis["high_risk"].extend(
                    js_result.get("high_risk", [])
                )
                combined_js_analysis["medium_risk"].extend(
                    js_result.get("medium_risk", [])
                )
                combined_js_analysis["credential_related"].extend(
                    js_result.get("credential_related", [])
                )

            for key in combined_js_analysis:
                combined_js_analysis[key] = list(set(combined_js_analysis[key]))

            if (
                combined_js_analysis["credential_related"]
                and not credential_analysis.get("credential_fields_detected", False)
            ):
                combined_js_analysis["medium_risk"].append(
                    "credential_behavior_without_password_fields"
                )
                combined_js_analysis["medium_risk"] = list(
                    set(combined_js_analysis["medium_risk"])
                )

            if not credential_analysis.get("credential_fields_detected", False):
                if combined_js_analysis.get("credential_related"):
                    combined_js_analysis["credential_related"] = []
                if "credential_like_script_behavior" not in combined_js_analysis["medium_risk"]:
                    combined_js_analysis["medium_risk"].append(
                        "credential_like_script_behavior"
                    )

            if combined_js_analysis["high_risk"]:
                summary = "High-risk JavaScript patterns detected."
            elif combined_js_analysis["medium_risk"]:
                summary = "Moderate dynamic behavior observed."
            else:
                summary = "No suspicious script patterns detected."

            combined_js_analysis["summary"] = summary
            results["javascript_intelligence"] = combined_js_analysis

            # ── Network exfiltration ──────────────────────────────────────
            exfiltration_results = analyze_post_requests(url, network_requests)
            results["network_exfiltration"] = exfiltration_results

            # ── Correlation engine ────────────────────────────────────────
            try:
                correlation_result = strict_three_layer_correlation(
                    redirect_analysis=redirect_analysis,
                    keyword_hits=keyword_hits,
                    js_analysis=combined_js_analysis,
                    credential_analysis=credential_analysis,
                    network_exfiltration=exfiltration_results,
                )
            except Exception:
                correlation_result = {
                    "classification": "No Significant Dynamic Threats Detected",
                    "confidence": "Low",
                    "signals": ["Correlation engine fallback triggered."],
                }

            results["classification"] = correlation_result.get(
                "classification", "No Significant Dynamic Threats Detected"
            )
            results["confidence"]  = correlation_result.get("confidence", "Low")
            results["correlation_signals"] = correlation_result.get("signals", [])

            await browser.close()
            return results

    except Exception as e:
        import traceback
        from app.core.logger import logger

        logger.error({
            "event": "dynamic_engine_crash",
            "exc_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        })

        results["classification"] = "Execution Error"
        results["confidence"] = "Low"
        results["correlation_signals"] = ["Correlation engine fallback triggered."]
        # Do NOT surface internal error details in the external response
        results["engine_error"] = {"type": type(e).__name__}

        if browser:
            try:
                await browser.close()
            except Exception:
                pass

        return results
