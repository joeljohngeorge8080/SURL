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
from app.dynamic_analysis.interaction_engine import simulate_interaction


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
        "screenshots": [],
        "classification": "Unknown",
        "confidence": "Low",
    }

    if static_results is None:
        static_results = {}

    browser = None  # 🔥 FIX: define before try

    try:
        async with async_playwright() as p:

            browser = await p.chromium.launch(headless=True)

            context = await browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True
            )

            page = await context.new_page()

            # =========================
            # NETWORK MONITORING
            # =========================
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
                        if body and len(body) < 500_000:
                            collected_js.append(body)
                except Exception:
                    pass

            page.on("response", capture_response)

            response = await page.goto(
                url,
                wait_until="domcontentloaded",
                timeout=15000
            )

            if not response:
                raise Exception("Page failed to load")

            # =========================
            # REDIRECT EXTRACTION
            # =========================
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

            # =========================
            # WAIT FOR FULL RENDER
            # =========================
            await asyncio.sleep(3)

            # =========================
            # PAGE TEXT EXTRACTION
            # =========================
            try:
                page_text = await page.inner_text("body")
            except Exception:
                page_text = ""

            keyword_hits = analyze_keywords(page_text)
            results["keyword_hits"] = keyword_hits
            # =========================
            # CREDENTIAL INTELLIGENCE
            # =========================
            credential_analysis = await analyze_credentials(page, url)
            results["credential_analysis"] = credential_analysis


            # =========================
            # CREDENTIAL INTELLIGENCE
            # =========================
            credential_analysis = await analyze_credentials(page, url)
            results["credential_analysis"] = credential_analysis

            # =========================
            # JS INTELLIGENCE
            # =========================
            await asyncio.sleep(2)

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

                    external_post_detected=preliminary_exfiltration.get("external_post_detected", False),

                )

                combined_js_analysis["high_risk"].extend(js_result.get("high_risk", []))
                combined_js_analysis["medium_risk"].extend(js_result.get("medium_risk", []))
                combined_js_analysis["credential_related"].extend(js_result.get("credential_related", []))

            for key in combined_js_analysis:
                combined_js_analysis[key] = list(set(combined_js_analysis[key]))
            
            if (
                combined_js_analysis["credential_related"]
                and not credential_analysis.get("credential_fields_detected", False)
            ):
                combined_js_analysis["medium_risk"].append("credential_behavior_without_password_fields")
                combined_js_analysis["medium_risk"] = list(set(combined_js_analysis["medium_risk"]))


            if not credential_analysis.get("credential_fields_detected", False):
                if combined_js_analysis.get("credential_related"):
                    combined_js_analysis["credential_related"] = []
                if "credential_like_script_behavior" not in combined_js_analysis["medium_risk"]:
                    combined_js_analysis["medium_risk"].append("credential_like_script_behavior")

            if combined_js_analysis["high_risk"]:
                summary = "High-risk JavaScript patterns detected."

            elif combined_js_analysis["medium_risk"]:
                summary = "Moderate dynamic behavior observed."
            else:
                summary = "No suspicious script patterns detected."

            combined_js_analysis["summary"] = summary
            results["javascript_intelligence"] = combined_js_analysis



            # =========================

            # SCREENSHOTS

            # =========================
            try:
                interaction_results = await simulate_interaction(page)
                results["interaction_results"] = interaction_results
            except Exception:
                results["interaction_results"] = {
                    "buttons_clicked": 0,
                    "forms_submitted": 0,
                    "post_interaction_redirect": False,
                    "post_interaction_network_activity": False,
                }

            # =========================
            # SCREENSHOTS (AFTER INTERACTION)
            # =========================
            post_interaction_shot = f"{uuid.uuid4()}_post_interaction.png"
            try:
                await page.screenshot(
                    path=os.path.join(SCREENSHOT_DIR, post_interaction_shot),
                    full_page=False
                )
                results["screenshots"].append(post_interaction_shot)
            except Exception:
                pass

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)

            scroll_shot = f"{uuid.uuid4()}_scrolled.png"
            await page.screenshot(
                path=os.path.join(SCREENSHOT_DIR, scroll_shot),
                full_page=True
            )
            results["screenshots"].append(scroll_shot)

            # =========================
            # NETWORK EXFILTRATION
            # =========================
            exfiltration_results = analyze_post_requests(url, network_requests)
            results["network_exfiltration"] = exfiltration_results

            # =========================
            # CORRELATION ENGINE
            # =========================
            try:
                correlation_result = strict_three_layer_correlation(
                    redirect_analysis=redirect_analysis,
                    keyword_hits=keyword_hits,
                    js_analysis=combined_js_analysis,
                    credential_analysis=credential_analysis,
                    network_exfiltration=exfiltration_results,
                )

            except Exception as e:
                correlation_result = {
                    "classification": "No Significant Dynamic Threats Detected",
                    "confidence": "Low",
                    "signals": ["Correlation engine fallback triggered."]
                }

            results["classification"] = correlation_result.get("classification", "No Significant Dynamic Threats Detected")
            results["confidence"] = correlation_result.get("confidence", "Low")
            results["correlation_signals"] = correlation_result.get("signals", [])


            await browser.close()
            return results

    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()

        print("=========== DYNAMIC ENGINE CRASH ===========")
        print(error_trace)
        print("=============================================")

        results["classification"] = "Execution Error"
        results["confidence"] = "Low"
        results["correlation_signals"] = ["Correlation engine fallback triggered."]
        results["engine_error"] = {
            "type": type(e).__name__,
            "message": str(e),
            "traceback": error_trace
        }

        if browser:
            try:
                await browser.close()
            except Exception:
                pass

        return results
