import asyncio
from playwright.async_api import async_playwright
from urllib.parse import urlparse
import uuid
import os
from datetime import datetime
from app.intelligence.redirect_intelligence import analyze_redirect_chain, extract_root_domain


SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)


async def run_dynamic_analysis(url: str) -> dict:
    """
    Executes deep behavioral inspection inside isolated headless browser.
    Fully async. Safe execution timeout enforced.
    """

    dynamic_results = {
        "redirect_chain": [],
        "redirect_count": 0,
        "cross_domain_redirect": False,
        "js_password_field_detected": False,
        "external_form_submission": False,
        "auto_redirect_script": False,
        "suspicious_network_calls": 0,
        "screenshot_path": None,
        "redirect_intelligence": None,
        "dynamic_risk_score": 0
    }

    parsed_original = urlparse(url)
    original_domain = parsed_original.hostname

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)


            context = await browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True
            )

            page = await context.new_page()

            # ─────────────────────────
            # REDIRECT CHAIN TRACKING
            # ─────────────────────────
            redirect_chain = []

            def handle_navigation(frame):
                if frame.url not in redirect_chain:
                    redirect_chain.append(frame.url)

            page.on("framenavigated", handle_navigation)

            try:
                await page.goto(url, wait_until="networkidle", timeout=10000)
            except Exception:
                # Continue to allow screenshot capture even if navigation fails or times out
                pass

            # Wait for JS execution and client-side redirects
            await asyncio.sleep(5)

            # ─────────────────────────
            # SUSPICIOUS CONTENT INTELLIGENCE
            # ─────────────────────────
            page_text = await page.inner_text("body")

            SUSPICIOUS_KEYWORDS = [
                "verify your account",
                "confirm password",
                "bank login",
                "update payment",
                "urgent action required",
                "account suspended",
                "security alert",
                "bitcoin payment",
                "gift card"
            ]

            detected_keywords = []

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in page_text.lower():
                    detected_keywords.append(keyword)

            dynamic_results["suspicious_keywords_detected"] = detected_keywords

            if detected_keywords:
                dynamic_results["dynamic_risk_score"] += 20

            page_html = await page.content()

            SUSPICIOUS_JS = [
                "eval(",
                "atob(",
                "document.write(",
                "window.location=",
                "unescape("
            ]

            detected_js_patterns = []

            for pattern in SUSPICIOUS_JS:
                if pattern in page_html:
                    detected_js_patterns.append(pattern)

            dynamic_results["suspicious_js_patterns"] = detected_js_patterns

            if detected_js_patterns:
                dynamic_results["dynamic_risk_score"] += 15

            # ─────────────────────────
            # REDIRECT ANALYSIS
            # ─────────────────────────
            final_url = page.url
            dynamic_results["redirect_chain"] = redirect_chain
            dynamic_results["redirect_count"] = len(redirect_chain)


            # Compare root domains instead of full hostnames
            original_root = extract_root_domain(url)
            final_root = extract_root_domain(final_url)

            if original_root != final_root:
                dynamic_results["cross_domain_redirect"] = True

            # Intelligent redirect analysis
            redirect_analysis = analyze_redirect_chain(url, redirect_chain)
            dynamic_results["redirect_intelligence"] = redirect_analysis

            if redirect_analysis["cross_root_detected"]:
                dynamic_results["dynamic_risk_score"] += 25

            if redirect_analysis["suspicious_redirect_detected"]:
                dynamic_results["dynamic_risk_score"] += 20


            # ─────────────────────────
            # PASSWORD FIELD DETECTION
            # ─────────────────────────
            password_fields = await page.query_selector_all("input[type='password']")
            if password_fields:
                dynamic_results["js_password_field_detected"] = True
                dynamic_results["dynamic_risk_score"] += 25

            # ─────────────────────────
            # EXTERNAL FORM ACTION
            # ─────────────────────────
            forms = await page.query_selector_all("form")
            original_root = extract_root_domain(url)

            for form in forms:
                try:
                    action = await form.get_attribute("action")

                    if action:
                        action_root = extract_root_domain(action)
                        if action_root and action_root != original_root:
                            dynamic_results["external_form_submission"] = True
                            dynamic_results["dynamic_risk_score"] += 25
                            break
                    # Relative URLs like "/submit" are same-domain, skip
                except Exception:
                    pass

            # ─────────────────────────
            # AUTO REDIRECT SCRIPT
            # ─────────────────────────
            scripts = await page.content()

            if "window.location" in scripts or "setTimeout" in scripts:
                dynamic_results["auto_redirect_script"] = True
                dynamic_results["dynamic_risk_score"] += 15

            # ─────────────────────────
            # SCREENSHOTS
            # ─────────────────────────
            dynamic_results["screenshots"] = []

            # 1️⃣ Landing page screenshot
            landing_name = f"{uuid.uuid4()}_landing.png"
            landing_path = os.path.join(SCREENSHOT_DIR, landing_name)
            await page.screenshot(path=landing_path, full_page=True)
            dynamic_results["screenshots"].append({
                "type": "landing",
                "path": f"/screenshots/{landing_name}"
            })

            # 2️⃣ Scroll screenshot
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await asyncio.sleep(1)

            scroll_name = f"{uuid.uuid4()}_scroll.png"
            scroll_path = os.path.join(SCREENSHOT_DIR, scroll_name)
            await page.screenshot(path=scroll_path, full_page=True)
            dynamic_results["screenshots"].append({
                "type": "scrolled",
                "path": f"/screenshots/{scroll_name}"
            })

            # 3️⃣ Form screenshot (if detected)
            forms = await page.query_selector_all("form")
            if forms:
                form_name = f"{uuid.uuid4()}_form.png"
                form_path = os.path.join(SCREENSHOT_DIR, form_name)
                await page.screenshot(path=form_path, full_page=True)
                dynamic_results["screenshots"].append({
                    "type": "form_detected",
                    "path": f"/screenshots/{form_name}"
                })

            await browser.close()

    except Exception:
        dynamic_results["dynamic_risk_score"] += 10

    return dynamic_results
