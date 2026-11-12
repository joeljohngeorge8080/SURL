import asyncio
import glob
import os
import time
from urllib.parse import urljoin, urlparse

from playwright.async_api import async_playwright

from app.intelligence.redirect_intelligence import analyze_redirect_chain
from app.intelligence.keyword_intelligence import analyze_keywords
from app.intelligence.js_intelligence import analyze_javascript
from app.intelligence.correlation_engine import strict_three_layer_correlation
from app.intelligence.credential_intelligence import analyze_credentials
from app.dynamic_analysis.network_monitor import analyze_post_requests
from app.dynamic_analysis.interaction_engine import simulate_interaction
from app.dynamic_analysis.screenshots import ScreenshotSession
from app.core.logger import logger
from static_analysis.net_guard import is_private_ip


SCREENSHOT_DIR = "screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)
SCREENSHOT_MAX_AGE_HOURS = float(os.getenv("SCREENSHOT_MAX_AGE_HOURS", "24"))
MAX_JS_BYTES = 500_000


def prune_old_screenshots(directory: str = SCREENSHOT_DIR, max_age_hours: float = SCREENSHOT_MAX_AGE_HOURS) -> int:
    """Delete scan screenshots (*.png) older than max_age_hours so the volume
    cannot fill the disk. Returns how many files were removed."""
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    for path in glob.glob(os.path.join(directory, "*.png")):
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
        except FileNotFoundError:
            continue  # removed concurrently by another worker
        except OSError as e:
            logger.warning(f"Could not prune screenshot {path}: {e}")
    return removed


def request_record(request) -> dict:
    """Network-log entry for one browser request. The body length comes from the
    request body itself: Playwright's request.headers usually omits content-length."""
    body = getattr(request, "post_data_buffer", None) or b""
    return {
        "method": request.method,
        "url": request.url,
        "content_length": len(body),
    }


def make_private_host_guard(blocked: list):
    """page.route handler that keeps the sandbox off non-public addresses, so a
    public page cannot steer Chromium into cloud metadata or the internal network.

    Playwright does not call route handlers for server-side redirect hops, so for
    navigations the guard fetches each hop itself (max_redirects=0), checks the
    Location, and hands the response back; Chromium then follows the redirect as
    a new request that comes through this guard again. Sub-resource redirects
    are not re-checked here; the host egress firewall covers those."""
    cache = {}

    async def is_blocked(url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname
        if parsed.scheme not in ("http", "https") or not host:
            return False
        if host not in cache:
            cache[host] = await asyncio.to_thread(is_private_ip, url)
        return cache[host]

    async def guard(route):
        request = route.request
        url = request.url
        if await is_blocked(url):
            blocked.append(url)
            await route.abort("blockedbyclient")
            return

        if request.is_navigation_request() and urlparse(url).scheme in ("http", "https"):
            response = await route.fetch(max_redirects=0)
            location = response.headers.get("location")
            if 300 <= response.status < 400 and location:
                target = urljoin(url, location)
                if await is_blocked(target):
                    blocked.append(target)
                    await route.abort("blockedbyclient")
                    return
            await route.fulfill(response=response)
            return

        await route.continue_()

    return guard


def aggregate_js_findings(
    js_sources: list,
    credential_analysis: dict,
    external_post_detected: bool,
) -> dict:
    """Merge per-script JS findings into one page-level verdict."""

    combined = {
        "high_risk": [],
        "medium_risk": [],
        "credential_related": [],
    }

    for js_code in js_sources:
        js_result = analyze_javascript(
            js_code,
            credential_analysis=credential_analysis,
            external_post_detected=external_post_detected,
        )
        for key, values in combined.items():
            values.extend(js_result.get(key, []))

    combined = {key: list(set(values)) for key, values in combined.items()}

    # Credential-style script behavior on a page with no password field is
    # downgraded to medium risk — but only when such behavior was actually seen.
    if (
        combined["credential_related"]
        and not credential_analysis.get("credential_fields_detected", False)
    ):
        combined["credential_related"] = []
        for flag in ("credential_behavior_without_password_fields", "credential_like_script_behavior"):
            if flag not in combined["medium_risk"]:
                combined["medium_risk"].append(flag)

    if combined["high_risk"]:
        summary = "High-risk JavaScript patterns detected."
    elif combined["medium_risk"]:
        summary = "Moderate dynamic behavior observed."
    else:
        summary = "No suspicious script patterns detected."

    combined["summary"] = summary
    return combined


# Each Chromium instance needs roughly 300-500 MB. On a small host (e.g. a 1 GB
# free-tier EC2 instance) running them in parallel gets the container OOM-killed,
# so scans queue behind this gate. Raise MAX_CONCURRENT_BROWSERS on bigger hosts.
MAX_CONCURRENT_BROWSERS = max(1, int(os.getenv("MAX_CONCURRENT_BROWSERS", "2")))
BROWSER_QUEUE_TIMEOUT = float(os.getenv("BROWSER_QUEUE_TIMEOUT", "60"))
# Total budget for one request (queue wait + scan). Must stay below the reverse
# proxy's read timeout (nginx proxy_read_timeout 130s) so the client gets a real
# answer instead of a 504 while Chromium keeps holding a browser slot.
DYNAMIC_SCAN_TIMEOUT = float(os.getenv("DYNAMIC_SCAN_TIMEOUT", "110"))
MIN_SCAN_SECONDS = 20.0
_browser_gate = asyncio.Semaphore(MAX_CONCURRENT_BROWSERS)


def _busy(reason: str) -> dict:
    return {
        "classification": "Busy",
        "confidence": "Low",
        "engine_error": {"type": "SandboxBusy"},
        "correlation_signals": [reason],
    }


async def run_dynamic_analysis(url: str, static_results: dict = None) -> dict:
    """Run the sandbox, queueing behind the concurrency gate, within one deadline."""
    loop = asyncio.get_running_loop()
    started = loop.time()
    try:
        await asyncio.wait_for(
            _browser_gate.acquire(),
            timeout=min(BROWSER_QUEUE_TIMEOUT, DYNAMIC_SCAN_TIMEOUT),
        )
    except asyncio.TimeoutError:
        return _busy("Sandbox is at capacity; retry shortly.")
    try:
        remaining = DYNAMIC_SCAN_TIMEOUT - (loop.time() - started)
        if remaining < MIN_SCAN_SECONDS:
            return _busy("Sandbox queue took too long; retry shortly.")
        try:
            # Cancelling the scan unwinds async_playwright(), which closes Chromium.
            return await asyncio.wait_for(_run_dynamic_analysis(url, static_results), timeout=remaining)
        except asyncio.TimeoutError:
            logger.warning(f"Dynamic scan exceeded {DYNAMIC_SCAN_TIMEOUT:.0f}s budget")
            return {
                "classification": "Timeout",
                "confidence": "Low",
                "engine_error": {"type": "SandboxTimeout"},
                "correlation_signals": ["The page did not finish loading and interacting in time."],
            }
    finally:
        _browser_gate.release()


async def _run_dynamic_analysis(url: str, static_results: dict = None) -> dict:

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

    prune_old_screenshots()

    browser = None
    blocked_requests = []

    try:
        async with async_playwright() as p:

            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--disable-gpu"]
            )

            context = await browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=True,
                # Realistic viewport
                viewport={"width": 1280, "height": 800},
            )

            # Every request is checked, including redirect hops and sub-resources.
            await context.route("**/*", make_private_host_guard(blocked_requests))

            page = await context.new_page()

            # ── Network monitoring ────────────────────────────────────────
            network_requests = []
            collected_js = []

            async def handle_request(request):
                try:
                    network_requests.append(request_record(request))
                except Exception as e:
                    logger.debug(f"request record skipped: {e}")

            page.on("request", handle_request)

            async def capture_response(response):
                try:
                    content_type = response.headers.get("content-type", "")
                    if "javascript" in content_type.lower():
                        body = await response.text()
                        if body and len(body) < MAX_JS_BYTES:
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

            # Inline <script> blocks never arrive as JS responses, but phishing
            # kits usually put their eval(atob(...)) payloads there.
            try:
                inline_js = await page.eval_on_selector_all(
                    "script:not([src])", "els => els.map(e => e.textContent || '')"
                )
                collected_js.extend(js for js in inline_js if js and len(js) < MAX_JS_BYTES)
            except Exception as e:
                logger.debug(f"inline script collection skipped: {e}")
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

            combined_js_analysis = aggregate_js_findings(
                collected_js,
                credential_analysis,
                preliminary_exfiltration.get("external_post_detected", False),
            )
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
            results["blocked_requests"] = blocked_requests

            await browser.close()
            return results

    except Exception as e:
        import traceback

        logger.error({
            "event": "dynamic_engine_crash",
            "exc_type": type(e).__name__,
            "traceback": traceback.format_exc(),
        })

        results["confidence"] = "Low"
        results["blocked_requests"] = blocked_requests
        # Do NOT surface internal error details in the external response
        if blocked_requests and not results["redirect_chain"]:
            # The navigation itself was aborted by the private-address guard.
            results["classification"] = "Blocked"
            results["correlation_signals"] = ["The page redirected to a private or internal address; the scan was stopped."]
            results["engine_error"] = {"type": "BlockedPrivateAddress"}
        else:
            results["classification"] = "Execution Error"
            results["correlation_signals"] = ["Correlation engine fallback triggered."]
            results["engine_error"] = {"type": type(e).__name__}

        if browser:
            try:
                await browser.close()
            except Exception:
                pass

        return results
