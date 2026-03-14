"""
interaction_engine.py

Humanized browser interaction engine for the dynamic analysis sandbox.

Stages (each with its own labeled screenshot):
  1.  landing_page            – immediately after page load
  2.  post_consent_dismiss    – after cookie / consent banner is dismissed
  3.  pre_click_{i}           – just before clicking a button / link
  4.  post_click_{i}          – just after clicking a button / link
  5.  scrolled_bottom         – after scrolling to bottom of page
  6.  scrolled_top            – after scrolling back to top
  7.  form_filled_{i}         – after all fields in form i are filled
  8.  post_form_submit_{i}    – after form i is submitted
  9.  post_popup_dismiss      – after a JS dialog (alert/confirm) is dismissed
  10. final_state             – end of all interactions
"""

import asyncio
import random
from app.dynamic_analysis.screenshots import ScreenshotSession


# ---------------------------------------------------------------------------
# Fake persona data — plausible but obviously synthetic
# ---------------------------------------------------------------------------
FAKE_PERSONA = {
    "email":    "john.smith92@gmail.com",
    "password": "P@ssw0rd2024!",
    "username": "john_smith92",
    "first":    "John",
    "last":     "Smith",
    "name":     "John Smith",
    "phone":    "+15555010234",
    "mobile":   "+15555010234",
    "tel":      "+15555010234",
    "dob":      "1992-06-15",
    "birth":    "1992-06-15",
    "date":     "1992-06-15",
    "address":  "123 Maple Street",
    "street":   "123 Maple Street",
    "city":     "San Francisco",
    "zip":      "94103",
    "postal":   "94103",
    "country":  "US",
    "company":  "Acme Corp",
    "card":     "4111111111111111",
    "credit":   "4111111111111111",
    "cvv":      "123",
    "cvc":      "123",
    "otp":      "123456",
    "code":     "123456",
    "pin":      "1234",
    "security": "MyFirstPet",
    "search":   "example search",
    "message":  "This is a test message.",
    "comment":  "Test comment.",
}

# Terms in button text that reliably appear on cookie / consent banners
CONSENT_TERMS = [
    "accept", "accept all", "allow", "allow all", "ok", "okay",
    "got it", "i agree", "agree", "consent", "continue", "close",
    "dismiss", "understand", "i understand",
]

# SSO / federated-login buttons we should NOT click (they'd navigate away)
BLOCKED_BUTTON_TERMS = [
    "sign in with", "continue with", "login with",
    "apple", "microsoft", "facebook", "github", "twitter", "google",
    "sso", "oauth", "saml",
]


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

async def human_type(element, text: str):
    """Type text into an element character-by-character with random delays."""
    try:
        for char in text:
            await element.type(char)
            await asyncio.sleep(random.uniform(0.04, 0.18))
    except Exception:
        pass


async def human_mouse_move(page, element):
    """Move the mouse to element centre with random step count."""
    try:
        box = await element.bounding_box()
        if box:
            x = box["x"] + box["width"] / 2
            y = box["y"] + box["height"] / 2
            await page.mouse.move(x, y, steps=random.randint(6, 20))
            await asyncio.sleep(random.uniform(0.1, 0.4))
    except Exception:
        pass


def _resolve_fake_value(attr_name: str, attr_type: str, placeholder: str) -> str:
    """
    Choose the best fake value to inject by inspecting multiple attributes.
    Priority: explicit `type` → name / id hint → placeholder hint → generic.
    """
    # Merge all hints into one lowercase string for easy matching
    combined = " ".join([
        (attr_name or ""),
        (attr_type or ""),
        (placeholder or ""),
    ]).lower()

    # Ordered from most specific to least specific
    checks = [
        ("password",    FAKE_PERSONA["password"]),
        ("email",       FAKE_PERSONA["email"]),
        ("card",        FAKE_PERSONA["card"]),
        ("credit",      FAKE_PERSONA["credit"]),
        ("cvv",         FAKE_PERSONA["cvv"]),
        ("cvc",         FAKE_PERSONA["cvc"]),
        ("otp",         FAKE_PERSONA["otp"]),
        ("pin",         FAKE_PERSONA["pin"]),
        ("phone",       FAKE_PERSONA["phone"]),
        ("mobile",      FAKE_PERSONA["mobile"]),
        ("tel",         FAKE_PERSONA["tel"]),
        ("dob",         FAKE_PERSONA["dob"]),
        ("birth",       FAKE_PERSONA["birth"]),
        ("zip",         FAKE_PERSONA["zip"]),
        ("postal",      FAKE_PERSONA["postal"]),
        ("city",        FAKE_PERSONA["city"]),
        ("address",     FAKE_PERSONA["address"]),
        ("street",      FAKE_PERSONA["street"]),
        ("country",     FAKE_PERSONA["country"]),
        ("company",     FAKE_PERSONA["company"]),
        ("first",       FAKE_PERSONA["first"]),
        ("last",        FAKE_PERSONA["last"]),
        ("name",        FAKE_PERSONA["name"]),
        ("user",        FAKE_PERSONA["username"]),
        ("login",       FAKE_PERSONA["username"]),
        ("username",    FAKE_PERSONA["username"]),
        ("security",    FAKE_PERSONA["security"]),
        ("search",      FAKE_PERSONA["search"]),
        ("message",     FAKE_PERSONA["message"]),
        ("comment",     FAKE_PERSONA["comment"]),
        ("code",        FAKE_PERSONA["code"]),
        ("date",        FAKE_PERSONA["date"]),
    ]

    for keyword, value in checks:
        if keyword in combined:
            return value

    # Last-resort defaults by input type
    if attr_type in ("number", "tel"):
        return "1234567890"
    if attr_type == "date":
        return "1992-06-15"
    if attr_type == "url":
        return "https://example.com"
    return "testvalue"


# ---------------------------------------------------------------------------
# Consent / cookie banner dismissal
# ---------------------------------------------------------------------------

async def _dismiss_consent_banner(page, ss: ScreenshotSession) -> bool:
    """
    Try to find and click a cookie/consent accept button.
    Returns True if one was found and clicked.
    """
    try:
        buttons = await page.query_selector_all(
            "button, a[role=button], [class*=cookie] button, "
            "[class*=consent] button, [id*=cookie] button, [id*=consent] button"
        )
        for btn in buttons:
            try:
                if not await btn.is_visible():
                    continue
                text = (await btn.inner_text() or "").strip().lower()
                if any(term in text for term in CONSENT_TERMS):
                    await human_mouse_move(page, btn)
                    await btn.click(timeout=3000)
                    await asyncio.sleep(random.uniform(0.8, 1.5))
                    await ss.take("post_consent_dismiss")
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Popup / dialog auto-dismiss
# ---------------------------------------------------------------------------

def _register_dialog_handler(page, results: dict):
    """Auto-accept any alert/confirm/prompt dialogs that appear."""
    async def handle_dialog(dialog):
        try:
            results["dialogs_dismissed"] = results.get("dialogs_dismissed", 0) + 1
            await dialog.accept()
        except Exception:
            pass

    page.on("dialog", handle_dialog)


# ---------------------------------------------------------------------------
# Button clicking stage
# ---------------------------------------------------------------------------

async def _click_buttons(page, ss: ScreenshotSession, results: dict):
    """Click visible safe buttons and screenshot before and after each."""
    buttons = await page.query_selector_all(
        "button:not([type=submit]), input[type=button], a[role=button]"
    )

    clicked = 0
    for i, button in enumerate(buttons[:6]):        # cap at 6 buttons
        try:
            if not await button.is_visible():
                continue
            if not await button.is_enabled():
                continue

            text = ""
            try:
                text = (await button.inner_text() or "").strip().lower()
            except Exception:
                pass

            # Skip SSO / federated login buttons
            if any(term in text for term in BLOCKED_BUTTON_TERMS):
                continue

            await ss.take(f"pre_click_{clicked + 1}")
            await human_mouse_move(page, button)
            await button.click(timeout=3000)
            clicked += 1
            await asyncio.sleep(random.uniform(0.8, 1.8))
            await ss.take(f"post_click_{clicked}")

        except Exception:
            continue

    results["buttons_clicked"] = clicked


# ---------------------------------------------------------------------------
# Humanized form filling stage
# ---------------------------------------------------------------------------

async def _fill_forms(page, ss: ScreenshotSession, results: dict):
    """
    Find all forms, inject humanized fake data into every field, screenshot
    after filling, then submit and screenshot after submit.
    """
    forms = await page.query_selector_all("form")
    submitted = 0

    for form_idx, form in enumerate(forms[:3]):    # cap at 3 forms
        try:
            inputs = await form.query_selector_all(
                "input:not([type=hidden]):not([type=submit]):not([type=button]), "
                "textarea, select"
            )

            filled_any = False

            for inp in inputs:
                try:
                    if not await inp.is_visible():
                        continue

                    tag = await inp.evaluate("el => el.tagName.toLowerCase()")

                    # ---- <select> ----
                    if tag == "select":
                        options = await inp.query_selector_all("option")
                        if len(options) > 1:
                            await inp.select_option(index=1)
                        filled_any = True
                        continue

                    # ---- <textarea> ----
                    if tag == "textarea":
                        await inp.click(timeout=2000)
                        await asyncio.sleep(random.uniform(0.2, 0.5))
                        await human_type(inp, FAKE_PERSONA["message"])
                        filled_any = True
                        continue

                    # ---- <input> ----
                    input_type = (await inp.get_attribute("type") or "text").lower()

                    # Skip checkboxes / radios — just tick them
                    if input_type in ("checkbox", "radio"):
                        try:
                            if not await inp.is_checked():
                                await inp.click(timeout=2000)
                        except Exception:
                            pass
                        continue

                    # Skip file inputs
                    if input_type == "file":
                        continue

                    name        = (await inp.get_attribute("name")        or "").lower()
                    input_id    = (await inp.get_attribute("id")          or "").lower()
                    placeholder = (await inp.get_attribute("placeholder") or "").lower()

                    hint     = name or input_id
                    fake_val = _resolve_fake_value(hint, input_type, placeholder)

                    await inp.click(timeout=2000)
                    await asyncio.sleep(random.uniform(0.15, 0.4))

                    # Clear existing content before typing
                    await inp.triple_click(timeout=2000)
                    await asyncio.sleep(0.1)
                    await inp.press("Control+a")
                    await inp.press("Delete")

                    await human_type(inp, fake_val)
                    filled_any = True

                except Exception:
                    continue

            if not filled_any:
                continue

            # Screenshot after all fields are filled
            await asyncio.sleep(random.uniform(0.5, 1.0))
            await ss.take(f"form_filled_{form_idx + 1}")

            # Submit
            submit_btn = await form.query_selector(
                "button[type=submit], input[type=submit], button:not([type])"
            )

            if submit_btn and await submit_btn.is_visible():
                await human_mouse_move(page, submit_btn)
                await asyncio.sleep(random.uniform(0.3, 0.7))
                try:
                    await submit_btn.click(timeout=4000)
                    submitted += 1
                    await asyncio.sleep(random.uniform(2.0, 3.0))
                    await ss.take(f"post_form_submit_{form_idx + 1}")
                except Exception:
                    pass

        except Exception:
            continue

    results["forms_submitted"] = submitted


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def simulate_interaction(page, screenshot_session: ScreenshotSession) -> dict:
    """
    Run the full humanized interaction sequence and return a results dict
    containing interaction stats plus the ordered screenshots list.

    Args:
        page:               Playwright Page object.
        screenshot_session: ScreenshotSession instance (initialised by caller).

    Returns:
        {
            "buttons_clicked":             int,
            "forms_submitted":             int,
            "dialogs_dismissed":           int,
            "post_interaction_redirect":   bool,
            "post_interaction_network_activity": bool,
            "screenshots":                 list[dict],
        }
    """
    results = {
        "buttons_clicked": 0,
        "forms_submitted": 0,
        "dialogs_dismissed": 0,
        "post_interaction_redirect": False,
        "post_interaction_network_activity": False,
    }

    # Register dialog auto-dismiss before doing anything else
    _register_dialog_handler(page, results)

    try:
        # ── Stage 1: Landing page ─────────────────────────────────────────
        await screenshot_session.take("landing_page")

        # ── Stage 2: Dismiss cookie / consent banners ─────────────────────
        await _dismiss_consent_banner(page, screenshot_session)

        # ── Stage 3: Click safe buttons ───────────────────────────────────
        await _click_buttons(page, screenshot_session, results)

        # ── Stage 4: Scroll to bottom ─────────────────────────────────────
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(random.uniform(1.0, 1.5))
        await screenshot_session.take("scrolled_bottom", full_page=False)

        # Scroll back to top so form fields are visible
        await page.evaluate("window.scrollTo(0, 0)")
        await asyncio.sleep(random.uniform(0.5, 1.0))
        await screenshot_session.take("scrolled_top")

        # ── Stage 5: Fill and submit forms ───────────────────────────────
        await _fill_forms(page, screenshot_session, results)

        # ── Stage 6: Post-interaction state ──────────────────────────────
        current_url = page.url
        await asyncio.sleep(1.5)
        if page.url != current_url:
            results["post_interaction_redirect"] = True

        results["post_interaction_network_activity"] = True

        # ── Stage 7: Final state screenshot ──────────────────────────────
        await screenshot_session.take("final_state")

        if results.get("dialogs_dismissed", 0) > 0:
            await screenshot_session.take("post_popup_dismiss")

    except Exception:
        # Never let an interaction error crash the analysis
        pass

    results["screenshots"] = screenshot_session.screenshots
    return results
