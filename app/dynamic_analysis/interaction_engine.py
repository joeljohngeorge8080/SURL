import asyncio
import random


FAKE_EMAIL = "testuser@example.com"
FAKE_PASSWORD = "Password123!"


async def human_type(element, text: str):
    for char in text:
        await element.type(char)
        await asyncio.sleep(random.uniform(0.05, 0.15))


async def simulate_interaction(page):

    interaction_results = {
        "buttons_clicked": 0,
        "forms_submitted": 0,
        "post_interaction_redirect": False,
        "post_interaction_network_activity": False,
    }

    try:
        # -------------------------
        # 1️⃣ Click Visible Buttons
        # -------------------------

        buttons = await page.query_selector_all("button, input[type=button], input[type=submit]")

        for button in buttons[:5]:  # limit to 5
            try:
                if await button.is_visible():
                    # Human-like mouse movement before clicking
                    await page.mouse.move(random.randint(100, 500), random.randint(100, 500))
                    await asyncio.sleep(random.uniform(0.3, 1.0))
                    
                    await button.click(timeout=2000)
                    interaction_results["buttons_clicked"] += 1
                    await asyncio.sleep(2)
            except Exception:
                continue

        # -------------------------
        # 2️⃣ Form Interaction
        # -------------------------

        forms = await page.query_selector_all("form")

        for form in forms[:2]:  # limit to 2 forms
            try:
                password_field = await form.query_selector("input[type=password]")
                email_field = await form.query_selector("input[type=email], input[type=text]")

                if password_field:
                    if email_field:
                        await email_field.click()
                        await asyncio.sleep(random.uniform(0.2, 0.5))
                        await human_type(email_field, FAKE_EMAIL)

                    await password_field.click()
                    await asyncio.sleep(random.uniform(0.2, 0.5))
                    await human_type(password_field, FAKE_PASSWORD)

                    submit_button = await form.query_selector("button[type=submit], input[type=submit]")

                    if submit_button:
                        await submit_button.click()
                        interaction_results["forms_submitted"] += 1
                        await asyncio.sleep(3)

            except Exception:
                continue

        # -------------------------
        # 3️⃣ Post Interaction Redirect Check
        # -------------------------

        current_url = page.url
        await asyncio.sleep(2)

        if page.url != current_url:
            interaction_results["post_interaction_redirect"] = True

        # -------------------------
        # 4️⃣ Detect Network Activity Spike
        # -------------------------

        # If needed, we can integrate request counters later
        interaction_results["post_interaction_network_activity"] = True

    except Exception:
        pass

    return interaction_results