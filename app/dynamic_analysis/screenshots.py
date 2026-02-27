"""
screenshots.py

A dedicated screenshot session manager for the dynamic analysis engine.
Each screenshot is captured with a human-readable label so the final report
contains a fully annotated timeline of the browser's journey through the
target page.
"""

import os
import uuid


SCREENSHOT_DIR = "screenshots"


class ScreenshotSession:
    """
    Wraps a Playwright `page` object and handles all screenshot capture
    for one dynamic scan run.

    Each call to `take(label)` saves a PNG and appends a metadata dict to
    `self.screenshots` so the caller can embed the full list in the report.

    Result dict format per screenshot:
        {
            "label":    human-readable stage name  (e.g. "landing_page"),
            "filename": bare filename              (e.g. "abc123_landing_page.png"),
            "path":     full path on disk
        }
    """

    def __init__(self, page, screenshot_dir: str = SCREENSHOT_DIR):
        self.page = page
        self.screenshot_dir = screenshot_dir
        self.screenshots: list[dict] = []
        os.makedirs(self.screenshot_dir, exist_ok=True)

    async def take(self, label: str, full_page: bool = False) -> dict | None:
        """
        Capture a screenshot of the current page state.

        Args:
            label:     Descriptive stage name, e.g. "landing_page".
            full_page: Whether to capture the full scrollable page height.

        Returns:
            The metadata dict for this screenshot, or None on error.
        """
        filename = f"{uuid.uuid4().hex}_{label}.png"
        path = os.path.join(self.screenshot_dir, filename)

        try:
            await self.page.screenshot(path=path, full_page=full_page)
            entry = {
                "label": label,
                "filename": filename,
                "path": path,
            }
            self.screenshots.append(entry)
            return entry
        except Exception:
            # Never crash the analysis because of a screenshot failure
            return None
