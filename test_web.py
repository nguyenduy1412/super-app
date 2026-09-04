#!/usr/bin/env python3
"""Test all clickable buttons in Mac App Mover web UI."""
import asyncio
from playwright.async_api import async_playwright

URL = "http://127.0.0.1:8765/"

async def test():
    errors = []
    broken_buttons = []

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        # Collect JS errors
        page.on("console", lambda msg: errors.append(f"[{msg.type}] {msg.text}") if msg.type == "error" else None)
        page.on("pageerror", lambda err: errors.append(f"[PAGE ERROR] {err}"))

        print("Loading page...")
        await page.goto(URL, wait_until="networkidle")
        await asyncio.sleep(1)

        # Get all buttons
        buttons = await page.query_selector_all("button")
        print(f"\n=== Found {len(buttons)} buttons ===")
        for btn in buttons:
            text = (await btn.inner_text()).strip()
            onclick = await btn.get_attribute("onclick") or ""
            disabled = await btn.is_disabled()
            visible = await btn.is_visible()
            print(f"  [{'disabled' if disabled else 'OK'}] [{'visible' if visible else 'HIDDEN'}] text='{text}' onclick='{onclick}'")

        # Test tab switching
        print("\n=== Testing Tab Switching ===")
        tab_names = ["mover", "storage", "stuck", "uninstall"]
        for tab in tab_names:
            btn = await page.query_selector(f'button[data-tab="{tab}"]')
            if btn:
                text = (await btn.inner_text()).strip()
                print(f"  Clicking tab: {tab} ({text})")
                await btn.click()
                await asyncio.sleep(0.5)
                active = await page.query_selector(f".tab-content.active")
                if active:
                    active_id = await active.get_attribute("id")
                    print(f"    -> Active tab: {active_id}")
                else:
                    print(f"    -> NO active tab!")
                    broken_buttons.append(f"Tab '{tab}'")
            else:
                print(f"  Tab '{tab}' button NOT FOUND")

        # Test specific buttons in each tab
        print("\n=== Testing Buttons in Each Tab ===")

        # Tab: mover
        await page.click('button[data-tab="mover"]')
        await asyncio.sleep(0.3)
        print("  Mover tab:")
        for sel, name in [("#refresh", "Làm mới"), ("#open", "Mở Razer"), ("#move", "Chuyển ứng dụng")]:
            btn = await page.query_selector(sel)
            if btn:
                disabled = await btn.is_disabled()
                visible = await btn.is_visible()
                print(f"    {name}: {'disabled' if disabled else 'enabled'}, {'visible' if visible else 'HIDDEN'}")

        # Tab: storage
        await page.click('button[data-tab="storage"]')
        await asyncio.sleep(0.3)
        print("  Storage tab:")
        btn = await page.query_selector("#btn-rescan")
        if btn:
            disabled = await btn.is_disabled()
            print(f"    Quét lại bộ nhớ: {'disabled' if disabled else 'enabled'}")

        # Tab: stuck
        await page.click('button[data-tab="stuck"]')
        await asyncio.sleep(0.5)
        print("  Stuck tab:")
        btn = await page.query_selector("#stuck-refresh-btn")
        if btn:
            disabled = await btn.is_disabled()
            print(f"    Làm mới: {'disabled' if disabled else 'enabled'}")
        else:
            print(f"    stuck-refresh-btn: NOT FOUND")

        # Tab: uninstall
        await page.click('button[data-tab="uninstall"]')
        await asyncio.sleep(0.3)
        print("  Uninstall tab:")
        for sel, name in [("#uninstall-scan-btn", "Quét"), ("#do-uninstall-btn", "Gỡ ứng dụng"), ("#toggle-all", "Chọn tất cả")]:
            btn = await page.query_selector(sel)
            if btn:
                disabled = await btn.is_disabled()
                text = (await btn.inner_text()).strip()
                print(f"    {name} ({sel}): {'disabled' if disabled else 'enabled'}, text='{text}'")
            else:
                print(f"    {name} ({sel}): NOT FOUND")

        # Summary
        print("\n=== JS Errors ===")
        if errors:
            for e in errors:
                print(f"  {e}")
        else:
            print("  (none)")

        print(f"\n=== Summary ===")
        if broken_buttons:
            print(f"  BROKEN: {', '.join(broken_buttons)}")
        else:
            print("  All buttons found!")

        await browser.close()

asyncio.run(test())
