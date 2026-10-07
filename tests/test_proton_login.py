import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from selenium.common.exceptions import TimeoutException
from selenium.webdriver.common.by import By

import proton_login as module


class Element:
    def __init__(self, driver, kind, displayed=True, enabled=True, text=""):
        self.driver, self.kind = driver, kind
        self.displayed, self.enabled, self.text = displayed, enabled, text

    def is_displayed(self):
        return self.displayed

    def is_enabled(self):
        return self.enabled

    def click(self):
        if self.kind == "submit":
            self.driver.submissions.append(dict(self.driver.values))
            if self.driver.stage == "username":
                self.driver.stage = "password"
            elif self.driver.stage == "otp":
                self.driver.stage = "otp_wait"
            else:
                self.driver.stage = "password_wait"
            self.driver.ticks = 0

    def clear(self):
        self.driver.values[self.kind] = ""

    def send_keys(self, value):
        self.driver.values[self.kind] = self.driver.values.get(self.kind, "") + value

    def find_element(self, *args):
        return self.driver  # The form scope uses the same fake element inventory.


class Driver:
    def __init__(self, combined=True, outcome="authenticated", keep_login_url=False):
        self.initial = "combined" if combined else "username"
        self.stage = self.initial
        self.outcome, self.keep_login_url = outcome, keep_login_url
        self.current_url = "https://account.protonvpn.com/login"
        self.values, self.submissions, self.waits = {}, [], []
        self.ticks = 0
        self.max_pending_ticks = 0

    def get(self, url):
        self.current_url = url
        self.stage = self.initial

    def implicitly_wait(self, value):
        self.waits.append(value)

    def tick(self):
        if self.stage in {"password_wait", "otp_wait", "no_nav"}:
            self.ticks += 1
            self.max_pending_ticks = max(self.max_pending_ticks, self.ticks)
            if self.ticks >= 12 and self.stage != "no_nav":
                self.stage = self.outcome if self.stage == "password_wait" else "authenticated"
                if self.stage in {"authenticated", "no_nav"} and not self.keep_login_url:
                    self.current_url = "https://account.protonvpn.com/dashboard"

    def find_elements(self, by, selector):
        if by == By.TAG_NAME:
            text = "Verify you are human" if self.stage == "challenge" else ""
            return [Element(self, "body", text=text)]
        if selector == module.USERNAME:
            return [Element(self, "username")] if self.stage in {"username", "combined", "password_wait"} else []
        if selector == module.PASSWORD:
            # Hidden fields must not force the combined-form path.
            if self.stage == "username":
                return [Element(self, "password", displayed=False)]
            return [Element(self, "password")] if self.stage in {"password", "combined", "password_wait"} else []
        if selector == module.OTP:
            return [Element(self, "otp")] if self.stage in {"otp", "otp_wait"} else []
        if selector == module.ACCOUNT_NAV:
            return [Element(self, "nav")] if self.stage == "authenticated" else []
        if selector == module.ERRORS:
            return ([Element(self, "error", text="Incorrect password: PRIVATE-PASSWORD")]
                    if self.stage == "error" else [])
        if selector == module.SUBMIT:
            return [Element(self, "submit", displayed=False), Element(self, "submit", enabled=False), Element(self, "submit")]
        return []


class Wait:
    """Simulate repeated Selenium polling without real browser waits."""
    def __init__(self, driver, timeout, **kwargs):
        self.driver = driver

    def until(self, predicate):
        for _ in range(30):
            result = predicate(self.driver)
            if result:
                return result
            self.driver.tick()
        raise TimeoutException()


class Client(module.ProtonLoginMixin):
    def __init__(self, driver):
        self.driver = driver


class LoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.previous_dir = os.getcwd()
        os.chdir(self.temp.name)
        self.addCleanup(os.chdir, self.previous_dir)
        self.env = patch.dict(os.environ, {"LOGIN_TIMEOUT_SECONDS": "120", "VPN_TOTP_SECRET": ""})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.wait = patch.object(module, "WebDriverWait", Wait)
        self.wait.start()
        self.addCleanup(self.wait.stop)

    def run_login(self, driver):
        client = Client(driver)
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            result = client.login("PRIVATE-USERNAME", "PRIVATE-PASSWORD")
        self.assertNotIn("PRIVATE-USERNAME", stream.getvalue())
        self.assertNotIn("PRIVATE-PASSWORD", stream.getvalue())
        self.assertEqual(driver.waits, [0, 10])
        return client, result

    def test_combined_form_submits_only_after_both_fields_are_filled(self):
        driver = Driver()
        _, result = self.run_login(driver)
        self.assertTrue(result)
        self.assertEqual(driver.submissions, [{"username": "PRIVATE-USERNAME", "password": "PRIVATE-PASSWORD"}])

    def test_two_step_form_skips_hidden_password_and_submits_twice(self):
        driver = Driver(combined=False)
        _, result = self.run_login(driver)
        self.assertTrue(result)
        self.assertEqual(len(driver.submissions), 2)
        self.assertNotIn("password", driver.submissions[0])
        self.assertEqual(driver.submissions[1]["password"], "PRIVATE-PASSWORD")

    def test_slow_login_is_polled_until_authenticated(self):
        driver = Driver()
        _, result = self.run_login(driver)
        self.assertTrue(result)
        self.assertGreater(driver.max_pending_ticks, 6)  # More than the old 3s at 0.5s per poll.

    def test_authenticated_navigation_can_succeed_with_login_still_in_url(self):
        driver = Driver(keep_login_url=True)
        _, result = self.run_login(driver)
        self.assertTrue(result)
        self.assertIn("/login", driver.current_url)

    def test_url_change_without_account_navigation_is_not_success(self):
        driver = Driver(outcome="no_nav")
        driver.keep_login_url = False
        client, result = self.run_login(driver)
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "login_timeout")

    def test_rejected_credentials_do_not_retry_or_publish_secrets(self):
        driver = Driver(outcome="error")
        client, result = self.run_login(driver)
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "credentials_rejected")
        self.assertEqual(len(driver.submissions), 1)
        report = Path("debug/login-status.json").read_text()
        self.assertNotIn("PRIVATE", report)
        self.assertNotIn("page.html", report)
        self.assertEqual(json.loads(report)["failure_code"], "credentials_rejected")

    def test_human_verification_returns_actionable_failure(self):
        client, result = self.run_login(Driver(outcome="challenge"))
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "human_verification")

    def test_two_factor_requires_setup_key(self):
        client, result = self.run_login(Driver(outcome="otp"))
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "totp_required")

    def test_two_factor_submission_waits_for_authenticated_navigation(self):
        driver = Driver(outcome="otp")
        with patch.object(Client, "_totp_code", return_value="654321"):
            _, result = self.run_login(driver)
        self.assertTrue(result)
        self.assertEqual(driver.submissions[-1]["otp"], "654321")

    def test_invalid_totp_setup_key_is_not_exposed(self):
        os.environ["VPN_TOTP_SECRET"] = "INVALID-PRIVATE-SETUP-KEY"
        client, result = self.run_login(Driver(outcome="otp"))
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "invalid_totp_secret")
        self.assertNotIn("PRIVATE", Path("debug/login-status.json").read_text())

    def test_totp_setup_key_generates_known_rfc_code(self):
        os.environ["VPN_TOTP_SECRET"] = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        with patch.object(module.pyotp.TOTP, "now", lambda generator: generator.at(59)), \
                patch.object(module.time, "time", return_value=45):
            self.assertEqual(Client(Driver())._totp_code(), "287082")

    def test_untrusted_origin_is_rejected_before_sending_credentials(self):
        driver = Driver()
        driver.get = lambda _: setattr(driver, "current_url", "https://example.com/login")
        client, result = self.run_login(driver)
        self.assertFalse(result)
        self.assertEqual(client.last_login_failure, "unexpected_origin")
        self.assertEqual(driver.values, {})


if __name__ == "__main__":
    unittest.main()
