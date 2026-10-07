"""Explicitly wait for Proton's single-page login flow without logging secrets."""

import json
import os
from pathlib import Path
import time
from urllib.parse import urlsplit

import pyotp
from selenium.common.exceptions import StaleElementReferenceException, TimeoutException, WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait


USERNAME = 'input#username, input[name="username"], input[autocomplete="username"]'
PASSWORD = 'input#password, input[name="password"], input[autocomplete="current-password"]'
OTP = 'input#twoFa, input#otp, input[name="twoFa"], input[name="otp"], input[autocomplete="one-time-code"]'
ERRORS = '[role="alert"], .text-danger, .error-message, .notification--error, .field-error'
SUBMIT = 'button[type="submit"], input[type="submit"]'
ACCOUNT_NAV = 'a[href*="/downloads"], a[href*="/dashboard"], a[href="/logout"], button[data-testid="user-dropdown:button"]'
VERIFICATION_UI = '[role="dialog"], dialog[open], h1, h2, h3'
VERIFICATION_FRAME = 'iframe[src*="verify.proton.me"], iframe[title*="captcha"], iframe[title*="CAPTCHA"]'
TRUSTED_HOSTS = {"account.protonvpn.com", "account.proton.me"}


class LoginFailure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class ProtonLoginMixin:
    def _human_verification_visible(self, body_text):
        phrases = ("verify you are human", "human verification", "complete the captcha")
        for element in self.driver.find_elements(By.CSS_SELECTOR, VERIFICATION_UI):
            if element.is_displayed() and any(p in element.text.lower() for p in phrases):
                return True
        # Do not interpret a help/footer mention of "human verification" as
        # a blocking challenge. The fallback requires an explicit instruction.
        return any(p in body_text for p in ("verify you are human", "complete the captcha"))

    def _visible(self, selector, scope=None, enabled=False):
        for element in (scope or self.driver).find_elements(By.CSS_SELECTOR, selector):
            try:
                if element.is_displayed() and (not enabled or element.is_enabled()):
                    return element
            except StaleElementReferenceException:
                continue
        return None

    def _assert_login_origin(self):
        location = urlsplit(self.driver.current_url)
        if location.scheme != "https" or location.hostname not in TRUSTED_HOSTS:
            raise LoginFailure("unexpected_origin", "Unexpected login origin; credentials were not submitted.")

    def _fill_login_field(self, element, value):
        self._assert_login_origin()
        element.click()
        element.clear()
        element.send_keys(value)

    def _submit_login_form(self, field):
        self._assert_login_origin()
        try:
            scope = field.find_element(By.XPATH, "./ancestor::form[1]")
        except WebDriverException:
            scope = self.driver
        button = WebDriverWait(self.driver, self._login_timeout).until(
            lambda _: self._visible(SUBMIT, scope=scope, enabled=True)
        )
        button.click()

    def _login_state(self):
        self._assert_login_origin()
        user = self._visible(USERNAME)
        password = self._visible(PASSWORD)
        otp = self._visible(OTP)
        # A changed URL alone is not proof of authentication: challenges can
        # redirect too, and the SPA can leave /login in the URL while updating.
        bodies = self.driver.find_elements(By.TAG_NAME, "body")
        text = bodies[0].text.lower() if bodies else ""
        if self._human_verification_visible(text):
            return "challenge", LoginFailure("human_verification", "Proton's human-verification prompt is still present. Complete it in a local headed browser, or use a runner where normal sign-in succeeds. The script does not solve interactive CAPTCHA challenges.")
        if any(phrase in text for phrase in ("code sent to your email", "check your email for", "verification email")):
            return "challenge", LoginFailure("email_verification", "Proton requires email verification, which this unattended login cannot complete.")

        error = self._visible(ERRORS)
        if error and error.text.strip():
            message = error.text.lower()
            if any(part in message for part in ("too many", "rate limit", "try again later")):
                failure = LoginFailure("rate_limited", "Proton limited login attempts. Wait before rerunning the workflow.")
            elif any(part in message for part in ("incorrect", "invalid", "wrong")):
                failure = LoginFailure("credentials_rejected", "Proton rejected a credential or verification code. Check VPN_USERNAME and VPN_PASSWORD (Proton Account credentials), and VPN_TOTP_SECRET if used.")
            else:
                failure = LoginFailure("form_error", "The login form reported an error. Check account sign-in and the repository secrets.")
            return "error", failure
        if otp:
            return "otp", otp
        if any(phrase in text for phrase in ("touch your security key", "insert your security key", "use your security key")) and not password:
            return "challenge", LoginFailure("security_key", "Proton requires a security key interaction that an unattended runner cannot perform.")
        if not user and not password and not otp and self._visible(ACCOUNT_NAV):
            return "authenticated", None
        if password:
            return "password", password
        if user:
            return "username", user
        return "pending", None

    def _wait_login_state(self, accepted):
        verification_started = None
        active_verification = None
        def poll(_):
            nonlocal verification_started, active_verification
            state = self._login_state()
            if state[0] == "challenge" and state[1].code == "human_verification":
                active_verification = state[1]
                if verification_started is None:
                    verification_started = time.monotonic()
                    print(f"Human verification is visible. Waiting up to {self._verification_timeout}s for it to complete; in a headed local browser, complete the prompt yourself.")
                if time.monotonic() - verification_started >= self._verification_timeout:
                    raise active_verification
                return False
            verification_started = None
            active_verification = None
            return state if state[0] in accepted | {"error", "challenge"} else False
        try:
            state, detail = WebDriverWait(
                self.driver, max(self._login_timeout, self._verification_timeout), poll_frequency=0.5,
                ignored_exceptions=(StaleElementReferenceException,),
            ).until(poll)
        except TimeoutException:
            if active_verification is not None:
                raise active_verification from None
            raise
        if state in {"error", "challenge"}:
            raise detail
        return state, detail

    def _totp_code(self):
        secret = os.environ.get("VPN_TOTP_SECRET", "").strip().replace(" ", "")
        if not secret:
            raise LoginFailure("totp_required", "Two-factor authentication is required. Add VPN_TOTP_SECRET as a repository secret containing your authenticator setup key, not a six-digit code.")
        try:
            generator = pyotp.parse_uri(secret) if secret.startswith("otpauth://") else pyotp.TOTP(secret)
            if not isinstance(generator, pyotp.TOTP):
                raise ValueError("Expected TOTP")
            # Do not submit a code that is about to expire.
            remaining = generator.interval - time.time() % generator.interval
            if remaining < 5:
                time.sleep(remaining + 0.2)
            return generator.now()
        except Exception:
            raise LoginFailure("invalid_totp_secret", "VPN_TOTP_SECRET must be the authenticator setup key or a TOTP otpauth URI.") from None

    def _save_login_diagnostics(self, code):
        # Only status flags are persisted: no DOM, screenshots, field values,
        # cookies, URL query strings, usernames, passwords, or OTPs.
        report = {"failure_code": code, "timeout_seconds": self._login_timeout,
                  "verification_timeout_seconds": self._verification_timeout,
                  "headless": os.environ.get("PROTON_HEADLESS", "true").lower() != "false"}
        try:
            report.update({
                "username_field_visible": self._visible(USERNAME) is not None,
                "password_field_visible": self._visible(PASSWORD) is not None,
                "otp_field_visible": self._visible(OTP) is not None,
                "alert_visible": self._visible(ERRORS) is not None,
                "verification_frame_visible": self._visible(VERIFICATION_FRAME) is not None,
            })
            target = Path("debug/login-status.json")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print("Sanitized login status saved to debug/login-status.json.")
        except Exception:
            print("Could not save sanitized login status.")

    def login(self, username, password):
        self._login_timeout = 120
        self._verification_timeout = 60
        self.last_login_failure = None
        try:
            self._login_timeout = int(os.environ.get("LOGIN_TIMEOUT_SECONDS", "120"))
            self._verification_timeout = int(os.environ.get("HUMAN_VERIFICATION_TIMEOUT_SECONDS", "60"))
            if not 30 <= self._login_timeout <= 600:
                raise ValueError
            if not 5 <= self._verification_timeout <= 600:
                raise ValueError
        except ValueError:
            self.last_login_failure = "invalid_timeout"
            print("LOGIN_TIMEOUT_SECONDS must be between 30 and 600; HUMAN_VERIFICATION_TIMEOUT_SECONDS must be between 5 and 600 (integer seconds).")
            return False
        try:
            if not username or not username.strip() or not password:
                raise LoginFailure("missing_credentials", "Set VPN_USERNAME and VPN_PASSWORD to your Proton Account credentials.")
            # Avoid multiplying every explicit wait by the 10-second implicit
            # wait used elsewhere in the original downloader.
            self.driver.implicitly_wait(0)
            self.driver.get("https://account.protonvpn.com/login?language=en")
            self._wait_login_state({"username", "password"})
            user = WebDriverWait(self.driver, self._login_timeout).until(lambda _: self._visible(USERNAME, enabled=True))
            self._fill_login_field(user, username.strip())
            password_field = self._visible(PASSWORD)
            if password_field is None:
                # Submit a username-only form only when a password field is
                # absent. Combined forms must be filled before any submission.
                self._submit_login_form(user)
                state, password_field = self._wait_login_state({"password", "authenticated"})
                if state == "authenticated":
                    print("Login successful.")
                    return True
            password_field = WebDriverWait(self.driver, self._login_timeout).until(
                lambda _: self._visible(PASSWORD, enabled=True)
            )
            self._fill_login_field(password_field, password)
            print(f"Submitting credentials; waiting up to {self._login_timeout}s for authentication.")
            self._submit_login_form(password_field)
            state, detail = self._wait_login_state({"authenticated", "otp"})
            if state == "otp":
                self._fill_login_field(detail, self._totp_code())
                self._submit_login_form(detail)
                self._wait_login_state({"authenticated"})
            print("Login successful.")
            return True
        except LoginFailure as exc:
            self.last_login_failure = exc.code
            print(f"Login failed ({exc.code}): {exc}")
        except TimeoutException:
            self.last_login_failure = "login_timeout"
            print(f"Login timed out after waiting up to {self._login_timeout}s per stage. No authenticated page was detected. Check Proton Account credentials and whether this runner receives a verification challenge.")
        except WebDriverException:
            self.last_login_failure = "browser_error"
            print("Login failed (browser_error): the browser could not complete the login form interaction.")
        finally:
            try:
                self.driver.implicitly_wait(10)
            except WebDriverException:
                pass
        self._save_login_diagnostics(self.last_login_failure)
        return False
