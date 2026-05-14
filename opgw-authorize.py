#!/usr/bin/env python3
"""
OPGW One-Click Authorize
Tkinter GUI tool that generates a signed JWT, sends an OAuth2 authorize
request via Python requests (NOT browser), captures the 302 redirect,
extracts the auth code, exchanges it for an access token, and opens the
Netlify redirect URL in the browser.

Key design: HTTP request uses minimal headers so TCP segment stays under
MSS (1460 bytes), allowing ZTE core network header enrichment to work.
"""

import random
import string
import time
import json
import re
import webbrowser
import urllib.parse
import tkinter as tk
from tkinter import ttk, messagebox

import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# ──────────────────────────────────────────────────────────────────────
# Hardcoded RSA private key
# ──────────────────────────────────────────────────────────────────────
PRIVATE_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC2kkx1lXHK1/cooE/YTm/KqVWB5UY/R0GmDoq3R3YsmYZEG0HXHR5+tk1qBukkDuY4d8n8GPce2gN08Bd21zlj9ZBJBrN2u6QyOrPHT80vhmh8NyzM7dJTyUmOLp/o1nRsbsOF3gQIOXKKxMR4oqJF0CMFSadcpBQrU8mFpkLqn+6kP4pcdnnxls2zDiaug4Z3XIB2EGP1dXu3T8Nf19Ve+qHCpdGqg4g/KlYsbj6V3MeIgRb3MvxyCDSH962O8zFGv3Eev1//chwoD8OhH0N5qZf6EuaOriOTY5WdDO7nEWpV4n06oOP39VHrr1ezeUe4LfAB8yI7QifqAuA2+7aZAgMBAAECggEABvp2k7P/ono4x0PBaYot+bgZPZrO4ZJOrxM1OCYyHShNGoNUM+24Aa3kLZ5QAQHUyOnDPbCSmYpJwYl/zBoT5n83YaMw7uPjNcxKnN6vABcKHV1aiAa7GFrERfwAPr0bvB1Lue0viETx3N4CiH3m5/Y5sHUNQZw/7RwJwuMFAcTEkaRasyVU3BFHwcrcmxnFY28eR0omLUtrJkqS6Di4L0R+c3ih/5Ohc39rnbkiD76jRHzeWp4RdI2LkaWTEdZKn66db5dHp3P6tU265HOzyQ4DwVjuMV6iXYMQ6IMambcNomK42gTRWR1j7TsGschubveg0jve4qatH3/SEClRUQKBgQDw6TAg7PHdRjccwgqNx21XT0Wt1z+2T9RRIEtBcZdmBT3tesQwi8yDk1FC7oL9dCXEduIJQ7+dfcYE2CwgEkmUCgyRHQ5O/jX7OLP7oaA6OIOmgjzSDPLIN5uQ6mJZ6mzGKAGeaCZX/PaEy9vh4rzku7Tvk66sQ5pNIJ0/khruLQKBgQDCAa9qTeR4jbkHL+c/lmpyEuIEWRL0oKnOvubz5lGP88dcf5HEQP0E9vmPzbvbj89vfEyzNUxTI17kCtY1wtWC35L6Wh6ygE0tyGCQfLou4yYQmcwcpti2zwOOMbG5YxQZ3RuBpXG4cUMqd7gUVxw5WhPZgh/2/LVD7ZR6UpJZnQKBgQCFM6nUyq4Adq5KTE+hjL68I6yXLgigOQtfv8dca/4V/pf7EoIfhWyS44VuyInMscegFUtta/QqlDxEuXHMWdAs9lF0euhKbOxT90osu3ToPA8upZwTV+11Hqn5Ol8e8CssdTpP564rwEZdronpH4Dpx4+HV9SgktBiDMJlP9d8EQKBgQCW7EaxFQ1idyX0oGBuSC5gta3cIgssAPx4mGwEWy0iJkv1+kvEd6YdwZ/dLfgxUwvVN8ZXN2Q73O1Jy+BejEYa/KBTX943kLX5osL0RAN2zEBlc6+krmsys5KZgLE4fgo6IJbwYWs5R+svU1kBgc60Ew4UDDWfp3G/+UejbS7qxQKBgD6aAClLoEy0eQHt8dPW5X7itfol3emcBNuHz7jp794Hu5ZiU2OEIVfQfpVpBA/uiPJA1LFIn8bp5mjO+sJjrSDep8aI2ckzJdlKyqjp9pZ9M/w+hH0KsuQ+4ay17OTJTbHLGBVgUh/FE5Dhf+7MsVeoqTzlhNzvL7C6aBp3ykpn
-----END PRIVATE KEY-----"""

# ──────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────
AUTHORIZE_URL = "https://opgwtest03-auth.u.com.my/api/oauth2/camc/authorize"
TOKEN_URL = "https://opgwtest03.u.com.my/api/oauth2/camc/token"
REDIRECT_URI = "https://opgw-bank.netlify.app/"
CLIENT_ID = "OPGWBank"
SCOPE = "openid dpv:FraudPreventionAndDetection number-verification:verify"
KID = "client-key-2025"
MAX_URL_LENGTH = 1400

# ──────────────────────────────────────────────────────────────────────
# Core Logic
# ──────────────────────────────────────────────────────────────────────

def generate_state():
    """Generate unique state: OPGWBank_<random6>_<unix_timestamp>"""
    rand = "".join(random.choices(string.ascii_uppercase + string.digits, k=6))
    ts = int(time.time())
    return f"OPGWBank_{rand}_{ts}"


def build_jwt(state):
    """Build and sign JWT with RS256 using the hardcoded private key."""
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend(),
    )

    # Subtract 60s to account for clock skew with authorization server
    now = int(time.time()) - 60
    payload = {
        "iss": "OPGWBank",
        "aud": AUTHORIZE_URL,
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "prompt": "none",
        "state": state,
        "iat": now,
        "exp": now + 86400,
    }

    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": KID,
    }

    token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
    return token, payload


def construct_url(jwt_token):
    """Build the full authorize URL. Returns (url, byte_length)."""
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "scope": SCOPE,
        "prompt": "none",
        "request": jwt_token,
    }
    query_string = urllib.parse.urlencode(params, safe="")
    full_url = f"{AUTHORIZE_URL}?{query_string}"
    return full_url, len(full_url.encode("utf-8"))


def send_authorize_request(full_url):
    """
    Send GET to authorize endpoint with minimal headers.
    Uses allow_redirects=False to capture the 302 ourselves.
    Returns the requests.Response object.
    """
    headers = {
        "Host": "opgwtest03-auth.u.com.my",
        "Connection": "close",
    }
    response = requests.get(
        full_url,
        headers=headers,
        allow_redirects=False,
        timeout=30,
    )
    return response


def extract_auth_code(location):
    """Parse the authorization code from the Location header URL."""
    if not location:
        return None

    # Try parsing the query string from the URL
    parsed = urllib.parse.urlparse(location)
    params = urllib.parse.parse_qs(parsed.query)
    code_list = params.get("code", [])
    if code_list:
        return code_list[0]

    # Fallback: regex
    m = re.search(r"[?&]code=([^&]+)", location)
    if m:
        return m.group(1)

    return None


def build_client_assertion():
    """Build client_assertion JWT for token exchange (RS256, kid=client-key-2025)."""
    private_key = serialization.load_pem_private_key(
        PRIVATE_KEY_PEM.encode(),
        password=None,
        backend=default_backend(),
    )
    now = int(time.time()) - 60
    jti = "".join(random.choices(string.ascii_uppercase + string.digits, k=16))
    payload = {
        "iss": "OPGWBank",
        "sub": "OPGWBank",
        "aud": TOKEN_URL,
        "iat": now,
        "exp": now + 300,
        "jti": jti,
    }
    headers = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": KID,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)


def exchange_code_for_token(code, client_assertion):
    """POST to token endpoint. Returns (access_token, response_json)."""
    params = {
        "grant_type": "authorization_code",
        "code": code,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "redirect_uri": REDIRECT_URI,
        "client_assertion": client_assertion,
    }
    response = requests.post(
        TOKEN_URL,
        data=params,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    data = response.json() if response.text else {}
    access_token = data.get("access_token", "")
    return access_token, data


# ──────────────────────────────────────────────────────────────────────
# Tkinter GUI
# ──────────────────────────────────────────────────────────────────────

# Dark theme colors
DARK_BG = "#1e1e2e"
DARKER_BG = "#181825"
SURFACE = "#313244"
TEXT = "#cdd6f4"
ACCENT = "#89b4fa"
ACCENT_HOVER = "#74c7ec"
SUCCESS = "#a6e3a1"
ERROR_COLOR = "#f38ba8"
WARN = "#fab387"
BORDER = "#45475a"
INPUT_BG = "#313244"
BUTTON_BG = "#45475a"
BUTTON_FG = "#cdd6f4"
BUTTON_ACCENT = "#89b4fa"


def copy_to_clipboard(widget, text):
    """Copy text to clipboard and briefly flash feedback."""
    widget.clipboard_clear()
    widget.clipboard_append(text)
    widget.update()


class OPGWAuthApp:
    def __init__(self, root):
        self.root = root
        self.root.title("OPGW One-Click Authorize")
        self.root.geometry("680x720")
        self.root.minsize(580, 600)
        self.root.configure(bg=DARK_BG)

        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TFrame", background=DARK_BG)
        style.configure("TLabel", background=DARK_BG, foreground=TEXT, font=("Segoe UI", 10))
        style.configure("TButton",
                        background=BUTTON_BG,
                        foreground=BUTTON_FG,
                        borderwidth=1,
                        font=("Segoe UI", 10, "bold"))
        style.map("TButton",
                  background=[("active", ACCENT_HOVER), ("pressed", ACCENT)],
                  foreground=[("active", "#1e1e2e")])
        style.configure("TEntry",
                        fieldbackground=INPUT_BG,
                        foreground=TEXT,
                        borderwidth=1,
                        relief="solid")
        style.configure("Accent.TButton",
                        background=ACCENT,
                        foreground="#1e1e2e",
                        font=("Segoe UI", 11, "bold"))
        style.map("Accent.TButton",
                  background=[("active", "#b4d0ff"), ("pressed", "#74c7ec")])

        self.built_url = ""
        self.auth_code = ""
        self.current_state = ""
        self.access_token = ""
        self.client_assertion_jwt = ""

        self._build_ui()

    def _build_ui(self):
        # ─────────────── Main container ───────────────
        main = ttk.Frame(self.root, padding=20)
        main.pack(fill=tk.BOTH, expand=True)

        # ─────────────── Title ───────────────
        title_frame = ttk.Frame(main)
        title_frame.pack(fill=tk.X, pady=(0, 15))

        title = tk.Label(
            title_frame,
            text="OPGW One-Click Authorize",
            font=("Segoe UI", 18, "bold"),
            bg=DARK_BG,
            fg=ACCENT,
        )
        title.pack(anchor="w")

        subtitle = tk.Label(
            title_frame,
            text="Signed JWT → Authorize → Capture 302 → Extract Code → Exchange Token → Open Netlify",
            font=("Segoe UI", 9),
            bg=DARK_BG,
            fg="#6c7086",
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        # ─────────────── Status area ───────────────
        status_frame = ttk.Frame(main)
        status_frame.pack(fill=tk.X, pady=(0, 12))

        tk.Label(
            status_frame,
            text="Status:",
            font=("Segoe UI", 10, "bold"),
            bg=DARK_BG,
            fg=TEXT,
        ).pack(anchor="w")

        self.status_text = tk.Text(
            status_frame,
            height=5,
            width=78,
            bg=DARKER_BG,
            fg=SUCCESS,
            font=("Consolas", 10),
            relief="flat",
            borderwidth=4,
            padx=8,
            pady=6,
            wrap=tk.WORD,
            state=tk.DISABLED,
        )
        self.status_text.pack(fill=tk.X, pady=(4, 0))

        # ─────────────── Authorize button ───────────────
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(0, 12))

        self.auth_btn = tk.Button(
            btn_frame,
            text="AUTHORIZE",
            font=("Segoe UI", 13, "bold"),
            bg=ACCENT,
            fg="#1e1e2e",
            activebackground="#b4d0ff",
            activeforeground="#1e1e2e",
            relief="flat",
            borderwidth=0,
            padx=30,
            pady=10,
            cursor="hand2",
            command=self.run_authorize,
        )
        self.auth_btn.pack(fill=tk.X)

        # ─────────────── Separator ───────────────
        sep = tk.Frame(main, height=1, bg=BORDER)
        sep.pack(fill=tk.X, pady=(4, 12))

        # ─────────────── Outputs ───────────────
        outputs_label = tk.Label(
            main,
            text="Outputs",
            font=("Segoe UI", 11, "bold"),
            bg=DARK_BG,
            fg=TEXT,
        )
        outputs_label.pack(anchor="w", pady=(0, 8))

        # State
        self._add_output_row(main, "State:", "state")
        # URL (scrollable)
        self._add_output_row(main, "URL:", "url", scrollable=True)
        # Auth Code
        self._add_output_row(main, "Auth Code:", "code")
        # Access Token (scrollable — can be long)
        self._add_output_row(main, "Access Token:", "token", scrollable=True)

        # ─────────────── Footer ───────────────
        footer = tk.Label(
            main,
            text="Built for ZTE header enrichment — HTTP request via Python, not browser.",
            font=("Segoe UI", 8),
            bg=DARK_BG,
            fg="#585b70",
        )
        footer.pack(side=tk.BOTTOM, pady=(10, 0))

    def _add_output_row(self, parent, label_text, key, scrollable=False):
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.X, pady=(0, 8))

        lbl = tk.Label(
            frame,
            text=label_text,
            font=("Segoe UI", 10, "bold"),
            bg=DARK_BG,
            fg=TEXT,
            width=12,
            anchor="w",
        )
        lbl.pack(side=tk.LEFT, anchor="n")

        right = ttk.Frame(frame)
        right.pack(side=tk.LEFT, fill=tk.X, expand=True)

        if scrollable:
            # Scrollable text for URL
            text_widget = tk.Text(
                right,
                height=3,
                width=54,
                bg=DARKER_BG,
                fg=TEXT,
                font=("Consolas", 9),
                relief="flat",
                borderwidth=3,
                padx=6,
                pady=4,
                wrap=tk.WORD,
                state=tk.DISABLED,
            )
            scrollbar = tk.Scrollbar(right, command=text_widget.yview, bg=DARKER_BG)
            text_widget.configure(yscrollcommand=scrollbar.set)
            text_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            setattr(self, f"text_{key}", text_widget)
        else:
            # Single-line entry
            var = tk.StringVar()
            entry = tk.Entry(
                right,
                textvariable=var,
                font=("Consolas", 10),
                bg=DARKER_BG,
                fg=TEXT,
                relief="flat",
                borderwidth=3,
                insertbackground=TEXT,
                state="readonly",
                readonlybackground=DARKER_BG,
            )
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
            setattr(self, f"var_{key}", var)
            setattr(self, f"entry_{key}", entry)

        # Copy button
        copy_btn = tk.Button(
            right,
            text="Copy",
            font=("Segoe UI", 8),
            bg=SURFACE,
            fg=TEXT,
            activebackground=ACCENT_HOVER,
            activeforeground="#1e1e2e",
            relief="flat",
            borderwidth=0,
            padx=10,
            pady=2,
            cursor="hand2",
        )
        copy_btn.pack(side=tk.RIGHT, padx=(6, 0))
        copy_btn.configure(command=lambda w=right, k=key: self._copy_output(k))

    def _copy_output(self, key):
        if key == "state":
            text = self.current_state
        elif key == "url":
            text = self.built_url
        elif key == "code":
            text = self.auth_code
        elif key == "token":
            text = self.access_token
        else:
            return
        if text:
            copy_to_clipboard(self.root, text)
            self._append_status("  (copied to clipboard)")

    def _append_status(self, msg, tag=None):
        self.status_text.configure(state=tk.NORMAL)
        ts = time.strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{ts}] {msg}\n")
        self.status_text.see(tk.END)
        self.status_text.configure(state=tk.DISABLED)
        self.root.update_idletasks()

    def _set_output(self, key, value):
        if key == "state":
            self.current_state = value
            entry = self.entry_state
        elif key == "url":
            self.built_url = value
        elif key == "code":
            self.auth_code = value
            entry = self.entry_code
        elif key == "token":
            self.access_token = value
        else:
            return

        if key in ("state", "code"):
            entry.configure(state=tk.NORMAL)
            getattr(self, f"var_{key}").set(value)
            entry.configure(state="readonly")
        elif key in ("url", "token"):
            text_widget = getattr(self, f"text_{key}")
            text_widget.configure(state=tk.NORMAL)
            text_widget.delete("1.0", tk.END)
            text_widget.insert("1.0", value)
            text_widget.configure(state=tk.DISABLED)

    def _clear_outputs(self):
        self._set_output("state", "")
        self._set_output("url", "")
        self._set_output("code", "")
        self._set_output("token", "")

    # ─────────────── Main flow ───────────────

    def run_authorize(self):
        """The one-click authorize flow."""
        self.auth_btn.configure(state=tk.DISABLED, bg=SURFACE, fg="#6c7086")
        self.status_text.configure(state=tk.NORMAL)
        self.status_text.delete("1.0", tk.END)
        self.status_text.configure(state=tk.DISABLED)
        self._clear_outputs()

        try:
            self._do_authorize()
        except Exception as e:
            self._append_status(f"ERROR: {e}", "error")
            messagebox.showerror("Authorization Failed", str(e))
        finally:
            self.auth_btn.configure(
                state=tk.NORMAL,
                bg=ACCENT,
                fg="#1e1e2e",
            )

    def _do_authorize(self):
        # Step 1: Generate state
        self._append_status("Step 1/6: Generating state...")
        state = generate_state()
        self._set_output("state", state)
        self._append_status(f"  State: {state}")

        # Step 2: Build and sign JWT
        self._append_status("Step 2/6: Building & signing JWT (RS256)...")
        jwt_token, payload = build_jwt(state)
        self._append_status(f"  JWT header: alg=RS256, kid={KID}")
        self._append_status(f"  JWT payload: iss={payload['iss']}, iat={payload['iat']}, exp={payload['exp']}")

        # Step 3: Construct URL
        self._append_status("Step 3/6: Constructing authorize URL...")
        full_url, url_bytes = construct_url(jwt_token)
        self._set_output("url", full_url)
        self._append_status(f"  URL length: {url_bytes} bytes")
        if url_bytes >= MAX_URL_LENGTH:
            self._append_status(f"  WARNING: URL exceeds {MAX_URL_LENGTH} bytes! May cause TCP fragmentation.", "warn")
        elif url_bytes >= 1300:
            self._append_status(f"  CAUTION: URL approaching {MAX_URL_LENGTH} byte limit.")
        else:
            self._append_status(f"  URL within safe limit ✓")

        # Step 4: Send authorize request
        self._append_status("Step 4/6: Sending authorize request via Python HTTP...")
        self._append_status("  Using minimal headers: Host + Connection: close only")
        self._append_status("  allow_redirects=False (capture 302 ourselves)")
        response = send_authorize_request(full_url)
        self._append_status(f"  Response: {response.status_code} {response.reason}")

        # Step 5: Handle response
        self._append_status("Step 5/6: Processing response...")
        if response.status_code in (301, 302, 303, 307, 308):
            location = response.headers.get("Location", "")
            self._append_status(f"  Redirect Location: {location[:120]}...")

            code = extract_auth_code(location)
            if code:
                self._set_output("code", code)
                self._append_status(f"  Auth code extracted: {code}")

                # Step 6: Exchange code for access token
                self._append_status("Step 6/6: Exchanging auth code for access token...")
                client_assertion = build_client_assertion()
                self.client_assertion_jwt = client_assertion
                self._append_status(f"  Client assertion JWT generated ({len(client_assertion)} chars)")
                access_token, token_data = exchange_code_for_token(code, client_assertion)
                if access_token:
                    self._set_output("token", access_token)
                    self._append_status(f"  Access token obtained: {access_token[:40]}...")
                    self._append_status("  Opening Netlify page in browser...")
                    webbrowser.open(location)
                    self._append_status("DONE. Token acquired + browser opened. ✓")
                else:
                    self._append_status(f"  WARNING: No access_token in response")
                    self._append_status(f"  Token response: {json.dumps(token_data)[:300]}")
                    self._append_status("  Opening Netlify page anyway...")
                    webbrowser.open(location)
                    self._append_status("DONE (no token). Browser opened to Netlify. ✓")
            else:
                self._append_status("  ERROR: Could not extract auth code from Location header!")
                self._append_status(f"  Full Location: {location}")
                messagebox.showerror(
                    "No Auth Code",
                    "Received 302 but could not find 'code' parameter in the redirect URL.\n\n"
                    f"Location: {location[:300]}",
                )
        elif response.status_code == 200:
            self._append_status("  Got 200 instead of 302 — no redirect received.")
            body = response.text[:500]
            self._append_status(f"  Response body: {body}")
            messagebox.showerror(
                "Unexpected 200",
                "Expected 302 redirect, got 200 OK.\n"
                "The authorization server may have returned an error page.\n\n"
                f"First 500 chars of body:\n{body}",
            )
        else:
            body = response.text[:300]
            self._append_status(f"  Unexpected response: {response.status_code}")
            self._append_status(f"  Body: {body}")
            messagebox.showerror(
                f"HTTP {response.status_code}",
                f"Unexpected response from authorization server: {response.status_code}\n\n{body}",
            )


def main():
    root = tk.Tk()
    # Try to set icon if available
    try:
        root.iconbitmap(default="")
    except Exception:
        pass
    app = OPGWAuthApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
