# OPGW One-Click Authorize - Implementation Plan

## Goal
Build a Python Tkinter GUI tool that generates a signed JWT, sends the authorize request via Python HTTP (NOT browser), captures the 302 redirect to extract auth code, then opens the Netlify redirect URL in the system browser.

## Why Python HTTP instead of browser
- Browser adds ~600B of auto headers (User-Agent, Accept-*, Sec-Fetch-*, etc.)
- URL (1061B) + Browser headers (600B) + TLS (40B) = ~1700B > MSS (1460B)
- Exceeding MSS causes TCP fragmentation -> ZTE core network cannot inject header enrichment
- Python requests with minimal headers: URL (1061B) + Host (35B) + Connection (20B) + TLS (40B) ≈ 1156B < MSS ✓

## Architecture

```
GUI (Tkinter)  
  └─ [Authorize] button
       ├─ Generate random state
       ├─ Build JWT payload + sign with RSA private key
       ├─ Construct full authorize URL (check <1400 bytes)
       ├─ Send GET via requests with minimal headers (allow_redirects=False)
       ├─ Receive 302, extract Location header
       ├─ Parse auth code from Location
       └─ webbrowser.open() -> Netlify page (existing workflow takes over)
```

## JWT Payload Structure

| Field          | Value                                                        | Source       |
|----------------|--------------------------------------------------------------|--------------|
| iss            | OPGWBank                                                      | Static       |
| aud            | https://opgwtest03-auth.u.com.my/api/oauth2/camc/authorize   | Static       |
| response_type  | code                                                          | Static       |
| client_id      | OPGWBank                                                      | Static       |
| redirect_uri   | https://opgw-bank.netlify.app/                               | Static       |
| scope          | openid dpv:FraudPreventionAndDetection number-verification:verify | Static  |
| prompt         | none                                                          | Static       |
| state          | OPGWBank_<random6>_<timestamp>                               | **Generated** |
| iat            | current Unix timestamp                                        | **Generated** |
| exp            | iat + 86400 (24h)                                            | **Generated** |

- Algorithm: RS256
- Key ID (kid): client-key-2025
- Private key: hardcoded in script

## State Generation

```python
state = f"OPGWBank_{random_string(6)}_{int(time.time())}"
```
- `random_string(6)`: uppercase letters + digits
- `timestamp`: Unix timestamp
- Guarantees uniqueness across all invocations

## Minimal HTTP Headers

```python
headers = {
    "Host": "opgwtest03-auth.u.com.my",
    "Connection": "close"
}
```

## Files

Single file: `/mnt/c/Users/shaun/OneDrive/Desktop/OPGWBank/opgw-authorize.py`

## Dependencies

```bash
pip install PyJWT cryptography requests tkinter
```
(tkinter is usually built-in)

## Tasks

### Task 1: Developer - Write opgw-authorize.py (core logic)
- RSA private key in PEM format (hardcoded)
- `generate_state()` function
- `build_jwt()` function using PyJWT + cryptography
- `construct_url()` function (validate <1400 bytes)
- `send_authorize_request()` function (requests.get, allow_redirects=False)
- `extract_auth_code()` function (parse Location header)
- `main_gui()` placeholder (terminal-diag mode first)

### Task 2: Developer - Write full Tkinter GUI
- Modern dark theme
- Phone number input (for reference)
- [Authorize] button
- Status area: shows step-by-step progress
- Output area: shows generated state, JWT (truncated), URL, auth code
- Copy buttons for state/URL/code
- Error display area

### Task 3: Designer - Design the Tkinter GUI layout
- Make it professional, OPGW branded
- Follow user's preferred style: dark theme, clean interface
- Layout: simple single-column, not over-complex
- Wireframe / mockup to developer

### Task 4: Tester - Test on phone hotspot
- Connect to mobile hotspot
- Verify JWT generation is valid (decode + verify signature)
- Verify URL < 1400 bytes
- Click Authorize, confirm 302 received
- Confirm auth code extracted correctly
- Confirm browser opens to Netlify page with code
- Confirm existing OPGW Bank workflow continues from there

## Success Criteria
1. JWT is valid RS256 signed with the correct private key
2. Full authorize URL < 1400 bytes (verified programmatically)
3. Python requests send succeeds (no TCP fragmentation)
4. 302 response received with Location header
5. Auth code extracted from Location
6. Browser opens to Netlify page with auth code
7. User can proceed with existing OPGW Bank workflow
