# Secure Login/Register System (Pure Lua + Go Helpers)

## Overview
A modern authentication system built in pure Lua (no frameworks) with Go helpers for cryptography, email, QR code, and reCAPTCHA. Designed for maximum security, transparency, and extensibility.

---

## Key Security Features

- **Strong Password Policies**: Enforced on both client and server. Passwords must be complex and are checked against the HaveIBeenPwned database to block breached credentials.
- **Argon2id Password Hashing**: All passwords are hashed using Argon2id (via Go helper) with unique salts per user.
- **Multi-Factor Authentication (MFA)**: TOTP-based MFA with QR code setup, enforced on login and high-risk events. Account lockout after repeated failed MFA attempts.
- **MFA Recovery Codes**: One-time use codes generated at setup, allowing account recovery if authenticator is lost.
- **CAPTCHA & reCAPTCHA**: Google reCAPTCHA v3 and a server-side math CAPTCHA to block bots and credential stuffing.
- **Rate Limiting**: Per-IP and per-user rate limiting for login and registration to prevent brute-force attacks.
- **Session Management**: Secure, random session tokens stored in HttpOnly, Secure, SameSite cookies. Sessions are invalidated on logout and account deletion.
- **CSRF Protection**: All state-changing endpoints require a CSRF token (cookie + form/header).
- **Security Headers**: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy set on all responses.
- **HTTPS Enforcement**: HTTP requests are redirected to HTTPS. All cookies are Secure.
- **Email Verification**: Time-limited, single-use verification links sent on registration.
- **Password Reset**: Secure, time-limited reset links sent via email. Password reset requires strong new password and (if enabled) MFA.
- **Input Validation & Sanitization**: All user input is validated and sanitized on both client and server.
- **Behavioral Biometrics & Adaptive Authentication**: Typing rhythm and mouse movement are analyzed on login; unusual patterns always require MFA.
- **Tamper-Evident Audit Logging**: (Planned) All authentication events, lockouts, and admin actions will be logged in a tamper-evident way.

---

## Additional Features

- **Password Strength Meter**: Real-time feedback using zxcvbn.js on registration.
- **Account Lockout**: After 5 failed MFA attempts, account is locked for 1 hour.
- **Fallback to Recovery Codes**: Users can use a recovery code if they lose access to their authenticator app.
- **No Frameworks**: All logic is pure Lua, with Go used only for cryptography, email, QR, and reCAPTCHA.
- **Modular Design**: All features are modular and can be extended or replaced as needed.
- **Environment-Based Secrets**: All sensitive keys and credentials are loaded from environment variables (see `.env`).
- **Minimal Dependencies**: Only LuaSocket, dkjson, and Go standard libraries are required.

---

## Project Structure

- `server.lua` — Main Lua HTTP server
- `lua_server/` — Core Lua modules (session, user, utils, captcha, routes)
- `lua_features/` — Feature modules (MFA, email, password policy, hashing, etc.)
- `helper_go/` — Go helper microservice for Argon2id, email, QR, reCAPTCHA
- `static/` — All static assets (HTML, JS, CSS)
- `.env` — Environment variables for secrets and configuration

---

## Feature Checklist (as of 2025-04-18)

- [x] Strong password policies & breached password blocking
- [x] Argon2id password hashing (Go helper)
- [x] TOTP MFA with QR setup
- [x] MFA recovery codes
- [x] Account lockout after failed MFA
- [x] CAPTCHA & Google reCAPTCHA v3
- [x] Per-IP and per-user rate limiting
- [x] Secure session management (HttpOnly, Secure, SameSite)
- [x] CSRF protection
- [x] Security headers (HSTS, CSP, etc.)
- [x] HTTPS enforcement
- [x] Email verification & password reset
- [x] Input validation & sanitization
- [x] Password strength meter (zxcvbn.js)
- [x] Behavioral biometrics & adaptive authentication (heuristics)
- [ ] Tamper-evident audit logging (Planned)
- [ ] True AI/ML anomaly detection (Planned)

---

## How It Works

- **Registration**: User submits email and strong password. Password is checked against breach database, hashed with Argon2id, and stored. Email verification link and MFA setup (with recovery codes) are sent.
- **Login**: User submits credentials, passes CAPTCHA and reCAPTCHA. Behavioral biometrics are analyzed. If risk is high, MFA is always required. On success, a secure session cookie is set.
- **MFA**: TOTP code or recovery code required if enabled or if risk is high. After 5 failed attempts, account is locked for 1 hour.
- **Password Reset**: User requests reset, receives a time-limited link, and must set a strong new password (with optional MFA).
- **Session & Security**: All cookies are Secure, HttpOnly, SameSite. All endpoints are protected by CSRF tokens. All responses have security headers. All sensitive actions are rate-limited.

---

## Environment Variables (`.env`)
- `RECAPTCHA_SECRET` — Google reCAPTCHA secret key
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` — SMTP credentials for email
- `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` — (Go helper, if using Postgres)
- `MFA_SECRET_KEY` — (Optional) Key for encrypting MFA secrets

---

## Planned Improvements
- Tamper-evident audit logging for all authentication events
- True AI/ML-based anomaly detection and risk scoring
- Device fingerprinting for even stronger adaptive authentication

---

## References
- OWASP Cheat Sheets (Password Storage, Session Management, etc.)
- HaveIBeenPwned API
- Google reCAPTCHA
- zxcvbn.js
- NIST SP 800-63B

---

_This project is pure Lua (no frameworks), with Go used only for tasks Lua cannot do natively. All code is modular and auditable._

