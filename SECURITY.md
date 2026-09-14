# Security Policy

Report a suspected vulnerability privately to **devopjj@gmail.com**. Do not
include OTP secrets, passwords, vault contents, backup files, QR images,
credentials, or private keys in a public issue or pull request.

## Scope

This repository covers the Core-only Rust library: TOTP, account models,
Argon2id KDF, AES-256-GCM vault primitives, `otpauth://` parsing, and portable
encrypted backup formats. Client UI, browser permissions, WASM, Sync, hosted
services, and official release systems are outside this repository's scope.

No bounty, response-time, CVE, or payment commitment is implied. Source being
available does not constitute an independent security audit.
