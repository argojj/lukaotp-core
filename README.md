# LukaOTP Core

LukaOTP Core is the local security library behind a TOTP authenticator. It
contains TOTP generation, account data models, Argon2id key derivation,
AES-256-GCM encrypted-vault primitives, `otpauth://` parsing, and the portable
encrypted offline backup format.

## Scope

This repository intentionally contains only `crates/lukaotp-core/`, its
embedded tests, Core-only Rust build configuration, data-format documentation,
and project governance files. It does not contain any browser extension, WASM,
desktop or mobile client, Sync implementation or protocol, Pro feature,
billing, license issuance, hosted service, release automation, signing key, or
store/deployment configuration.

## Build and test

Install a current stable Rust toolchain, then run:

```bash
cargo test -p lukaotp-core --locked
cargo clippy -p lukaotp-core --all-targets --locked -- -D warnings
```

The CI workflow performs only these Core-only checks and has no deploy, sign,
publish, or secret-dependent step.

## Security and contributing

Report suspected vulnerabilities privately through `SECURITY.md`; do not put
secrets, vault data, passwords, QR images, or credentials in public issues.
Source availability is not an independent security audit. Contributions require
the DCO sign-off described in `CONTRIBUTING.md`.

## License

Copyright (c) 2026 Lin ShihWei.

Licensed under the Mozilla Public License 2.0 — see `LICENSE`. Third-party
material is listed in `NOTICE`; the LukaOTP name is governed by
`TRADEMARK.md`.
