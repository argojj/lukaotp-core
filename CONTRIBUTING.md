# Contributing to LukaOTP Core

This is a curated public repository for the LukaOTP security core only. Keep
contributions limited to TOTP, account data models, encrypted-vault/KDF,
`otpauth://` parsing, portable encrypted backup formats, their tests, and the
Core-only documentation or CI. Client code, WASM, Sync, hosted services, Pro,
billing, license issuance, release automation, and store/deployment material
are out of scope.

Report vulnerabilities through `SECURITY.md`, not in a public issue or pull
request. For non-trivial changes, open an issue first.

## Developer Certificate of Origin

Every commit must include a `Signed-off-by` line matching its author. Add it
with `git commit -s`. By signing off, you certify that you have the right to
submit the contribution under the Mozilla Public License 2.0.

## Checks

```bash
cargo test -p lukaotp-core --locked
cargo clippy -p lukaotp-core --all-targets --locked -- -D warnings
```

Do not include real TOTP seeds, recovery codes, credentials, private keys, or
user vault data in commits, tests, issues, or pull requests.
