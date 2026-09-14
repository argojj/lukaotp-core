# LukaOTP Core portable data format

The Core-only portable backup format is a JSON envelope with `schema_version`,
a Base64-encoded 16-byte Argon2id salt, and a Base64-encoded AES-256-GCM blob.
The blob encrypts serialized `Account` records. Each account includes its UUID,
issuer, label, TOTP algorithm, digits, period, and secret.

The export password is independent of any caller-managed vault credential. Each
export creates a new salt and nonce. Unknown schema versions and invalid account
UUIDs are rejected rather than partially imported. Changing cryptographic
parameters or field meaning requires a schema-version change.
