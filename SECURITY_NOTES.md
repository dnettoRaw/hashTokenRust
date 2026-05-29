# Security Notes

- Native `htr1` tokens are signed, not encrypted.
- Payloads are Base64URL encoded and readable by anyone who has the token.
- HMAC authenticates version, payload and metadata using the shared secret plus selected salt.
- Verification checks algorithm, salt index, expiration, max age, issuer and audience when configured.
- Signature comparison is constant-time for equal-length signatures.
- Use an encrypted token mode for payload secrecy.
