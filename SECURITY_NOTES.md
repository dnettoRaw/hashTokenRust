# Security Notes

- Native `htr1` tokens are signed, not encrypted.
- Native `hte1` tokens are encrypted and authenticated with ChaCha20-Poly1305.
- `htr1` payloads are Base64URL encoded and readable by anyone who has the token.
- `hte1` payloads are not readable without the shared secret and selected salt.
- HMAC authenticates version, payload and metadata using the shared secret plus selected salt.
- Verification checks algorithm, salt index, expiration, max age, issuer and audience when configured.
- Signature comparison is constant-time for equal-length signatures.
- Use sealed `hte1` tokens for payload secrecy.
