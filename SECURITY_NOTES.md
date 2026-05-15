# Security Notes

- JWT verification rejects `alg: none` and accepts only exact `HS256` or `HS512`.
- Signatures and legacy token checksums are compared without early exit for equal-length inputs.
- Base64URL segments must use the unpadded URL-safe alphabet. Empty or malformed segments are rejected.
- `exp`, `nbf`, `iat`, `iss`, `aud` and `sub` are validated when present, and required when configured in verify options.
- `clock_tolerance` is non-negative and temporal arithmetic uses checked operations.
- `max_payload_size` is checked before and after payload decoding to limit unauthenticated allocation.
- Use high-entropy secrets. `AdvancedTokenManager::new` requires at least 16 characters for its main secret.
