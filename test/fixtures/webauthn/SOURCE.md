# Sources of the WebAuthn and ECDSA vectors (KBOX-9)

`vectors.json` holds published vectors only; nothing in it was made by `softAuthenticator()` or by this repo's code.

- **WebAuthn assertions and COSE keys**: W3C, *Web Authentication: An API for accessing Public Key Credentials, Level 3*,
  section 16 "Test Vectors" (non-normative), Editor's Draft of 25 August 2026, https://w3c.github.io/webauthn/#sctn-test-vectors
  (page sha256 `b154c137594d81beedaa7ea212d1e602cf401ce9800383ae28301759c5b2c28f` when copied, 2026-11-11). RP ID `example.org`,
  origin `https://example.org`.
  - `packed.ES256` is section 16.7's authentication (flags `0x0d`: UP, UV, BE). It is the vector the verifier must accept.
  - `none.ES256` is section 16.2's authentication (flags `0x19`: UP, BE, BS, no UV). Its signature is valid; the verifier must
    refuse it for the missing user verification.
  - `crossOrigin.ES256` is section 16.4's authentication (`"crossOrigin": true` in clientDataJSON). Its signature is valid; the
    verifier must refuse it.
  - `cosePublicKey` of each is the credential public key copied out of that section's registration `attestationObject`
    (the bytes after the credential id in `authData`).
- **Raw ECDSA P-256 signature**: RFC 6979, appendix A.2.5 (public key `Ux`, `Uy`; "With SHA-256, message = \"sample\"": `r`, `s`),
  https://www.rfc-editor.org/rfc/rfc6979.txt. Used for the device-key verify (raw `r||s`) and for the DER-to-raw conversion.
