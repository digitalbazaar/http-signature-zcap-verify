# http-signature-zcap-verify _(@digitalbazaar/http-signature-zcap-verify)_

A library for verifying Authorization Capability (ZCAP) invocations via HTTP
signatures

## Install

- Browsers and Node.js 22+ are supported.
- [Web Crypto API][] required. Older browsers and Node.js 14 must use a
  polyfill.

To install from NPM:

```
npm install @digitalbazaar/http-signature-zcap-verify
```

## Example "getVerifier" for "verifyCapabilityInvocation"

```js
import * as Ed25519Multikey from '@digitalbazaar/ed25519-multikey';

async function getVerifier({keyId, documentLoader}) {
  const {document} = await documentLoader(keyId);
  const key = await Ed25519Multikey.from(document);
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}
```

[Web Crypto API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
