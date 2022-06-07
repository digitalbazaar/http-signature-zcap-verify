# http-signature-zcap-verify _(@digitalbazaar/http-signature-zcap-verify)_

A library for verifying Authorization Capability (ZCAP) invocations via HTTP
signatures

## Install

- Browsers and Node.js 14+ are supported.
- [Web Crypto API][] required. Older browsers and Node.js 14 must use a
  polyfill.

To install from NPM:

```
npm install @digitalbazaar/http-signature-zcap-verify
```

## Example "getVerifier" for "verifyCapabilityInvocation"

```js
import {CryptoLD} from 'crypto-ld';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

async function getVerifier({keyId, documentLoader}) {
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});
  const verifier = key.verifier();
  return {verifier, verificationMethod};
}
```

[Web Crypto API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
