# http-signature-zcap-verify
A library for verifying Authorization Capability (ZCAP) invocations via HTTP signatures

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
