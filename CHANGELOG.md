# http-signature-zcap-verify ChangeLog

## 9.0.0 - 2022-01-xx

### Added
- Add optional parameters `maxChainLength`, `maxDelegationTtl`, and
  `maxTimestampDelta` to allow for more fine grained control. These parameters
  all have defaults in zcapld that could previously not be set to other
  values at this layer.

### Changed
- **BREAKING**: A new function parameter `getVerifier` must now be passed. This
  function will be given the `keyId` for the key to be used to verify a
  signature and the `documentLoader` passed to `verifyCapabilityInvocation`. It
  must return a `verifier` and a `verificationMethod`. The `verifier` object
  must have a `verify` function that can be called with `data` and a
  `signature` and that returns a boolean. The `verificationMethod` object
  must include a verification method expressing the key information. The
  `getVerifier` function may throw an exception if the key is revoked. This
  new `getVerifier` function allows specific cryptographic suites to be
  decoupled from this library and, as such, the crypto-ld and ed25519 libraries
  are no longer dependencies of this library.

### Removed
- **BREAKING**: The `getInvokedCapability` parameter has been removed as it is
  no longer needed.

## 8.2.0 - 2021-08-19

### Added
- Allow `now` to be passed as a JS Date instance.

## 8.1.1 - 2021-07-21

### Fixed
- Ensure that zcap context is included in proof.

## 8.1.0 - 2021-07-11

### Changed
- Use zcapld@5.1.x, which brings in DID document-based optimizations.

## 8.0.0 - 2021-07-10

### Changed
- **BREAKING**: Updated ed25519 signature and key libraries to new major versions
  that address problems with key formats. These changes are not backwards compatible;
  systems updating this library will only be able to verify invocations from properly
  formatted keys.

## 7.2.1 - 2021-07-23

### Changed
- Backport fix to work with zcapld@5.

## 7.2.0 - 2021-07-02

### Changed
- Update to zcapld@5.x.

## 7.1.0 - 2021-05-04

### Changed
- Remove `jsonld-signatures@8.0` dependency.
- Update deps in test and fix tests.

## 7.0.0 - 2021-04-26

### Changed
- **BREAKING**: Use [`@digitalbazaar/zcapld@4.0`](https://github.com/digitalbazaar/zcapld/blob/main/CHANGELOG.md).
  - Uses new ZCAP context.

## 6.0.0 - 2021-04-06

### Changed
- **BREAKING**: Use `@digitalbazaar/zcapld@3.0` instead of `ocapld@v2.0`.
  `zcapld` required Node.js >= 12.
- **BREAKING**: Node.js >= 12 is now required.

## 5.0.0 - 2021-04-01

### Changed
- **BREAKING**: Only support `Ed25519Signature2020` proofs.
- Use `crytold@5`.

## 4.0.0 - 2021-03-02

### Changed
- **BREAKING**: Use `http-signature-header@2`.
- **BREAKING**: Use Unix time stamps (seconds since epoch) instead of ms since
  epoch.

### Added
- Parameter `now` to `verifyCapabilityInvocation` API.

## 3.0.0 - 2020-04-02

### Changed
- **BREAKING**: Use ocapld@2.

## 2.0.0 - 2020-02-19

### Changed
- **BREAKING**: Do not wrap errors in a 'NotAllowedError'.

## 1.3.0 - 2020-02-14

### Changed
- Use jsonld-signatures@5.
- Improve test coverage.

## 1.2.1 - 2020-02-11

### Fixed
- Add missing import for `TextDecoder`.

## 1.2.0 - 2020-02-10

### Added
- Add support for an `inspectCapabilityChain` handler in
  `verifyCapabilityInvocation`. This handler can be used to find revocations
  in the capability chain.
- Add support for a capability embedded in the header. The capability must be
  encoded as a JSON string that is compressed using gzip and then base64url
  endcoded.

## 1.1.0 - 2020-02-05

### Changed
- Use jsonld@2.0.2.

## 1.0.3 - 2020-02-05

### Fixed
- Return value from base64Decode helper.

## 1.0.2 - 2019-11-25

### Fixed
- Fix typo with verification method resolver frame.

## 1.0.1 - 2019-11-25

### Fixed
- Do not embed `controller` when resolving verification method.

## 1.0.0 - 2019-08-02

## 0.1.0 - 2019-08-02

### Added
- Add core files.

- See git history for changes previous to this release.
