# http-signature-zcap-verify ChangeLog

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
