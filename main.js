/*!
 * Copyright (c) 2019 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import pako from 'pako';
import {LDKeyPair} from 'crypto-ld';
import {frame} from 'jsonld';
import {extendContextLoader, SECURITY_CONTEXT_V2_URL} from 'jsonld-signatures';
import {parseRequest, parseSignatureHeader} from 'http-signature-header';
import {CapabilityInvocation} from 'ocapld';
import {TextDecoder, TextEncoder, base64Decode} from './util.js';

export async function verifyCapabilityInvocation({
  url, method, headers, getInvokedCapability, documentLoader,
  expectedHost, expectedTarget, expectedRootCapability,
  expectedAction, inspectCapabilityChain, suite, additionalHeaders = []
}) {
  if(!getInvokedCapability) {
    throw new TypeError(
      '"getInvokedCapability" must be given to dereference the ' +
      'invoked capability.');
  }

  // wrap doc loader to ensure local security contexts are always used
  documentLoader = extendContextLoader(documentLoader);

  // parse http header for signature
  const expectedHeaders = [
    '(key-id)', '(created)', '(expires)', '(request-target)',
    'host', 'capability-invocation'
  ];
  const reqHeaders = _lowerCaseObjectKeys(headers);
  if(reqHeaders['content-type']) {
    additionalHeaders.push('content-type');
    additionalHeaders.push('digest');
  }
  expectedHeaders.push(...additionalHeaders);
  let parsed;
  try {
    parsed = parseRequest({url, method, headers}, {headers: expectedHeaders});
  } catch(e) {
    return {verified: false, error: _createNotAllowedError(e)};
  }

  // verify that `host` matches server host
  if(!Array.isArray(expectedHost)) {
    expectedHost = [expectedHost];
  }
  const {host} = reqHeaders;
  if(!expectedHost.includes(host)) {
    const error = new Error('Host header contains an unexpected host name.');
    error.name = 'NotAllowedError';
    error.httpStatusCode = 400;
    error.host = host;
    error.expectedHost = expectedHost;
    return {verified: false, error};
  }

  /* Note: The order in which we run these checks can introduce side channels
  that leak information (e.g., timing). However, we are not presently concerned
  about leaking information about existing capabilities as such leaks do not
  pose any security risk -- and any privacy correlation risk is low if the
  capability identifiers are infeasible to guess. */

  // get parsed parameters from from HTTP header and generate signing string
  const {keyId, signingString, params: {signature: b64Signature}} = parsed;

  // fetch verification method from `keyId` and import as a crypto-ld key
  const verificationMethod = await _getVerificationMethod(
    {keyId, documentLoader});
  const key = await LDKeyPair.from(verificationMethod);

  // verify HTTP signature
  const verifier = key.verifier();
  const encoder = new TextEncoder();
  const data = encoder.encode(signingString);
  const signature = base64Decode(b64Signature);
  const verified = await verifier.verify({data, signature});
  if(!verified) {
    const error = new Error('Signature not verified.');
    error.name = 'DataError';
    error.httpStatusCode = 400;
    return {verified: false, error: _createNotAllowedError(error)};
  }

  // always dereference the invoked capability to ensure that the system can
  // dereference it authoritatively (which may include ensuring that it is
  // saved in an authorized list, etc.)
  const invocationHeader = reqHeaders['capability-invocation'];
  const parsedInvocationHeader = parseSignatureHeader(invocationHeader);
  if(parsedInvocationHeader.scheme !== 'zcap') {
    const error = new Error('Capability invocation scheme must be "zcap".');
    error.name = 'DataError';
    error.httpStatusCode = 400;
    return {verified: false, error: _createNotAllowedError(error)};
  }

  let capability = parsedInvocationHeader.params.id;
  if(capability) {
    capability = await getInvokedCapability({id: capability, expectedTarget});
  } else {
    capability = parsedInvocationHeader.params.capability;
    if(capability) {
      try {
        capability = JSON.parse(
          new TextDecoder('utf-8').decode(
            pako.ungzip(base64url.decode(capability))));
      } catch(e) {
        const error = new Error(
          'Capability in Capability-Invocation header is improperly encoded.');
        error.name = 'DataError';
        error.httpStatusCode = 400;
        return {verified: false, error};
      }
    }
  }
  if(!capability) {
    const error = new Error(
      'Capability not present in Capability-Invocation header.');
    error.name = 'DataError';
    error.httpStatusCode = 400;
    return {verified: false, error: _createNotAllowedError(error)};
  }

  // check capability invocation
  // TODO: add parameters to check any other caveats in the capability as
  // appropriate... noting that caveats like "file size" can't be checked
  // until the file received hits the limit, so that won't happen here
  const purpose = new CapabilityInvocation({
    expectedTarget,
    expectedRootCapability,
    expectedAction,
    inspectCapabilityChain,
    suite
  });
  const capabilityAction = parsedInvocationHeader.params.action;
  const proof = {
    capability,
    capabilityAction,
    verificationMethod: keyId
  };
  const {valid, error} = await purpose.validate(proof, {
    verificationMethod,
    documentLoader
  });
  if(!valid) {
    return {verified: false, error: _createNotAllowedError(error)};
  }

  return {
    verified: true,
    invoker: key.controller || key.id,
    capability,
    capabilityAction,
    verificationMethod
  };
}

function _createNotAllowedError(cause) {
  const error = new Error('Permission denied.');
  error.name = 'NotAllowedError';
  error.httpStatusCode = 400;
  error.cause = cause;
  return error;
}

async function _getVerificationMethod({keyId, documentLoader}) {
  // Note: `expansionMap` is intentionally not passed; we can safely drop
  // properties here and must allow for it
  const {'@graph': [framed]} = await frame(keyId, {
    '@context': SECURITY_CONTEXT_V2_URL,
    '@embed': '@always',
    id: keyId,
    controller: {'@embed': '@never'}
  }, {documentLoader, compactToRelative: false});
  if(!framed) {
    throw new Error(`Verification method ${keyId} not found.`);
  }

  // ensure verification method has not been revoked
  if(framed.revoked !== undefined) {
    throw new Error('The verification method has been revoked.');
  }

  return framed;
}

function _lowerCaseObjectKeys(obj) {
  const newObject = {};
  for(const [k, v] of Object.entries(obj)) {
    newObject[k.toLowerCase()] = v;
  }
  return newObject;
}
