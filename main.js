/*!
 * Copyright (c) 2021 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import pako from 'pako';
import {CryptoLD} from 'crypto-ld';
import {parseRequest, parseSignatureHeader} from 'http-signature-header';
import {CapabilityInvocation, constants} from '@digitalbazaar/zcapld';
import {TextDecoder, TextEncoder, base64Decode} from './util.js';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

/**
 * Verifies a zcap invocation in the form of an http-signature header.
 *
 * @param {object} options - Options to use.
 * @param {string} options.url - The url of the request.
 * @param {string} options.method - The HTTP request method.
 * @param {Array<string>} options.headers - The headers from the request.
 * @param {Function<Promise>} options.getInvokedCapability - An async
 *   function to call to dereference the invoked capability if it was passed
 *   by reference.
 * @param {Function} options.documentLoader - A jsonld documentloader.
 * @param {string} options.expectedHost - The expected host of the request.
 * @param {string} options.expectedTarget - The expected target of the zcap.
 * @param {string} options.expectedRootCapability - The expected root capability
 *   of the zcap.
 * @param {string} options.expectedAction - The expected allowed action of the
 *  zcap.
 * @param {Function} options.inspectCapabilityChain - A function that can
 *   inspect a capability chain.
 * @param {object} options.suite - A jsigs signature suite.
 * @param {Array<string>} [options.additionalHeaders=[]] - Additional headers
 *  to verify.
 * @param {boolean} [options.allowTargetAttenuation=false] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {integer} [options.now=now] - A unix time stamp.
 *
 * @returns {Promise<object>} The result of the verification.
*/
export async function verifyCapabilityInvocation({
  url, method, headers, getInvokedCapability, documentLoader,
  expectedHost, expectedTarget, expectedRootCapability,
  expectedAction, inspectCapabilityChain, suite, additionalHeaders = [],
  allowTargetAttenuation = false, now = Math.floor(Date.now() / 1000)
}) {
  if(!getInvokedCapability) {
    throw new TypeError(
      '"getInvokedCapability" must be given to dereference the ' +
      'invoked capability.');
  }

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
    parsed = parseRequest(
      {url, method, headers}, {headers: expectedHeaders, now});
  } catch(error) {
    return {verified: false, error};
  }

  // verify that `host` matches server host
  if(!Array.isArray(expectedHost)) {
    expectedHost = [expectedHost];
  }
  const {host} = reqHeaders;
  if(!expectedHost.includes(host)) {
    const error = new Error('Host header contains an unexpected host name.');
    error.name = 'NotAllowedError';
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

  // fromKeyId ensures that the key is valid and is not revoked
  const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
  const verificationMethod = await key.export(
    {publicKey: true, includeContext: true});

  // verify HTTP signature
  const verifier = key.verifier();
  const encoder = new TextEncoder();
  const data = encoder.encode(signingString);
  const signature = base64Decode(b64Signature);
  const verified = await verifier.verify({data, signature});
  if(!verified) {
    const error = new Error('Signature not verified.');
    error.name = 'DataError';
    return {verified: false, error};
  }

  // always dereference the invoked capability to ensure that the system can
  // dereference it authoritatively (which may include ensuring that it is
  // saved in an authorized list, etc.)
  const invocationHeader = reqHeaders['capability-invocation'];
  const parsedInvocationHeader = parseSignatureHeader(invocationHeader);
  if(parsedInvocationHeader.scheme !== 'zcap') {
    const error = new Error('Capability invocation scheme must be "zcap".');
    error.name = 'DataError';
    return {verified: false, error};
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
        return {verified: false, error};
      }
    }
  }
  if(!capability) {
    const error = new Error(
      'Capability not present in Capability-Invocation header.');
    error.name = 'DataError';
    return {verified: false, error};
  }

  // check capability invocation
  const purpose = new CapabilityInvocation({
    allowTargetAttenuation,
    expectedTarget,
    expectedRootCapability,
    expectedAction,
    inspectCapabilityChain,
    suite
  });
  const capabilityAction = parsedInvocationHeader.params.action;
  const proof = {
    '@context': constants.ZCAP_CONTEXT_URL,
    capability,
    capabilityAction,
    verificationMethod: keyId
  };
  const {valid, error} = await purpose.validate(proof, {
    verificationMethod,
    documentLoader
  });
  if(!valid) {
    return {verified: false, error};
  }

  return {
    verified: true,
    invoker: key.controller || key.id,
    capability,
    capabilityAction,
    verificationMethod
  };
}

function _lowerCaseObjectKeys(obj) {
  const newObject = {};
  for(const [k, v] of Object.entries(obj)) {
    newObject[k.toLowerCase()] = v;
  }
  return newObject;
}
