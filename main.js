/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import {base64Decode} from './util.js';
import base64url from 'base64url-universal';
import {CapabilityInvocation, constants} from '@digitalbazaar/zcap';
import pako from 'pako';
import {
  parseRequest, parseSignatureHeader
} from '@digitalbazaar/http-signature-header';

/**
 * Verifies a zcap invocation in the form of an http-signature header.
 *
 * @param {object} options - Options to use.
 * @param {string} options.url - The url of the request.
 * @param {string} options.method - The HTTP request method.
 * @param {Array<string>} options.headers - The headers from the request.
 * @param {Function<Promise>} options.getVerifier - An async function to
 *   call to get a verifier and verification method for the key ID.
 * @param {Function} options.documentLoader - A jsonld document loader; it
 *   must be able to load the root zcap and any contexts used in the zcap
 *   delegation chain.
 * @param {string} options.expectedHost - The expected host of the request.
 * @param {string} options.expectedAction - The expected action of the zcap.
 * @param {string} options.expectedRootCapability - The expected root
 *   capability of the zcap.
 * @param {string} options.expectedTarget - The expected target of the zcap.
 * @param {object} options.suite - The jsigs signature suite(s) for verifying
 *   the capability delegation chain.
 * @param {boolean} [options.allowTargetAttenuation=false] - Allow the
 *   invocationTarget of a delegation chain to be increasingly restrictive
 *   based on a hierarchical RESTful URL structure.
 * @param {Array<string>} [options.additionalHeaders=[]] - Additional headers
 *  to verify.
 * @param {Function} [options.inspectCapabilityChain] - A function that can
 *   inspect a capability chain.
 * @param {number} [options.maxChainLength] - The maximum length of the
 *   capability delegation chain.
 * @param {number} [options.maxDelegationTtl] - The maximum milliseconds to
 *   live for a delegated zcap as measured by the time difference between
 *   `expires` and `created` on the delegation proof.
 * @param {number} [options.maxClockSkew=300] - A maximum number of seconds
 *   that clocks may be skewed when checking capability expiration date-times
 *   against `date`, when comparing invocation proof creation time against
 *   delegation proof creation time, and when comparing the capability
 *   invocation expiration time against `now`.
 * @param {integer|Date} [options.now=now] - A unix timestamp or an
 *   instance of Date.
 *
 * @returns {Promise<object>} The result of the verification.
*/
export async function verifyCapabilityInvocation({
  url, method, headers, getVerifier, documentLoader,
  expectedHost, expectedAction, expectedRootCapability, expectedTarget, suite,
  additionalHeaders = [], allowTargetAttenuation = false,
  inspectCapabilityChain, maxChainLength, maxClockSkew = 300, maxDelegationTtl,
  now = Math.floor(Date.now() / 1000)
}) {
  if(now instanceof Date) {
    now = Math.floor(now.getTime() / 1000);
  }
  if(!getVerifier) {
    throw new TypeError(
      '"getVerifier" must be given to dereference the key for verifying ' +
      'the capability invocation signature.');
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
    // `now` will be used to check against the expiry on the signature using
    // a clock skew of 5 minutes
    parsed = parseRequest({url, method, headers}, {
      headers: expectedHeaders,
      clockSkew: maxClockSkew,
      now
    });
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
  const {
    keyId, signingString,
    params: {created, signature: b64Signature}
  } = parsed;

  // verify HTTP signature
  const {verifier, verificationMethod} = await getVerifier(
    {keyId, documentLoader});
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
  if(!capability) {
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
    if(!capability.parentCapability) {
      const error = new Error(
        'A root capability must be invoked using only its ID.');
      error.name = 'DataError';
      return {verified: false, error};
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
    // `date` is in milliseconds and `now` is in seconds, so convert
    date: now * 1000,
    expectedAction,
    expectedRootCapability,
    expectedTarget,
    inspectCapabilityChain,
    maxChainLength,
    maxClockSkew,
    maxDelegationTtl,
    suite
  });
  // invocation target must match absolute url
  let invocationTarget;
  if(url.includes(':')) {
    invocationTarget = url;
  } else {
    invocationTarget = `https://${headers.host}${url}`;
  }
  const capabilityAction = parsedInvocationHeader.params.action;
  const proof = {
    '@context': constants.ZCAP_CONTEXT_URL,
    capability,
    capabilityAction,
    // use second precision for created date
    created: new Date(created * 1000).toISOString().slice(0, -5) + 'Z',
    invocationTarget,
    verificationMethod: keyId
  };
  const {valid, error} = await purpose.validate(proof, {
    verificationMethod,
    documentLoader
  });
  if(!valid) {
    return {verified: false, error};
  }

  const controller = verificationMethod.controller || verificationMethod.id;
  return {
    verified: true,
    controller,
    invoker: controller,
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
