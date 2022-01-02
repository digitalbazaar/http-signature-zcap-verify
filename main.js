/*!
 * Copyright (c) 2021-2022 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

import base64url from 'base64url-universal';
import {base64Decode} from './util.js';
import {CapabilityInvocation, constants} from '@digitalbazaar/zcapld';
import pako from 'pako';
import {parseRequest, parseSignatureHeader} from 'http-signature-header';

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
 * @param {Function<Promise>} options.getVerifier - An async function to
 *   call to get a verifier and verification method for the key ID.
 * @param {Function} options.documentLoader - A jsonld documentloader.
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
 * @param {number} [options.maxTimestampDelta] - A maximum number of seconds
 *   that the date on the signature can deviate from, defaults to `Infinity`.
 * @param {integer|Date} [options.now=now] - A unix timestamp or an
 *   instance of Date.
 *
 * @returns {Promise<object>} The result of the verification.
*/
export async function verifyCapabilityInvocation({
  url, method, headers, getInvokedCapability, getVerifier, documentLoader,
  expectedHost, expectedAction, expectedRootCapability, expectedTarget, suite,
  additionalHeaders = [], allowTargetAttenuation = false,
  inspectCapabilityChain, maxChainLength, maxDelegationTtl, maxTimestampDelta,
  now = Math.floor(Date.now() / 1000)
}) {
  if(now instanceof Date) {
    now = Math.floor(now.getTime() / 1000);
  }
  // FIXME: try to remove this param
  if(!getInvokedCapability) {
    throw new TypeError(
      '"getInvokedCapability" must be given to dereference the ' +
      'invoked capability.');
  }
  if(!getVerifier) {
    throw new TypeError(
      '"getVerifier" must be given to dereference keys for verifying ' +
      'signatures.');
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
    date: now,
    expectedAction,
    expectedRootCapability,
    expectedTarget,
    inspectCapabilityChain,
    maxChainLength,
    maxDelegationTtl,
    maxTimestampDelta,
    suite
  });
  const capabilityAction = parsedInvocationHeader.params.action;
  const proof = {
    '@context': constants.ZCAP_CONTEXT_URL,
    capability,
    capabilityAction,
    invocationTarget: url,
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
