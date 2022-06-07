/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import chai from 'chai';
global.should = chai.should();

// WebCrypto polyfill if needed
import crypto from 'node:crypto';
import webcrypto from 'isomorphic-webcrypto';

if(!crypto.webcrypto) {
  crypto.webcrypto = webcrypto;
}
