/*!
 * Copyright (c) 2020-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {createRootCapability} from '@digitalbazaar/zcap';
import {verifyCapabilityInvocation} from '../lib/index.js';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {CryptoLD} from 'crypto-ld';
import {securityDocumentLoader} from './document-loader.js';
import {signCapabilityInvocation} from
  '@digitalbazaar/http-signature-zcap-invoke';
import zcapCtx from 'zcap-context';

const controller = 'did:test:controller';

const cryptoLd = new CryptoLD();
cryptoLd.use(Ed25519VerificationKey2020);

const Ed25519 = {
  type: 'Ed25519VerificationKey2020',
  Suite: Ed25519Signature2020,
};

const invocationResourceUrl = 'https://test.org/zcaps/foo';
const method = 'GET';

let keyPair;

const setup = async ({Suite, type}) => {
  let expectedHost = 'test.org';
  if(typeof window !== 'undefined') {
    expectedHost = window.location.host; // eslint-disable-line no-undef
  }
  // the tests will use a mock didKey.
  keyPair = await cryptoLd.generate({
    controller,
    type,
  });
  const {id: keyId} = keyPair;
  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });

  // this is the root zCap
  const rootCapability = createRootCapability({
    controller,
    invocationTarget: invocationResourceUrl
  });

  const documentLoader = async uri => {
    // the controller should return a didDocument
    // with the ProofPurpose's term on it
    // In this case that term is capabilityInvocation
    if(uri === controller) {
      const doc = {
        id: controller,
        '@context': zcapCtx.CONTEXT_URL,
        capabilityInvocation: [keyId]
      };
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    // when we dereference the keyId for verification
    // all we need is the publicNode
    if(uri === keyId) {
      const doc = keyPair.export({publicKey: true, includeContext: true});
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    if(uri === rootCapability.id) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    return securityDocumentLoader(uri);
  };
  const getVerifier = async ({keyId, documentLoader}) => {
    const key = await cryptoLd.fromKeyId({id: keyId, documentLoader});
    const verificationMethod = await key.export(
      {publicKey: true, includeContext: true});
    const verifier = key.verifier();
    return {verifier, verificationMethod};
  };
  const created = Date.now() - 1000;
  // we need a signer just for the sign step
  const invocationSigner = keyPair.signer();
  invocationSigner.id = keyId;
  const signed = await signCapabilityInvocation({
    url: invocationResourceUrl,
    method,
    headers: {
      keyId,
      date: created
    },
    json: {foo: true},
    invocationSigner,
    capabilityAction: 'read'
  });
  // in browsers we need to set the host explicitly
  signed.host = signed.host || expectedHost;
  return {
    expectedHost,
    // method used in tests is always GET which maps to `read`
    expectedAction: 'read',
    expectedRootCapability: rootCapability.id,
    keyId,
    keyPair,
    suite,
    signed,
    documentLoader,
    getVerifier
  };
};

describe('verifyCapabilityInvocation', function() {
  [Ed25519].forEach(function(suiteType) {

    describe(suiteType.type, function() {
      let suite;
      let documentLoader;
      let keyId;
      let getVerifier;
      let signed;
      let expectedHost;
      let expectedAction;
      let expectedRootCapability;

      beforeEach(async function() {
        ({
          expectedHost,
          expectedAction,
          expectedRootCapability,
          suite,
          documentLoader,
          keyId,
          getVerifier,
          signed
        } = await setup(suiteType));
      });

      it('should verify a valid request', async function() {
        const result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          getVerifier,
          documentLoader,
          expectedTarget: invocationResourceUrl,
          keyId
        });
        should.exist(result);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.be.an('boolean');
        result.verified.should.equal(true);
      });
      it('should call `beforeValidatePurpose` handler', async function() {
        let called = 0;
        let params;
        const result = await verifyCapabilityInvocation({
          url: invocationResourceUrl,
          method,
          suite,
          headers: signed,
          expectedHost,
          expectedAction,
          expectedRootCapability,
          getVerifier,
          documentLoader,
          expectedTarget: invocationResourceUrl,
          keyId,
          beforeValidatePurpose(_params) {
            called += 1;
            params = _params;
          }
        });
        should.exist(result);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.be.an('boolean');
        result.verified.should.equal(true);
        called.should.equal(1);
        params.should.include.keys([
          'capability', 'capabilityAction', 'purpose', 'proof'
        ]);
      });
      it('should verify a valid request when "now" is a JS date instance',
        async function() {
          const now = new Date(Date.now());
          const result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            getVerifier,
            documentLoader,
            keyId,
            now
          });
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.be.an('boolean');
          result.verified.should.equal(true);
        });
      it('should verify a valid request with multiple expectedHosts',
        async function() {
          const result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            headers: signed,
            expectedHost: [expectedHost, 'bar.org'],
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            getVerifier,
            documentLoader,
            keyId
          });
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.be.an('boolean');
          result.verified.should.equal(true);
        });

      it('should THROW if verificationMethod has been revoked',
        async function() {
          let result;
          let error = null;
          const pastDate = new Date(2020, 11, 17).toISOString()
            .replace(/\.[0-9]{3}/, '');
          const _documentLoader = async url => {
            if(keyId === url) {
              const doc = keyPair.export(
                {publicKey: true, includeContext: true});
              doc.revoked = pastDate;
              return {
                contextUrl: null,
                documentUrl: url,
                document: doc
              };
            }
            return documentLoader(url);
          };
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.message.should.contain('revoked');
          error.message.should.contain(pastDate);
        });

      it('should THROW if no getVerifier', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            headers: signed,
            documentLoader,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
        error.message.should.contain('getVerifier');
      });

      it('should THROW if no documentLoader', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
        error.message.should.contain('documentLoader');
      });

      it('should THROW if there are no headers', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            documentLoader,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
        error.name.should.equal('TypeError');
        error.message.should.contain('undefined');
      });

      it('should THROW if keyId can not be dereferenced by the ' +
        'documentLoader', async function() {
        let result;
        let error = null;
        const _documentLoader = async uri => {
          throw new Error(`NotFoundError: ${uri}`);
        };
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            documentLoader: _documentLoader,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        should.not.exist(result);
        error.message.should.contain('NotFoundError');
      });

      it('should THROW if verificationMethod type is not supported',
        async function() {
          let result;
          let error = null;
          const _documentLoader = async uri => {
            if(uri === keyId) {
              const doc = {
                id: uri,
                '@context': zcapCtx.CONTEXT_URL,
                controller,
                type: 'AESVerificationKey2001'
              };
              return {
                contextUrl: null,
                documentUrl: uri,
                document: doc
              };
            }
            return documentLoader(uri);
          };
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.message.should.contain(
            '"AESVerificationKey2001" is not installed.');
        });

      it('should NOT verify unless both content-type and digest are set',
        async function() {
          let result;
          let error = null;
          delete signed.digest;
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(error);
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('SyntaxError');
          result.error.message.should.contain('digest was not in the request');
        });

      it('should NOT verify if there is no url', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            method,
            suite,
            getVerifier,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.exist(result);
        should.not.exist(error);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.equal(false);
        result.error.name.should.equal('TypeError');
        result.error.message.should.contain('startsWith');
      });

      it('should NOT verify if host is not in expectedHost', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            documentLoader,
            headers: signed,
            expectedHost: 'not-foo.org',
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.exist(result);
        should.not.exist(error);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.equal(false);
        result.error.name.should.equal('NotAllowedError');
        result.error.message.should.equal(
          'Host header contains an unexpected host name.');
      });

      it('should NOT verify if Signature is missing keyId', async function() {
        let result;
        let error = null;
        // this is just to ensure no keyId is passed in headers
        delete signed.keyid;
        const keyIdReplacer = /keyId\=\"[^"]+\"\,/i;
        // this will remove keyId from the signature
        // this is where the error should come from
        signed.authorization = signed.authorization.replace(keyIdReplacer, '');
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.exist(result);
        should.not.exist(error);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.equal(false);
        result.error.name.should.equal('SyntaxError');
        result.error.message.should.equal('keyId was not specified');
      });

      it('should NOT verify if Signature is missing created',
        async function() {
          let result;
          let error = null;
          const createdReplacer = /created\=\"[^"]+\"\,/i;
          // this will remove created from the signature
          // this is where the error should come from
          signed.authorization = signed.authorization.replace(
            createdReplacer, '');
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.exist(result);
          should.not.exist(error);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('SyntaxError');
          result.error.message.should.equal('created was not in the request');
        });

      it('should NOT verify if Signature is missing expires',
        async function() {
          let result;
          let error = null;
          const expiresReplacer = /expires\=\"[^"]+\"\,?/i;
          // this will remove created from the signature
          // this is where the error should come from
          signed.authorization = signed.authorization.replace(
            expiresReplacer, '');
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.exist(result);
          should.not.exist(error);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('SyntaxError');
          result.error.message.should.equal('expires was not in the request');
        });

      it('should NOT verify if there is no method',
        async function() {
          let result;
          let error = null;
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(error);
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('TypeError');
          result.error.message.should.contain('toLowerCase');
        });

      it('should NOT verify if headers is missing host', async function() {
        let result;
        let error = null;
        delete signed.host;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getVerifier,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedAction,
            expectedRootCapability,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(error);
        should.exist(result);
        result.should.be.an('object');
        should.exist(result.verified);
        result.verified.should.equal(false);
        result.error.name.should.equal('NotAllowedError');
        result.error.message.should.equal(
          'Host header contains an unexpected host name.');
      });

      it('should NOT verify with additionalHeaders not used in Signature',
        async function() {
          let result;
          let error = null;
          try {
            result = await verifyCapabilityInvocation({
              additionalHeaders: ['foo'],
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction,
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(error);
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('SyntaxError');
          result.error.message.should.equal('foo was not a signed header');
        });

      it('should NOT verify if headers is missing capability-invocation',
        async function() {
          let result;
          let error = null;
          delete signed['capability-invocation'];
          try {
            result = await verifyCapabilityInvocation({
              url: invocationResourceUrl,
              method,
              suite,
              getVerifier,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedAction: 'read',
              expectedRootCapability,
              expectedTarget: invocationResourceUrl,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(error);
          should.exist(result);
          result.should.be.an('object');
          should.exist(result.verified);
          result.verified.should.equal(false);
          result.error.name.should.equal('SyntaxError');
          result.error.message.should.equal(
            'capability-invocation was not in the request');
        });
    });
  });
});
