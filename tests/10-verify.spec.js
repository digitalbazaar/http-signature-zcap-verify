/*!
 * Copyright (c) 2020-2021 Digital Bazaar, Inc. All rights reserved.
 */
import {verifyCapabilityInvocation} from '..';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';
import {Ed25519VerificationKey2020} from
  '@digitalbazaar/ed25519-verification-key-2020';
import {Ed25519Signature2020} from '@digitalbazaar/ed25519-signature-2020';
import {CryptoLD} from 'crypto-ld';
import zcapCtx from 'zcap-context';
import {securityDocumentLoader} from './document-loader.js';

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

  // this is a zCap
  const rootCapability = {
    '@context': zcapCtx.CONTEXT_URL,
    id: invocationResourceUrl,
    invocationTarget: invocationResourceUrl,
    controller,
  };

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
    if(uri === invocationResourceUrl) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    return securityDocumentLoader(uri);
  };
  const getInvokedCapability = () => rootCapability;
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
    keyId,
    keyPair,
    suite,
    signed,
    documentLoader,
    getInvokedCapability,
  };
};

describe('verifyCapabilityInvocation', function() {
  [Ed25519].forEach(function(suiteType) {

    describe(suiteType.type, function() {
      let suite = null;
      let documentLoader = null;
      let keyId = null;
      let getInvokedCapability = null;
      let signed = null;
      let expectedHost = null;

      beforeEach(async function() {
        ({
          expectedHost,
          suite,
          documentLoader,
          keyId,
          getInvokedCapability,
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
          getInvokedCapability,
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

      it('should verify a valid request with multiple expectedHosts',
        async function() {
          const result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            headers: signed,
            expectedHost: [expectedHost, 'bar.org'],
            getInvokedCapability,
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
              getInvokedCapability,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
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

      it('should THROW if no getInvokedCapability', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            headers: signed,
            expectedHost,
            documentLoader,
            expectedTarget: invocationResourceUrl,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
        error.message.should.contain('getInvokedCapability');
      });

      it('should THROW if no documentLoader', async function() {
        let result;
        let error = null;
        try {
          result = await verifyCapabilityInvocation({
            url: invocationResourceUrl,
            method,
            suite,
            getInvokedCapability,
            headers: signed,
            expectedHost,
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
            getInvokedCapability,
            documentLoader,
            expectedHost,
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
            getInvokedCapability,
            documentLoader: _documentLoader,
            headers: signed,
            expectedHost,
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
              getInvokedCapability,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
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
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost: 'not-foo.org',
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
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
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
