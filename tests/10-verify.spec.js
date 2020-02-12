/*!
 * Copyright (c) 2020 Digital Bazaar, Inc. All rights reserved.
 */
import {verifyCapabilityInvocation} from '..';
import {signCapabilityInvocation} from 'http-signature-zcap-invoke';
import {suites, SECURITY_CONTEXT_V2_URL} from 'jsonld-signatures';
import {Ed25519KeyPair, RSAKeyPair} from 'crypto-ld';
import uuid from 'uuid-random';

const {Ed25519Signature2018, RsaSignature2018} = suites;

const Ed25519 = {
  type: 'Ed25519',
  Suite: Ed25519Signature2018,
  LDKeyPair: Ed25519KeyPair,
};

const Rsa = {
  type: 'RSA',
  Suite: RsaSignature2018,
  LDKeyPair: RSAKeyPair
};

const controller = 'did:test:controller';
const delegator = 'did:test:delegator';
const url = 'https://test.org/zcaps/foo';
const method = 'GET';

const setup = async ({Suite, LDKeyPair}) => {
  let expectedHost = 'test.org';
  if(typeof window !== 'undefined') {
    expectedHost = window.location.host; // eslint-disable-line no-undef
  }
  // the tests will use a mock didKey.
  const keyId = `did:key:${uuid()}`;
  const keyPair = await LDKeyPair.generate({
    id: keyId,
    controller
  });
  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });
  // this is a zCap
  const rootCapability = {
    '@context': SECURITY_CONTEXT_V2_URL,
    id: url,
    invocationTarget: url,
    controller,
    delegator,
    invoker: keyId
  };

  const documentLoader = async uri => {
    // the controller should return a didDocument
    // with the ProofPurpose's term on it
    // In this case that term is capabilityInvocation
    if(uri === controller) {
      const doc = {
        id: controller,
        '@context': SECURITY_CONTEXT_V2_URL,
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
      const doc = keyPair.publicNode();
      doc['@context'] = SECURITY_CONTEXT_V2_URL;
      doc.controller = controller;
      return {
        contextUrl: null,
        documentUrl: uri,
        document: doc
      };
    }
    if(uri === url) {
      return {
        contextUrl: null,
        documentUrl: uri,
        document: rootCapability
      };
    }
    throw new Error(`documentLoader unable to resolve ${uri}`);
  };
  const getInvokedCapability = () => rootCapability;
  const created = Date.now() - 1000;
  // we need a signer just for the sign step
  const invocationSigner = keyPair.signer();
  invocationSigner.id = keyId;
  const signed = await signCapabilityInvocation({
    url,
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
  [Ed25519, Rsa].forEach(function(suiteType) {

    describe(suiteType.type, function() {
      let suite,
        documentLoader,
        keyId,
        getInvokedCapability,
        signed,
        expectedHost = null;

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
          url,
          method,
          suite,
          headers: signed,
          expectedHost,
          getInvokedCapability,
          documentLoader,
          expectedTarget: url,
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
            url,
            method,
            suite,
            headers: signed,
            expectedHost: [expectedHost, 'bar.org'],
            getInvokedCapability,
            documentLoader,
            expectedTarget: url,
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
          let result, error = null;
          const _documentLoader = async uri => {
            if(keyId === uri) {
              const doc = {id: keyId};
              doc['@context'] = SECURITY_CONTEXT_V2_URL;
              doc.controller = controller;
              doc.revoked = 'foo';
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
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.message.should.contain('verification method has been revoked');
        });

      it('should THROW if verificationMethod can not be framed',
        async function() {
          let result, error = null;
          const _documentLoader = async uri => {
            if(keyId === uri) {
              const doc = {id: keyId};
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
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.message.should.contain(
            `Verification method ${keyId} not found.`);
        });

      it('should THROW if no getInvokedCapability', async function() {
        let result, error = null;
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            headers: signed,
            expectedHost,
            documentLoader,
            expectedTarget: url,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
      });

      it('should THROW if no documentLoader', async function() {
        let result, error = null;
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            headers: signed,
            expectedHost,
            expectedTarget: url,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
      });

      it('should THROW if there are no headers', async function() {
        let result, error = null;
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            documentLoader,
            expectedHost,
            expectedTarget: url,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.not.exist(result);
        should.exist(error);
      });

      it('should THROW if keyId can not be dereferenced by the ' +
        'documentLoader', async function() {
        let result, error = null;
        const _documentLoader = async uri => {
          if(uri === keyId) {
            return {
              contextUrl: null,
              documentUrl: uri,
              document: null
            };
          }
          return documentLoader(uri);
        };
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            documentLoader: _documentLoader,
            headers: signed,
            expectedHost,
            expectedTarget: url,
            keyId
          });
        } catch(e) {
          error = e;
        }
        should.exist(error);
        should.not.exist(result);
        error.message.should.equal('Could not retrieve a JSON-LD ' +
          'document from the URL.');
      });

      it('should THROW if verificationMethod type is not supported',
        async function() {
          let result, error = null;
          const _documentLoader = async uri => {
            if(uri === keyId) {
              const doc = {
                id: uri,
                '@context': SECURITY_CONTEXT_V2_URL,
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
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader: _documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
              keyId
            });
          } catch(e) {
            error = e;
          }
          should.not.exist(result);
          should.exist(error);
          error.message.should.contain('Unsupported Key Type');
        });

      it('should NOT verify unless both content-type and digest are set',
        async function() {
          let result, error = null;
          delete signed.digest;
          try {
            result = await verifyCapabilityInvocation({
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });

      it('should NOT verify if there is no url', async function() {
        let result, error = null;
        try {
          result = await verifyCapabilityInvocation({
            method,
            suite,
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedTarget: url,
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
      });

      it('should NOT verify if host is not in expectedHost', async function() {
        let result, error = null;
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost: 'not-foo.org',
            expectedTarget: url,
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
      });

      it('should NOT verify if Signature is missing keyId', async function() {
        let result, error = null;
        // this is just to ensure no keyId is passed in headers
        delete signed.keyid;
        const keyIdReplacer = /keyId\=\"[^"]+\"\,/i;
        // this will remove keyId from the signature
        // this is where the error should come from
        signed.authorization = signed.authorization.replace(keyIdReplacer, '');
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedTarget: url,
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
      });

      it('should NOT verify if Signature is missing created',
        async function() {
          let result, error = null;
          const createdReplacer = /created\=\"[^"]+\"\,/i;
          // this will remove created from the signature
          // this is where the error should come from
          signed.authorization = signed.authorization.replace(
            createdReplacer, '');
          try {
            result = await verifyCapabilityInvocation({
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });

      it('should NOT verify if Signature is missing expires',
        async function() {
          let result, error = null;
          const expiresReplacer = /expires\=\"[^"]+\"\,?/i;
          // this will remove created from the signature
          // this is where the error should come from
          signed.authorization = signed.authorization.replace(
            expiresReplacer, '');
          try {
            result = await verifyCapabilityInvocation({
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });

      it('should NOT verify if there is no method',
        async function() {
          let result, error = null;
          try {
            result = await verifyCapabilityInvocation({
              url,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });

      it('should NOT verify if headers is missing host', async function() {
        let result, error = null;
        delete signed.host;
        try {
          result = await verifyCapabilityInvocation({
            url,
            method,
            suite,
            getInvokedCapability,
            documentLoader,
            headers: signed,
            expectedHost,
            expectedTarget: url,
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

      });

      it('should NOT verify with additionalHeaders not used in Signature',
        async function() {
          let result, error = null;
          try {
            result = await verifyCapabilityInvocation({
              additionalHeaders: ['foo'],
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });

      it('should NOT verify if headers is missing capability-invocation',
        async function() {
          let result, error = null;
          delete signed['capability-invocation'];
          try {
            result = await verifyCapabilityInvocation({
              url,
              method,
              suite,
              getInvokedCapability,
              documentLoader,
              headers: signed,
              expectedHost,
              expectedTarget: url,
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
        });
    });
  });
});
