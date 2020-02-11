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
const expectedHost = 'test.org';

const setup = async ({Suite, LDKeyPair}) => {
  const keyId = `did:key:${uuid()}`;
  const keyPair = await LDKeyPair.generate({
    id: keyId,
    controller
  });
  const suite = new Suite({
    verificationMethod: keyId,
    key: keyPair
  });
  const rootCapability = {
    '@context': SECURITY_CONTEXT_V2_URL,
    id: url,
    invocationTarget: url,
    controller,
    delegator,
    invoker: keyId
  };

  const documentLoader = async uri => {
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
    if(uri === keyId || uri === controller) {
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
  return {
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
      let suite, documentLoader, keyId, getInvokedCapability, signed = null;

      beforeEach(async function() {
        ({
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

      it.skip('should add headers if content-type is in headers', async function() {

      });

      it.skip('should verify with additionalHeaders', async function() {

      });

      it.skip('should THROW if no getInvokedCapability', async function() {

      });

      it.skip('should THROW if no documentLoader', async function() {

      });

      it.skip('should THROW if there are no headers', async function() {

      });

      it.skip('should THROW if verificationMethod type is not supported',
        async function() {

        });

      it.skip('should NOT verify if there is no url', async function() {

      });


      it.skip('should NOT verify if host is not in expectedHost', async function() {

      });

      it.skip('should NOT verify if keyId can not be dereferenced by the ' +
        'documentLoader', async function() {

      });

      it.skip('should NOT verify if headers is missing (key-id)', async function() {

      });

      it.skip('should NOT verify if headers is missing (created)', async function() {

      });

      it.skip('should NOT verify if headers is missing (expires)', async function() {

      });

      it.skip('should NOT verify if headers is missing (request-target)',
        async function() {

        });

      it.skip('should NOT verify if headers is missing host', async function() {

      });

      it.skip('should NOT verify if headers is missing capability-invocation',
        async function() {

        });

    });
  });
});
