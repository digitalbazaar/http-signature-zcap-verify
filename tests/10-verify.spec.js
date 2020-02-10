import {verifyCapabilityInvocation} from '..';
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
const invoker = 'did:test:invoker';
const url = 'https://test.org/zcaps/foo';
const expectedHost = 'test';

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
  const documentLoader = async url => {
    if(url === keyId) {
      return keyPair.publicNode();
    }
    throw new Error(`documentLoader unable to resolve ${url}`);
  };
  const getInvokedCapability = ({id, expectedTarget}) => {
    return {
      '@context': SECURITY_CONTEXT_V2_URL,
      id: url,
      invocationTarget: url,
      controller,
      delegator,
      invoker
    };
  };
  const created = Date.now() - 1000;
  const expires = Date.now() + 10000;
  const headers = {
    url,
    host: expectedHost,
    date: created,
    'capability-invocation': url,
    authorization: `Signature keyId="${keyId}",created="${created}",` +
      `expires="${expires}",requestTarget="${url}",signature="foo"`
  };
  return {keyId, keyPair, suite, documentLoader, getInvokedCapability, headers};
};

describe('verifyCapabilityInvocation', function() {
  [Ed25519, Rsa].forEach(function(suiteType) {

    describe(suiteType.type, function() {
      let suite, documentLoader, keyId, getInvokedCapability, headers = null;

      beforeEach(async function() {
        ({
          suite,
          documentLoader,
          keyId,
          headers,
          getInvokedCapability
        } = await setup(suiteType));
      });

      it('should verify a valid request', async function() {
        console.log('headers', headers);
        const result = await verifyCapabilityInvocation({
          url,
          suite,
          headers,
          getInvokedCapability,
          documentLoader,
          keyId
        });
        console.log('result', result);
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
