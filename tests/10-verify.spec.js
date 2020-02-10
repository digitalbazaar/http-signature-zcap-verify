import {verifyCapabilityInvocation} from '..';
import {suites} from 'jsonld-signatures';
import {Ed25519KeyPair, RSAKeyPair} from 'crypto-ld';
import uuid from 'uuid-random';

const {Ed25519Signature2018, RsaSignature2018} = suites;

const Ed25519 = {
  type: 'Ed25519',
  Suite: Ed25519Signature2018,
  LDKeyPair: Ed25519KeyPair,
};

const Rsa = {
  type: 'Rsa',
  Suite: RsaSignature2018,
  LDKeyPair: RSAKeyPair
};

const controller = 'did:test:controller';

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
  return {keyId, keyPair, suite, documentLoader};
};

describe('verifyCapabilityInvocation', function() {
  [Ed25519, Rsa].forEach(function(suiteType) {

    let suite, documentLoader, keyId = null;

    before(async function() {
      ({suite, documentLoader, keyId} = await setup(suiteType));
    });

    describe(suite.type, function() {

      it('should verify a valid requiest', async function() {

      });

      it('should add headers if content-type is in headers', async function() {

      });

      it('should verify with additionalHeaders', async function() {

      });

      it('should THROW if no getInvokedCapability', async function() {

      });

      it('should THROW if no documentLoader', async function() {

      });

      it('should THROW if verificationMethod type is not supported',
        async function() {

        });

      it('should NOT verify if there is no url', async function() {

      });

      it('should NOT verify if there are no headers', async function() {

      });

      it('should NOT verify if host is not in expectedHost', async function() {

      });

      it('should NOT verify if keyId can not be dereferenced by the ' +
        'documentLoader', async function() {

      });

      it('should NOT verify if headers is missing (key-id)', async function() {

      });

      it('should NOT verify if headers is missing (created)', async function() {

      });

      it('should NOT verify if headers is missing (expires)', async function() {

      });

      it('should NOT verify if headers is missing (request-target)',
        async function() {

        });

      it('should NOT verify if headers is missing host', async function() {

      });

      it('should NOT verify if headers is missing capability-invocation',
        async function() {

        });

    });
  });
});
