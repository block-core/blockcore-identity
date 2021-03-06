import { OperationCanceledException } from 'typescript';
import { BlockcoreIdentity, BlockcoreIdentityTools } from '../index';
import { decodeJWT, verifyJWT } from 'did-jwt';
import { Resolver } from 'did-resolver';
import { JwtCredentialPayload, createVerifiableCredentialJwt, JwtPresentationPayload, createVerifiablePresentationJwt, verifyCredential, verifyPresentation, normalizeCredential } from 'did-jwt-vc';
import { bitcoin } from 'bitcoinjs-lib/types/networks';
import { ECPair, payments } from 'bitcoinjs-lib';
import { keyUtils, Secp256k1KeyPair } from '@transmute/did-key-secp256k1';
import randomBytes from 'randombytes';

const fs = require('fs');
const path = require('path');

function save(filename: string, content: string) {
  const filePath = path.join(__dirname, '..', '..', 'examples/', filename);
  console.log('Saving: ' + filePath);
  const data = fs.writeFileSync(filePath, content);
}

test('Generate Examples', async () => {
  const tools = new BlockcoreIdentityTools();
  var random = Buffer.from('a5a65522bf1490644e31289f5e77a9737c3fac762b2606276979dd25691513e8', 'hex');

  const didKeyPair = await Secp256k1KeyPair.generate({
    secureRandom: () => random
  });

  const didPublicKeyBase58 = keyUtils.publicKeyBase58FromPublicKeyHex(
    didKeyPair.publicKeyBuffer.toString('hex')
  );

  console.log('didPublicKeyBase58: ' + didPublicKeyBase58);
  console.log('private key hex: ' + didKeyPair.privateKeyBuffer?.toString('hex'));

  let keyPairDid = await tools.keyPairFrom({ publicKeyBase58: didPublicKeyBase58, privateKeyHex: didKeyPair.privateKeyBuffer?.toString('hex') });
  let keyPairWebKey = await didKeyPair.toJsonWebKeyPair(true);

  // The WebKey get "did-key" values as they are not read from the keypair instance, so we have to override:
  keyPairWebKey.id = keyPairDid.id;
  keyPairWebKey.controller = keyPairDid.controller;

  save('web-key-pair.json', JSON.stringify(keyPairWebKey, null, 2));

  // Create an instance of Blockcore Identity using only public key.
  const identity = new BlockcoreIdentity(keyPairDid.toKeyPair(false));

  // Content for the DID document.
  const services = [
    {
      "id": `${identity.id}#blockexplorer`,
      "type": "BlockExplorer",
      "serviceEndpoint": "https://explorer.blockcore.net"
    },
    {
      "id": `${identity.id}#didresolver`,
      "type": "DIDResolver",
      "serviceEndpoint": "https://my.did.is"
    },
    {
      "id": `${identity.id}#edv`,
      "type": "EncryptedDataVault",
      "serviceEndpoint": "https://vault.blockcore.net/"
    }
  ];

  const payload = identity.document({ service: services });
  save('did-document-payload.json', JSON.stringify(payload, null, 2));

  // const signedJwt = await identity.signJwt({ payload: payload, privateKeyJwk: keyPairWebKey.privateKeyJwk });
  // console.log('SIGNED PAYLOAD:');
  // console.log(signedJwt);

  const jwt = await identity.jwt({
    payload: payload,
    privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
  });

  save('did-document-jwt.txt', jwt);
  save('did-document-jwt-decoded.json', JSON.stringify(decodeJWT(jwt), null, 2));

  const jws = await identity.jws({
    payload: payload,
    privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
  });

  save('did-document-jws.txt', jws);
  save('did-document-jws-decoded.json', JSON.stringify(decodeJWT(jws), null, 2));

  var didDocumentDecoded = decodeJWT(jws);
  var didDocumentPayload = JSON.stringify(didDocumentDecoded.payload, null, 2);

  save('did.json', JSON.stringify(identity.did(), null, 2));

  // Create an issuer from the identity, this is used to issue VCs.
  const issuer = identity.issuer({ privateKey: didKeyPair.privateKeyBuffer?.toString('hex') });

  var configuration = await identity.configuration('https://www.blockcore.net', issuer);

  save('did-configuration.json', JSON.stringify(configuration, null, 2));

  var vc = await identity.configurationVerifiableCredential('https://www.blockcore.net', issuer);
  save('did-configuration-vc-jwt.txt', vc);

  // This decoding of an JWT-VC is invalid, as it does not copy the JWT-fields into the VC JSON structure.
  // Added as an example, and these outputs should not be used.
  var vcDecoded = decodeJWT(vc);
  save('did-configuration-vc-jwt-decoded.json', JSON.stringify(vcDecoded, null, 2));

  const didJwt = configuration.linked_dids[1];

  // This will transform an JWT-VC into an JSON-VC and embedd the "JwtProof2020" proof type.
  save('vc-normalized.json', JSON.stringify(normalizeCredential(didJwt, true), null, 2));
  save('vc-normalized-original-values.json', JSON.stringify(normalizeCredential(didJwt, false), null, 2));

  var didPayload = await identity.generateDidPayload(jws);
  save('did-payload.json', JSON.stringify(didPayload, null, 2));

  var operationPayloadCreate = await identity.generateOperation('identity', 'create', 0, jws);

  const operationCreateJws = await identity.jws({
    payload: operationPayloadCreate,
    privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
  });

  save('operation-create.json', JSON.stringify(operationCreateJws, null, 2));

  // var operationPayload = await identity.generateOperation('identity', 'replace', 1, jws);

  // const operationReplaceJws = await identity.jws({
  //    payload: operationPayload,
  //    privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
  // });

  // save('operation-replace.json', JSON.stringify(operationReplaceJws, null, 2));

  for (var i = 1; i < 11; i++) {

    var operationPayload = await identity.generateOperation('identity', 'replace', i, jws);

    const operationReplaceJws = await identity.jws({
      payload: operationPayload,
      privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
    });

    save('operation-replace-' + i + '.json', JSON.stringify(operationReplaceJws, null, 2));
  }

  // Get the Bitcoin Resolver used to resolver DID Documents from REST API.
  // const resolver = new Resolver(getResolver());

  // var verified = await verifyJWT(didJwt, { resolver: resolver });
  // save('vc-verified.json', JSON.stringify(verified, null, 2));
});