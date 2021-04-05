import { decodeJWT, verifyJWT } from 'did-jwt';
import { Resolver } from 'did-resolver';
import { JwtCredentialPayload, createVerifiableCredentialJwt, JwtPresentationPayload, createVerifiablePresentationJwt, verifyCredential, verifyPresentation } from 'did-jwt-vc';

import { getResolver } from '../lib/blockcore-did-resolver';
import { BlockcoreIdentity, BlockcoreIdentityTools } from '../lib/blockcore-identity';
import { bitcoin } from 'bitcoinjs-lib/types/networks';
import { ECPair, payments } from 'bitcoinjs-lib';
import { keyUtils, Secp256k1KeyPair } from '@transmute/did-key-secp256k1';
import randomBytes from 'randombytes';

export async function app() {
   // private key User:
   const privateKeyWif = '7A1HsYie1A7hnzTh7wYwrWmUw1o2Ca4YXdwpkrEgnyDHNLqXPvZ';
   const privateKeyHex = '0xA82AA158A4801BABCA9361D06404E077B7D9D5FDF9674DFCC6B581FA1F32A36F';
   const privateKeyBase64 = 'qCqhWKSAG6vKk2HQZATgd7fZ1f35Z038xrWB+h8yo28=';
   const address2 = 'PTcn77wZrhugyrxX8AwZxy4xmmqbCvZcKu';

   // private key Blockcore
   const privateKeyBlockcoreHex = '039C4896D85A3121039AB57637B9D18FB8686E23AA3EBD26C9731A5F04D5298119';
   const addressBlockcore = 'PU5DqJxAif5Jr1H3od4ynrnXxLuMejaHuU';

   // const signer2 = didJWT.ES256KSigner('278a5de700e29faae8e40e366ec5012b5ec63d36ec77e8a2417154cc1d25383f')

   // let jwt2 = await didJWT.createJWT(
   //   { aud: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', exp: 1957463421, name: 'uPort Developer' },
   //   { issuer: 'did:ethr:0xf3beac30c498d9e26865f34fcaa57dbb935b0d74', signer: signer2 },
   //   { alg: 'ES256K' }
   // )
   // console.log(jwt2);

   // let decoded = didJWT.decodeJWT(jwt2);
   // console.log(decoded);

   const tools = new BlockcoreIdentityTools();

   // var random = randomBytes(32);
   var random = Buffer.from('a5a65522bf1490644e31289f5e77a9737c3fac762b2606276979dd25691513e8', 'hex');

   // Create a key pair using the "bitcoinjs-lib".
   const bitcoinKeyPair = ECPair.makeRandom({ rng: () => random });

   // Create a key pair using '@transmute/did-key-secp256k1'.
   const didKeyPair = await Secp256k1KeyPair.generate({
      secureRandom: () => random
   });

   // Get the base58 value of the public key.
   const bitcoinPublicKeyBase58 = keyUtils.publicKeyBase58FromPublicKeyHex(
      bitcoinKeyPair.publicKey.toString('hex')
   );

   // Get the base58 value of the public key.
   const didPublicKeyBase58 = keyUtils.publicKeyBase58FromPublicKeyHex(
      didKeyPair.publicKeyBuffer.toString('hex')
   );

   // Keep both the keypair and webkey available to use.
   let keyPairBitcoin = await tools.keyPairFrom({ publicKeyBase58: bitcoinPublicKeyBase58, privateKeyHex: bitcoinKeyPair.privateKey?.toString('hex') });

   let keyPairDid = await tools.keyPairFrom({ publicKeyBase58: didPublicKeyBase58, privateKeyHex: didKeyPair.privateKeyBuffer?.toString('hex') });
   console.log(keyPairDid.toKeyPair(true));

   // Alternative to generate both keys and wrap it.
   // let randomKeys = await tools.generateKeyPair();

   if (keyPairBitcoin.controller != keyPairDid.controller) {
      throw Error('Should be equal!');
   }

   let keyPairWebKey = await didKeyPair.toJsonWebKeyPair(true);

   // The WebKey get "did-key" values as they are not read from the keypair instance, so we have to override:
   keyPairWebKey.id = keyPairDid.id;
   keyPairWebKey.controller = keyPairDid.controller;

   console.log(keyPairWebKey);

   // Create an instance of Blockcore Identity using only public key.
   const identity = new BlockcoreIdentity(keyPairDid.toKeyPair(false));

   // Get the DID Document for this identity. This document is not signed.
   // Make the DID Document that will be hosted on blockcore.net
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

   console.log('DID DOCUMENT (JSON):');
   console.log(payload);

   // const signedJwt = await identity.signJwt({ payload: payload, privateKeyJwk: keyPairWebKey.privateKeyJwk });
   // console.log('SIGNED PAYLOAD:');
   // console.log(signedJwt);

   const jwt = await identity.jwt({
      payload: payload,
      privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
   });

   // Decode the JWT
   console.log('DID DOCUMENT (JWT):');
   console.log(jwt);
   console.log(JSON.stringify(decodeJWT(jwt)));


   const jws = await identity.jws({
      payload: payload,
      privateKey: didKeyPair.privateKeyBuffer?.toString('hex')
   });

   // Decode the JWS
   console.log('DID DOCUMENT (JWS):');
   console.log(jws);
   console.log(JSON.stringify(decodeJWT(jws)));

   var didDocumentDecoded = decodeJWT(jws);
   var didDocumentPayload = JSON.stringify(didDocumentDecoded.payload);

   console.log('COPY THIS:');
   console.log(didDocumentPayload);
   console.log('');

   console.log('JWS:');
   console.log(jws);

   // const { address } = payments.p2pkh({ pubkey: publicKeyBase58 });
   // const { address } = payments.p2pkh({ pubkey: keyPair2.publicKey });

   // Create a copy of the VerificationMethod that does not contain private key.
   // let publicKey = tools.removePrivateKey(keyPair);

   // console.log(keyPair);
   // console.log(randomKeys);
   // console.log(keyPairWebKey);

   // Create an instance of Blockcore Identity.
   // const identity = new BlockcoreIdentity(address, privateKeyHex);
   // const identity = new BlockcoreIdentity(keyPair.toKeyPair(false));

   // // Get the DID Document for this identity. This document is not signed.

   // // Make the DID Document that will be hosted on blockcore.net
   // const services = [
   //    {
   //       "id": `${identity.id}#blockexplorer`,
   //       "type": "BlockExplorer",
   //       "serviceEndpoint": "https://explorer.blockcore.net"
   //    },
   //    {
   //       "id": `${identity.id}#didresolver`,
   //       "type": "DIDResolver",
   //       "serviceEndpoint": "https://my.did.is"
   //    },
   //    {
   //       "id": `${identity.id}#edv`,
   //       "type": "EncryptedDataVault",
   //       "serviceEndpoint": "https://vault.blockcore.net/"
   //    }
   // ];

   // const payload = identity.document({ service: services });

   // console.log('PAYLOAD:');
   // console.log(payload);

   // // const jwt = await identity.jwt();
   // // console.log('JWT: ' + jwt);
   // // 
   // const signedJwt = await identity.signJwt({ payload: payload, privateKeyJwk: keyPairWebKey.privateKeyJwk });
   // console.log('SIGNED PAYLOAD:');
   // console.log(signedJwt);

   // const jwt = await identity.jwt(keyPairWebKey.privateKeyJwk);
   // console.log('JWT PAYLOAD:');
   // console.log(jwt);

   // return;

   // console.log('Blockcore Identity (CLI): Create');

   console.log('Your DID is: ', identity.did());
   //console.log('Your DID document is: ' + JSON.stringify(didJWT.decodeJWT(jwt)));
   // console.log('.well-known configuration: ' + JSON.stringify(identity.wellKnownConfiguration('did.is')));
   // // console.log('JWT: ' + identity.jwt());

   // Get the Bitcoin Resolver used to resolver DID Documents from REST API.
   const resolver = new Resolver(getResolver());

   // Create an issuer from the identity, this is used to issue VCs.
   const issuer = identity.issuer({ privateKey: didKeyPair.privateKeyBuffer?.toString('hex') });

   // import * as EthrDID from 'ethr-did'
   // import { Issuer } from 'did-jwt-vc'

   // const issuer: Issuer = new EthrDID({
   //   address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   //   privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
   // })

   var configuration = await identity.configuration('https://www.blockcore.net', issuer);
   console.log('did.configuration document:');
   console.log(JSON.stringify(configuration));

   const didJwt = configuration.linked_dids[1];

   // Decode the JWT, used for viewing.
   console.log(decodeJWT(didJwt));


   var didPayload = await identity.generateDidPayload(jws);
   console.log(didPayload);


   var verified = await verifyJWT(didJwt, { resolver: resolver });

   console.log('VERIFIED:');
   console.log(verified);

   console.log(JSON.stringify(identity.did()));

   // console.log('VERYFING:');
   // const verifiedVC = await verifyCredential(vcJwt, resolver);
   // console.log(verifiedVC);

   // const doc = await resolver.resolve(identity.id);
   // console.log('DID Document: ' + doc);

   // const vcPayload: JwtCredentialPayload = {
   //    sub: identity.id,
   //    nbf: Math.floor(Date.now() / 1000),
   //    vc: {
   //       '@context': ['https://www.w3.org/2018/credentials/v1'],
   //       type: ['VerifiableCredential', 'UniversityDegreeCredential'],
   //       credentialSubject: {
   //          degree: {
   //             type: 'BachelorDegree',
   //             name: 'Bachelor of Science and Arts'
   //          }
   //       }
   //    }
   // }

   // const issuer: Issuer = new issuer EthrDID({
   //    address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   //    privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
   //  })

   // const issuer: Issuer = new BlockcoreDID({
   //    address: addressBlockcore,
   //    privateKey: privateKeyBlockcoreHex
   // })

   // //  const issuer2: Issuer = new EthrDID({
   // //    address: '0xf1232f840f3ad7d23fcdaa84d6c66dac24efb198',
   // //    privateKey: 'd8b595680851765f38ea5405129244ba3cbad84467d190859f4c8b20c1ff6c75'
   // //  })

   // // const issuer = new Issuer().  didJWT.SimpleSigner(privateKeyHex);

   // const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer)
   // console.log('VC JWT:');
   // console.log(vcJwt);

   // const vpPayload: JwtPresentationPayload = {
   //    vp: {
   //       '@context': ['https://www.w3.org/2018/credentials/v1'],
   //       type: ['VerifiablePresentation'],
   //       verifiableCredential: [vcJwt]
   //    }
   // }

   // const vpJwt = await createVerifiablePresentationJwt(vpPayload, issuer)
   // console.log('VP JWT:');
   // console.log(vpJwt);

   // const verifiedVP = await verifyPresentation(vpJwt, resolver)
   // console.log('');
   // console.log('VERIFIED VP:');
   // console.log(verifiedVP);
   // console.log('');
   // console.log('');

   // console.log('VERYFING:');
   // const verifiedVC = await verifyCredential(vcJwt, resolver);
   // console.log(verifiedVC);

   // You can also use ES7 async/await syntax
   // const doc = await resolver.resolve('did:uport:2nQtiQG6Cgm1GYTBaaKAgr76uY7iSexUkqX/some/path#fragment=123')

   // pass the JWT from step 1 & 2
   // let verifiedResponse = await didJWT.verifyJWT(jwt, { resolver: resolver, audience: identity.id })
   // console.log(verifiedResponse);

   // var verfied = await verifyJWT(jwt, {audience: identity.id});
   // console.log(verfied);

   // import base64url from 'base64url'; // Should we replicate this code to avoid dependency? It's a very simple utility.
   // import utf8 from 'utf8';
   // import * as city from 'city-lib';
   // import * as blockcoreMessage from '@blockcore/message';

}

