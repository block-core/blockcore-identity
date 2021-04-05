// Based on Decentralized Identifiers (DIDs) v1.0
// W3C Working Draft 26 January 2021 / W3C Working Draft 09 March 2021
// https://w3c.github.io/did-core/

import base64url from 'base64url'; // Should we replicate this code to avoid dependency? It's a very simple utility.
import utf8 from 'utf8';
import { createJWS, createJWT, decodeJWT, ES256KSigner } from 'did-jwt';
import fetch from 'cross-fetch'
import { DIDDocument, ParsedDID, Resolver } from 'did-resolver';
import * as randomBytes from 'randombytes';
import * as secp256k1 from '@transmute/did-key-secp256k1';
import { Secp256k1KeyPair } from '@transmute/did-key-secp256k1';
import { ISecp256k1PrivateKeyJwk } from '@transmute/did-key-secp256k1/dist/keyUtils';
import { VerificationMethod } from './interfaces';
import { createVerifiableCredentialJwt, Issuer, JwtCredentialPayload, normalizeCredential } from 'did-jwt-vc';

export class BlockcoreIdentityIssuer {

}

/** Blockcore DID only supports secp256k so APIs and code is simplified compared to variuos other implementations. */
export class BlockcoreIdentity {

   public static readonly PREFIX = 'did:is:';
   public readonly id: string;

   // readonly privateKey: string;
   private readonly verificationMethod;

   constructor(verificationMethod: VerificationMethod) {

      console.log('BlockcoreIdentity input:');
      console.log(verificationMethod);

      this.id = verificationMethod.controller;
      this.verificationMethod = verificationMethod;

      // if (privateKey.substring(0, 2) != '0x') {
      //    privateKey += '0x';
      // }

      // this.privateKey = privateKey;
   }

   // constructor(address: string, privateKey: string) {
   //    this.id = 'did:is:' + address;

   //    if (privateKey.substring(0, 2) != '0x') {
   //       privateKey += '0x';
   //    }

   //    this.privateKey = privateKey;
   // }

   private ordered(a: any, b: any) {
      let comparison = 0;
      if (a.id > b.id) {
         comparison = 1;
      } else if (a.id < b.id) {
         comparison = -1;
      }
      return comparison;
   }

   /** Sign a payload, this method only supports ES256K. */
   // public async signJwt(params: { header?: any, payload: any, privateKeyJwk: ISecp256k1PrivateKeyJwk }) {

   //    let method = 'sign';
   //    let header = params.header || {};

   //    header = Object.assign(header, {
   //       alg: 'ES256K'
   //    });

   //    // TODO: Until the signing library supports Multibase, we'll rely on Jwk for now.
   //    // Initially we performed transforms to multibase on all our APIs, but changed to Jwk to reduce code.
   //    const signed = await secp256k1.ES256K.sign(params.payload, params.privateKeyJwk, header);
   //    return signed;
   // }

   /** Signs a payload and encodes as JWT (JWS). The key should be in string format (hex, base58, base64). Adds "iat", "iss" to payload and "typ" to header. */
   public async jwt(options: { privateKey: string | any, payload: any }) {
      const signer = ES256KSigner(options.privateKey);
      let jwt = await createJWT(options.payload, { issuer: this.id, signer });
      return jwt;
   }

   /** Returns a signed JWS from the payload. This method does NOT append any extra fields to the payload, but adds "issuer" to header. */
   public async jws(options: { privateKey: string | any, payload: any }) {
      const signer = ES256KSigner(options.privateKey);
      let jwt = await createJWS(options.payload, signer, { issuer: this.id });
      return jwt;
   }

   // public async vc(options: { privateKey: string | any, payload: any }) {

   //    const vcPayload: JwtCredentialPayload = {
   //       sub: this.id,
   //       nbf: Math.floor(Date.now() / 1000),
   //       vc: {
   //         '@context': ['https://www.w3.org/2018/credentials/v1'],
   //         type: ['VerifiableCredential'],
   //         credentialSubject: {
   //           degree: {
   //             type: 'BachelorDegree',
   //             name: 'Baccalauréat en musiques numériques'
   //           }
   //         }
   //       }
   //     }

   //    const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);
   //    console.log(vcJwt);


   //    const signer = ES256KSigner(options.privateKey);
   //    let jwt = await createJWT(options.payload, { alg: 'ES256K', issuer: this.id, signer })
   //    return jwt;
   // }

   /** Generate the did.json document for this identity. This is a simple structure with only the identifier. */
   public did() {
      return {
         '@context': ['https://www.w3.org/ns/did/v1'],
         id: this.id
      };
   }

   /** Generates the DID document for the current identity. */
   public document(options: { service: [] } | any = null) {
      const data: any = {};
      data['@context'] = ['https://www.w3.org/ns/did/v1'];
      data.id = this.id;
      data.verificationMethod = [this.verificationMethod];

      if (options?.service) {
         data.service = options.service.sort(this.ordered);
      }

      // Get the unique ID of the verification method, this might have extra data to make it unique in the list (#key-1).
      data.authentication = [this.verificationMethod.id];

      return data;
   }

   /** Generates the DID document for the current identity. */
   public configuration2(options: { service: [] } | any = null) {
      const data: any = {};
      data['@context'] = ['https://www.w3.org/2018/credentials/v1', 'https://identity.foundation/.well-known/did-configuration/v1'];
      data.id = this.id;
      data.verificationMethod = [this.verificationMethod];

      data.issuer = this.id;
      // data.issuanceDate = 

      if (options?.service) {
         data.service = options.service.sort(this.ordered);
      }

      return data;
   }

   /** Generates an issuer based on the identity */
   public issuer(options: { privateKey: Uint8Array | string | any }): Issuer {
      return {
         did: this.id,
         signer: ES256KSigner(options.privateKey),
         alg: 'ES256K'
      };
   }

   /** Generates a well known configuration for DID resolver host. */
   public async configurationVerifiableCredential(domain: string, issuer: any) {
      const date = new Date();
      const expiredate = new Date(new Date().setFullYear(date.getFullYear() + 100));

      const vcPayload: JwtCredentialPayload = {
         exp: Math.floor(expiredate.getTime() / 1000),
         iss: this.id,
         nbf: Math.floor(date.getTime() / 1000),
         sub: this.id,
         vc: {
            '@context': ['https://www.w3.org/2018/credentials/v1', 'https://identity.foundation/.well-known/did-configuration/v1'],
            type: ['VerifiableCredential', 'DomainLinkageCredential'],
            credentialSubject: {
               'id': this.id,
               'origin': domain
            },
            //"expirationDate": expiredate.toISOString(),
            //"issuanceDate": date.toISOString(),
            //"issuer": this.id,
         }
      }

      const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer);

      return vcJwt;
   }

   /** Generates a well known configuration for DID resolver host. */
   public async configuration(domain: string, issuer: any) {

      var vc = await this.configurationVerifiableCredential(domain, issuer);

      var vcNormalized = normalizeCredential(vc, true)
      // var vcDecoded = decodeJWT(vc); // This is wrong and does not convert the JWT-VC according to the "vc-data-model" specification. Use normalize from "did-jwt-vc" library.

      const data: any = {};
      data['@context'] = 'https://identity.foundation/.well-known/did-configuration/v1';

      data.linked_dids = [
         vcNormalized, vc
      ];

      return data;
   }
}

export interface Identity {

}

// JWK example:
// const { publicKeyJwk, privateKeyJwk } = await keyPair.toJsonWebKeyPair(true);

// return {
//    publicJwk: publicKeyJwk,
//    privateJwk: privateKeyJwk
// };
