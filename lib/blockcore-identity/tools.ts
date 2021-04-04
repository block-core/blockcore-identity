import { keyUtils, Secp256k1KeyPair } from "@transmute/did-key-secp256k1";
import { ISecp256k1PrivateKeyJwk } from "@transmute/did-key-secp256k1/dist/keyUtils";
import { payments } from "bitcoinjs-lib";
import randomBytes from "randombytes";
import { BlockcoreIdentity } from "./identity";
import { VerificationMethodWithPrivateKey } from "./interfaces";
import * as bs58 from 'bs58';

export class BlockcoreIdentityTools {

   /** Get the address (identity) of this DID. Returned format is "did:is:[identity]" */
   getIdentity(options: { publicKeyBase58?: string | any, publicKeyBuffer?: Buffer }) {

      // If the buffer is not supplied, then we'll convert base58 to buffer.
      if (!options.publicKeyBuffer) {
         options.publicKeyBuffer = bs58.decode(options.publicKeyBase58);
      }

      const { address } = payments.p2pkh({
         pubkey: options.publicKeyBuffer,
         network: this.getProfileNetwork(),
      });

      return `${BlockcoreIdentity.PREFIX}${address}`;
   }

   getIdentifiers(identity: string | any): { id: string, controller: string } {
      return {
         id: `${identity}#key-1`,
         controller: `${identity}`
      };
   }

   getProfileNetwork() {
      return {
         messagePrefix: '\x18Identity Signed Message:\n',
         bech32: 'id',
         bip32: {
            public: 0x0488b21e,
            private: 0x0488ade4
         },
         pubKeyHash: 55,
         scriptHash: 117,
         wif: 0x08
      };
   }

   /** Generates a new pair of public and private key that can be used for an Blockcore Identity. */
   async generateKeyPair(): Promise<Secp256k1KeyPair> {

      const keyPair = await Secp256k1KeyPair.generate({
         secureRandom: () => randomBytes(32)
      });

      const publicKeyBase58 = keyUtils.publicKeyBase58FromPublicKeyHex(
         Buffer.from(keyPair.publicKeyBuffer).toString('hex')
      );

      const identity = this.getIdentity({ publicKeyBase58 });
      const identifiers = this.getIdentifiers(identity);

      keyPair.id = identifiers.id;
      keyPair.controller = identifiers.controller;

      return keyPair;
   }

   /** Used to create an instance of the key pair from base58/hex formats. The public key must be in base58 encoding. */
   async keyPairFrom(options: {
      publicKeyBase58: string | any,
      privateKeyBase58?: string,
      privateKeyHex?: string,
      privateKeyJwk?: string | any | ISecp256k1PrivateKeyJwk
   }): Promise<Secp256k1KeyPair> {

      if (options.privateKeyHex && options.privateKeyHex.startsWith('0x')) {
         options.privateKeyHex = options.privateKeyHex.substring(2);
      }

      const identity = this.getIdentity(options);
      const identifiers = this.getIdentifiers(identity);

      options = Object.assign(options, identifiers);

      // Get a new key instance parsed from either base58, hex or jwk.
      // The public key we require to base58, because we must include it in the options to override defaults.
      const key = await Secp256k1KeyPair.from(options);

      return key;
   }

   /** Converts the KeyPair and returns an verificationMethod structure with multibase public key. */
   convertToMultibase(key: Secp256k1KeyPair | any): VerificationMethodWithPrivateKey {
      key.publicKeyMultibase = 'z' + key.publicKeyBase58;
      delete key.publicKeyBase58;

      key.privateKeyMultibase = 'z' + key.privateKeyBase58;
      delete key.privateKeyBase58;

      return key;
   }

   removePrivateKey(verificationMethod: VerificationMethodWithPrivateKey) {
      return {
         id: verificationMethod.id,
         type: verificationMethod.type,
         controller: verificationMethod.controller,
         publicKeyMultibase: verificationMethod.controller,
      };
   }
}