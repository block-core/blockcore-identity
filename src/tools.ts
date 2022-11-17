import { BlockcoreIdentity } from './identity';
import { VerificationMethod } from './interfaces';
import * as secp from '@noble/secp256k1';
import { ES256KSigner } from 'did-jwt';
import { base64url } from '@scure/base';

export class BlockcoreIdentityTools {
  private numTo32String(num: number | bigint): string {
    return num.toString(16).padStart(64, '0');
  }

  getTimestampInSeconds() {
    return Math.floor(Date.now() / 1000);
  }

  /** Returns the public key in schnorr format. */
  getSchnorrPublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
    return secp.schnorr.getPublicKey(privateKey);
  }

  bytesToHex(publicKey: Uint8Array) {
    return secp.utils.bytesToHex(publicKey);
  }

  /** Takes a public key (either Schnorr or Edsca) and converts it into a schnorr public key and formats as hex. */
  getSchnorrPublicKeyHex(publicKey: Uint8Array) {
    if (publicKey.length === 33) {
      publicKey = this.convertEdcsaPublicKeyToSchnorr(publicKey);
    }

    return this.bytesToHex(publicKey);
  }

  convertEdcsaPublicKeyToSchnorr(publicKey: Uint8Array) {
    if (publicKey.length != 33) {
      throw Error('The public key must be compressed EDCSA public key of length 33.');
    }

    const schnorrPublicKey = publicKey.slice(1);
    return schnorrPublicKey;
  }

  getSigner(privateKey: Uint8Array) {
    return ES256KSigner(privateKey);
  }

  generateKey(): Uint8Array {
    return secp.utils.randomPrivateKey();
  }

  /** Get a VerificationMethod structure from a public key. */
  getVerificationMethod(
    publicKey: Uint8Array,
    keyIndex: number = 0,
    method: string = BlockcoreIdentity.PREFIX,
  ): VerificationMethod {
    const publicKeyHex = this.bytesToHex(publicKey);
    const did = `${method}:${publicKeyHex}`;

    return {
      id: `#key${keyIndex}`,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: this.getJsonWebKey(publicKeyHex),
    };
  }

  /** Returns a pair of JSON Web Key that holds public key and private key. */
  getKeyPair(privateKey: Uint8Array) {
    const publicKey = secp.schnorr.getPublicKey(privateKey);
    const publicKeyHex = secp.utils.bytesToHex(publicKey);

    const d = base64url.encode(privateKey);
    const publicJwk = this.getJsonWebKey(publicKeyHex);
    const privateJwk = { ...publicJwk, d };

    return { publicJwk, privateJwk };
  }

  /** Creates a JsonWebKey from a public key hex. */
  getJsonWebKey(publicKeyHex: string): JsonWebKey {
    const pub = secp.Point.fromHex(publicKeyHex);
    const x = secp.utils.hexToBytes(this.numTo32String(pub.x));
    const y = secp.utils.hexToBytes(this.numTo32String(pub.y));

    return {
      kty: 'EC',
      crv: 'secp256k1',
      x: base64url.encode(x), // This version of base64url uses padding.
      y: base64url.encode(y), // Without padding: Buffer.from(bytesOfX).toString('base64url')
      // Example from did-jwt: bytesToBase64url(hexToBytes(kp.getPublic().getY().toString('hex')))
    };
  }
}
