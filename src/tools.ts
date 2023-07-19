import { BlockcoreIdentity } from './identity';
import { VerificationMethod } from './interfaces';
import { ES256KSigner } from 'did-jwt';
import { base64url } from '@scure/base';
import * as secp from '@noble/secp256k1';
import { createVerifiableCredentialJwt, Issuer, JwtCredentialPayload, normalizeCredential } from 'did-jwt-vc';

export class BlockcoreIdentityTools {
	getTimestampInSeconds() {
		return Math.floor(Date.now() / 1000);
	}

	getSigner(privateKey: Uint8Array) {
		return ES256KSigner(privateKey);
	}

	getIssuer(did: string, privateKey: Uint8Array): Issuer {
		return {
			did: did,
			signer: ES256KSigner(privateKey),
			alg: 'ES256K',
		};
	}

	/** Generates a new random private key. */
	generatePrivateKey(): Uint8Array {
		return secp.utils.randomPrivateKey();
	}

	bytesToHex(bytes: Uint8Array) {
		return secp.utils.bytesToHex(bytes);
	}

	/** Get a VerificationMethod structure from a public key. */
	getVerificationMethod(
		publicKey: Uint8Array,
		keyIndex: number = 0,
		method: string = BlockcoreIdentity.PREFIX,
	): VerificationMethod {
		// The DID ID is based on schnorr public key hex:
		const id = this.convertPublicKeyToSchnorrPublicKeyHex(publicKey);
		// const id2 = this.bytesToHex(publicKey.slice(1).subarray(0, 32));
		const did = `${method}:${id}`;

		return {
			id: `#key${keyIndex}`,
			type: 'JsonWebKey2020',
			controller: did,
			publicKeyJwk: this.convertPublicKeyToJsonWebKey(publicKey),
		};
	}

	/** Retrieves the DID ID from the JsonWebKey. */
	getIdentifierFromJsonWebKey(publicKey: JsonWebKey) {
		const transformedKey = this.convertJsonWebKeyToPublicKey(publicKey);
		return this.convertPublicKeyToSchnorrPublicKeyHex(transformedKey);
	}

	/** Returns the public key in schnorr format, supported both compressed and uncompressed public keys. */
	getSchnorrPublicKeyFromPrivateKey(privateKey: Uint8Array): Uint8Array {
		return secp.schnorr.getPublicKey(privateKey);
	}

	/** Returns the public key in Edsca format. */
	getPublicKeyFromPrivateKey(privateKey: Uint8Array, compressed: boolean = false): Uint8Array {
		return secp.getPublicKey(privateKey, compressed);
	}

	/** Takes a public key (either Schnorr or Edsca) and converts it into a schnorr public key and formats as hex. */
	convertPublicKeyToSchnorrPublicKeyHex(publicKey: Uint8Array) {
		// Slice & Dice
		if (publicKey.length > 32) {
			publicKey = publicKey.slice(1);
		}

		if (publicKey.length > 32) {
			publicKey = publicKey.subarray(0, 32);
		}

		return this.bytesToHex(publicKey);
	}

	/** Returns a pair of JSON Web Key that holds public key and private key. */
	convertPrivateKeyToJsonWebKeyPair(privateKey: Uint8Array) {
		const publicKey = secp.getPublicKey(privateKey);
		const publicKeyHex = secp.utils.bytesToHex(publicKey);

		const d = base64url.encode(privateKey);
		const publicJwk = this.convertPublicKeyHexToJsonWebKey(publicKeyHex);
		const privateJwk = { ...publicJwk, d };

		return { publicJwk, privateJwk };
	}

	/** Returns a pair of JSON Web Key that holds public key and private key. */
	convertPrivateKeyToJsonWebKeyPairWithoutPadding(privateKey: Uint8Array) {
		const publicKey = secp.getPublicKey(privateKey);
		const publicKeyHex = secp.utils.bytesToHex(publicKey);

		const d = base64url.encode(privateKey);
		const publicJwk = this.convertPublicKeyHexToJsonWebKeyWithoutPadding(publicKeyHex);
		const privateJwk = { ...publicJwk, d };

		return { publicJwk, privateJwk };
	}

	/** Creates a JsonWebKey from a public key hex. Allows conversion of both compressed and uncompressed public keys. */
	convertPublicKeyHexToJsonWebKey(publicKeyHex: string): JsonWebKey {
		if (publicKeyHex.length <= 64) {
			throw new Error('The public key hex must be uncompressed.');
		}

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

	convertPublicKeyHexToJsonWebKeyWithoutPadding(publicKeyHex: string): JsonWebKey {
		if (publicKeyHex.length <= 64) {
			throw new Error('The public key hex must be uncompressed.');
		}

		const pub = secp.Point.fromHex(publicKeyHex);
		const x = secp.utils.hexToBytes(this.numTo32String(pub.x));
		const y = secp.utils.hexToBytes(this.numTo32String(pub.y));

		return {
			kty: 'EC',
			crv: 'secp256k1',
			x: Buffer.from(x).toString('base64url'),
			y: Buffer.from(y).toString('base64url'),
		};
	}

	/** Creates a JsonWebKey from a public key array. Allows conversion of both compressed and uncompressed public keys. */
	convertPublicKeyToJsonWebKey(publicKey: Uint8Array): JsonWebKey {
		return this.convertPublicKeyHexToJsonWebKey(this.bytesToHex(publicKey));
	}

	/** Transforms a JSON Web Key into a hex string. */
	convertJsonWebKeyToPublicKeyHex(key: JsonWebKey): string {
		return secp.utils.bytesToHex(this.convertJsonWebKeyToPublicKey(key));
	}

	/** Transforms a JSON Web Key into a byte array. */
	convertJsonWebKeyToPublicKey(key: JsonWebKey) {
		if (!key.x) {
			throw new Error('The key has undefined x.');
		}

		if (!key.y) {
			throw new Error('The key has undefined y.');
		}

		const x = base64url.decode(key.x);
		const y = base64url.decode(key.y);

		const point = new secp.Point(this.bytesToNumber(x), this.bytesToNumber(y));
		point.assertValidity();

		return point.toRawBytes(false);
	}

	private bytesToNumber(bytes: Uint8Array): bigint {
		return this.hexToNumber(this.bytesToHex(bytes));
	}

	private hexToNumber(hex: string): bigint {
		if (typeof hex !== 'string') {
			throw new TypeError('hexToNumber: expected string, got ' + typeof hex);
		}
		// Big Endian
		return BigInt(`0x${hex}`);
	}

	private numTo32String(num: number | bigint): string {
		return num.toString(16).padStart(64, '0');
	}
}
