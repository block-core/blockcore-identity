import { OperationCanceledException } from 'typescript';
import { BlockcoreIdentityTools, BlockcoreIdentity } from '../index';

test('My Identity', async () => {
	const tool = new BlockcoreIdentityTools();
	const privateKey = Uint8Array.from([
		224, 238, 59, 150, 73, 84, 228, 234, 104, 62, 83, 160, 122, 31, 108, 129, 74, 29, 104, 195, 192, 81, 158, 11, 167,
		100, 217, 121, 110, 12, 178, 14,
	]);

	const signer = tool.getSigner(privateKey);
	const publicKey = tool.getPublicKeyFromPrivateKey(privateKey);
	const verificationMethod = tool.getVerificationMethod(publicKey);
	const identity = new BlockcoreIdentity(verificationMethod);

	const didDocument = identity.document({
		service: [
			{
				id: '#blockexplorer',
				type: 'BlockExplorer',
				serviceEndpoint: 'https://explorer.blockcore.net',
			},
		],
	});

	expect(didDocument != null).toBeTruthy();

	// The default pattern for key identifier is #key{keyIndex}.
	const kid = didDocument.id + '#key0';
	const jws = await identity.sign(
		signer,
		{ version: 0, iat: tool.getTimestampInSeconds(), didDocument: didDocument },
		kid,
	);
});

test('Key transformations', () => {
	const tool = new BlockcoreIdentityTools();

	const privateKey = Uint8Array.from([
		224, 238, 59, 150, 73, 84, 228, 234, 104, 62, 83, 160, 122, 31, 108, 129, 74, 29, 104, 195, 192, 81, 158, 11, 167,
		100, 217, 121, 110, 12, 178, 14,
	]);

	const privateKey2 = Uint8Array.from([
		135, 180, 63, 60, 189, 43, 198, 233, 203, 31, 154, 96, 217, 192, 199, 149, 133, 174, 153, 50, 102, 21, 84, 244, 94,
		56, 88, 29, 104, 231, 150, 12,
	]);

	const keyHex = tool.bytesToHex(privateKey);
	expect(keyHex).toEqual('e0ee3b964954e4ea683e53a07a1f6c814a1d68c3c0519e0ba764d9796e0cb20e');

	const keyPair = tool.convertPrivateKeyToJsonWebKeyPair(privateKey);
	expect(keyPair.privateJwk.d).toEqual('4O47lklU5OpoPlOgeh9sgUodaMPAUZ4Lp2TZeW4Msg4=');

	// This key has no prefix.
	const publicKeySchnorr = tool.getSchnorrPublicKeyFromPrivateKey(privateKey);

	// This key has prefix for odd/even
	const publicKeyCompressed = tool.getPublicKeyFromPrivateKey(privateKey, true);
	const publicKeyCompressed2 = tool.getPublicKeyFromPrivateKey(privateKey2, true);

	// This key has prefix for uncompressed
	const publicKeyUncompressed = tool.getPublicKeyFromPrivateKey(privateKey);

	expect(publicKeySchnorr).toEqual(publicKeyCompressed.subarray(1));
	expect(publicKeyUncompressed[0]).toEqual(4);

	expect(publicKeyCompressed[0]).toEqual(3); // odd
	expect(publicKeyCompressed2[0]).toEqual(2); // even

	// The DID ID is based upon hex formatted schnorr public key.
	const did = tool.bytesToHex(publicKeySchnorr);
	expect(did).toEqual('0f254e55a2633d468e92aa7dd5a76c0c9101fab8e282c8c20b3fefde0d68f217');

	const publicKey = tool.convertPublicKeyToJsonWebKey(publicKeyUncompressed);

	expect(publicKey.x).toEqual('DyVOVaJjPUaOkqp91adsDJEB-rjigsjCCz_v3g1o8hc=');
	expect(publicKey.y).toEqual('lV1bYtyeizYCO5ycRQKx8Ug7cYzsliPcjFWtO-f8w6s=');

	expect(tool.convertJsonWebKeyToPublicKeyHex(publicKey)).toEqual(
		'040f254e55a2633d468e92aa7dd5a76c0c9101fab8e282c8c20b3fefde0d68f217955d5b62dc9e8b36023b9c9c4502b1f1483b718cec9623dc8c55ad3be7fcc3ab',
	);
});

test('Random Key transformations', () => {
	const tool = new BlockcoreIdentityTools();
	const privateKey = tool.generatePrivateKey();
	const keyHex = tool.bytesToHex(privateKey);
	expect(keyHex.length).toBe(64);

	const keyPair = tool.convertPrivateKeyToJsonWebKeyPair(privateKey);
	expect(keyPair.privateJwk.d.length).toBe(44);

	// This key has no prefix.
	const publicKeySchnorr = tool.getSchnorrPublicKeyFromPrivateKey(privateKey);

	// This key has prefix for odd/even
	const publicKeyCompressed = tool.getPublicKeyFromPrivateKey(privateKey, true);

	// This key has prefix for uncompressed
	const publicKeyUncompressed = tool.getPublicKeyFromPrivateKey(privateKey);

	expect(publicKeySchnorr).toEqual(publicKeyCompressed.subarray(1));
	expect(publicKeyUncompressed[0]).toEqual(4);

	// The DID ID is based upon hex formatted schnorr public key.
	const did = tool.bytesToHex(publicKeySchnorr);
	expect(did.length).toBe(64);

	const publicKey = tool.convertPublicKeyToJsonWebKey(publicKeyUncompressed);

	expect(publicKey.x?.length).toBe(44);
	expect(publicKey.y?.length).toBe(44);

	expect(tool.convertJsonWebKeyToPublicKeyHex(publicKey).length).toBe(130);
});
