import { OperationCanceledException } from 'typescript';
import { BlockcoreIdentityTools, BlockcoreIdentity } from '../index';

test('Create Verifiable Credentials', async () => {
	const tool = new BlockcoreIdentityTools();
	const privateKey = Uint8Array.from([
		224, 238, 59, 150, 73, 84, 228, 234, 104, 62, 83, 160, 122, 31, 108, 129, 74, 29, 104, 195, 192, 81, 158, 11, 167,
		100, 217, 121, 110, 12, 178, 14,
	]);

	const signer = tool.getSigner(privateKey);
	const publicKey = tool.getPublicKeyFromPrivateKey(privateKey);
	const verificationMethod = tool.getVerificationMethod(publicKey);
	const identity = new BlockcoreIdentity(verificationMethod);

	const kid = `${verificationMethod.controller}${verificationMethod.id}`;
	const issuer = tool.getIssuer(identity.did, privateKey);

	const vc = await identity.verifiableCredential(
		{ id: 'did:is:0f254e55a2633d468e92aa7dd5a76c0c9101fab8e282c8c20b3fefde0d68f217', sameAs: 'mail@mail.com' },
		issuer,
		kid,
		'123',
		'EmailVerification',
	);

	console.log(vc);

	expect(vc != null).toBeTruthy();

	// const didDocument = identity.document({
	// 	service: [
	// 		{
	// 			id: '#blockexplorer',
	// 			type: 'BlockExplorer',
	// 			serviceEndpoint: 'https://explorer.blockcore.net',
	// 		},
	// 	],
	// });

	// expect(didDocument != null).toBeTruthy();

	// // The default pattern for key identifier is #key{keyIndex}.
	// const kid = didDocument.id + '#key0';
	// const jws = await identity.sign(
	// 	signer,
	// 	{ version: 0, iat: tool.getTimestampInSeconds(), didDocument: didDocument },
	// 	kid,
	// );
});
