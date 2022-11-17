import { OperationCanceledException } from 'typescript';
import { BlockcoreIdentityTools, BlockcoreIdentity } from '../index';

test('My Identity', async () => {
  const tool = new BlockcoreIdentityTools();
  const privateKey = Uint8Array.from([
    224, 238, 59, 150, 73, 84, 228, 234, 104, 62, 83, 160, 122, 31, 108, 129, 74, 29, 104, 195, 192, 81, 158, 11, 167,
    100, 217, 121, 110, 12, 178, 14,
  ]);

  const signer = tool.getSigner(privateKey);
  const publicKey = tool.getSchnorrPublicKeyFromPrivateKey(privateKey);
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
  const jws = await identity.sign(signer, { version: 0, iat: tool.getTimestampInSeconds(), didDocument: didDocument });
  console.log(jws);
});
