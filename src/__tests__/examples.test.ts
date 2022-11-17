import { BlockcoreIdentity, BlockcoreIdentityTools } from '../index';
import { decodeJWT } from 'did-jwt';

const fs = require('fs');
const path = require('path');

function save(filename: string, content: string) {
  const filePath = path.join(__dirname, '..', '..', 'examples/', filename);
  const data = fs.writeFileSync(filePath, content);
}

test('Generate Examples', async () => {
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

  // The default pattern for key identifier is #key{keyIndex}.
  const kid = didDocument.id + '#key0';
  const jws = await identity.sign(signer, { version: 0, iat: 1668686145, didDocument: didDocument }, kid);

  save('did-document.json', JSON.stringify(didDocument, null, 2));
  save('did-document-operation-jws.txt', JSON.stringify(jws, null, 2));
  save('did-document-operation-jws.json', JSON.stringify(decodeJWT(jws), null, 2));

  const keyPair = tool.convertPrivateKeyToJsonWebKeyPair(privateKey);
  save('web-key-pair.json', JSON.stringify(keyPair, null, 2));

  for (var i = 1; i < 5; i++) {
    const replacement = await identity.sign(
      signer,
      {
        version: i,
        iat: 1668686145,
        didDocument: didDocument,
      },
      kid,
    );

    save('did-document-operation-replace-' + i + '.txt', JSON.stringify(replacement, null, 2));
    save('did-document-operation-replace-' + i + '.json', JSON.stringify(decodeJWT(replacement), null, 2));
  }
});
