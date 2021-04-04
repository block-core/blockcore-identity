# Blockcore Identity Library (JS)

Library that helps working with DIDs (decentralized identities) on Blockcore and resolve DID Document from the "did:is" DID Method.

## Sanity Notes

`did-configuration.json` specification is a VC that prove ownership of DID. It is not a DID Document by itself, but a list of linked IDs (DIDs). Example: https://identity.foundation/.well-known/did-configuration.json

`did.json` document should simply be the DID and nothing more. Example: https://identity.foundation/.well-known/did.json

`identity.document()` returns the DID Document for the identity.

`identity.configuration()` returns the DID Configuration for the identity, in the format defined by the specification and as embedded VCs.

## Examples created by the library

[did-configuration.json](https://www.blockcore.net/.well-known/did-configuration.json)

[did.json](https://www.blockcore.net/.well-known/did.json)
