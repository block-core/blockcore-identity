# Blockcore Identity Library (JS)

Library that helps working with DIDs (decentralized identities) on Blockcore and resolve DID Document from the "did:is" DID Method.

## Development and Status

The current implementation supports JWT VCs and can decode the JWT VSs into an JSON structure that is similar to JSON-LD, but is not compliant with the standard ("proof" element of it).

The next goal is to implement Linked Data Signature / JSON-LD, making the VCs more easily indexed / searchable and human readable.

https://github.com/w3c-ccg/lds-jws2020

https://github.com/digitalbazaar/vc-js

Support for JWT VCs will likely be removed from this library in the future and should not be used.

https://github.com/decentralized-identity/.well-known/issues/25

## Building and Testing

The library can be built using TypeScript Compiler, either directly or through npm:

```
npm run build
```

To generate and update the example documents, use this command:

```
npm run examples
```

This will update the example documents available at [test/examples](test/examples)

## Sanity Notes

`did-configuration.json` specification is a VC that prove ownership of DID. It is not a DID Document by itself, but a list of linked IDs (DIDs). Example: https://identity.foundation/.well-known/did-configuration.json

`did.json` document should simply be the DID and nothing more. Example: https://identity.foundation/.well-known/did.json

`identity.document()` returns the DID Document for the identity.

`identity.configuration()` returns the DID Configuration for the identity, in the format defined by the specification and as embedded VCs.

## Examples created by the library

[did-configuration.json](https://www.blockcore.net/.well-known/did-configuration.json)

[did.json](https://www.blockcore.net/.well-known/did.json)
