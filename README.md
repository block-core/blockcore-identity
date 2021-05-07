# Blockcore Identity Library (JS)

Library that helps working with DIDs (decentralized identities) on Blockcore and resolve DID Document from the "did:is" DID Method.

## Development and Status

The current implementation supports JWT VCs and can decode the JWT VSs into an JSON structure, but is not compliant with the W3C standard due to the "proof" type.

Future goal is to implemented Linked Data Signature / JSON-LD, but at the current time (April 2021) the available VC libraries are not accessible enough and 
updated with the latest W3C specification. The following libraries could likely be foundation for JSON-LD VCs:

https://github.com/w3c-ccg/lds-jws2020

https://github.com/digitalbazaar/vc-js

## Verifiable Credentials (VC)

Ensure that IANA claims are used if they fit:

https://www.iana.org/assignments/jwt/jwt.xhtml

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

## Resources

https://www.w3.org/TR/vc-imp-guide/
