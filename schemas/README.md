# Schemas

https://github.com/w3c-ccg/vc-json-schemas

Some known schemas from specifications:

- "DomainLinkageCredential"

```json
    "credentialSubject": {
        "id": "did:key:z6MkoTHsgNNrby8JzCNQ1iRLyW5QQ6R8Xuu6AA8igGrMVPUM",
        "origin": "https://identity.foundation"
    }
```

- "NameCredential"
- "UniversityDegreeCredential"

 ```json
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "degree": {
      "type": "BachelorDegree",
      "name": "Bachelor of Science and Arts"
    }
 ```

- "RelationshipCredential"

```json
  "credentialSubject": [{
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Jayden Doe",
    "spouse": "did:example:c276e12ec21ebfeb1f712ebc6f1"
  }, {
    "id": "did:example:c276e12ec21ebfeb1f712ebc6f1",
    "name": "Morgan Doe",
    "spouse": "did:example:ebfeb1f712ebc6f1c276e12ec21"
  }]
```

```json
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "parent": {
      "id": "did:example:ebfeb1c276e12ec211f712ebc6f",
      "type": "Mother"
    }
```

```json
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "ageUnder": 16,
    "parent": {
      "id": "did:example:ebfeb1c276e12ec211f712ebc6f",
      "type": "Mother"
    }
```

- "PrescriptionCredential"

```json
    "credentialSubject": {
        "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
        "prescription": {....}
    }
```

- "NameAndAddress"

```json
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "name": "Mr John Doe",
    "address": "10 Some Street, Anytown, ThisLocal, Country X"
  }
```



# DID Method / Controller / Vault API

CRUD

"revokeKey"

