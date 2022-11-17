// Based on Decentralized Identifiers (DIDs) v1.0
// W3C Recommendation 19 July 2022
// https://w3c.github.io/did-core/

import { createJWS, Signer } from 'did-jwt';
import { VerificationMethod } from './interfaces';

/** Use to simplify operations around handling of DID Documents for the "did:is" DID Method. */
export class BlockcoreIdentity {
  public static readonly PREFIX = 'did:is';

  constructor(private verificationMethod: VerificationMethod) {}

  private ordered(a: any, b: any) {
    let comparison = 0;
    if (a.id > b.id) {
      comparison = 1;
    } else if (a.id < b.id) {
      comparison = -1;
    }
    return comparison;
  }

  /** Generates the DID document for the current identity. */
  document(options: { service: [] } | any = null) {
    const data: any = {};
    // data['@context'] = ['https://www.w3.org/ns/did/v1'];  // We only implement application/did+json
    data.id = this.verificationMethod.controller;
    data.verificationMethod = [this.verificationMethod];

    if (options?.service) {
      data.service = options.service.sort(this.ordered);
    }

    // Get the unique ID of the verification method, this might have extra data to make it unique in the list (#key-1).
    data.authentication = [this.getFragment(this.verificationMethod.id)];
    data.assertionMethod = [this.getFragment(this.verificationMethod.id)];

    return data;
  }

  private getFragment(keyIdentfier: string) {
    const index = keyIdentfier.indexOf('#');

    if (index === -1) {
      return keyIdentfier;
    }

    return keyIdentfier.substring(index);
  }

  /** Returns a signed JWS from the payload. Requires that didDocument in the payload has an verificationMethod. */
  async sign(signer: Signer, payload: { version: number; iat: number; didDocument: any }, kid: string) {
    return await createJWS(payload, signer, { kid });
  }
}
