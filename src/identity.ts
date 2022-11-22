// Based on Decentralized Identifiers (DIDs) v1.0
// W3C Recommendation 19 July 2022
// https://w3c.github.io/did-core/

import { createJWS, Signer } from 'did-jwt';
import { createVerifiableCredentialJwt, Issuer, JwtCredentialPayload, normalizeCredential } from 'did-jwt-vc';
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

	get did() {
		return this.verificationMethod.controller;
	}

	/** Generates the DID document for the current identity. */
	document(options: { service: [] } | any = null) {
		const data: any = {};
		// data['@context'] = ['https://www.w3.org/ns/did/v1'];  // We only implement application/did+json
		data.id = this.did;
		data.verificationMethod = [this.verificationMethod];

		if (options?.service) {
			data.service = options.service.sort(this.ordered);
		}

		// Get the unique ID of the verification method, this might have extra data to make it unique in the list (#key-1).
		data.authentication = [this.getFragment(this.verificationMethod.id)];
		data.assertionMethod = [this.getFragment(this.verificationMethod.id)];

		return data;
	}

	/** Generates a well known configuration for DID resolver host. */
	public async configurationVerifiableCredential(domain: string, issuer: any, kid: string) {
		const date = new Date();
		const expiredate = new Date(new Date().setFullYear(date.getFullYear() + 100));
		let expiredateNumber = Math.floor(expiredate.getTime() / 1000);

		// Due to issue with Microsoft middleware for JWT validation, we cannot go higher than this expiration date.
		// Source: https://stackoverflow.com/questions/43593074/jwt-validation-fails/46654832#46654832
		if (expiredateNumber > 2147483647) {
			expiredateNumber = 2147483647;
		}

		const currentDateNumber = Math.floor(date.getTime() / 1000);

		const vcPayload: JwtCredentialPayload = {
			// iss: this.id, // This is automatically added by the library and not needed.
			exp: expiredateNumber,
			iat: currentDateNumber,
			nbf: currentDateNumber,
			sub: this.did,
			vc: {
				'@context': [
					'https://www.w3.org/2018/credentials/v1',
					'https://identity.foundation/.well-known/did-configuration/v1',
				],
				type: ['VerifiableCredential', 'DomainLinkageCredential'],
				credentialSubject: {
					id: this.did,
					origin: domain,
				},
				//"expirationDate": expiredate.toISOString(),
				//"issuanceDate": date.toISOString(),
				//"issuer": this.id,
			},
		};

		const vcJwt = await createVerifiableCredentialJwt(vcPayload, issuer, { header: { kid: kid } });

		return vcJwt;
	}

	/** Generates a well known configuration for DID resolver host. */
	public async configuration(domain: string, issuer: any, kid: string, includeNormalized = false) {
		var vc = await this.configurationVerifiableCredential(domain, issuer, kid);

		const data: any = {};
		data['@context'] = 'https://identity.foundation/.well-known/did-configuration/v1';
		data.linked_dids = [vc];

		if (includeNormalized) {
			var vcNormalized = normalizeCredential(vc, true);
			data.linked_dids.push(vcNormalized);
		}

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
