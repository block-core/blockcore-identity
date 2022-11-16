export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: JsonWebKey;
}
