export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  // publicKeyMultibase: string; // TODO: Migrate to use Multibase for all APIs.
  publicKeyBase58: string;
}

export interface VerificationMethodWithPrivateKey extends VerificationMethod {
  // privateKeyMultibase: string; // TODO: Migrate to use Multibase for all APIs.
  privateKeyBase58: string;
}
