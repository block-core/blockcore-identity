# Use Cases for Blockcore Identity

## Store Purchases

After scanning/entering the products the customer want to buy, the sellers Point-of-Sale terminal would show a payment request. This could potentially be an regular payment request using various scheme already used. Alternatively it could be an `Presentation Request` that would contain transaction ID, and potentially the full signed transaction to pay for the goods and services. In the `Presentation Request`, the store could also ask for `Bonus Card`, which is an VC that the store has issued previously to the customer.

Bonus Cards should normally not be linked to an DID, for privacy reasons. The store itself can potentially store data relating the customers Bonus Cards and their DID, if needed or approved by the customer.

The Bonus Card will allow a customer to collect points / bonus, in a safe and privacy safe manner.

The PR to perform payment, should normally be signed with an ephemeral private key and not the regular signing key. This is to ensure privacy and the store does not need to know the identity of the purchaser in most cases. In some cases depending on the items purchased and need to show proof of payment, the DID might be used for signing a payment.

After receiving the `Verifiable Presentation` and verifying that the transaction is accepted by the blockchain, the Point-of-Sale solution can display an receipt VC that the customer can scan using QR code.

The customer should/could keep their receipts on their local device, cloud or personal data vault (confidential storage).

## Car Sales

The buyer enters a car dealer and finds a car available for sales. The car is marked with a QR code that is the DID (decentralized identitfier) for the car. 
The customer scans the ID and get all the technical details on the car.

Seller comes to buyer and buyer claims he want to purchase this car.

The seller first asks for the DID of the buyer, and scans this using a QR code provided by the mobile device of the buyer.

Based on the DID of the buyer, the seller will automatically perform an resolve to retrieve the DID Document for the buyer.

The seller can either search up the car to be sold in his Point-of-Sale solution, or by scanning the QR code on the car, or the initial QR code scanned from 
the buyer could include the DID of the object to be purchased.

The seller prepares the final details in the sales agreement, and then asks customer what channel they want to receive communication on?

The DID Document has many options, including e-mail and Telegram. The customer says he prefered e-mail.

The seller can both present a QR code on the Point-of-Sale terminal that the customer can scan, or the customer can open the e-mail he received. The e-mail 
will contain an attachment that is encrypted with the public key provided in the buyers DID Document.

The encrypted document sent to the customer, or the QR code scanned, is an `Presentation Request`(PR). The PR includes requirements such as:

- Driver's License
- Legal Age Above 20
- Active Health Insurrance

The encrypted e-mail attachment can be automatically read and decrypted by the Blockcore Hub app installed on the mobile device, and it can automatically generate an `Verifiable Presentation` (VP) based on the all the `Verifiable Credentials` (VC) that the buyer have in his personal data vault (local device, cloud, confidential storage).

The next step is similar, in which the sellers sends a request for signing an VC that contains all the contractual details of the car sales. The contract is referrenced with a link to an document that is stored in IPFS. This document could potentially be encrypted, with an document hash that is available publicly. This will make the content only available to the buyer, but in future disputes, a court can verify that the buyer has signed on having read and understood the document.

- Buyer issues an VC that is transferred to the seller, verifying agreement.
- The VC can also include invoicing details in terms of credit purchase.
- When there is a credit purchase, the seller can request proof of credit-line.

When agreement is finalize, the seller will sign an VC that contains information that the car has changed ownership from the dealership to the buyer. This information can potentially be published in a public vault, or provided to an "DMV"-equivalent entity that exists on a registry of companies.

### Future disputes

If the buyer ends up not being able to pay according to the agreement, the dealership can first attempt dispute resolution through an legal agency or legal system. All the VCs can be utilized as evidence.

The dealership can also if no other means of resolution is possible, issue a VC with a claim that the buyer has not paid according to the agreement. The dealership can provide evidence that there are no blockchain transactions to the accounts/address provided in the agreement.

If the buyer eventually is able to make the payments, the buyer can issue an dispute VC on the claim initially made by the dealership, with included evidence of full payment.

The ability to perform public sharing of evidence in a dispute, can be valuable, but can also be abused. It should be a last effort resort, but can be efficient as the public reputation of a person (identity) might be valuable, and if that reputation is damaged, it can hurt future business and personal relations.

## References

Verifiable Credentials Use Cases: https://www.w3.org/TR/vc-use-cases/