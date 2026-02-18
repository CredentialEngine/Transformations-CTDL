# Ed25519 Proof JWT Generator

This script generates a **Proof JWT** signed with
**Ed25519 (EdDSA)**, and verifies the JWT signature using a public key
resolved from the DID in the challenge.

It supports:

-   **did:key** --- resolves the public key offline from the DID itself
-   **did:web** --- fetches did.json over HTTPS and extracts the public
    key from the matching verificationMethod
 


## What the script does

1.  Reads a CE-generated challenge JSON file.
2.  Uses the challenge `did` value as the JWT header `kid`.
3.  Signs the challenge as-is using Ed25519 (alg `EdDSA`).
4.  Verifies the JWT signature:
    -   Resolves a public key from the DID indicated by `kid`
    -   Verifies the signature using that public key

## Requirements

### Python

Python 3.10+ recommended

### Install dependencies

    pip install pyjwt cryptography base58 requests truststore


## Challenge JSON format

The challenge JSON file must be a JSON object and include:

-   did (string) 
-   challenge
-   aud
-   iat
-   exp

Example:

{ "did": "did:key:z6Mkm...#z6Mkm...", "challenge": "b2f0c5...", "aud":
"https://example.org", "iat": 1739832000, "exp": 1739835600 }


## Usage

### Generate 

    python Ed25519_proof_jwt_generator.py       --privateKey z...       --challengeFile .\challenge.json

Prints the signed JWT to stdout. Prints "Signature verification: OK" if
verification succeeds.


### Write output JWT to a file

    python Ed25519_proof_jwt_generator.py       --privateKey z...       --challengeFile .\challenge.json       --out .\proof.jwt


## How verification works

### did:key

-   Public key is encoded inside the DID.
-   Script decodes the multibase/multicodec key material and verifies
    offline.
-   No HTTPS fetch required.

### did:web

-   Fetches the DID document at:

    did:web:example.org -\> https://example.org/.well-known/did.json\
    did:web:example.org:user:alice -\>
    https://example.org/user/alice/did.json

-   Finds the matching verificationMethod entry whose id matches the
    kid.

-   Decodes publicKeyMultibase to a raw 32-byte Ed25519 public key.

-   Verifies the JWT signature.

------------------------------------------------------------------------

## Common troubleshooting

### Signature verification failed

This usually means:

-   The kid resolved to a different public key than the private key used
    for signing, OR
-   You are testing with a did for which you don't have the
    corresponding private key, OR
-   The kid does not match any verificationMethod.id in the DID
    document.




