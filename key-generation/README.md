# Key generation tool

It allows generating a new Ed25519 key pair for signing.
Keys are serialized in JWK format, hex format and PKCS format. 

The public key JWK can be used together with this [web tool](https://iotaledger.github.io/ebsi-stardust-components/public/encode_identity.html) to obtain a command line that will allow to register a new DID on the Rebased Ledger using the [iota tool](https://docs.iota.org/references/cli). The registered DID will contain a Verification Method with the corresponding public key. 

## Installation

(From [this folder](.))

```sh
npm install
npm run dist
```

## Execution

```sh
node ./es/createJWKEd25519.js 
```

Optionally it can be given a URI pointing to where a digital certificate for the public key will be hosted (`x5u` JWK property). 
