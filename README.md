# ec-sign-js
[![Build](https://github.com/rising3/ec-sign-js/actions/workflows/build.yml/badge.svg)](https://github.com/rising3/ec-sign-js/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

ECDSA cryptographic signature library for JavaScript.

Elliptic Curve | Hash Algorithm
--- | ---
P-256(Default) | SHA256(Default)
P-384 | SHA384
secp256k1 | SHA256

## Requirements

* Node.js 18 or higher

## How to install

```sh
npm i ec-sign
```

## How to use library

### Generate keypair

```javascript
const sign = require('ec-sign')

// Synchronous
const keypair = sign.SignUtils.generateKeyPairSync('secp224r1');

// Asynchronous
const keypair = await sign.SignUtils.generateKeyPair('secp224r1');
```

### Converts public key to PEM

```javascript
const pubPem = sign.SignUtils.toPem(keypair.publicKey);

console.info(pubPem);
// -----BEGIN PUBLIC KEY-----
// MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEm1eVSAq73aR2Oo8L8rvDzBU214+uhgIj
// MkiasZgxKDJtMbGosVVCPd8drgkr3NrZ1Eqhrf0mveProOsJdaF5Ag==
// -----END PUBLIC KEY-----
```

### Converts private key to PEM

```javascript
const priPem = sign.SignUtils.toPem(keypair.privateKey);

console.info(priPem);
// -----BEGIN PRIVATE KEY-----
// MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgH4RMksnOnI68DAm0PzqQ
// rtS1oznTSsb/pVDQLNPguqShRANCAASbV5VICrvdpHY6jwvyu8PMFTbXj66GAiMy
// SJqxmDEoMm0xsaixVUI93x2uCSvc2tnUSqGt/Sa94+ug6wl1oXkC
// -----END PRIVATE KEY-----
```

### Sign with data and private key

```javascript
const signer = new sign.Signer(priPem);
const result = signer.sign("hello, message");

console.info(result.timestamp);
// 1688895463045

console.info(result.signature);
// MEYCIQCeYobZ2BIoL7jCV4eGYrT/yXGtNLhEFY2MchsIDGCsywIhAMwak6nBiHgJsNfuY2zSdcX235Xy7Ucj2bGMvFh/xdTy
```

### Verify signature with data, timestamp and public key

```javascript
const verifier = new sign.Verifier(pubPem);
const valid = verifier.verify("hello, message", result.timestamp, result.signature.toString());

console.info(`signature was verified: ${valid}`);
// signature was verified: true
```

## How to build from source

### prerequisites

node.js, npm, git need to be installed.

```sh
git clone https://github.com/rising3/ec-sign-js.git
cd ec-sign-js
npm i
npm run test
npm run build
```

## License

[Apache 2.0](LICENSE)
