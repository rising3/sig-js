import * as sig from '../src/index'

const TestMessage = 'hello, message'

const TestTimestamp = 1688895463045

// P-256/SHA256
const TestPublicKeyPem = `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwp4/QyKS/fN5cLFULWtRL5ISmoud
GpOgtgDMZAj8m1bt3kBjrBY1WWDQj8VOAjKTRcGwxiOYdcD5VelU+GJQ5g==
-----END PUBLIC KEY-----`

const TestPrivateKeyPem = `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg7zyYxvCg89jDUvbS
u1wkzYRhOUtPFwHnkfY/voD0IB6hRANCAATCnj9DIpL983lwsVQta1EvkhKai50a
k6C2AMxkCPybVu3eQGOsFjVZYNCPxU4CMpNFwbDGI5h1wPlV6VT4YlDm
-----END PRIVATE KEY-----`

const TestSignature =
  'MEUCIBQ07TYo91z1xr2iz7ePmqEpBgp1QI92I1zp0fSFAUobAiEAwHVHl9nUFLhQovpiufn8Hc4ZOFeZW3C8heAOmkdls6s='

// P-384/SHA384
const TestPublicKeyPemWithP384 = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEk7n3ELZsD8c4K0B/cUxyFg1mtXrJKs1G
jmZBEzU+w11gcQUEi6oI4fcpGFApLlxK5ZAQnOjWOj1g8XTVeMW9xNBnO0joivQx
B8upCECQ/IgPz0SI8uZhlXLDBRS2CwEg
-----END PUBLIC KEY-----`

const TestPrivateKeyPemWithP384 = `
-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDCeJKS522euvo1mP3Cm
PBsWgId7SBjcihjG7a3mXYpYc3Mioe4MgiF1Fqm7RcWRXBWhZANiAASTufcQtmwP
xzgrQH9xTHIWDWa1eskqzUaOZkETNT7DXWBxBQSLqgjh9ykYUCkuXErlkBCc6NY6
PWDxdNV4xb3E0Gc7SOiK9DEHy6kIQJD8iA/PRIjy5mGVcsMFFLYLASA=
-----END PRIVATE KEY-----`

const TestSignatureWithP384 =
  'MGQCMFiTH1LNtexNuLBzqLt8r8k5XByfVOzfwUZBnGr1pBGniMyc1LDjSLaB3YXegsRlFAIwaAgdtBiTlq5onMY5cSWo/F2jGuXeObTUhqsAlW2MRhkuu0vvVjGSKY3lErYqMdLR'

// secp256k1/SHA256
const TestPublicKeyPemWithSecp256k1 = `
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEm1eVSAq73aR2Oo8L8rvDzBU214+uhgIj
MkiasZgxKDJtMbGosVVCPd8drgkr3NrZ1Eqhrf0mveProOsJdaF5Ag==
-----END PUBLIC KEY-----`

const TestPrivateKeyPemWithSecp256k1 = `
-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgH4RMksnOnI68DAm0PzqQ
rtS1oznTSsb/pVDQLNPguqShRANCAASbV5VICrvdpHY6jwvyu8PMFTbXj66GAiMy
SJqxmDEoMm0xsaixVUI93x2uCSvc2tnUSqGt/Sa94+ug6wl1oXkC
-----END PRIVATE KEY-----`

const TestSignatureWithSecp256k1 =
  'MEYCIQCeYobZ2BIoL7jCV4eGYrT/yXGtNLhEFY2MchsIDGCsywIhAMwak6nBiHgJsNfuY2zSdcX235Xy7Ucj2bGMvFh/xdTy'

const RegexPublicKey =
  // eslint-disable-next-line no-useless-escape
  /(-----BEGIN PUBLIC KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END PUBLIC KEY-----)/
const RegexPrivateKey =
  // eslint-disable-next-line no-useless-escape
  /(-----BEGIN PRIVATE KEY-----(\n|\r|\r\n)([0-9a-zA-Z\+\/=]{64}(\n|\r|\r\n))*([0-9a-zA-Z\+\/=]{1,63}(\n|\r|\r\n))?-----END PRIVATE KEY-----)/

describe('Sig Library unittests', () => {
  beforeEach(() => {
    // setup mocks
    jest.useFakeTimers()
    jest.setSystemTime(new Date(TestTimestamp))
  })

  describe('SignUtils Class unittest', () => {
    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] generate ECDSA key pair', ({nc}) => {
      const actual = sig.SignUtils.generateKeyPairSync(nc)
      expect(actual.publicKey.type).toBe('public')
      expect(actual.privateKey.type).toBe('private')
    })

    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] generate ECDSA key pair aync', async ({nc}) => {
      const actual = await sig.SignUtils.generateKeyPair(nc)
      expect(actual.publicKey.type).toBe('public')
      expect(actual.privateKey.type).toBe('private')
    })

    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] converts private key to PEM', ({nc}) => {
      const key = sig.SignUtils.generateKeyPairSync(nc).privateKey
      const actual = sig.SignUtils.toPem(key) as string
      expect(actual.match(RegexPrivateKey)).toBeTruthy()
    })

    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] converts private key to PEM aync', async ({nc}) => {
      const key = (await sig.SignUtils.generateKeyPair(nc)).privateKey
      const actual = sig.SignUtils.toPem(key) as string
      expect(actual.match(RegexPrivateKey)).toBeTruthy()
    })

    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] converts public key to PEM', ({nc}) => {
      const key = sig.SignUtils.generateKeyPairSync(nc).publicKey
      const actual = sig.SignUtils.toPem(key) as string
      expect(actual.match(RegexPublicKey)).toBeTruthy()
    })

    test.each`
      nc
      ${'P-256'}
      ${'P-384'}
      ${'secp256k1'}
    `('[$nc] converts public key to PEM aync', async ({nc}) => {
      const key = (await sig.SignUtils.generateKeyPair(nc)).publicKey
      const actual = sig.SignUtils.toPem(key) as string
      expect(actual.match(RegexPublicKey)).toBeTruthy()
    })

    test.each`
      pem
      ${TestPrivateKeyPem}
      ${TestPrivateKeyPemWithP384}
      ${TestPrivateKeyPemWithSecp256k1}
    `('converts PEM to private key', ({pem}) => {
      const actual = sig.SignUtils.toPrivateKey(pem)
      expect(actual.type).toBe('private')
    })

    test.each`
      pem
      ${TestPublicKeyPem}
      ${TestPublicKeyPemWithP384}
      ${TestPublicKeyPemWithSecp256k1}
    `('converts PEM to public key', ({pem}) => {
      const actual = sig.SignUtils.toPublicKey(pem)
      expect(actual.type).toBe('public')
    })

    test('get timestamp', () => {
      expect(sig.SignUtils.timestamp()).toBe(TestTimestamp)
    })
  })

  describe('Signer Class unittest', () => {
    test.each`
      nc             | privateKeyPem                     | hashAlgo
      ${'P-256'}     | ${TestPrivateKeyPem}              | ${'SHA256'}
      ${'P-384'}     | ${TestPrivateKeyPemWithP384}      | ${'SHA384'}
      ${'secp256k1'} | ${TestPrivateKeyPemWithSecp256k1} | ${'SHA256'}
    `(
      '[$nc/$hashAlgo] Sign with data and private key',
      ({privateKeyPem, hashAlgo}) => {
        const signer = new sig.Signer(privateKeyPem)
        const actual = signer.sign(TestMessage, hashAlgo)
        expect(actual.timestamp).toBe(TestTimestamp)
        expect(actual.signature).not.toBeNull()
      }
    )
  })

  describe('Verifier Class unittest', () => {
    test.each`
      nc             | publicKeyPem                     | data           | timestamp        | signature                     | hashAlgo    | expected
      ${'P-256'}     | ${TestPublicKeyPem}              | ${TestMessage} | ${TestTimestamp} | ${TestSignature}              | ${'SHA256'} | ${true}
      ${'P-256'}     | ${TestPublicKeyPem}              | ${'bad data '} | ${TestTimestamp} | ${TestSignature}              | ${'SHA256'} | ${false}
      ${'P-256'}     | ${TestPublicKeyPem}              | ${TestMessage} | ${1}             | ${TestSignature}              | ${'SHA256'} | ${false}
      ${'P-384'}     | ${TestPublicKeyPemWithP384}      | ${TestMessage} | ${TestTimestamp} | ${TestSignatureWithP384}      | ${'SHA384'} | ${true}
      ${'P-384'}     | ${TestPublicKeyPemWithP384}      | ${'bad data '} | ${TestTimestamp} | ${TestSignatureWithP384}      | ${'SHA384'} | ${false}
      ${'P-384'}     | ${TestPublicKeyPemWithP384}      | ${TestMessage} | ${1}             | ${TestSignatureWithP384}      | ${'SHA384'} | ${false}
      ${'secp256k1'} | ${TestPublicKeyPemWithSecp256k1} | ${TestMessage} | ${TestTimestamp} | ${TestSignatureWithSecp256k1} | ${'SHA256'} | ${true}
      ${'secp256k1'} | ${TestPublicKeyPemWithSecp256k1} | ${'bad data '} | ${TestTimestamp} | ${TestSignatureWithSecp256k1} | ${'SHA256'} | ${false}
      ${'secp256k1'} | ${TestPublicKeyPemWithSecp256k1} | ${TestMessage} | ${1}             | ${TestSignatureWithSecp256k1} | ${'SHA256'} | ${false}
    `(
      "[$nc/$hashAlgo] Verify signature with '$data', $timestamp and public key, result is $expected",
      ({publicKeyPem, data, timestamp, signature, hashAlgo, expected}) => {
        const verifier = new sig.Verifier(publicKeyPem)
        const actual = verifier.verify(data, timestamp, signature, hashAlgo)
        expect(actual).toBe(expected)
      }
    )
  })
})
