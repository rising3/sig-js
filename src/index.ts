import * as crypto from 'crypto'

const DefaultNamedCurve = 'P-256'
const DefaultHashAlgo = 'SHA256'
const DefaultFormat = 'base64'

type publicKeyType =
  | crypto.KeyLike
  | crypto.VerifyKeyObjectInput
  | crypto.VerifyPublicKeyInput
  | crypto.VerifyJsonWebKeyInput

type privateKeyType =
  | crypto.KeyLike
  | crypto.SignKeyObjectInput
  | crypto.SignPrivateKeyInput

type publicKeyPemType =
  | string
  | crypto.KeyObject
  | Buffer
  | crypto.PublicKeyInput
  | crypto.JsonWebKeyInput

type privateKeyPemType =
  | string
  | Buffer
  | crypto.PrivateKeyInput
  | crypto.JsonWebKeyInput

export interface SignResult {
  timestamp: number
  signature: string | Buffer
}

export class SignUtils {
  static generateKeyPairSync(
    nc = DefaultNamedCurve
  ): crypto.KeyPairKeyObjectResult {
    return crypto.generateKeyPairSync('ec', {
      namedCurve: nc
    })
  }

  static async generateKeyPair(
    nc = DefaultNamedCurve
  ): Promise<crypto.KeyPairKeyObjectResult> {
    return new Promise((resolve, reject) => {
      crypto.generateKeyPair(
        'ec',
        {
          namedCurve: nc
        },
        (err, publicKey, privateKey) => {
          if (err) {
            return reject(err)
          } else {
            resolve({
              publicKey: publicKey,
              privateKey: privateKey
            } as crypto.KeyPairKeyObjectResult)
          }
        }
      )
    })
  }

  static toPem(key: crypto.KeyObject): string | Buffer {
    return key.type.toLocaleLowerCase() === 'private'
      ? key.export({type: 'pkcs8', format: 'pem'})
      : key.export({type: 'spki', format: 'pem'})
  }

  static toPublicKey(pem: publicKeyPemType): crypto.KeyObject {
    return crypto.createPublicKey(pem)
  }

  static toPrivateKey(pem: privateKeyPemType): crypto.KeyObject {
    return crypto.createPrivateKey(pem)
  }

  static timestamp(): number {
    const now = new Date()
    const tzOffset = now.getTimezoneOffset() * 60 * 1000
    return now.getTime() + tzOffset
  }
}

export class Signer {
  private readonly privateKey: privateKeyType

  constructor(privateKeyPem: privateKeyPemType) {
    this.privateKey = SignUtils.toPrivateKey(privateKeyPem)
  }

  sign(data: string, hashAlgo: string = DefaultHashAlgo): SignResult {
    const signer = crypto.createSign(hashAlgo)
    const timestamp = SignUtils.timestamp()
    const encoder = new TextEncoder()
    signer.update(encoder.encode(timestamp + data))
    signer.end()
    const signature = signer.sign(this.privateKey, DefaultFormat)
    return {timestamp, signature}
  }
}

export class Verifier {
  private readonly publicKey: publicKeyType

  constructor(publicKeyPem: publicKeyPemType) {
    this.publicKey = SignUtils.toPublicKey(publicKeyPem)
  }

  verify(
    data: string,
    timestamp: number,
    signature: string,
    hashAlgo: string = DefaultHashAlgo
  ): boolean {
    const verifier = crypto.createVerify(hashAlgo)
    const encoder = new TextEncoder()
    verifier.update(encoder.encode(timestamp + data))
    verifier.end()
    return verifier.verify(this.publicKey, signature, DefaultFormat)
  }
}
