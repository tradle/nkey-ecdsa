const asn1 = require('asn1.js')
const BN = require('bn.js')

module.exports = {
  toJWK,
  toJWKCurve,
  fromJWK,
  toBuffer,
  toArrayBuffer,
  fromDER: asn1SigToConcatSig,
  toDER: concatSigToAsn1Sig,
  assert
}

function fromJWK (jwk) {
  const x = new Buffer(jwk.x, 'base64')
  const y = new Buffer(jwk.y, 'base64')
  const pub = new Buffer(65)
  pub[0] = 4
  x.copy(pub, 1)
  y.copy(pub, 33)
  const curve = jwk.crv.replace('-', '').toLowerCase()
  const priv = jwk.d && new Buffer(jwk.d, 'base64')

  return {
    pub,
    priv,
    curve
  }
}

function toJWK (key) {
  const priv = key.priv && toBuffer(key.priv)
  if (priv) {
    assert(priv.length === 32, 'Expected 32 byte private key')
  }

  const pub = toBuffer(key.pub)
  assert(pub.length === 65, 'Expected non-compressed public key')
  assert(pub[0] === 4, `Unexpected key encoding, expected hex: '04' + hex(x) + hex(y)`)

  const jwk = {
    kty: 'EC',
    crv: toJWKCurve(key.curve),
    x: toUnpaddedBase64(pub.slice(1, 33)),
    y: toUnpaddedBase64(pub.slice(33)),
    ext: true
  }

  if (priv) {
    jwk.d = toUnpaddedBase64(priv)
  }

  return jwk
}

function toBuffer (val) {
  if (Buffer.isBuffer(val)) return val
  if (typeof val === 'string') return new Buffer(val, 'hex')

  throw new Error('expected string or Buffer')
}

function assert (statement, message) {
  if (!statement) throw new Error(message || 'assertion failed')
}

function toUnpaddedBase64 (buf) {
  const padded = buf.toString('base64')
  return padded.replace(/[=]+$/, '').replace(/[+]/g, '-').replace(/[/]/g, '_')
}

function toJWKCurve (curve) {
  return 'P-' + curve.slice(1)
}

function toArrayBuffer (val) {
  if (val instanceof ArrayBuffer) return val

  if (typeof val === 'string') {
    return new Buffer(val).buffer
  }

  if (Buffer.isBuffer(val)) {
    return val.buffer
  }

  throw new Error('expected string, Buffer or ArrayBuffer')
}

// http://stackoverflow.com/questions/39499040/generating-ecdsa-signature-with-node-js-crypto
const EcdsaDerSig = asn1.define('ECPrivateKey', function() {
  return this.seq().obj(
    this.key('r').int(),
    this.key('s').int()
  )
})

function asn1SigToConcatSig (asn1SigBuffer) {
  const rsSig = EcdsaDerSig.decode(asn1SigBuffer, 'der')
  return Buffer.concat([
    rsSig.r.toArrayLike(Buffer, 'be', 32),
    rsSig.s.toArrayLike(Buffer, 'be', 32)
  ])
}

function concatSigToAsn1Sig (concatSigBuffer) {
  const r = new BN(concatSigBuffer.slice(0, 32).toString('hex'), 16, 'be')
  const s = new BN(concatSigBuffer.slice(32).toString('hex'), 16, 'be')
  return EcdsaDerSig.encode({r, s}, 'der')
}

