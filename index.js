'use strict'

const crypto = require('crypto')
const extend = require('xtend')
const KeyEncoder = require('key-encoder')
const nkey = require('nkey')
const special = {
  secp256k1: require('nkey-secp256k1')
}

const curves = {
  p192: 'prime192v1',
  p256: 'prime256v1',
  p384: 'secp384r1',
  p521: 'secp521r1'
}

function createECDH (curve) {
  return crypto.createECDH(curves[curve] || curve)
}

const PUB_PROPS = ['curve', 'pub']
const type = 'ec'

const impl = nkey.wrapAPI({
  type,
  gen,
  genSync,
  fromJSON
})

function getImpl (opts) {
  return special[opts.curve] || impl
}

module.exports = exports = nkey.wrapAPI({
  gen: function (opts, cb) {
    opts = normalizeOpts(opts)
    return getImpl(opts).gen(opts, cb)
  },
  genSync: function (opts) {
    opts = normalizeOpts(opts)
    return getImpl(opts).genSync(opts)
  },
  fromJSON: function (json) {
    json = normalizeOpts(json)
    return getImpl(json).fromJSON(json)
  }
})

exports.DEFAULT_ALGORITHM = 'sha256'
exports.DEFAULT_CURVE = 'secp256k1'
exports.setImplementationForCurve = function (curve, impl) {
  special[curve] = impl
}

function normalizeOpts (opts) {
  opts = opts || {}
  const copy = {}
  for (var p in opts) copy[p] = opts[p]

  if (!copy.curve) copy.curve = exports.DEFAULT_CURVE

  return copy
}

function genSync (opts) {
  const curve = opts.curve
  const ec = createECDH(curve)
  ec.generateKeys()
  return impl.fromJSON({
    curve: curve,
    priv: ec.getPrivateKey()
  })
}

function gen (opts, cb) {
  process.nextTick(() => cb(null, genSync(opts)))
}

function fromJSON (opts) {
  if (!(opts.priv || opts.pub)) {
    throw new Error('expected "priv" or "pub"')
  }

  if (!opts.curve) throw new Error('expected "curve"')

  const curve = opts.curve
  const ec = createECDH(curve)
  const priv = typeof opts.priv === 'string' ? new Buffer(opts.priv, 'hex') : opts.priv
  if (priv) ec.setPrivateKey(priv)

  let pub = typeof opts.pub === 'string' ? new Buffer(opts.pub, 'hex') : opts.pub
  if (!pub) pub = ec.getPublicKey()

  const pubKeyString = pub.toString('hex')
  const fingerprint = crypto.createHash('sha256').update(pub).digest('hex')
  const encoder = new KeyEncoder(curve)
  let privPEM
  let pubPEM

  return nkey.wrapInstance({
    type,
    signSync,
    verifySync,
    hasDeterministicSig: true,
    pubKeyString,
    fingerprint,
    pub,
    priv,
    toJSON
  })

  function getEncodedPriv () {
    return privPEM || (privPEM = encoder.encodePrivate(priv, 'raw', 'pem'))
  }

  function getEncodedPub () {
    return pubPEM || (pubPEM = encoder.encodePublic(pub, 'raw', 'pem'))
  }

  function signSync (data, algorithm) {
    let priv = getEncodedPriv()
    algorithm = algorithm || exports.DEFAULT_ALGORITHM
    return crypto.createSign(algorithm).update(data).sign(priv, 'hex')
  }

  function verifySync (data, algorithm, sig) {
    let pub = getEncodedPub()
    if (typeof sig === 'undefined') {
      sig = algorithm
      algorithm = exports.DEFAULT_ALGORITHM
    }

    if (typeof sig === 'string') sig = new Buffer(sig, 'hex')

    return crypto.createVerify(algorithm).update(data).verify(pub, sig)
  }

  function toJSON (exportPrivateKey) {
    const obj = {
      type,
      curve,
      pub: pubKeyString,
      fingerprint
    }

    if (exportPrivateKey) obj.priv = priv.toString('hex')

    return obj
  }
}
