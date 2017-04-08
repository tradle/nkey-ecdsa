
const subtle = window.crypto.subtle
const omit = require('object.omit')
const extend = require('xtend/mutable')
const debug = require('debug')('nkey-ecdsa:browser')
const nkey = require('nkey')
const Promise = require('any-promise')
const co = require('co')
const type = 'ec'
const {
  toJWK,
  fromJWK,
  toJWKCurve,
  toArrayBuffer,
  toDER,
  fromDER
} = require('./utils')

const ZERO_BUF = new Buffer(16)
ZERO_BUF.fill(0)
const EXTRACTABLE = true
const checked = new Map()
const KEY_PROPS = [
  'type',
  'pubKeyString',
  'fingerprint',
  'toJSON',
  'isPrivateKey'
]

const gen = co.wrap(function* (opts, cb) {
  let key
  try {
    const ecOpts = getCurveSpec(opts.curve || exports.DEFAULT_CURVE)
    const raw = yield subtle.generateKey(ecOpts, EXTRACTABLE, ['sign', 'verify'])
    const privJWK = yield subtle.exportKey('jwk', raw.privateKey)
    const imported = fromJWK(privJWK)
    const fingerprint = yield subtle.digest({ name: 'SHA-256' }, imported.pub)
    key = fromCryptoKey({
      key: raw,
      json: {
        type,
        curve: imported.curve,
        priv: imported.priv.toString('hex'),
        pub: imported.pub.toString('hex'),
        fingerprint: new Buffer(fingerprint).toString('hex')
      }
    })
  } catch (err) {
    debug('failed to generate key', err)
    return cb(err)
  }

  cb(null, key)
})

function getCurveSpec (curve) {
  return {
    name: 'ECDSA',
    namedCurve: toJWKCurve(curve),
    hash: {
      name: normalizeAlgorithm(exports.DEFAULT_ALGORITHM)
    }
  }
}

function fromCryptoKey ({ key, json }) {
  const { curve } = json
  const ecOpts = getCurveSpec(curve)
  const api = getPropsForJSON(json)
  api.sign = co.wrap(function* (data, algorithm, cb) {
    if (typeof algorithm === 'function') {
      cb = algorithm
    } else if (normalizeAlgorithm(algorithm) !== exports.DEFAULT_ALGORITHM) {
      return cb(new Error('algorithm must be specified during key generation'))
    }

    let sig
    try {
      sig = yield subtle.sign(ecOpts, key.privateKey, toArrayBuffer(data))
    } catch (err) {
      return cb(err)
    }

    const der = toDER(new Buffer(sig)).toString('hex')
    cb(null, der)
  })

  api.verify = co.wrap(function* (data, algorithm, sig, cb) {
    if (typeof sig === 'function') {
      cb = sig
      sig = algorithm
    } else if (normalizeAlgorithm(algorithm) !== exports.DEFAULT_ALGORITHM) {
      return cb(new Error('algorithm must be specified during key generation'))
    }

    const concatSig = fromDER(new Buffer(sig, 'hex'))

    let verified
    try {
      verified = yield subtle.verify(ecOpts, key.publicKey, toArrayBuffer(concatSig), toArrayBuffer(data))
    } catch (err) {
      return cb(err)
    }

    cb(null, verified)
  })

  return nkey.wrapInstance(api)
}

const HASH_ALGOS = {
  'sha1': 'SHA-1',
  'sha256': 'SHA-256',
  'sha384': 'SHA-384',
  'sha512': 'SHA-512'
}

function normalizeAlgorithm (algo) {
  algo = algo.toLowerCase()
  if (!HASH_ALGOS[algo]) {
    throw new Error(`expected one of: ${Object.keys(HASH_ALGOS).join(', ')}`)
  }

  return HASH_ALGOS[algo]
}

function getPropsForJSON (json) {
  const pubKeyString = json.pub.toString('hex')
  return {
    type,
    pubKeyString,
    fingerprint: json.fingerprint,
    isPrivateKey: !!json.priv,
    toJSON: function toJSON (exportPrivateKey) {
      if (exportPrivateKey) {
        if (!json.priv) {
          throw new Error('this is a public key')
        }

        return json
      }

      const exported = omit(json, 'priv')
      if (!exported.pub) exported.pub = pubKeyString
      if (!exported.type) exported.type = type

      return exported
    }
  }
}

function fromJSON (json) {
  const ops = json.priv ? ['sign'] : ['verify']
  const jwk = toJWK(json)
  const ecOpts = getCurveSpec(json.curve)
  const check = checkNative('ECDSA', ecOpts.hash.name, ecOpts.namedCurve)

  let supported
  const api = co.wrap(function* () {
    supported = yield check
    if (supported) {
      return subtle.importKey('jwk', jwk, ecOpts, EXTRACTABLE, ops)
    } else {
      return require('./default').fromJSON(json)
    }
  })()

  const syncProps = getPropsForJSON(json)
  extend(api, syncProps)

  let loadedKey
  co.wrap(function* () {
    const someKey = yield api
    if (!supported) {
      return loadedKey = someKey
    }

    loadedKey = fromCryptoKey({
      json,
      key: {
        privateKey: json.priv && someKey,
        publicKey: someKey
      }
    })
  })()

  KEY_PROPS.forEach(prop => {
    Object.defineProperty(api, prop, {
      get: function () {
        return loadedKey && loadedKey[prop] || syncProps[prop]
      }
    })
  })

  ;['sign', 'verify'].forEach(method => {
    api[method] = co.wrap(function* () {
      // wait for reimport
      yield api
      return loadedKey[method].apply(loadedKey, arguments)
    })
  })

  return nkey.wrapInstance(api)
}

function pad (buf, length) {
  const padded = new Buffer(length)
  for (let i = 0, l = length - buf.length; i < l; i++) {
    padded[i] = 0
  }

  return padded
}

// https://github.com/calvinmetcalf/native-crypto/blob/master/lib/signature.js
const checkNative = co.wrap(function* (type, algo, curve) {
  if (global.process && !global.process.browser) {
    return false
  }

  if (!subtle || !subtle.importKey || !subtle.sign || !subtle.verify) {
    return false
  }

  const id = `${algo}-${type}-${curve}`
  if (checked.has(id)) {
    return checked.get(id)
  }

  const opts = {
    name: type
  }

  if (curve) {
    opts.namedCurve = curve
  } else {
    opts.modulusLength = 1024
    opts.publicExponent = new Buffer([0x01, 0x00, 0x01])
    opts.hash = {
      name: algo
    }
  }

  const signOpts = {
    name: type
  }

  if (curve) {
    signOpts.hash = {
      name: algo
    }
  }

  const prom = testSign({ opts, signOpts })
  checked.set(algo, prom)
  const works = yield prom
  if (works) {
    debug(`has working sublte crypto for type: ${type} with digest ${algo} ${curve ? `with curve: ${curve}` : ''}`)
  }

  return works
})

const testSign = co.wrap(function* ({ opts, signOpts }) {
  try {
    const key = yield subtle.generateKey(opts, false, ['sign'])
    yield subtle.sign(signOpts, key.privateKey, ZERO_BUF)
    return true
  } catch (err) {
    debug(err.message)
    return false
  }
})

module.exports = exports = nkey.wrapAPI({ gen, fromJSON })
exports.DEFAULT_ALGORITHM = 'sha256'
exports.DEFAULT_CURVE = 'p256'
