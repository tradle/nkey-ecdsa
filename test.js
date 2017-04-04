const crypto = require('crypto')
const test = require('tape')
const typeforce = require('typeforce')
// const Benchmark = require('benchmark')
const impl = require('./')
const defaultImpl = require('./default')
const browserImpl = process.browser && require('./browser')
// const testImpl = require('nkey/test')
const types = require('nkey/types')
const utils = require('./utils')
const jwk = {
  publicKey: {
    kty: 'EC',
    crv: 'P-256',
    x: 'zWZ3ERH-hcvCGhAZoa3WjHcu5m1ebnJtRfG1rgxlzVs',
    y: 'isiNnLLKyEvG3lldK9tfOYyaqrZrvuuTbDGASoW85bk',
    ext: true
  },
  privateKey: {
    kty: 'EC',
    crv: 'P-256',
    x: 'zWZ3ERH-hcvCGhAZoa3WjHcu5m1ebnJtRfG1rgxlzVs',
    y: 'isiNnLLKyEvG3lldK9tfOYyaqrZrvuuTbDGASoW85bk',
    ext: true,
    d: 'pZQouIrKG7bcs8yobvk1MAhGLT_TPG1VTSUiaMiliYw'
  }
}

test('import/export jwk', function (t) {
  const priv = new Buffer(jwk.privateKey.d, 'base64')
  const x = new Buffer(jwk.privateKey.x, 'base64')
  const y = new Buffer(jwk.privateKey.y, 'base64')
  const pub = new Buffer('04' + x.toString('hex') + y.toString('hex'), 'hex')
  t.same(utils.toJWK({
    pub,
    curve: 'p256'
  }), jwk.publicKey)

  t.same(utils.toJWK({
    pub,
    priv,
    curve: 'p256'
  }), jwk.privateKey)

  t.end()
})

test(`gen (ecdsa)`, function (t) {
  impl.gen({}, function (err, key) {
    if (err) throw err

    t.equal(key.isPrivateKey, true)

    // if (name === 'sync') {
    //   ;['sign', 'verify'].forEach(method => {
    //     impl[method] = utils.asyncify(impl[method + 'Sync'].bind(impl))
    //   })
    // }

    t.doesNotThrow(function () {
      typeforce(types.key, key)
    })

    const exported = key.toJSON()
    t.doesNotThrow(function () {
      typeforce(types.pub, exported)
    })

    t.same(impl.fromJSON(exported).toJSON(), exported)
    t.end()
  })
})

test(`sign (ecdsa)`, function (t) {
  t.plan(1)
  impl.gen({}, function (err, key) {
    if (err) throw err

    const data = sha256('blah')
    key.sign(data, function (err, sig) {
      if (err) throw err

      key = impl.fromJSON(key.toJSON())
      key.verify(data, sig, function (err, verified) {
        if (err) throw err

        t.ok(verified)
      })
    })
  })
})

if (process.browser) {
  test('cross-verify against default implementation', function (t) {
    t.plan(1)
    const key = browserImpl.fromJSON({
      curve: 'p256',
      type: 'ec',
      pub: '04d5d1b28f7f9f185047f9467b3f540b8d349ffe0d783c6dd95090d23ae04bed84fab52d815740a99bc23300f8063fc2ed058417539e203c512ab0a50617771b92',
      fingerprint: '516e58303dc81a928390120414b2c8e350702e1e2be34c4e314615ed891cba8c'
    })

    const data = new Buffer('8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', 'hex')
    const sig = '3044022047ef93ab82b95019fe2cf8a4c6cfdb22ff9f1316138839b703d90da6b8e32082022004fcf078549cf95e05f629e4a488d0a8a42a3c5d1106350461feda2c5dbbfbcc'
    key.verify(data, sig, function (err, verified) {
      if (err) throw err

      t.ok(verified)
    })
  })

  // test('benchmark', function (t) {
  //   const key = browserImpl.gen()
  //   const [browserKey, defaultKey] = [browserImpl, defaultImpl].map(impl => {
  //     return impl.fromJSON({
  //       curve: 'p256',
  //       type: 'ec',
  //       pub: '04d723cb9ececf0b6b066b53eceecdfc308f9dfa07e101698ca871d7ba777c5e22be3ffab7fae8d9e9cf2d19014be8bdb604b4e45c8a8dca4b251baf4c2258c658',
  //       fingerprint: 'bc461f10a687c00faa6122bcdd04ebbb249e4de37ba4c25caae0257ac027a7f5',
  //       priv: '3496cf361b381b4ee7e3a4ece668dfeed8c7ce890aefd6122a65b9afaf7307bd'
  //     })
  //   })

  //   const data = new Buffer('8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', 'hex')
  //   let iterations = 1000
  //   let togo = iterations
  //   let currentKey = browserKey
  //   let start = Date.now()
  //   next()

  //   function next () {
  //     browserKey.sign(data, function (err, sig) {
  //       if (err) throw err

  //       if (--togo) return next()
  //       if (currentKey === defaultKey) return t.end()

  //       console.log('time: ' + (Date.now() - start))
  //       start = Date.now()
  //       togo = iterations
  //       currentKey = defaultKey
  //       next()
  //     })
  //   }
  // })
} else {
  test('cross-verify against browser implementation', function (t) {
    t.plan(1)
    const key = defaultImpl.fromJSON({
      type: 'ec',
      curve: 'p256',
      pub: '047b27281550f1e47666675532c285488b9e00c24a7eb815c99cf9c5637d810c0d88680bbfc6c7e84d35e3a2ae90db1f82e55cf0266b1b8b17e5ecc211fb2c1521',
      fingerprint: 'ce33c0789348f33bcf8e7f9fe339b3c7127c7e5d19cd632949c1ebd159498bbd'
    })

    const data = new Buffer('8b7df143d91c716ecfa5fc1730022f6b421b05cedee8fd52b1fc65a96030ad52', 'hex')
    const sig = '304502205d08c2987ce7cc0283e568142fd05aa4de9809f727893b205e1a3991af56bb6f0221008de87e5f28f446c8bf3163f6d12ad930675773574184cbfa9730e2d8d66387ab'
    key.verify(data, sig, function (err, verified) {
      if (err) throw err

      t.ok(verified)
    })
  })
}

const sha256 = function (data) {
  return crypto.createHash('sha256').update(data).digest()
}
