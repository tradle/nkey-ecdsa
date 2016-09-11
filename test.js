const test = require('tape')
const impl = require('./')
const testImpl = require('nkey/test')
testImpl(impl, function () {
  impl.DEFAULT_CURVE = 'secp256k1'
  testImpl(impl, function () {
    impl.DEFAULT_CURVE = 'p256'
    testImpl(impl)
  })
})
