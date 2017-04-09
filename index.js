
module.exports = typeof window !== 'undefined' && window.crypto && window.crypto.subtle
  ? require('./browser')
  : require('./default')
