/* eslint-disable eqeqeq */
import { RSAKey } from './lib/jsbn/rsa.js'
import { BigInteger, parseBigInt } from './lib/jsbn/jsbn.js'

var RSA = /** @class**/ (function() {
  function RSA() {
    this.keyLength = 1024
    this.n = ''
    this.d = ''
    this.e = null
    this.p = ''
    this.q = ''
    this.dmp1 = ''
    this.dmq1 = ''
    this.coeff = ''
    this.log = false
    this.rsa = new RSAKey()
  }

  RSA.prototype.setPublicExponent = function(e) {
    this.e = '10001'
  }

  /**
     * use p,q,e calculate n d dmp1 dmq1 coeff
     * **/
  RSA.prototype.calculateRsaKey = function() {
    var n
    var d
    var dmp1
    var dmq1
    var coeff
    var e = parseBigInt(this.e, 16)
    var p = parseBigInt(this.p, 16)
    var q = parseBigInt(this.q, 16)
    var p1 = p.subtract(BigInteger.ONE) // p1 = p-1
    var q1 = q.subtract(BigInteger.ONE) // q1 = q-1
    var phi = p1.multiply(q1)
    if (phi.gcd(e).compareTo(BigInteger.ONE) == 0) {
      n = p.multiply(q)
      d = e.modInverse(phi)
      dmp1 = d.mod(p1)
      dmq1 = d.mod(q1)
      coeff = q.modInverse(p)
      // break
      this.n = n.toString(16)
      this.d = d.toString(16)
      this.dmp1 = dmp1.toString(16)
      this.dmq1 = dmq1.toString(16)
      this.coeff = coeff.toString(16)
    }
  }

  RSA.prototype.setKeyLength = function(size) {
    this.keyLength = size ? parseInt(size, 10) : 1024
  }

  RSA.prototype.setPublic = function(n, e) {
    this.n = n
    // setPublicExponent(e)
    this.e = e
    this.rsa.setPublic(this.n, this.e)
  }

  RSA.prototype.setCrtPrivate = function(p, q, e) {
    this.p = p
    this.q = q
    this.e = e
    // setPublicExponent(e)
    this.calculateRsaKey()
    this.rsa.setPrivateEx(this.n, this.e, this.d, this.p, this.q, this.dmp1, this.dmq1, this.coeff)
  }

  RSA.prototype.setPrivate = function(n, d, e) {
    this.n = n
    this.d = d
    this.e = e
    this.rsa.setPrivate(n, e, d)
  }

  RSA.prototype.generate = function(e) {
    this.setPublicExponent(e)
    this.rsa.generate(this.keyLength, this.e)
    this.n = this.rsa.n.toString(16)
    this.d = this.rsa.d.toString(16)
    this.p = this.rsa.p.toString(16)
    this.q = this.rsa.q.toString(16)
    this.dmp1 = this.rsa.dmp1.toString(16)
    this.dmq1 = this.rsa.dmq1.toString(16)
    this.coeff = this.rsa.coeff.toString(16)
  }

  RSA.prototype.encrypt = function(plaintext) {
    return this.rsa.encrypt(plaintext)
  }

  RSA.prototype.decrypt = function(ciphertext) {
    return this.rsa.decrypt(ciphertext)
  }

  return RSA
}())
export { RSA }
