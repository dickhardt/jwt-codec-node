var crypto = require('crypto');

/*
*    URL Safe Base64 routines.
*/
var b64url = {};

b64url.rtrim = function (data, chr) {
  var drop = 0
    , len = data.length
  while (data.charAt(len - 1 - drop) === chr) drop++
  return data.substr(0, len - drop)
}

b64url.safe = function(b64data) {
  return b64url.rtrim(b64data, '=').replace(/\+/g, '-').replace(/\//g, '_')
}

b64url.encode = function(data) {
  var buf = data
  if (!(data instanceof Buffer)) {
    buf = new Buffer(Buffer.byteLength(data))
    buf.write(data)
  }
  return b64url.safe(buf.toString('base64'))
}

b64url.decode = function(data, encoding) {
  encoding = encoding === undefined ? 'utf8' : encoding
  var buf = new Buffer(data.replace(/-/g, '+').replace(/_/g, '/'), 'base64')
  if (!encoding) return buf
  return buf.toString(encoding)
}

b64url.valid = function(s) {
    var invalid = /[^\w\-] /.exec(s);   // likely a more efficient way to do this
    return !invalid;
}


var plainText = '"The true sign of intelligence is not knowledge but imagination."'
var cmkBytes = Buffer([64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207, 217])
var key = Buffer([25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82])
var ivBytes = Buffer([253, 220, 80, 25, 166, 152, 178, 168, 97, 99, 67, 89])

    var cipher = crypto.createCipheriv( 'aes128', key, ivBytes)
    var cipherText = cipher.update(plainText)
    cipherText += b64url.safe(cipher.final('base64'))

