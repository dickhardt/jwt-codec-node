/*
*
*
*
*/

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


/*
*   Error Functions
*/
var decodeError = function(message) {
    throw("JWT decode ERROR:"+message)
}

var encodeError = function(message) {
    throw("JWT encode ERROR:"+message)
}

var headerError = function(message) {
    throw("JWT header ERROR:"+message)
}


/*
*   JWS signing and verifying functions
*/


var signHS256 = function (details, input) {
    var hmac = crypto.createHmac('sha256', details.credentials.key).update(input);
    var token = input +'.'+ b64url.safe(hmac.digest('base64'))
    return token;
}

var verifyHS256 = function (header, input, signature, credentials) {
    if (!credentials.key) decodeError('no credentials.key value')
    var hmac = crypto.createHmac('sha256', credentials.key).update(input);
    var inputSignature = b64url.safe(hmac.digest('base64'))
    return (inputSignature === signature);    
}

var signHS512 = function (details, input) {
    var hmac = crypto.createHmac('sha512', details.credentials.key).update(input);
    var token = input +'.'+ b64url.safe(hmac.digest('base64'))
    return token;
}

var verifyHS512 = function (header, input, signature, credentials) {
    if (!credentials.key) decodeError('no credentials.key value')
    var hmac = crypto.createHmac('sha512', credentials.key).update(input);
    var inputSignature = b64url.safe(hmac.digest('base64'))
    return (inputSignature === signature);    
}


var signJWS =
    { 'HS256': signHS256
    , 'HS512': signHS512
    }

var verifyJWS =
    { 'HS256': verifyHS256
    , 'HS512': verifyHS512
    , 'none' : function () {return true;}
    }


/*
*   JWE encrypting and decrypting functions
*/

var encryptA128CBCHS256 = function () {
    
}

var encryptA256CBCHS512 = function () {
    
}

var decryptA128CBCHS256 = function () {
    
}

var decryptA256CBCHS512 = function () {
    
}


// out of sync with code written on MacPro :(


var encryptJWE =
    { "A128CBC+HS256": encryptA128CBCHS256
    , "A256CBC+HS512": encryptA256CBCHS512
    }

var decryptJWE =
    { "dir"
    , "A128CBC+HS256": decryptA128CBCHS256
    , "A256CBC+HS512": decryptA256CBCHS512
    }


/*
*   Exported functions
*/
exports.encode = function (details) {

    if (!details.header) return encodeError('header must be provided')
    if (!details.payload) return encodeError('payload must be provided')
    var header = details.header
    var payload = details.payload
        
    // deal with plain JWT
    if (header.alg === 'none') {
        return ( b64url.encode(JSON.stringify(header)) +'.'+ b64url.encode(JSON.stringify(payload)) )
    }
    
    if (!details.credentials) return encodeError('credentials must be provided')

    // check we support alg and enc
    if (!header.alg) return encodeError('no "alg" in header')
    if (header.enc) { // payload will be encrypted
        if (!encryptJWS[header.alg]) return encodeError('unsupported algorithm:"'+header.alg+'"')
    } else {
        if (!signJWS[header.alg]) return encodeError('unsupported algorithm:"'+header.alg+'"')
    }
    
    // create the token
    if (header.enc) {   // encrypt payload
        
    } else {            // sign payload
        var input = null
        if (details.headerBytes && details.payloadBytes) // used to pass specific bytes in for testing
            input = b64url.encode(details.headerBytes) +'.'+ b64url.encode(details.payloadBytes);
        else
            input = b64url.encode(JSON.stringify(header)) +'.'+ b64url.encode(JSON.stringify(payload));
        return (signJWS[header.alg]( details, input))
    }

};

exports.decode = function (token, getCreds) {

    
    // parse token
    var parts = token.split('.');
    if (!parts.every(b64url.valid)) decodeError('token contains invalid URL safe base 64 character(s)')

    try {
        var header = JSON.parse(b64url.decode(parts[0]));
    }
    catch (e) {
        return decodeError('token header is not valid JSON')
    }
    
    // check we support alg and enc
    if (!header.alg) return decodeError('no "alg" in header')
    if (header.enc) { // payload is encrypted
        if (!decryptJWS[header.alg]) return decodeError('unsupported algorithm:"'+header.alg+'"')
    } else {
        if (!verifyJWS[header.alg]) return decodeError('unsupported algorithm:"'+header.alg+'"')
    }
    
    // get credentials from caller
    var credentials = getCreds(header)
    if (header.alg != 'none' && !credentials) return decodeError('no key returned for:'+JSON.stringify(header))
    
    // decrypt or verify
    if (header.enc) { // token is encrypted
        
    } else { // verify
        var signature = parts[2]
        var input = parts[0] + '.' + parts[1]
        
        if (!verifyJWS[header.alg]( header, input, signature, credentials))
            return decodeError('invalid signature:"'+signature+'"')
        
        var payload = b64url.decode(parts[1])
        try { // try to parse payload
            payload = JSON.parse(payload);
        }
        catch (e) {
            // leave payload as it is
        }
        return payload
    }
};

exports.header = function (token) {
    var parts = token.split('.');
    if (!parts.every(b64url.valid)) headerError('token contains invalid URL safe base 64 character(s)')

    try {
        var header = JSON.parse(b64url.decode(parts[0]));
        return header;
    }
    catch (e) {
        return headerError('token header is not valid JSON')
    }
}

/*
var JWT_ALGORITHM = 'HS256';
var OPENSSL_ALGORITHM = 'sha256';

var sign = function (token, key) {
	var hmac = crypto.createHmac(OPENSSL_ALGORITHM, key).update(token);
	return b64url.safe(hmac.digest('base64'));
};

exports.stringify = function (header, payload, key) {
	if (header.alg != JWT_ALGORITHM) throw ('unsupported JWT algorithm'); 
	if (header.typ && (header.typ != 'JWT')) throw ('unsupported JWT header type'); 
	if (!key) throw ('a key must be provided');
		
	header.typ = 'JWT'; 
	header.iss = Math.round(Date.now() / 1000);
	
	var token = b64url.encode(JSON.stringify(header)) + '.' + b64url.encode(JSON.stringify(payload));
	
	return token + '.' + sign(token, key);
};

exports.parse = function (token, key, ttl) {
    if (!key) throw ('key required');
    if (!token) throw ('token required');
    if (!ttl) var ttl = 5 * 60; // default expiry of token is 5 minutes
    
    var parts = token.split('.');
    var headerB64 = parts[0], 
        payloadB64 = parts[1], 
        signature = parts[2];
    
    var header = JSON.parse(b64url.decode(headerB64));
    var payload = JSON.parse(b64url.decode(payloadB64));
    
	if (header.typ != 'JWT') throw ('unsupported JWT header type'); 
	if (header.alg != JWT_ALGORITHM) throw ('unsupported JWT algorithm'); 
    if (!header.iss || ((header.iss + ttl) < Math.round(Date.now() / 1000))) throw ('expired token');
    if (signature != sign(headerB64 + '.' + payloadB64, key)) throw ('invalid signature');
    
    return ({'header':header,'payload':payload});
}

*/