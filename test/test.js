/*
* JWS and JWT tests from RFC drafts
*
*/

var jwt = require('../lib/jwt');
var b64url = require('../lib/b64url');
var assert = require('assert');

var detailsHSA256 = 
    { 'header': {"typ":"JWT","alg":"HS256"}
    , 'headerBytes': 
        Buffer( [123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32,
                34, 97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125] )
    , 'payload': {"iss":"joe", "exp":1300819380, "http://example.com/is_root":true}
    , 'payloadBytes': 
        Buffer( [123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10,
            32, 34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56,
            48, 44, 13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97,
            109, 112, 108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111,
            111, 116, 34, 58, 116, 114, 117, 101, 125] )
    , 'credentials': {'key':
        b64url.safe(
            Buffer([3, 35, 53, 75, 43, 15, 165, 188, 131, 126, 6, 101, 119, 123, 166,
               143, 90, 179, 40, 230, 240, 84, 201, 40, 169, 15, 132, 178, 210, 80,
               46, 191, 211, 251, 90, 146, 210, 6, 71, 239, 150, 138, 180, 195, 119,
               98, 61, 34, 61, 46, 33, 114, 5, 46, 79, 8, 192, 205, 154, 245, 103,
               208, 128, 163]).toString('base64') )}
    }
var tokenHSA256 = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// test encode and encode with byte arrays
var encodeResult = jwt.encode(detailsHSA256)
assert.equal( encodeResult, tokenHSA256)
var decodeResult = jwt.decode( tokenHSA256, function (header) {
        return detailsHSA256.credentials;
    });
assert.deepEqual( decodeResult, detailsHSA256.payload)

// test round trip without byte arrays
delete detailsHSA256.headerBytes
delete detailsHSA256.payloadBytes
var token = jwt.encode(detailsHSA256)
var payload = jwt.decode(token, function (header) {
        return detailsHSA256.credentials;
    });
assert.deepEqual( payload, detailsHSA256.payload)

// test round trip with "alg":"none"

var detailsNone =
    { 'header': {"typ":"JWT","alg":"none"}
    , 'payload': {"foo":"Alice", "bar":"Bob"}
    }
var token = jwt.encode(detailsNone)
var payload = jwt.decode(token, function (header) {
        return null;
    });
        assert.deepEqual( payload, detailsNone.payload)
        
        
