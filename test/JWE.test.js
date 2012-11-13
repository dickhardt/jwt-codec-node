

var jwt = require('../lib/jwt');
var assert = require('assert');

/*
*   create and test an Agent Request
*/
console.log('\n-------- Agent Request --------- \n')

var detailsRequestAgent =
    { 'header': {'typ':'JWS','alg':'HS256','kid':'f-y9zuV0-kryL5DV_xZo'}
    , 'payload':
        { 'iat': 1352841943
        , 'iss': 'app.example.com'
        , 'aud': 'ix.ca'
        , 'request.a2p3.org':
            { 'passcode': true
            , 'authorization': true
            , 'returnURL': 'https://app.example.com/return'
            , 'resources': 
                [ 'people.bc.ca/details'
                , 'health.bc.ca/number'
                ]
            }
        }
    , 'credentials':{'key':'nWyeZJJcUHCWSlVI-4AQs1JnCwz7xd8gEHlOMD4_pYo'}
    }

console.log( detailsRequestAgent)

var requestAgent = jwt.encode(detailsRequestAgent)

console.log( '\nAgent Request length:', requestAgent.length)
console.log( requestAgent)

crackRequestAgent = jwt.jwsCrack(requestAgent);

console.log( crackRequestAgent)

var payloadRequestAgent = jwt.decode( requestAgent, function (header) { return detailsRequestAgent.credentials } )

console.log( payloadRequestAgent)

/*
* Create and test an IX Token
*/
console.log('\n-------- IX Token --------- \n')

var detailsTokenIX = 
    { 'header': {'typ':'JWE','alg':'dir','enc':'A128CBC+HS256', 'kid':'DqDQ-rycvZwKNV6drtkIq2Y'}
    , 'payload':
        { 'iat': 1352841943
        , 'iss': 'as.example.com'
        , 'aud': 'ix.ca'
        , 'prn': 'nYXNwK6q9zGSTVB9s_TdeBmE6sfKq0xd1b1DVv_7aog'
        , 'token.a2p3.org':
            { 'auth':
                { 'nfc': false
                , 'passcode': true
                , 'authorization': true
                }
            , 'sig': crackRequestAgent.signature
            }
        }
    , 'credentials':{'key': 'gj2twWrfqCpAVohMcFUjoCJErCLi6maKz73qySjEJOw'}
    }

var tokenIX = jwt.encode(detailsTokenIX)

console.log( detailsTokenIX)

console.log( '\nAS Token length:', tokenIX.length)
console.log( tokenIX)

var payloadTokenIX = jwt.decode(tokenIX, function (header) { return detailsTokenIX.credentials } )

console.log(payloadTokenIX)

/*
* Create and test an IX Request
*/
console.log('\n-------- IX Request --------- \n')

var detailsRequestIX =
{ 'header': {'typ':'JWS','alg':'HS256','kid':'f-y9zuV0-kryL5DV_xZo'}
, 'payload':
    { 'iat': 1352841943
    , 'iss': 'app.example.com'
    , 'aud': 'ix.ca'
    , 'request.a2p3.org':
        { 'token': tokenIX
        , 'request': requestAgent
        }
    }
, 'credentials':{'key':'nWyeZJJcUHCWSlVI-4AQs1JnCwz7xd8gEHlOMD4_pYo'}
}

console.log( detailsRequestIX)

var requestIX = jwt.encode(detailsRequestIX)

console.log( '\nIX Request length:', requestIX.length)
console.log( requestIX)

var payloadRequestIX = jwt.decode( requestIX, function (header) { return detailsRequestIX.credentials } )

console.log( payloadRequestIX)

/*
* Create and test an RS Token
*/
console.log('\n-------- RS Token --------- \n')

var detailsTokenRS =
    { 'header': {'typ':'JWE','alg':'dir','enc':'A128CBC+HS256', 'kid':'DqDQ-NVsXP5rdNcUPSAdRUoh'}
    , 'payload':
        { 'iat': 1352841943
        , 'iss': 'ix.ca'
        , 'aud': 'health.bc.ca'
        , 'prn': 'Kc3yf3Yuvot0XUPF7dvh36l5odgkuish26dLSdDyNd0'
        , 'token.a2p3.org':
            { 'auth':
                { 'nfc': false
                , 'passcode': true
                , 'authorization': true
                }
            , 'app': 'app.example.com'
            , 'scope': 'health.bc.ca/number'
            }
        }
    , 'credentials':{'key': 'NVsXP5rdNcUPSAdRUoh-Hs4WIOemoY-AJXq9H4dCltw'}
    }

var tokenRS = jwt.encode(detailsTokenRS)

console.log( detailsTokenRS)

console.log( '\nRS Token length:', tokenRS.length)
console.log( tokenRS)

var payloadTokenRS = jwt.decode(tokenRS, function (header) { return detailsTokenRS.credentials } )

console.log(payloadTokenRS)


/*
* Create and test an RS Request
*/
console.log('\n-------- RS Request --------- \n')

var detailsRequestRS =
{ 'header': {'typ':'JWS','alg':'HS256','kid':'Wh8E-SbwKbNCN5CyOyjy'}
, 'payload':
    { 'iat': 1352841943
    , 'iss': 'app.example.com'
    , 'aud': 'ix.ca'
    , 'request.a2p3.org':
        { 'token': tokenRS }
    }
, 'credentials':{'key':'PsW9khg7lAQRlDJhmrjOwBRufOzDhXhjhYLz3nTHfqI'}
}

console.log( detailsRequestRS)

var requestRS = jwt.encode(detailsRequestRS)

console.log( '\nRS Request length:', requestRS.length)
console.log( requestRS)

var payloadRequestRS = jwt.decode( requestRS, function (header) { return detailsRequestRS.credentials } )

console.log( payloadRequestRS)




/*
for (var i=0; i<20; i++) {
    console.log(jwt.keygen('HS256'))
}

console.log(Math.round(new Date().getTime() / 1000))


nYXNwK6q9zGSTVB9s_TdeBmE6sfKq0xd1b1DVv_7aog
nWyeZJJcUHCWSlVI-4AQs1JnCwz7xd8gEHlOMD4_pYo
cwfQLm77C-3WIkjRqJSI-pZ2mU6EFTTQvZdc01Y2jtM
5bzRlITmgfro2nXegcydPDC54YwE-eFq11KbihRsIDM
gj2twWrfqCpAVohMcFUjoCJErCLi6maKz73qySjEJOw
t5Cwc39MPgCFzMeIhyROnyC42zt1urY7EtZ84JK9tQc
9fXXgbjMtMLqX1Sqf5wMplGLndTOO2wTOBAfWqQxxxo
iBJcki61-tJShT-cuOhaSTOCFTzo_EU591RoBT5sYsI
Kc3yf3Yuvot0XUPF7dvh36l5odgkuish26dLSdDyNd0
JxnwT9oJ1Xxy3ip5Nr47GiR3cdINyikWRk9f9qiDJPc
s142uVs4dkc02FOF42g06VChpvkt2p_gEASZvVoSeZk
6g0TqnCaWYWLpoc9qNM7KQ2nWBFD54xNcQBoOY3Pn9o
PsW9khg7lAQRlDJhmrjOwBRufOzDhXhjhYLz3nTHfqI
C02up13BHSxkB3rgwU5zTWh8E-SbwKbNCN5CyOyjySY
1NfizBg_1htabd8xEfdzfZIacFqX0_bdh65ymCovAVw
0ntw-3Yo7XWpyuiiNhbbCL4uEaAZDSOjs5pPpcFg-0E
NVsXP5rdNcUPSAdRUoh-Hs4WIOemoY-AJXq9H4dCltw
bYoDZ4v_zFL5r4kYVxmLEpisxFLtCRotnru98wXER-E
uo5-VsHCFg6TluiBhLkPAtnHE6I-UhS69KlwGyYrH6w
f-y9zuV0-kryL5DV_xZo DqDQ-rycvZwKNV6drtkIq2Y
*/