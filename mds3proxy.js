// mds3proxy
const fs = require('fs');
const crypto = require('crypto');
const jsrsasign = require('jsrsasign');
const logger = require('./logging.js');

var _cachedMDSVersion = 0;
var _cachedEntries = [];

function x5cToPEM(b64cert) {
    let result = "-----BEGIN CERTIFICATE-----\n";
    for (; b64cert.length > 64; b64cert = b64cert.slice(64)) {
        result += b64cert.slice(0, 64) + "\n";
    }
    if (b64cert.length > 0) {
        result += b64cert + "\n";
    }
    result += "-----END CERTIFICATE-----\n";
    return result;
}

function validateAndProcessMDS(mdstxt) {

    // testing
    //mdstxt = fs.readFileSync('/Users/sweeden/tmp/x.x').toString();
    //logger.logWithTS("validateAndProcessMDS: " + mdstxt);

    let isValidJWTSignature = false;
    try {
        let headerObj = jsrsasign.KJUR.jws.JWS.readSafeJSONString(jsrsasign.b64utoutf8(mdstxt.split(".")[0]));
        if (headerObj != null && headerObj.x5c != null && headerObj.x5c.length > 0) {
            // verify the x5c chain
            for (let i = 0; i < (headerObj.x5c.length-1); i++) {
                let cert = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[i])));
                let ca = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[i+1])));
                if (!cert.verify(ca.publicKey)) {
                    throw ("x5c at index: " + i + " could not be verified by certificate in x5c at index: " + (i+1));
                }
            }

            // then last in chain against the CA
            let cert = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[headerObj.x5c.length-1])));
            let ca = new crypto.X509Certificate(fs.readFileSync('./'+process.env.MDSPROXY_JWT_SIGNER).toString());
            if (!cert.verify(ca.publicKey)) {
                throw ("last element of JWT x5c not signed by JWS root CA");
            }

            // now verify the JWT is signed by headerObj.x5c[0]
            let pubkey = jsrsasign.KEYUTIL.getKey(x5cToPEM(headerObj.x5c[0]));
            isValidJWTSignature = jsrsasign.KJUR.jws.JWS.verifyJWT(mdstxt, pubkey, {alg: ['RS256']});
        } else {
            throw "x5c not found in JWT header";
        }
    } catch (e) {
        logger.logWithTS("Caught error verifying MDS JWT signature: " + e);
        isValidJWTSignature = false;
    }

    if (isValidJWTSignature) {
        logger.logWithTS("MDS JWT signature valid");
        let payloadObj = jsrsasign.KJUR.jws.JWS.readSafeJSONString(jsrsasign.b64utoutf8(mdstxt.split(".")[1]));

        if (_cachedMDSVersion != payloadObj.no) {
            _cachedMDSVersion = payloadObj.no;
            logger.logWithTS("caching new MDS version: " + _cachedMDSVersion);
            // deep copy
            _cachedEntries = JSON.parse(JSON.stringify(payloadObj.entries));
        } else {
            logger.logWithTS("MDS already cached - version no: " + _cachedMDSVersion);
        }
    } else {
        logger.logWithTS("unable to validate JWT signature, ignoring MDS");
    }
}

function proxyMDS() {
    // this is async - just kicks off periodic MDS refresh to cache
    logger.logWithTS("Fetching MDS from FIDO");
	fetch( 
		'https://mds.fidoalliance.org/', 
		{
			method: 'GET'
		}
	).then((response) => {
		// work on text output
        return response.text();
    }).then((txt) => {
        // validate and process the MDS blob
        validateAndProcessMDS(txt);

        // do it all again soon
        setTimeout(proxyMDS, process.env.MDSPROXY_REFRESH_INTERVAL);
    }).catch((error) => {
		console.log("proxyMDS error: " + error);
        // try it again soon
        setTimeout(proxyMDS, process.env.MDSPROXY_REFRESH_INTERVAL);
	});
}

function getCachedEntries() {
    return _cachedEntries;
}


module.exports = { 
    getCachedEntries: getCachedEntries,
    proxyMDS: proxyMDS
};
