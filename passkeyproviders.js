// passkeyproviders - builds skeleton MDS "entries" array documents from a list of passkey provider basic UX info found at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json
// asssumes all these providers only support "none" attestation since otherwise they should really be in the MDS

const logger = require('./logging.js');

var _cachedPPEntries = [];

function validateAndProcessMDS(mdstxt) {

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

function buildEntries() {
    // this is async - just kicks off periodic get, build, and refresh to cache
    logger.logWithTS("Fetching Passkey Provider info from github");
	fetch( 
		'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json',
		{
			method: 'GET'
		}
	).then((response) => {
		// work on JSON output
        return response.json();
    }).then((data) => {
        let newCachedEntries = [];
        // there should be better representation of "required" fields (see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys)
        // depending on what your MDS client really needs however these are the minimum required fields for IBM Security Verify Access
        Object.keys(data).forEach((k) => {
            newCachedEntries.push({
                aaguid: k,
                metadataStatement: {
                    aaguid: k,
                    description: data[k].name,
                    schema: 3,
                    protocolFamily: "fido2",
                    attestationRootCertificates: [],
                    attestationTypes: [ "none" ],
                    icon: data[k].icon_light
                }
            });
        });
        _cachedPPEntries = newCachedEntries;
    }).then(() => {
        // do it all again soon
        setTimeout(buildEntries, process.env.MDSPROXY_REFRESH_INTERVAL);
    }).catch((error) => {
		console.log("proxyMDS error: " + error);
        // try it again soon
        setTimeout(buildEntries, process.env.MDSPROXY_REFRESH_INTERVAL);
	});
}

function getCachedEntries() {
    return _cachedPPEntries;
}


module.exports = { 
    getCachedEntries: getCachedEntries,
    buildEntries: buildEntries
};
