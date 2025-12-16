// generateAAGUIDLookupTable.js
//

//
// A standalone client that helps generate a JS variable that is useful in client-side autonaming of passkeys
//
const fs = require('fs');
const crypto = require('crypto');
const jsrsasign = require('jsrsasign');
const logger = require('./logging.js');

// get configuration in place
require('dotenv').config();

let mdsServersConfig = JSON.parse(process.env.MDSPROXY_MDS_SERVERS);
let allPromises = [];
let aaguidLookupTable = {};

let INCLUDE_ICON = false;

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

function processMDS(mdsServerConfig) {
    return fetch( 
        mdsServerConfig.url, 
        {
            method: 'GET'
        }
    ).then((response) => {
        // work on text output
        return response.text();
    }).then((mdstxt) => {

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
                let ca = new crypto.X509Certificate(fs.readFileSync('./'+mdsServerConfig.signerPEMFile).toString());
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
            let payloadObj = jsrsasign.KJUR.jws.JWS.readSafeJSONString(jsrsasign.b64utoutf8(mdstxt.split(".")[1]));

            payloadObj.entries.forEach((e) => {
                if (e.protocolFamily == "fido2") {
                    let aaguid = e.aaguid;
                    let description = e.description;

                    if (!(aaguid in aaguidLookupTable)) {
                        aaguidLookupTable[aaguid] = {};
                        aaguidLookupTable[aaguid]["name"] = description;
                        if (INCLUDE_ICON && e.icon != null) {
                            aaguidLookupTable[aaguid]["icon"] = e.icon;
                        }
                    }
                }
            });    
        } else {
            logger.logWithTS("unable to validate JWT signature, ignoring MDS: " + mdsServerConfig.url);
        }
    });
}

function processPasskeyDeveloper() {
    return fetch( 
        "https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/refs/heads/main/combined_aaguid.json", 
        {
            method: 'GET'
        }
    ).then((response) => {
		// work on JSON output
        return response.json();
    }).then((data) => {
        Object.keys(data).forEach((k) => {
            let aaguid = k;
            let description = data[k].name;
            if (!(aaguid in aaguidLookupTable)) {
                aaguidLookupTable[aaguid] = {};
                aaguidLookupTable[aaguid]["name"] = description;

                if (INCLUDE_ICON && data[k].icon_light != null) {
                    aaguidLookupTable[aaguid]["icon"] = data[k].icon_light;
                }
            }
        });
    });
}

/*
 * Main entry point here 
 */
mdsServersConfig.forEach((mdsServerConfig) => {
    allPromises.push(processMDS(mdsServerConfig));
});
allPromises.push(processPasskeyDeveloper());

Promise.all(allPromises)
.then(() => {
    console.log("const aaguidLookupTable = " + JSON.stringify(aaguidLookupTable) + ";");
});
