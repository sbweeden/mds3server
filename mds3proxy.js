// mds3proxy
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jsrsasign = require('jsrsasign');
const logger = require('./logging.js');

// each key in this cache is of the format:
// {
//    "https url of the mds server we are proxying": {
//        "cachedMDSVersion": integer value
//        "entries": [ array of blob entries ]
//    }
// }
//
//
var _cachedServers = {};

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

function validateAndProcessMDS(mdsServerConfig, mdstxt) {

    // establish _cachedServers entry if not already present
    if (_cachedServers[mdsServerConfig.url] == null) {
        _cachedServers[mdsServerConfig.url] = {
            cachedMDSVersion: 0,
            entries: []
        };
    }

    let isValidJWTSignature = false;
    try {
        let headerObj = jsrsasign.KJUR.jws.JWS.readSafeJSONString(jsrsasign.b64utoutf8(mdstxt.split(".")[0]));
        if (headerObj != null && headerObj.x5c != null && headerObj.x5c.length > 0) {
            // verify the x5c chain
            for (let i = 0; i < (headerObj.x5c.length-1); i++) {
                let cert = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[i])));
                let ca = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[i+1])));
                if (!cert.verify(ca.publicKey)) {
                    throw ("x5c at index: " + i + " could not be verified by certificate in x5c at index: " + (i+1) + " for MDS: " + mdsServerConfig.url);
                }
            }

            // then last in chain against the CA
            let cert = new crypto.X509Certificate(new Uint8Array(jsrsasign.b64toBA(headerObj.x5c[headerObj.x5c.length-1])));
            let ca = new crypto.X509Certificate(fs.readFileSync('./'+mdsServerConfig.signerPEMFile).toString());
            if (!cert.verify(ca.publicKey)) {
                throw ("last element of JWT x5c not signed by JWS root CA for MDS: " + mdsServerConfig.url);
            }

            // now verify the JWT is signed by headerObj.x5c[0]
            let pubkey = jsrsasign.KEYUTIL.getKey(x5cToPEM(headerObj.x5c[0]));
            const allowedAlgs = ['RS256', 'ES256'];
            if (headerObj.alg == null || allowedAlgs.indexOf(headerObj.alg) == -1) {
                throw (" alg: " + headerObj.alg + " is not allowed for MDS: " + mdsServerConfig.url);
            }


            isValidJWTSignature = jsrsasign.KJUR.jws.JWS.verifyJWT(mdstxt, pubkey, {alg: [headerObj.alg]});
            if (!isValidJWTSignature) {
                logger.logWithTS("The MDS JWT signature did not validate against headerObj.x5c[0] for MDS: " + mdsServerConfig.url);
            }
        } else {
            throw ("x5c not found in JWT header for MDS: " + mdsServerConfig.url);
        }
    } catch (e) {
        logger.logWithTS("Caught error verifying MDS JWT signature: " + e + " for MDS: " + mdsServerConfig.url);
        isValidJWTSignature = false;
    }

    if (isValidJWTSignature) {
        logger.logWithTS("MDS JWT signature valid for MDS server with URL: " + mdsServerConfig.url);
        let payloadObj = jsrsasign.KJUR.jws.JWS.readSafeJSONString(jsrsasign.b64utoutf8(mdstxt.split(".")[1]));

        if (_cachedServers[mdsServerConfig.url].cachedMDSVersion != payloadObj.no) {
            _cachedServers[mdsServerConfig.url].cachedMDSVersion = payloadObj.no;
            logger.logWithTS("caching new MDS version: " + payloadObj.no + " from: " + mdsServerConfig.url);
            // deep copy
            _cachedServers[mdsServerConfig.url].entries = JSON.parse(JSON.stringify(payloadObj.entries));
        } else {
            logger.logWithTS("MDS already cached - version no: " + payloadObj.no);
        }
    } else {
        logger.logWithTS("unable to validate JWT signature, ignoring MDS: " + mdsServerConfig.url);
    }
}

function proxyMDS(mdsServerConfig) {
    // this is async - just kicks off periodic MDS refresh to cache
    logger.logWithTS("Fetching MDS from: " + mdsServerConfig.url);
	fetch( 
		mdsServerConfig.url, 
		{
			method: 'GET'
		}
	).then((response) => {
        if (response.ok) {
            // work on text output
            let txtOutput = null;
            return response.text()
            .then((txt) => {
                txtOutput = txt;
                // if there is a cacheFile configured for this mds server, try writing the txt content to the cache file now
                if (mdsServerConfig.cacheFile != null) {
                    console.log("Writing MDS cache file: " + mdsServerConfig.cacheFile);
                    return fs.promises.writeFile(mdsServerConfig.cacheFile, txt, { encoding: 'utf8' })
                    .then(() => {
                        console.log("Successfully wrote MDS cache file: " + mdsServerConfig.cacheFile);
                    }).catch((e) => {
                        console.error("Error writing MDS cache file: " + mdsServerConfig.cacheFile + " error: " + e);
                    });
                }
            }).then(() => {
                // saved, or at least attempted to, now return the txt to be processed
                return txtOutput;
            });
        } else {
            console.log("Unable to fetch MDS url: " + mdsServerConfig.url + " response status: " + response.status)
            // see if we can open local file for this MDS text from a filename from mdsServerConifg.cacheFile 
            let cacheFilename = mdsServerConfig.cacheFile;
            if (cacheFilename != null) {
                // try to read local file
                console.log("Attempting to read MDS cache file: " + cacheFilename);
                return fs.promises.stat(cacheFilename)
                .then((stat) => {
                    if (stat.isFile()) {
                        return fs.promises.readFile(cacheFilename, { encoding: 'utf8' });
                    } else {
                        throw "Unable to read MDS cache file: " + cacheFilename;
                    }
                }).then((txt) => {
                    console.log("Using contents of MDS cache file: " + cacheFilename);
                    return txt;
                }).catch((e) => {
                    let errorStr = ("Error processing cache file: " + cacheFilename + " error: " + e);
                    throw errorStr;
                });
            } else {
                throw "Unable to fetch MDS from: " + mdsServerConfig.url + " and no cache file configured";
            }
        }
    }).then((txt) => {
        // validate and process the MDS blob
        validateAndProcessMDS(mdsServerConfig, txt);
    }).then(() => {
        // do it all again soon
        setTimeout(() => proxyMDS(mdsServerConfig), process.env.MDSPROXY_REFRESH_INTERVAL);
    }).catch((error) => {
		console.log("proxyMDS error: " + error);
        // try it again soon
        setTimeout(() => proxyMDS(mdsServerConfig), process.env.MDSPROXY_REFRESH_INTERVAL);
	});
}

function proxyMDSServers() {
    let mdsServersConfig = JSON.parse(process.env.MDSPROXY_MDS_SERVERS);
    mdsServersConfig.forEach((mdsServerConfig) => {
        proxyMDS(mdsServerConfig);
    });
}

function getCachedServers() {
    return _cachedServers;
}


module.exports = { 
    getCachedServers: getCachedServers,
    proxyMDSServers: proxyMDSServers
};
