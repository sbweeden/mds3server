// mds3builder
const fs = require('fs');
const jsrsasign = require('jsrsasign');
const logger = require('./logging.js');

function processFileOrDirectory(docs, fod) {
    //logger.logWithTS("Processing fod: " + fod);
    // if fod is a file, add contents to docs, otherwise
    // recurse directory
    return fs.promises.stat(fod)
    .then((stat) => {
        if (stat.isFile()) {
            if (!fod.endsWith(".json")) {
                logger.logWithTS("Ignoring non-JSON file: " + fod);
            } else {
                return fs.promises.readFile(fod, { encoding: 'utf8' })
                .then((contents) => {
                    return JSON.parse(contents);
                }).then((jdoc) => {
                    if (!filterDoc(jdoc)) {
                        docs.push({ 
                            filename: fod, 
                            contents: jdoc
                        });
                    } else {
                        logger.logWithTS("Filtering out: "+fod);
                    }
                });
            }
        } else if (stat.isDirectory()) {
            // process each entry in the directory
            return fs.promises.readdir(fod)
            .then((files) => {
                let allPromises = [];
                files.forEach((f) => {
                    allPromises.push(processFileOrDirectory(docs,fod+"/"+f));
                });                
                return Promise.all(allPromises);
            });
        } else {
            // how odd
            logger.logWithTS("Unknown fs type for path: " + fod + " type: " + stat);
        }
    });
}

function buildJWT(docs) {
    let result = "Unknown error";
    try {
        let signerCert = new jsrsasign.X509();
        let certContents = fs.readFileSync('./'+process.env.MDSSIGNER_CRT).toString();
        signerCert.readCertPEM(certContents);
        let jwtHeader = { alg: "RS256", typ: "JWT", x5c: [ jsrsasign.hextob64(signerCert.hex) ]};

        let now = new Date();
        let tomorrow = new Date(now);
        tomorrow.setDate(tomorrow.getDate() + 1);

        let jwtClaims = {
            legalHeader: "Please be legal",
            no: 1,
            nextUpdate: tomorrow.toISOString().split('T')[0],
            "entries": []
        };
        docs.forEach((d) => {
            // builds an mdsentry from a plain metadata document with empty statusReports
            try {
                let mdsEntry = {
                    metadataStatement: d.contents,
                    statusReports: [],
                    timeOfLastStatusChange: "2000-01-01"
                }
                if (d.contents.protocolFamily == "fido2") {
                    mdsEntry.aaguid = d.contents.aaguid;
                } else if (d.contents.protocolFamily == "u2f") {
                    mdsEntry.attestationCertificateKeyIdentifiers = d.contents.attestationCertificateKeyIdentifiers;
                } else {
                    throw ("Unrecognized protocol family: " + d.contents.protocolFamily);
                }
                jwtClaims.entries.push(mdsEntry);
            } catch (e) {
                logger.logWithTS("Skipping entry for filename: " + d.filename + " because unable to build mds entry");
            }
        });

        let prvKey = jsrsasign.KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(fs.readFileSync('./'+process.env.MDSSIGNER_KEY).toString());

        let sHeader = JSON.stringify(jwtHeader);
        let sPayload = JSON.stringify(jwtClaims);
        logger.logWithTS("About to sign JWT");
        let sJWT = jsrsasign.KJUR.jws.JWS.sign(jwtHeader.alg, sHeader, sPayload, prvKey);
        result = sJWT;
    } catch (e) {
        logger.logWithTS("buildJWT ecountered error: " + e);
    }
    return result;
}

function filterDoc(mds) {
    // decide if we want this file or not - this is sample code, and you can change it however you want
    let result = false;
    // the example here only keeps u2f and fido2 docs
    if (!(["u2f","fido2"].indexOf(mds.protocolFamily || "") >= 0)) {
        result = true;
    } else {
        // this weeds out a known issue with an MDS3 doc that was deploy at some point
        if (mds.attestationCertificateKeyIdentifiers != null) {
            try {
                mds.attestationCertificateKeyIdentifiers.forEach((aki) => {
                    if (aki.length != 40) {
                        result = true;
                    }
                });
            } catch (e) {
                result = true;
            }
        }
    }
    return result;
}

// builds an MDS3 JWT from .json files within a directory (and all subdirectories)
function buildMDS3JWT(dir) {
    let allDocs = [];
    return processFileOrDirectory(allDocs, dir)
        .then(() => {
            return buildJWT(allDocs);
        })
        .catch((e) => {
            return null;
        })
}


module.exports = { 
	buildMDS3JWT: buildMDS3JWT
};
