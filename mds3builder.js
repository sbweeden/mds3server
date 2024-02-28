// mds3builder
const fs = require('fs');
const jsrsasign = require('jsrsasign');
const logger = require('./logging.js');
const mds3proxy = require('./mds3proxy.js');
const passkeyproviders = require('./passkeyproviders.js');

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

function buildRejectTraceStr(mds) {
    // seems as good a way as any
    let result = mds.protocolFamily;
    if (mds.protocolFamily == "fido2") {
        result += "-" + mds.aagiud;
    } else if (mds.protocolFamily == "uaf") {
        result += "-" + mds.aaid;        
    }
    result += "-" + mds.description;
    return result;
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

        // something to use as the version number of the MDS doc
        let fullDaysSinceEpoch = Math.floor(now/8.64e7);

        let jwtClaims = {
            legalHeader: "Please be legal",
            no: fullDaysSinceEpoch,
            nextUpdate: tomorrow.toISOString().split('T')[0],
            "entries": []
        };

        let alreadyIncludedAAGUIDs = [];
        let alreadyIncludedAKIs = [];

        // if there are any cached entries from FIDO MDS, add them, subject to filtering and de-duplication
        let mdsCachedEntries = mds3proxy.getCachedEntries();
        if (mdsCachedEntries != null) {
            logger.logWithTS("Processing: " + mdsCachedEntries.length + " mds3proxy cached entries for possible JWT inclusion");
            mdsCachedEntries.forEach((e) => {
                if (!filterDoc(e.metadataStatement)) {
                    let alreadyIncluded = false;
                    if (e.metadataStatement.protocolFamily == "fido2") {
                        alreadyIncluded = (alreadyIncludedAAGUIDs.indexOf(e.metadataStatement.aaguid) >= 0);
                        if (!alreadyIncluded) {
                            alreadyIncludedAAGUIDs.push(e.metadataStatement.aaguid);
                        }
                    } else if (e.metadataStatement.protocolFamily == "u2f") {
                        // shouldn't be necessary but because of an issue with an MDS entry I saw once...
                        let uniqueAKIs = e.metadataStatement.attestationCertificateKeyIdentifiers.filter(
                            (value, index, array) => {
                                return array.indexOf(value) === index;
                            }
                        );
                        if (uniqueAKIs.length != e.metadataStatement.attestationCertificateKeyIdentifiers.length) {
                            logger.logWithTS("WARNING: Entry had duplicate akis that were de-duplicated: " + buildRejectTraceStr(e.metadataStatement));
                        }

                        uniqueAKIs.forEach((aki) => {
                            if (!alreadyIncluded) {
                                alreadyIncluded = (alreadyIncludedAKIs.indexOf(aki) >= 0);
                                if (!alreadyIncluded) {
                                    alreadyIncludedAKIs.push(aki);
                                }
                            }
                        });
                    }
                    if (!alreadyIncluded) {
                        jwtClaims.entries.push(e);
                    } else {
                        logger.logWithTS("Filtering out entry because detected duplicate aaguid or aki: " + buildRejectTraceStr(e.metadataStatement));
                    }
                } else {
                    logger.logWithTS("Filtering out mds cache entry: " + buildRejectTraceStr(e.metadataStatement));
                }
            });
        } else {
            logger.logWithTS("No mds3proxy cached entries to add to JWT output");
        }

        // now do the same for any static files we have, subject to them not already having 
        // an entry from FIDO MDS for that aaguid or akis, and subject to de-duplication
        docs.forEach((d) => {
            // builds an mdsentry from a plain metadata document with empty statusReports
            try {
                let alreadyExists = false;
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

                let alreadyIncluded = false;
                if (mdsEntry.metadataStatement.protocolFamily == "fido2") {
                    alreadyIncluded = (alreadyIncludedAAGUIDs.indexOf(mdsEntry.metadataStatement.aaguid) >= 0);
                    if (!alreadyIncluded) {
                        alreadyIncludedAAGUIDs.push(mdsEntry.metadataStatement.aaguid);
                    }
                } else if (mdsEntry.metadataStatement.protocolFamily == "u2f") {
                    let uniqueAKIs = mdsEntry.metadataStatement.attestationCertificateKeyIdentifiers.filter(
                        (value, index, array) => {
                            return array.indexOf(value) === index;
                        }
                    );
                    uniqueAKIs.forEach((aki) => {
                        if (!alreadyIncluded) {
                            alreadyIncluded = (alreadyIncludedAKIs.indexOf(aki) >= 0);
                            if (!alreadyIncluded) {
                                alreadyIncludedAKIs.push(aki);
                            }
                        }
                    });
                }
                if (!alreadyIncluded) {
                    jwtClaims.entries.push(mdsEntry);
                } else {
                    logger.logWithTS("Filtering out file entry because detected duplicate aaguid or aki: " + d.filename);
                }
            } catch (e) {
                logger.logWithTS("Skipping entry for filename: " + d.filename + " because unable to build mds entry with error: " + e);
            }
        });

        // now do the same for any auto-generated entries from the passkey provider github repo,
        // filtering out any entries we find that are already populated via MDS or files above (i.e. MDS and files take precendence)
        let ppCachedEntries = passkeyproviders.getCachedEntries();
        if (ppCachedEntries != null) {
            logger.logWithTS("Processing: " + ppCachedEntries.length + " passkey provider cached entries for possible JWT inclusion");
            ppCachedEntries.forEach((e) => {
                if (!filterDoc(e.metadataStatement)) {
                    let alreadyIncluded = false;
                    let skipEntry = false;
                    if (e.metadataStatement.protocolFamily == "fido2") {
                        alreadyIncluded = (alreadyIncludedAAGUIDs.indexOf(e.metadataStatement.aaguid) >= 0);
                        if (!alreadyIncluded) {
                            alreadyIncludedAAGUIDs.push(e.metadataStatement.aaguid);
                        }
                    } else if (e.metadataStatement.protocolFamily == "u2f") {
                        // shouldn't be necessary but because of an issue with an MDS entry I saw once...
                        let uniqueAKIs = e.metadataStatement.attestationCertificateKeyIdentifiers.filter(
                            (value, index, array) => {
                                return array.indexOf(value) === index;
                            }
                        );
                        if (uniqueAKIs.length != e.metadataStatement.attestationCertificateKeyIdentifiers.length) {
                            logger.logWithTS("WARNING: Entry had duplicate akis that were de-duplicated: " + buildRejectTraceStr(e.metadataStatement));
                        }

                        uniqueAKIs.forEach((aki) => {
                            if (!alreadyIncluded) {
                                alreadyIncluded = (alreadyIncludedAKIs.indexOf(aki) >= 0);
                                if (!alreadyIncluded) {
                                    alreadyIncludedAKIs.push(aki);
                                }
                            }
                        });
                    } else {
                        logger.logWithTS("Filtering out passkey provider entry because of unrecognised protocolFamily: " + buildRejectTraceStr(e.metadataStatement));
                        skipEntry = true;
                    }

                    if (!alreadyIncluded && !skipEntry) {
                        jwtClaims.entries.push(e);
                    } else {
                        logger.logWithTS("Filtering out entry because either invalid document or detected duplicate aaguid or aki: " + buildRejectTraceStr(e.metadataStatement));
                    }
                } else {
                    logger.logWithTS("Filtering out passkey provider cache entry: " + buildRejectTraceStr(e));
                }
            });
        } else {
            logger.logWithTS("No mds3proxy cached entries to add to JWT output");
        }        

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
