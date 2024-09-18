// passkeyproviders - builds skeleton MDS "entries" array documents from a list of passkey provider basic UX info found at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json
// asssumes all these providers only support "none" attestation since otherwise they should really be in the MDS

const logger = require('./logging.js');

var _cachedPPEntries = [];

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
