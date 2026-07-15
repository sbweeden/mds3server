const fs = require('fs');

// passkeyproviders - builds skeleton MDS "entries" array documents from a list of passkey provider basic UX info found at
// https://github.com/passkeydeveloper/passkey-authenticator-aaguids/blob/main/aaguid.json
// asssumes all these providers only support "none" attestation since otherwise they should really be in the MDS

const OUTPUT_DIR = "./passkeyprovidersmds";

console.log("Fetching passkey provider data from github");
fetch( 
    'https://raw.githubusercontent.com/passkeydeveloper/passkey-authenticator-aaguids/main/aaguid.json',
    {
        method: 'GET'
    }
).then((response) => {
    // work on JSON output
    return response.json();
}).then((data) => {
    return fs.promises.mkdir(OUTPUT_DIR, { recursive: true }).then(() => data);
}).then((data) => {
    // there could be better representation of "required" fields (see https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#metadata-keys)
    // depending on what your MDS client really needs however these are the minimum required fields for IBM Security Verify Access
    let allPromises = [];
    Object.keys(data).forEach((k) => {
        let mdsData = {
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
        };

        allPromises.push(
            fs.promises.writeFile(
                `${OUTPUT_DIR}/${k}.json`,
                JSON.stringify(mdsData, null, 2), 
                { encoding: 'utf8', flag: 'w' }
            )
        );
    });
    return Promise.all(allPromises);
}).then(() => {
    console.log("Passkey provider processing complete");
}).catch((error) => {
    console.log("error processing passkeys provider: " + error);
});

