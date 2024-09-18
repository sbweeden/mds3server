// confighelper

//
// Returns the value of a named property in the stringified object specified 
// in the MDSPROXY_ADVANCED entry of .env or null if there is any problem
//
function getAdvancedConfiguration(param) {
    let result = null;
    let cfgObj = null;
    try {
        cfgObj = JSON.parse(process.env.MDSPROXY_ADVANCED);
    } catch(e) {
        console.log("Invalid value for advanced configuration property MDSPROXY_ADVANCED: " + process.env.MDSPROXY_ADVANCED);
    }
    if (cfgObj != null && cfgObj instanceof Object) {
        result = cfgObj[param];
    }
    return result;
}

module.exports = { 
	getAdvancedConfiguration: getAdvancedConfiguration
};
