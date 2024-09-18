// server.js
// where your node app starts

// init project
const express = require('express');
const https = require('https');
const fs = require('fs');
const app = express();
const mds3proxy = require('./mds3proxy.js');
const passkeyproviders = require('./passkeyproviders.js');
const mds3builder = require('./mds3builder.js');

// set to ignore ssl cert errors when making requests
process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = 0;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// http://expressjs.com/en/starter/static-files.html
app.use('/static', express.static('public'));



//console.log(process.env);

// http://expressjs.com/en/starter/basic-routing.html
app.get('/', (req, rsp) => {
  	rsp.sendFile(__dirname + '/views/index.html');
});

app.get('/mds', (req, rsp) => {
	mds3builder.buildMDS3JWT(process.env.METADATA_DIR)
	.then((jwtstr) => {
		const buf = Buffer.from(jwtstr);
		// I don't think content-disposition is strictly necessary here, but including to be consistent with FIDO MDS3 server
		rsp.writeHead(200, {
		  'Content-Type': 'application/octet-stream',
		  'Content-Disposition': 'attachment; filename=blob.jwt'
		});
		rsp.write(buf);
		rsp.end();    	
	})
});

// some one-time startup
mds3proxy.proxyMDSServers();
passkeyproviders.buildEntries();

// listen for requests
if (process.env.LOCAL_SSL_SERVER == "true") {
	https.createServer({
	    key: fs.readFileSync('./'+process.env.MDSSIGNER_KEY),
	    cert: fs.readFileSync('./'+process.env.MDSSIGNER_CRT)
	}, app)
	.listen(process.env.LOCAL_SSL_PORT, function() {
	  	console.log('Your SSL app is listening on port ' + process.env.LOCAL_SSL_PORT);
	});
} else {
	const listener = app.listen(process.env.PORT, function() {
	  	console.log('Your app is listening on port ' + listener.address().port);
	});
}