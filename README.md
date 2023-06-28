# mds3server
Simple example of a FIDO MDS3 server that exposes local MDS documents using the MDS3 server format


## How I created the self-signed key and certificate
```
openssl req -x509 -nodes -days 9999 -newkey rsa:2048 -sha256 -keyout "mds3server.key.pem" -out "mds3server.crt.pem" -subj /C=us/O=ibm/CN=mds3server.example.com
```
