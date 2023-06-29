# mds3server
Simple example of a FIDO MDS3 server that proxies and filteres entries from the FIDO MDS then augments the list from local MDS document files


## How I created the self-signed key and certificate
```
openssl req -x509 -nodes -days 9999 -newkey rsa:2048 -sha256 -keyout "mds3server.key.pem" -out "mds3server.crt.pem" -subj /C=us/O=ibm/CN=mds3server.example.com
```
