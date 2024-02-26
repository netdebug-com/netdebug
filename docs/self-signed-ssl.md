To test/run the webserver with SSL during development we can use self-signed SSL certs. 

## Create self signed cert with openssl

1. Create a config file with the info to put into the cert. Note, apparently commonName is no longer
the preferred place to put the DNS names of the server. Instead SubjectAlternativeName is used. We pick **netdebug-local** as our host-/dns-name. 

```
cat > req.conf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
[req_distinguished_name]
C = US
ST = VA
L = SomeCity
O = Netdebug local development
OU = MyDivision
CN = netdebug-local
[v3_req]
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = netdebug-local
EOF
```

2. Create the private key and cert

```
openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout key.pem -out cert.pem -config req.conf -extensions 'v3_req'
```

We now have `key.pem` and `cert.pem`

## Add certificate as trusted cert to OS (optional)

### MacOS

* right-click cert.pem -> "Open With" -> "Keychain Access". This 
should import the cert. 
* Then click on the "Certificates" tab in Keychain Access, select the newly imported cert, and double-click it. This should open a detailed view of 
the cert
* Expand the "Trust" section (above Details). 
* Select "When using this certificate": "Always Trust". Done

### Windows 

tbd

### Linux 

tbd

## Add host entry to /etc/hosts 

No idea how to do it under windows. There's probably a way though. 

Edit `/etc/hosts` and add and entry or entries for the dns-name we used in the cert (`netdebug-local`):

```
127.0.0.1   netdebug-local
::1   netdebug-local
```

## Start the webserver

* The key.pem and cert.pem files can now be passed to the webserver binary with 
`--tls-cert` and `--tls-key`. 
  * **NOTE:** currently, you need to pass `--production` to the webserver for it to use ssl. 
* Point your browser to `https://netdebug-local:3030`
* Profit.