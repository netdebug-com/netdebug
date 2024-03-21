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

Rename the cert.pem to cert.crt, then right click and "Install Certificate".  Select "Current User" and
hit 'Next', instead of "Automatically select the store", click "Browse" and select "Trusted Root 
Certificate Authorities"-> "Next" -> "Finish".

NOTE you don't need to follow the (21!) steps from this URL : https://learn.microsoft.com/en-us/biztalk/adapters-and-accelerators/accelerator-swift/adding-certificates-to-the-certificates-store-on-the-client to import the certificate.

To update /etc/hosts in windows, follow:


    Open the Start menu.

    In the Run box, type Notepad.exe and before you hit enter you must right-click on Notepad and Run as administrator.
    In Notepad, select File then Open.
    Navigate to C:\Windows\System32\drivers\etc.
    Change the file type to open from Text Documents (*.txt) to All Files (*.*).
    Open the hosts file.
    Read the comments in the host file. The comments begin with a # character.
    Observe the host records stored in the file. At a minimum you should find a record for 127.0.0.1 localhost.

NOTE: if you are developing in WSL, you don't need to do *any* of this... (deep sigh)

### Linux or WSL

Follow https://unix.stackexchange.com/questions/90450/adding-a-self-signed-certificate-to-the-trusted-list but basically it's 

1. sudo apt-get install ca-certificates
2. cp cert.pem /usr/share/ca-certificates/mozilla/netdebug-local.crt   # NOTE the new .crt extension!
3. dpkg-reconfigure ca-certificates

NOTE: if you're on WSL and you've added the 'netdebug-local' entry to /etc/hosts on the *windows* machine,
WSL will read that automatically so you don't need to (but still can) add it to the WSL /etc/hosts.

## Add host entry to /etc/hosts 

Edit `/etc/hosts` and add and entry or entries for the dns-name we used in the cert (`netdebug-local`):
See the Windows section above for how to edit the hosts file in Windows.  Make sure to install both v4
and v6 addresses (NOTE: especially for Windows with WSL).


```
127.0.0.1   netdebug-local
::1   netdebug-local
```

```ping netdebug-local``` to make sure it worked.
## Start the webserver

* The key.pem and cert.pem files can now be passed to the webserver binary with 
`--tls-cert` and `--tls-key`. 
  * **NOTE:** currently, you need to pass `--production` to the webserver for it to use ssl. 
* Point your browser to `https://netdebug-local:3030`
* Profit.