# TLS

## Creating everything that is needed to run TLS

Cherrypicked from [here](https://gist.github.com/denji/12b3a568f092ab951456) and [here](https://kb.op5.com/pages/viewpage.action?pageId=19073746) and [here](https://github.com/jcbsmpsn/golang-https-example) and of course [here](https://github.com/cloudflare/cfssl)

0. Get cfssl: `go get -u github.com/cloudflare/cfssl/cmd/cfssl` and `go get -u github.com/cloudflare/cfssl/cmd/cfssljson`
1. Generate a CSR and save it to a file, e.g. `csr.json`. It contains basic information about the CA: 

~~~JSON
{
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C":  "DE",
            "L":  "Munich",
            "O":  "nray-scanner"
        }
    ]
}
~~~

2. Generate a local CA: `cfssl  genkey -initca csr.json | cfssljson -bare ca`. This creates `ca-key.pem`, the CA's private key, as well as `ca.pem`, the certificate and `ca.csr` which is of no further use and may be deleted.
3. Generate server certificate. If the host where nray is going to run has a DNS name, you may include it here, otherwise keep localhost: `cfssl gencert -ca ca.pem -ca-key ca-key.pem -hostname=localhost csr.json | cfssljson -bare server`. This creates files analogous to our CA, but with `server*` in their names.
4. (if node auth is desired) Generate node certificate. Analogous to server. You may omit the hostname field and ignore the warning. Repeat for every node or reuse certificate.

As you do not need the csr's anymore, you may delete them if you want.

## What you need for operation

### Server

- `ca.pem` (This is public knowledge btw)
- `server.pem` (public if you want)
- `server-key.pem` (private)

### Node

- `ca.pem` (This is public knowledge btw)
- `client.pem` (public if you want)
- `client-key.pem` (private)

## HowTo run

### Trust every server, no client auth

- Server: Set `TLS.enabled: true`, `TLS.CA: "/path/to/your/ca.pem"`, `TLS.cert: /path/to/your/server.pem`, and `TLS.key: /path/to/your/server-key.pem`
- Node: `./nray node -s <ip-or-dnsname> -p 8601 --use-tls --tls-insecure`. **This is insecure and traffic may be intercepted/modified by a 3rd party!**

#### Trust only this server, no client auth

- Server: Set `TLS.enabled: true`, `TLS.CA: "/path/to/your/ca.pem"`, `TLS.cert: /path/to/your/server.pem`, and `TLS.key: /path/to/your/server-key.pem`
- Node: `./nray node -s <ip-or-dnsname> -p 8601 --use-tls --tls-ca-cert /path/to/your/ca.pem --tls-server-SAN "<hostname>"`. If the nray-server has actually a DNS name that is also reflected in the cert, you can omit `--tls-server-SAN`, but if you are in an ad-hoc scenario or there is no DNS available and nray complains that the server name is missing, `--tls-server-SAN` is your friend.

#### Trust only this server, client authentication

- Server: Set `TLS.enabled: true`, `TLS.CA: "/path/to/your/ca.pem"`, `TLS.cert: /path/to/your/server.pem`, and `TLS.key: /path/to/your/server-key.pem`
- Node: `./nray-node -s <ip-or-dnsname> -p 8601 --use-tls --tls-ca-cert /path/to/your/ca.pem --tls-server-SAN "<hostname>" --tls-client-cert /path/to/your/client.pem --tls-client-key /path/to/your/client-key.pem`. If the nray-server has actually a DNS name that is also reflected in the cert, you can omit `--tls-server-SAN`, but if you are in an ad-hoc scenario or there is no DNS available and nray complains that the server name is missing, `--tls-server-SAN` is your friend.