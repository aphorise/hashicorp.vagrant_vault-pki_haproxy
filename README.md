# HashiCorp `vagrant` demo of **`vault`** PKI CA with HAProxy.
This repo contains a `Vagrantfile` mock of a [Vault](https://www.vaultproject.io/) server acting as a [CA](https://tools.ietf.org/html/rfc2459) using [Vault PKI Engine](https://www.vaultproject.io/docs/secrets/pki/) which manages certificates generated by it. A [HAProxy](https://www.haproxy.org/) acts as an entry load-balancer & TLS/SSL terminator where consumers must present a valid certificates.

[![demo](https://asciinema.org/a/307990.svg)](https://asciinema.org/a/307990?autoplay=1)


## Makeup & Concept

A [HAProxy](https://www.haproxy.org/) load-balancer (haproxy) host is created first wherein initial private key, CSR and Certificate approval are generated for both CA-root and CA-intermediate using [openssl](https://www.openssl.org).

The second host is a vault server (vault1 - in dev mode) minimally configured with PKI engine enabled and using the CA-intermediate certificate that was generated on the haproxy host; subsequent user / consumer certificates can then be generated and revoked in vault with [CRL](https://en.wikipedia.org/wiki/Certificate_revocation_list), [OCSP](https://en.wikipedia.org/wiki/Online_Certificate_Status_Protocol) provided at its configured paths.

Conceptually, certificates for consumers may be generated (in vault) and distributed via existing (& secure :smile:) mechanisms.

Consumer clients (devices, application, users) will need to present certificates when attempting to establish `https` connection (ie port 443) to the local DNS entry (default: `subdomain.tld.com.local`) of the load-balancer; the common certificate chain including CA-root and a certificate that's currently valid (eg not expired or on CRL) permits a connection and a response would then be rendered (HTTP-200 & text).

A depiction below shows the two (2) hosts; consumers approach the load-balancer, which screens against any unauthorised access inbound to its backend servers without a valid certificates.

```
                                          certificate generation
internet / consumers with certificates         o      o
            🌍           🌍                    -|-    -|- 
        💻--||--🔑   💻--||--🔑             ... /\ ... /\ ...
   ...     / \  ...     / \   ...               🔐🔐🔐🔐
               ________________            ._____⇪_⇪_⇪_⇪_____.
                       ╲                   |     vault1      |
                   TLS  ╲                  |   ca server     |-OCSP (provides)
             connection  ╲                 |_________________|-CRL  (provides)
                          ╲
                      ╔╦══════════════╦.200
                      ║ load-balancer  ║
      backend         ║   (haproxy)    ║
  ,=============.     ╚╩══════════════╩╝
  |   servers   |             ║ 
  |.-----------.|             ▼
  || s1, s2, … || ◄ ════ ◄ ═══╝
  |'-----------'|
  |||||||||||||||
  |=============|
```
**NOTE**: The load balancer's IP (.200) is statically set so as to copy CA-intermediate certificate on the vault host.


### Prerequisites
Ensure that you already have the following hardware & software requirements:
 
##### HARDWARE
 - **RAM** **2**+ Gb Free at least (ensure you're not hitting SWAP either or are < 100Mb)
 - **CPU** **2**+ Cores Free at least (2 or more per instance better) 
 - **Network** interface allowing IP assignment and interconnection in VirtualBox bridged mode for all instances.
 - - adjust `sNET='en0: Wi-Fi (Wireless)'` in **`Vagrantfile`** to match your system.

##### SOFTWARE
 - [**Virtualbox**](https://www.virtualbox.org/)
 - [**Virtualbox Guest Additions (VBox GA)**](https://download.virtualbox.org/virtualbox/)
 - > **MacOS** (aka OSX) - VirtualBox 6.x+ is expected to be shipped with the related .iso present under (eg):
 `/Applications/VirtualBox.app/Contents/MacOS/VBoxGuestAdditions.iso`
You may however need to download the .iso specific to your version (mount it) and execute the VBoxDarwinAdditions.pkg
 - [**Vagrant**](https://www.vagrantup.com/)
 - **Few** (**2-4**) **`shell`** or **`screen`** sessions to allow for multiple SSH sessions.


## Usage & Workflow
Refer to the contents of **`Vagrantfile`** for provisioning steps.

The provided **`.sh`** script are installer helpers that download the latest binaries (or specific versions) and write configuration of both haproxy and vault host nodes. Vault is configured in development mode with PKI enabled. Once ready (`vagrant up`) you may generate certificates in vault and distribute to consumers (for browsers or cli usage) and thereby other procedures related to revocation of certificates or their expiry can be tested.

**Inline Environment Variables** can be set for specific versions and other settings that are part of `4.install_vault.sh`.

```bash
# // Your localhost:
vagrant up --provider virtualbox ;
# // ... output of provisioning steps.
vagrant global-status ; # should show running nodes
# id       name    provider   state   directory
# -------------------------------------------------------------------------------
# 3066b4c  haproxy virtualbox running /home/auser/hashicorp.vagrant_vault-pki_haproxy
# df5c909  vault1  virtualbox running /home/auser/hashicorp.vagrant_vault-pki_haproxy

if ! grep 'subdomain.tld.com.local' /etc/hosts ; \
then printf '192.168.178.200 subdomain.tld.com.local\n' | sudo tee -a /etc/hosts ; fi ;
# // On your local host set /etc/hosts entry for subdomain.tld.com.local
curl -v https://subdomain.tld.com.local ; # // should fail
# // ...


# // SSH to vault1:
vagrant ssh vault1 ;
# // ...
vagrant@vault1:~$ \
./vcert.sh 'allowed1.tld.com.local' ;
# ...
# // Requests vault for certificate and uses provided certificates to create pkcs12. 
# // vault write -format=json pki/issue/www.tld.com.local common_name=allowed1.tld.com.local > allowed1.tld.com.local.json ;


# // back on localhost:
rsync -va -e "ssh -p2200 -i \"$(pwd)/.vagrant/machines/vault1/virtualbox/private_key\"" vagrant@127.0.0.1:~/allowed*.pem . ;
CERT_CA="allowed1.tld.com.local_cachain.pem" ;
CERT_VAULT="allowed1.tld.com.local_bundle.pem" ;
# // ... repeat curl again providing ca & cert.
curl -v --cacert ${CERT_CA} --cert ${CERT_VAULT} https://subdomain.tld.com.local/ ;
# < HTTP/1.0 200 OK
# // ... repeat with Browser
# // TTL 5 minutes so your access should not work after.

# when completely done:
vagrant destroy -f haproxy vault1 ; # ... destroy all
vagrant box remove -f debian/buster64 --provider virtualbox ; # ... delete box images
```


## Client Certificate Usage
Refer to your browsers settings for importing the CA Root Certificate (firefox url: `about:preferences#privacy`, chrome url: `chrome://settings/privacy`).

Be user to set the appropriate trust level on the CA Root Certificate that may be on a separate OS level dialogue (eg: on :apple: macOS **Keychain** Trust levels). 

Consumer Certificates in pkcs12 format can be created from generated certificates by vault and the helper script `vcert.sh` can do the certificate request and conversion.


## Notes
This is intended as a mere practise / training exercise extending the [Vault material: Build Your Own Certificate Authority (CA)](https://learn.hashicorp.com/vault/secrets-management/sm-pki-engine).

See also:
 - [Vault TLS Certificates Auth Method](https://www.vaultproject.io/docs/auth/cert/)
 - [PKI Secrets Engine (API)](https://www.vaultproject.io/api/secret/pki/index.html)

Reference material used:
 * [Be your own Certificate Authority (CA)](https://www.g-loaded.eu/2005/11/10/be-your-own-ca/)
 * [Client Certificate Authentication with HAProxy](https://www.loadbalancer.org/blog/client-certificate-authentication-with-haproxy/)
 * [haproxy: client side ssl certificates](https://raymii.org/s/tutorials/haproxy_client_side_ssl_certificates.html)
 * [Automatically generate PKI certificates with Vault](https://werner-dijkerman.nl/2017/08/25/automatically-generate-certificates-with-vault/)
------
