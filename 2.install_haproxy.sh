#!/usr/bin/env bash
export DEBIAN_FRONTEND=noninteractive ;
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands.

# // to get IP values
source ~/.profile ;

# // if no IP has been defined / read then set some default from current host adapter.
if [[ ! ${IP_WAN_INTERFACE+x} ]]; then IP_WAN_INTERFACE="$(ip a | awk '/: / { print $2 }' | sed -n 3p | cut -d ':' -f1)" ; fi ; # // 2nd interface 'eth1'
if [[ ! ${IP_WAN+x} ]]; then
	IP_WAN="$(ip a show ${IP_WAN_INTERFACE} | grep -oE '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n 1)" ;
	if (( $? != 0 )) ; then pERR "ERROR: Unable to determine WAN IP of ${IP_WAN_INTERFACE}" ; fi ;
fi ;

if [[ ! ${IP+x} ]] ; then IP=(${IP_WAN}) ; fi ; # // default to IP WAN interface if no array of IPs are provided.

# // FOR LINUX BINARIES SEE: https://haproxy.debian.net/
if ! [[ -s /etc/apt/sources.list.d/haproxy.list ]] ; then
	curl -s https://haproxy.debian.net/bernat.debian.org.gpg | sudo APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1 apt-key add - ;
	printf 'deb http://haproxy.debian.net buster-backports-2.1 main\n' > /etc/apt/sources.list.d/haproxy.list ;
fi ;
sudo apt-get update 2>&1> /dev/null && sudo apt-get -yqq install haproxy=2.1.\* 2>&1> /dev/null ;

mv /etc/haproxy/haproxy.cfg /etc/haproxy/original.haproxy.cfg ;

printf '%s' '''
HTTP/1.0 200 OK
Cache-Control: no-cache
Connection: close
Content-Type: text/html

<html><body><h1>200 HERE AT HAPROXY LB FOR VAULT.</h1>
</body></html>
''' > /etc/haproxy/errors/200.http ;

printf '%s' """global
 log /dev/log    local0
 log /dev/log    local1 notice
 chroot /var/lib/haproxy
 stats socket /run/haproxy/admin.sock mode 666 level admin
 stats timeout 30s
 user haproxy
 group haproxy
 daemon
 pidfile /var/run/haproxy.pid
 # Default SSL material locations
 ca-base /usr/lib/ssl/certs
 crt-base /usr/lib/ssl/private
 tune.ssl.default-dh-param 2048
 tune.maxaccept 4096
 ssl-server-verify required
 ssl-default-bind-options no-sslv3
 ssl-default-bind-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS
 ssl-default-server-options no-sslv3
 ssl-default-server-ciphers ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5:!DSS

defaults
 log     global
 mode    http
 option  httplog clf
 option  dontlognull
 timeout connect 5000
 timeout client  5000
 timeout server  5000
 maxconn 900000
 option httpclose
 option httpchk
 # http-check expect status 200  # // over-written / defined in-line with each backend.
 # option forwardfor  // over-written / defined in-line with each backend.
 errorfile 200 /etc/haproxy/errors/200.http
 errorfile 400 /etc/haproxy/errors/400.http
 errorfile 403 /etc/haproxy/errors/403.http
 errorfile 408 /etc/haproxy/errors/408.http
 errorfile 500 /etc/haproxy/errors/500.http
 errorfile 502 /etc/haproxy/errors/502.http
 errorfile 503 /etc/haproxy/errors/503.http
 errorfile 504 /etc/haproxy/errors/504.http
#//--------------------------------

#peers mypeers
# peer lb1 1.0.0.1:1024
# peer lb2 1.1.1.1:1024
#//--------------------------------

frontend inwebs_https
# HTTP all traffic to HTTPS
 redirect scheme https if !{ ssl_fc }
 bind *:80
 bind *:443 verify required ssl crt /usr/lib/ssl/haproxy_cert.pem ca-file /usr/lib/ssl/cacert.pem alpn h2,http/1.1
 # bind 2a00:c98:2050:b010::a1:80
 # bind 2a00:c98:2050:b010::a1:443 ssl crt /etc/ssl/private/mtvplay.tv.pem
 compression algo gzip
 compression type text/html text/plain text/javascript application/javascript application/xml text/css
 log-format %ci\ [%T]\ %{+Q}r\ %ST\ %B\ %{+Q}hrl\ %{+Q}hsl\ %U\ %{+Q}b\ %{+Q}s
 log /dev/log    local0 info
 capture request header User-Agent len 8192
 capture request header Accept-language len 64
 #//check for regional target & use that if present
 acl url_VAULT_API hdr(host) -i subdomain.tld.com.local
# acl url_VAULT1 hdr(host) -i vaul1.subdomain.tld.com.local  # could do per instance entry too.
 use_backend VAULT_API if url_VAULT_API
 default_backend UFO
#//--------------------------------

backend UFO
 http-request deny deny_status 200
#if ! valid_method
# http-send-name-header Host
# server UFO.busybox.tld 127.0.0.1:58800
#//--------------------------------

backend VAULT_API
 #stick-table type ip size 20k
 #stick on src
 #http-request add-header X-Forwarded-Proto https if { ssl_fc }  # optional but can be handy
 option forwardfor
 option persist
 http-send-name-header Host
 #http-check expect status 307  # // default vault response with basic check
 http-check expect status 400 rstring {\"errors\":[\"missing client token\"]}
 option httpchk GET /v1/kv/data/health-check HTTP/1.1
 # // based on host header target vault-server
 use-server vault1 if { req.hdr(host) vault1.tld.local }
 server vault1 ${IP[0]}:8200 check
 # use-server vault2 if { req.hdr(host) vault2.tld.local }
 # server vault2 \${IP[1]}:8200 check
 # use-server vault3 if { req.hdr(host) vault3.tld.local }
 # server vault3 \${IP[2]}:8200 check
 # // ^^ adjust or put others as needed.
 # // for a per target response 
 # http-request return 503 content-type text/plain string \"down\" if { req.hdr(host) vault1.tld.local } !{ serv_is_up(DC1_VAULT_PRIMARY_API/vault1) }
#//--------------------------------

backend VAULT_RPC
 mode    tcp
 option tcp-check
 server vault1 ${IP[0]}:8201 check
 # server vault2 \${IP[1]}:8201 check
 # server vault3 \${IP[2]}:8201 check
 # ^^ adjust or put others as needed.
#//--------------------------------


defaults

listen haadmin
 bind *:60100
 mode http
 timeout connect 5000
 timeout client  5000
 timeout server  5000
 log /dev/log    local0
 no log
 stats uri /
 stats hide-version
 stats refresh 4
 stats show-desc Vault (LB) - PKI & CA
 stats realm   Vault Load-Balancer - PKI
""" > /etc/haproxy/haproxy.cfg ;
