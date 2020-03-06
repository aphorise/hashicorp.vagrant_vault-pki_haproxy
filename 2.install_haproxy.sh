#!/usr/bin/env bash
export DEBIAN_FRONTEND=noninteractive ;
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands.

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

<html><body><h1>200 HERE WERE ARE AT VAULT</h1>
</body></html>
''' > /etc/haproxy/errors/200.http ;

printf '%s' '''global
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
 option forwardfor
 maxconn 900000
 option httpclose
 option httpchk
 http-check expect status 200
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
# peer lb1 37.48.93.65:1024
# peer lb2 37.48.93.77:1024
#//--------------------------------

frontend inwebs_https
# HTTP all traffic to HTTPS
 redirect scheme https if !{ ssl_fc }
 bind *:80
 bind *:443 verify required ssl crt /usr/lib/ssl/haproxy_cert.pem ca-file /usr/lib/ssl/cacert.pem
# bind 2a00:c98:2050:b010::a1:80
 #bind 2a00:c98:2050:b010::a1:443 ssl crt /etc/ssl/private/mtvplay.tv.pem
 compression algo gzip
 compression type text/html text/plain text/javascript application/javascript application/xml text/css
 log-format %ci\ [%T]\ %{+Q}r\ %ST\ %B\ %{+Q}hrl\ %{+Q}hsl\ %U\ %{+Q}b\ %{+Q}s
 log /dev/log    local0 info
 capture request header User-Agent len 8192
 capture request header Accept-language len 64
 #//check for regional target & use that if present
# acl url_AT hdr(host) -i at-hubs.mtvplay.tv
# acl url_AT hdr(host) -i at-hubs1.mtvplay.tv
# use_backend AT if url_AT
 default_backend UFO
#//--------------------------------

backend UFO
 http-request deny deny_status 200
#if ! valid_method
# http-send-name-header Host
# server UFO.busybox.tld 127.0.0.1:58800
#//--------------------------------

backend AT
 stick-table type ip size 20k
 stick on src
 fullconn 500000
 balance leastconn
 http-send-name-header Host
 http-request add-header X-Proto https if { ssl_fc }
 http-request add-header X-Forwarded-Proto https if { ssl_fc }
# use-server A template point for injection script to work check
 use-server at01 if { urlp(h) at01 }
 server at01 37.48.93.71:58001 check
 use-server at02 if { urlp(h) at02 }
 server at02 37.48.93.71:58002 check
 use-server at03 if { urlp(h) at03 }
 server at03 37.48.93.71:58003 check
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
''' > /etc/haproxy/haproxy.cfg ;
