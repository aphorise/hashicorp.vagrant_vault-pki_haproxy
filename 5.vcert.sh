#!/usr/bin/env bash
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands.

# // No argument or just --help then print
if [[ (($# == 0)) ]] || [[ ${1-} && (($# == 1)) && $1 == "-h" || $1 == "--help" || $1 == "help" ]] ; then
    if (($# == 0)) ; then printf "REQUIRE: 'fqdn.domain.tld.local' argument.\n" ; fi ;
    printf """Usage: TLD='...' ${0##*/} fqdn.domain.tld.local
Requests certificates from Vault on (default) pki path & creates PEM as well as PKCS12 files.

EXAMPLES:
		${0##*/} 'subdomain.tld.com.local' ;
		# outputs to results to files: .json, .pem & .p12 in current path. 

		TLD='www.new.tld.local' ${0##*/} 'subdomain.new.tld.local' ;

${0##*/} 0.0.1				March 2020
""" ;
    exit 0 ;
fi ;

FQDN=$1 ;

# // if file already exists append epoch for unique file names.
if [[ -s ${FQDN}.json ]] ; then E=$(date +%s) ; FQDN=$1_${E} ; fi ;

FILE_JSON=${FQDN}.json ;  # // output
FILE_PEM=${FQDN}.pem ;  # // output
FILE_PKCS=${FQDN}.pk12 ;  # // output
FILE_CAC=${FQDN}_cachain.pem ;  # // output
FILE_BUNDLE=${FQDN}_bundle ;  # // output .p12 & .pem
FILE_KEY=${FQDN}_private_key.pem ;  # // temp output
FILE_CRT=${FQDN}_certificate.pem ;  # // temp output

if [[ ! ${TLD+x} ]]; then TLD='tld.com.local' ; fi ; # // tld default

vault write -format=json pki/issue/${TLD} common_name=${FQDN} ttl="5m" > ${FILE_JSON} ;

jq -r '.data.certificate' ${FILE_JSON} > ${FILE_CRT} ;
jq -r '.data.private_key' ${FILE_JSON} > ${FILE_KEY} ;
jq -r '.data.ca_chain[0,1]' ${FILE_JSON} > ${FILE_CAC} ;
# jq -r '.data.issuing_ca' ${FILE_JSON} >> ${FILE_CAC} ;

# // bundle with intermediate
cat ${FILE_CRT} ${FILE_KEY} ${FILE_CAC} > ${FILE_BUNDLE}.pem ;

# // pkcs12 for browsers.
openssl pkcs12 -export -clcerts -in ${FILE_CRT} -inkey ${FILE_KEY} -chain -CAfile ${FILE_CAC} -out ${FILE_BUNDLE}.p12 ;

rm -rf ${FILE_KEY} ${FILE_CRT} ; # // clean up key & certificate
