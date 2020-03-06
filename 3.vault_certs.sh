#!/usr/bin/env bash
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands

# // OpenSSL Configuration & paths
OPENSSL_PATH=$(openssl version -a | grep OPENSSLDIR | grep -oP '"\K[^"\047]+(?=["\047])') ; # // get directory path
OPENSSL_CONF="${OPENSSL_PATH}/openssl.cnf" ;

CA_CSN='3141' ; # // CA - Certificate Serial Number
SECRET_CA='' ;
SECRET_HAP='' ;
CA_FILE_KEY="${OPENSSL_PATH}/private/cakey.pem" ;
CA_FILE_CSR='cacert.csr' ;
CA_FILE_CRT="${OPENSSL_PATH}/cacert.pem" ;

INT_FILE_KEY="${OPENSSL_PATH}/private/intermediate.pem" ;
INT_FILE_CSR='intermediate.csr' ;
INT_FILE_CRT="${OPENSSL_PATH}/intermediate_certificate.pem" ;

I_TLS_COUNTRY='GB' ; # // Intermediate COUNTRY 2-letters - MUST PROVIDE
I_TLS_STATE='.' ; # // Intermediate STATE OR PROVINCE
I_TLS_CITY='.' ; # // Intermediate CITY
I_TLS_ORG='.' ; # // Intermediate ORGANISATION
I_TLS_ORGU='Vault CA' ; # // Intermediate ORGANISATIONAL UNIT
I_TLS_CN='vault.tld.com.local' ; # // Intermediate COMMON NAME
I_TLS_EMAIL='user@tld.com.local' ; # // Intermediate EMAIL ADDRESS
I_CSR_SUB="/C=${I_TLS_COUNTRY}/ST=${I_TLS_STATE}/L=${I_TLS_CITY}/O=${I_TLS_ORG}/OU=${I_TLS_ORGU}/CN=${I_TLS_CN}/emailAddress=${I_TLS_EMAIL}" ;


TLS_TTL=3652 ; # // 10 years approximately
HAP_FILE_KEY='haproxy_privatekey.pem' ;
HAP_FILE_CSR='haproxy_tbc.csr' ;
HAP_FILE_CRT='haproxy_certificate.pem' ;


C_TLS_COUNTRY='GB' ; # // CA COUNTRY 2-letters - MUST PROVIDE
C_TLS_STATE='.' ; # // CA STATE OR PROVINCE
C_TLS_CITY='.' ; # // CA CITY
C_TLS_ORG='.' ; # // CA ORGANISATION
C_TLS_ORGU='.' ; # // CA ORGANISATIONAL UNIT
C_TLS_CN='www.tld.com.local' ; # // CA COMMON NAME
C_TLS_EMAIL='user@tld.com.local' ; # // CA EMAIL ADDRESS
CA_CSR_SUB="/C=${C_TLS_COUNTRY}/ST=${C_TLS_STATE}/L=${C_TLS_CITY}/O=${C_TLS_ORG}/OU=${C_TLS_ORGU}/CN=${C_TLS_CN}/emailAddress=${C_TLS_EMAIL}" ;

H_TLS_COUNTRY='GB' ; # // HAProxy COUNTRY 2-letters - MUST PROVIDE
H_TLS_STATE='.' ; # // HAProxy STATE OR PROVINCE
H_TLS_CITY='.' ; # // HAProxy CITY
H_TLS_ORG='.' ; # // HAProxy ORGANISATION
H_TLS_ORGU='.' ; # // HAProxy ORGANISATIONAL UNIT
H_TLS_CN='subdomain.tld.com.local' ; # // HAProxy COMMON NAME
H_TLS_EMAIL='user2@subdomain.tld.local' ; # // HAProxy EMAIL ADDRESS
HAP_CSR_SUB="/C=${H_TLS_COUNTRY}/ST=${H_TLS_STATE}/L=${H_TLS_CITY}/O=${H_TLS_ORG}/OU=${H_TLS_ORGU}/CN=${H_TLS_CN}/emailAddress=${H_TLS_EMAIL}" ;

LOGNAME=$(logname) ;

mkdir -p "${OPENSSL_PATH}/newcerts" "${OPENSSL_PATH}/certs" "${OPENSSL_PATH}/crl" "${OPENSSL_PATH}/private" "${OPENSSL_PATH}/requests" ;
touch "${OPENSSL_PATH}/index.txt" ;

if ! [[ -s "${OPENSSL_PATH}/serial" ]] ; then
	printf "${CA_CSN}\n" > "${OPENSSL_PATH}/serial" ; # starting certificate serial
fi ;

if grep -E '\[\s?CA_default\s?]|\[\s?ca\s?\]' ${OPENSSL_CONF} 2>&1>/dev/null ; then
	printf '[ CA_default ] - exists in OpenSSL configuration.\n'
	# // CHANGE DEFAULT DIR PATH - '/' forward slashes need escaping.
	sed -i 's/^dir.*\.\/demoCA/dir\t\t= '${OPENSSL_PATH////\\/}'/g' ${OPENSSL_CONF} ;
else
	printf "ERROR: Malformed / bad or empty configuration file (${OPENSSL_CONF}).\n" ; exit 1 ;
fi ;

function makeRootCA()
{
	# // ---------------------------------------------------------------------------
	# // ROOT CA PRIVATE KEY
	if ! [[ -s ${CA_FILE_KEY} ]] ; then
		# // CA Private Key
		if [[ ${SECRET_CA} == '' ]] ; then
			# // openssl genrsa -aes256 -out ${CA_FILE_KEY} 4096 ;
			openssl genrsa -out ${CA_FILE_KEY} 4096 2>/dev/null ;
		else
			openssl genrsa -aes256 -passout pass:${SECRET_CA} -out ${CA_FILE_KEY} 4096 2>/dev/null ;
		fi ;
		printf "GENERATED: Key - CA - ${CA_FILE_KEY}.\n" ;
	else
		printf "ALREADY have: ${CA_FILE_KEY}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // CA certificate signing request CSR
	if ! [[ -s ${CA_FILE_CSR} ]] ; then
		if [[ ${SECRET_CA} == '' ]] ; then
			openssl req -new -key ${CA_FILE_KEY} -out ${CA_FILE_CSR} -subj "${CA_CSR_SUB}" 2>/dev/null ;
		else
			openssl req -passin pass:${SECRET_CA} -new -key ${CA_FILE_KEY} -out ${CA_FILE_CSR} -subj "${CA_CSR_SUB}" 2>/dev/null ; # -sha256
		fi ;
		printf "GENERATED: CSR - CA - ${CA_FILE_CSR}.\n" ;
	else
		printf "ALREADY have: ${CA_FILE_CSR}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // CA CSR to self-sign / approve
	# openssl req -passin pass:${SECRET_CA} -x509 -sha256 -days ${TLS_TTL} -key ${CA_FILE_KEY} -in ${CA_FILE_CSR} -out ${CA_FILE_CRT}
	if ! [[ -s ${CA_FILE_CRT} ]] ; then
		if [[ ${SECRET_CA} == '' ]] ; then
	#		openssl ca -batch -days ${TLS_TTL} -in ${CA_FILE_CSR} -out ${CA_FILE_CRT} ;
			openssl req -extensions v3_ca -x509 -days ${TLS_TTL} -key ${CA_FILE_KEY} -in ${CA_FILE_CSR} -out ${CA_FILE_CRT} 2>/dev/null ;
		else
	#		openssl ca -batch -passin pass:${SECRET_CA} -days ${TLS_TTL} -in ${CA_FILE_CSR} -out ${CA_FILE_CRT} ;
			openssl req -extensions v3_ca -passin pass:${SECRET_CA} -x509 -sha256 -days ${TLS_TTL} -key ${CA_FILE_KEY} -in ${CA_FILE_CSR} -out ${CA_FILE_CRT} 2>/dev/null ;
		fi ;
		# // ^^ To be distributed consumers of certificates and other certificates signed by us.
		printf "GENERATED: Certficate - CA - ${CA_FILE_CRT}.\n" ;
		cp ${CA_FILE_CRT} . ;
	else
		printf "ALREADY have: ${CA_FILE_CRT}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // ---------------------------------------------------------------------------
}

function makeInermediateCA()
{
	# // ---------------------------------------------------------------------------
	# // INTERMEDIATE PRIVATE KEY
	if ! [[ -s ${INT_FILE_KEY} ]] ; then
		# // CA Private Key
		if [[ ${SECRET_CA} == '' ]] ; then
			# // openssl genrsa -aes256 -out ${CA_FILE_KEY} 4096 ;
			openssl genrsa -out ${INT_FILE_KEY} 4096 2>/dev/null ;
		else
			openssl genrsa -aes256 -passout pass:${SECRET_CA} -out ${INT_FILE_KEY} 4096 2>/dev/null ;
		fi ;
		printf "GENERATED: Key - Intermediate - ${INT_FILE_KEY}.\n" ;
	else
		printf "ALREADY have: ${INT_FILE_KEY}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // INTERMEDIATE certificate signing request CSR
	if ! [[ -s ${INT_FILE_CSR} ]] ; then
		if [[ ${SECRET_CA} == '' ]] ; then
			openssl req -new -key ${INT_FILE_KEY} -out ${INT_FILE_CSR} -subj "${I_CSR_SUB}" 2>/dev/null ;
		else
			openssl req -passin pass:${SECRET_CA} -new -key ${INT_FILE_KEY} -out ${INT_FILE_CSR} -subj "${I_CSR_SUB}" 2>/dev/null ; # -sha256
		fi ;
		printf "GENERATED: CSR - Intermediate - ${INT_FILE_CSR}.\n" ;
	else
		printf "ALREADY have: ${INT_FILE_CSR}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // INTERMEDIATE CSR to self-sign / approve
	if ! [[ -s ${INT_FILE_CRT} ]] ; then
		if [[ ${SECRET_CA} == '' ]] ; then
			openssl ca -extensions v3_ca -batch -days ${TLS_TTL} -in ${INT_FILE_CSR} -out ${INT_FILE_CRT} 2>/dev/null ;
		else
			openssl ca -extensions v3_ca -batch -passin pass:${SECRET_CA} -days ${TLS_TTL} -in ${INT_FILE_CSR} -out ${INT_FILE_CRT} 2>/dev/null ;
		fi ;
		printf "GENERATED: Certifiate - Intermediate - ${INT_FILE_CRT}.\n" ;
		# // ^^ To be distributed to issuing CA (Vault).
		cp ${INT_FILE_CRT} . ;
		CERT_INTER_BUNDLE='ca_intermediate.pem' ;
		cat ${INT_FILE_CRT} ${INT_FILE_KEY} ${CA_FILE_CRT} > ${CERT_INTER_BUNDLE} ;
	else
		printf "ALREADY have: ${INT_FILE_CRT}\n" ;
	fi ;
	# // ---------------------------------------------------------------------------
	# // ---------------------------------------------------------------------------
}

function makeHAPCertificates()
{
	# // ---------------------------------------------------------------------------
	# // HAPROXY Private Key
	if ! [[ -s ${HAP_FILE_KEY} ]] ; then
		if [[ ${SECRET_HAP} == '' ]] ; then
			openssl genrsa -out ${HAP_FILE_KEY} 4096 2>/dev/null ;
		else
			openssl genrsa -aes256 -passout pass:${SECRET_HAP} -out ${HAP_FILE_KEY} 4096 2>/dev/null ;
		fi ;
	else
		printf "ALREADY have: ${HAP_FILE_KEY}\n" ;
	fi ;

	# // HAPROXY CSR Generate
	if ! [[ -s ${HAP_FILE_CSR} ]] ; then
		if [[ ${SECRET_HAP} == '' ]] ; then
			openssl req -new -key ${HAP_FILE_KEY} -out ${HAP_FILE_CSR} -subj "${HAP_CSR_SUB}" 2>/dev/null ; # -sha256
		else
			openssl req -passout pass:${SECRET_HAP} -new -key ${HAP_FILE_KEY} -out ${HAP_FILE_CSR} -subj "${HAP_CSR_SUB}" 2>/dev/null ; # -sha256
		fi ;
	else
		printf "ALREADY have: ${HAP_FILE_CSR}\n" ;
	fi ;

	# // HAPROXY CSR Sign / Approve
	# openssl req -passin pass:${SECRET_CA} -x509 -sha256 -days ${TLS_TTL} -key ${CA_FILE_KEY} -in ${HAP_FILE_CSR} -out ${HAP_FILE_CRT} ;
	if ! [[ -s ${HAP_FILE_CRT} ]] ; then
		if [[ ${SECRET_CA} == '' ]] ; then
			openssl ca -batch -days ${TLS_TTL} -in ${HAP_FILE_CSR} -out ${HAP_FILE_CRT} 2>/dev/null ;
		else
			openssl ca -batch -passin pass:${SECRET_CA} -days ${TLS_TTL} -in ${HAP_FILE_CSR} -out ${HAP_FILE_CRT} 2>/dev/null ;
		fi ;
	else
		printf "ALREADY have: ${HAP_FILE_CRT}\n" ;
	fi ;
}

makeRootCA ; 
makeInermediateCA ;
makeHAPCertificates ;

# // COPY KEY & CRT to OpenSSL Paths.
cp ${HAP_FILE_KEY} ${OPENSSL_PATH}/private/.  && cp ${HAP_FILE_CRT} ${OPENSSL_PATH}/certs/.

cat ${HAP_FILE_KEY} ${HAP_FILE_CRT} > /usr/lib/ssl/haproxy_cert.pem ;

chown -R ${LOGNAME} . ;

# // need to restart HAPROXY since we now have certs.
service haproxy restart ;

# // generation of p12
# sudo openssl pkcs12 -export -clcerts -in vault_certificate.pem -inkey vault_privatekey.pem -out client.p12

# // p12 with issuing (intermediate) ca cert (generated by vault) 
#openssl pkcs12 -export -clcerts -in testing1.tld.com.local_certificate.pem -inkey testing1.tld.com.local_key.pem -chain -CAfile vault_ca.pem -out testing1.tld.com.local2.p12

# // REGENERATE SERVICE READY KEY with no pass prompts
# openssl rsa -in ${HAP_FILE_KEY} -out unsecured.${HAP_FILE_KEY}
