#!/usr/bin/env bash
set -eu ; # abort this script when a command fails or an unset variable is used.
#set -x ; # echo all the executed commands.

if [[ ${1-} ]] && [[ (($# == 1)) || $1 == "-h" || $1 == "--help" || $1 == "help" ]] ; then
printf """Usage: VARIABLE='...' ${0##*/} [OPTIONS]
Installs HashiCorp Vault in development mode for PKI certificate generation..

By default this script only downloads & copies binaries where no inline SETUP
value is provided ('server'). The server instane is a single development node ('-dev')

Some of the inline variables and values that can be set are show below.

For upto date & complete documentation of Vault see: https://www.vaultproject.io/

VARIABLES:
		SETUP='' # // default just download binary otherwise 'server'
		VAULT_VERSION='' # // default LATEST - '1.3.2+ent' for enterprise or oss by default.
		IP_WAN_INTERFACE='eth1' # // default for cluster_address uses where not set eth1.

EXAMPLES:
		SETUP='server' ${0##*/} ;
			# install latest vault version setting up systemd services too.

		SETUP='server' IP_WAN_INTERFACE='eth0' ${0##*/} ;
			# Use a differnt interface ip for vault cluster_address binding.

${0##*/} 0.0.1				February 2020
""" ;
fi ;

if ! which curl 2>&1>/dev/null ; then printf 'ERROR: curl utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;
if ! which unzip 2>&1>/dev/null ; then printf 'ERROR: unzip utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;
if ! which jq 2>&1>/dev/null ; then printf 'ERROR: jq utility missing & required. Install & retry again.\n' ; exit 1 ; fi ;

LOGNAME=$(logname) ;

if [[ ! ${SETUP+x} ]]; then SETUP='server' ; fi ; # // default 'server' setup or change to 'client'

if [[ ! ${USER_VAULT+x} ]] ; then USER_VAULT='vault' ; fi ; # // default vault user.

if [[ ! ${URL_VAULT+x} ]]; then URL_VAULT='https://releases.hashicorp.com/vault/' ; fi ;
if [[ ! ${VAULT_VERSION+x} ]]; then VAULT_VERSION='' ; fi ; # // VERSIONS: "1.3.2' for OSS, '1.3.2+ent' for Enterprise, '1.3.2+ent.hsm' for Enterprise with HSM.
if [[ ! ${OS_CPU+x} ]]; then OS_CPU='' ; fi ; # // ARCH CPU's: 'amd64', '386', 'arm64' or 'arm'.
if [[ ! ${OS_VERSION+x} ]]; then OS_VERSION=$(uname -ar) ; fi ; # // OS's: 'Darwin', 'Linux', 'Solaris', 'FreeBSD', 'NetBSD', 'OpenBSD'.

if [[ ! ${PATH_INSTALL+x} ]]; then PATH_INSTALL="$(pwd)/vault_installs" ; fi ; # // where vault install files will be.
if ! mkdir -p ${PATH_INSTALL} 2>/dev/null ; then printf "\nERROR: Could not create directory at: ${PATH_INSTALL}\n"; exit 1; fi ;

if [[ ! ${SYSD_FILE+x} ]]; then SYSD_FILE='/etc/systemd/system/vault.service' ; fi ; # name of SystemD service for vault.
if [[ ! ${PATH_VAULT+x} ]]; then PATH_VAULT='/etc/vault.d' ; fi ; # // Vault Daemon Path where configuration & files are to reside.
if [[ ! ${PATH_BINARY+x} ]]; then PATH_BINARY='/usr/local/bin/vault' ; fi ; # // Target binary location for vault executable.
if [[ ! ${PATH_VAULT_CONFIG+x} ]]; then PATH_VAULT_CONFIG="${PATH_VAULT}/vault.hcl" ; fi ; # // Main vault config.
if [[ ! ${PATH_VAULT_DATA+x} ]]; then PATH_VAULT_DATA='/vault/data' ; fi ; # // Where local storage is used local data path.

if [[ ! ${IP_VAULT_ACTIVE+x} ]]; then IP_VAULT_ACTIVE='192.168.10.252' ; fi ;
if [[ ! ${IP_RAFT_JOIN+x} ]]; then IP_RAFT_JOIN="http://${IP_VAULT_ACTIVE}:8200" ; fi ;

if [[ ! ${IP_WAN_INTERFACE+x} ]]; then IP_WAN_INTERFACE="$(ip a | awk '/: / { print $2 }' | sed -n 3p | cut -d ':' -f1)" ; fi ; # 2nd interface 'eth1'
if [[ ! ${IP_LAN_INTERFACE+x} ]]; then IP_LAN_INTERFACE="$(ip a | awk '/: / { print $2 }' | sed -n 3p | cut -d ':' -f1)" ; fi ; # 2nd interface 'eth1'

if [[ ! ${IP_WAN+x} ]]; then
	IP_WAN="$(ip a show ${IP_WAN_INTERFACE} | grep -oE '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n 1)" ;
	if (( $? != 0 )) ; then printf "ERROR: Unable to determine WAN IP of ${IP_WAN_INTERFACE}\n" ; fi ;
fi ;

if [[ ! ${IP_LAN+x} ]]; then
	IP_LAN="$(ip a show ${IP_LAN_INTERFACE} | grep -oE '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' | head -n 1)" ;
	if (( $? != 0 )) ; then printf "ERROR: Unable to determine LAN IP of ${IP_LAN_INTERFACE}\n" ; fi ;
fi ;

VAULT_ADDR="http://${IP_WAN}:8200" ;

if [[ ! ${VAULT_NODENAME+x} ]]; then VAULT_NODENAME=$(hostname) ; fi ; # // will be based on hostname *1 == main, others standby.

# // ----------------------------------------------------------
# // WARNING! DO NOT USE IN REAL LIFE.
# // development mode root key is root.
if [[ ${VAULT_TOKEN+x} ]] ; then return ; else VAULT_TOKEN='root' ; fi ;
# // ----------------------------------------------------------

if [[ ! ${VAULT_CONFIG_SETTINGS+x} ]]; then VAULT_CONFIG_SETTINGS='' ; fi ; # // vault config settings.
if [[ ${VAULT_CONFIG_SETTINGS} == '' ]] ; then VAULT_CONFIG_SETTINGS='# // see systemd start-up\n' ; fi ;

sERR="\nREFER TO: ${URL_VAULT}\n\nERROR: Operating System Not Supported.\n" ;
sERR_DL="\nREFER TO: ${URL_VAULT}\n\nERROR: Could not determined download state.\n" ;

# // PGP Public Key on Security Page which can be piped to file.
#PGP_KEY_PUB=$(curl -s https://www.hashicorp.com/security.html | grep -Pzo '\-\-\-\-\-BEGIN PGP PUBLIC KEY BLOCK\-\-\-\-\-\n.*\n(\n.*){27}?') ;
#curl -s ${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS.sig ;
#getconf LONG_BIT ; # // can be handy for 32bit vs 64bit determination

# // DETERMINE LATEST VERSION - where none are provided.
if [[ ${VAULT_VERSION} == '' ]] ; then
	VAULT_VERSION=$(curl -s ${URL_VAULT} | grep '<a href="/vault/' | grep -v -E 'rc|ent|beta|hsm' | head -n 1 | grep -E -o '([0-9]{1,3}[\.]){2}[0-9]{1,3}' | head -n 1) ;
	if [[ ${VAULT_VERSION} == '' ]] ; then
		printf '\nERROR: Could not determine valid / current vault version to download.\n' ;
		exit 1 ;
	fi ;
fi ;

if [[ ! ${FILE+x} ]] ; then FILE="vault_${VAULT_VERSION}_" ; fi ; # // to be appended later.
if [[ ! ${URL+x} ]] ; then URL="${URL_VAULT}${VAULT_VERSION}/" ; fi ; # // to be appended later.
if [[ ! ${URL2+x} ]] ; then URL2="${URL_VAULT}${VAULT_VERSION}/vault_${VAULT_VERSION}_SHA256SUMS" ; fi ;

set +e ; CHECK=$(vault --version 2>&1) ; set -e ; # // maybe required vault version is already installed.
if [[ ${CHECK} == *"v${VAULT_VERSION}"* ]] && [[ (($# == 0)) || $1 != "-f" || $2 != "-f" ]] ; then printf "Vault v${VAULT_VERSION} already installed; Use '-f' to force this script to run anyway.\nNo action taken.\n" && exit 0 ; fi ;

sAOK="Remember to copy ('cp'), link ('ln') or path the vault executable as required.\n" ;
sAOK+="Try: '${PATH_BINARY} --version' ; # to test.\nSuccessfully installed Vault ${VAULT_VERSION} in: ${PATH_INSTALL}\n" ;

function donwloadUnpack()
{
	printf "Downloading from: ${URL}\n" ;
	cd ${PATH_INSTALL} && \
	if wget -qc ${URL} && wget -qc ${URL2} ; then
		if [[ $(shasum -a 256 -c vault_${VAULT_VERSION}_SHA256SUMS 2>&1>/dev/null | grep OK) == "" ]] ; then
			if unzip -qo ${FILE} ; then printf "${sAOK}" ; else printf "\nERROR: Could not unzip.\n" ; exit 1 ; fi ;
			chown -R ${LOGNAME} ${PATH_INSTALL} ;
		else
			printf '\nERROR: During shasum - Downloaded .zip corrupted?\n' ;
			exit 1 ;
		fi ;
	else
		printf "${sERR_DL}" ;
	fi ;
}

if [[ ${OS_CPU} == '' ]] ; then
	if [[ ${OS_VERSION} == *'x86_64'* ]] ; then
		OS_CPU='amd64' ;
	else
		if [[ ${OS_VERSION} == *' i386'* || ${OS_VERSION} == *' i686'* ]] ; then OS_CPU='386' ; fi ;
		if [[ ${OS_VERSION} == *' armv6'* || ${OS_VERSION} == *' armv7'* ]] ; then OS_CPU='arm' ; fi ;
		if [[ ${OS_VERSION} == *' armv8'* || ${OS_VERSION} == *' aarch64'* ]] ; then OS_CPU='arm64' ; fi ;
		if [[ ${OS_VERSION} == *'solaris'* ]] ; then OS_CPU='amd64' ; fi ;
	fi ;
	if [[ ${OS_CPU} == '' ]] ; then printf "${sERR}" ; exit 1 ; fi ;
fi ;

case "$(uname -ar)" in
	Darwin*)
		printf 'macOS (aka OSX)\n' ;
		if which brew > /dev/null ; then
			printf 'Consider: "brew install vault" since you have HomeBrew availble.\n' ;
		else :; fi ;
		FILE="${FILE}darwin_${OS_CPU}.zip" ;
	;;
	Linux*)
		printf 'Linux\n' ;
		FILE="${FILE}linux_${OS_CPU}.zip" ;
	;;
	*Solaris)
		printf 'SunOS / Solaris\n' ;
		FILE="${FILE}solaris_${OS_CPU}.zip" ;
	;;
	*FreeBSD*)
		printf 'FreeBSD\n' ;
		FILE="${FILE}freebsd_${OS_CPU}.zip" ;
	;;
	*NetBSD*)
		printf 'NetBSD\n' ;
		FILE="${FILE}netbsd_${OS_CPU}.zip" ;
	;;
	*OpenBSD*)
		printf 'OpenBSD\n' ;
		FILE="${FILE}netbsd_${OS_CPU}.zip" ;
	;;
	*Cygwin)
		printf 'Cygwin - POSIX on MS Windows\n'
		FILE="${FILE}windows_${OS_CPU}.zip" ;
		URL="${URL}${FILE}" ;
		printf "Conisder downloading (exe) from: ${URL}.\nUse vault.exe from CMD / Windows Prompt(s).\n" ;
		exit 0 ;
	;;
	*)
		printf "${sERR}" ;
		exit 1 ;
	;;
esac ;


function sudoSetup()
{
	if [[ ${FILE} == *"darwin"* ]] ; then printf '\nWARNING: On MacOS - all other setup setps will need to be appropriatly completed by the user.\n' ; exit 0 ; fi ;
	if ! [[ $(id -u) == 0 ]] ; then printf 'ERROR: Root privileges lacking to peform all setup tasks. Consider "sudo ..." re-execution.\n' ; exit 1 ; fi ;

	# // Move vault to default paths
	cd ${PATH_INSTALL} && \
	chown root:root vault && \
	mv vault ${PATH_BINARY} ;

	# Give ability to mlock syscall without running the process as root & preventing memory from being swapped to disk.
	setcap cap_ipc_lock=+ep ${PATH_BINARY} ; # // /usr/local/bin/vault

	# Create a unique, non-privileged system user to run Vault.
	if ! id -u ${USER_VAULT} &>/dev/null ; then
		useradd --system --home ${PATH_VAULT} --shell /bin/false ${USER_VAULT} ;
	else
		printf 'USER: vault - already present.\n' ;
	fi ;

	# // Enable auto complete
	set +e
	vault -autocomplete-install 2>/dev/null && complete -C ${PATH_BINARY} vault 2>/dev/null;
	USER=$(logname) ;
	su -l ${USER} -c "vault -autocomplete-install 2>/dev/null && complete -C ${PATH_BINARY} vault 2>/dev/null;"
	set -e

	# // SystemD for service / startup
	if ! which systemctl 2>&1>/dev/null ; then printf '\nERROR: No systemctl / SystemD installed on system.' ; exit 1 ; fi ;
	if [[ ${FILE} == *"darwin"* ]] ; then printf '\nERROR: Only SystemD can be provisioned - build MacOS launchd plist yourself.\n' ; exit 1 ; fi ;

	if ! [[ -d ${PATH_VAULT_DATA} ]] ; then mkdir -p ${PATH_VAULT_DATA} && chown -R ${USER_VAULT}:${USER_VAULT} ${PATH_VAULT_DATA} ; fi ;

	if mkdir -p ${PATH_VAULT} && touch ${PATH_VAULT_CONFIG} && chown -R ${USER_VAULT}:${USER_VAULT} ${PATH_VAULT} && chmod 640 ${PATH_VAULT_CONFIG} ; then
		if ! [[ -s ${PATH_VAULT_CONFIG} ]] ; then
			printf "${VAULT_CONFIG_SETTINGS}" >> ${PATH_VAULT_CONFIG} ;
		else
			printf "VAULT Conifg: ${PATH_VAULT_CONFIG} - already present.\n" ;
		fi ;
	else
		printf "\nERROR: Unable to create ${PATH_VAULT}.\n" ; exit 1 ;
	fi ;

	if ! [[ -s ${SYSD_FILE} ]] && [[ ${SETUP,,} == *'server'* ]]; then
		UNIT_SYSTEMD='[Unit]\nDescription=Vault\nDocumentation=https://www.vaultproject.io/docs/\nRequires=network-online.target\nAfter=network-online.target\n\n[Service]\nEnvironment=VAULT_DEV_ROOT_TOKEN_ID=root\nRestart=on-failure\nExecStart=/usr/local/bin/vault server -dev -dev-listen-address=0.0.0.0:8200\nExecReload=/bin/kill -HUP $MAINPID\nKillSignal=SIGINT\n\n[Install]\nWantedBy=multi-user.target\n' ;
		printf "${UNIT_SYSTEMD}" > ${SYSD_FILE} && chmod 664 ${SYSD_FILE} ;
		systemctl daemon-reload ;
		systemctl enable vault.service ;
		systemctl start vault.service ;
	fi ;
}

function setupPKI()
{
	CERT_INTER_BUNDLE='/home/vagrant/ca_intermediate.pem' ;

	sleep 3 ; # // wait for 3 secs for server to properly start.
	# // Env Variable VAULT_TOKEN for CLI 
	if ! grep VAULT_TOKEN /home/${LOGNAME}/.bashrc ; then
		printf "\nexport VAULT_TOKEN=${VAULT_TOKEN}\n" >> /home/${LOGNAME}/.bashrc ;
	fi ;
	if ! grep VAULT_ADDR /home/${LOGNAME}/.bashrc ; then
		printf "\nexport VAULT_ADDR=${VAULT_ADDR}\n" >> /home/${LOGNAME}/.bashrc ;
		printf "REMEMBER to: \`source ~/.bashrc ; # // or you'll need: VAULT_ADDR='${VAULT_ADDR}' vault ...\`\n" ;
	fi ;

	export VAULT_ADDR=${VAULT_ADDR} ;

	vault secrets enable pki 2>&1 > /dev/null ;
	if (($? == 0)) ; then printf "SUCCESSFULLY: Enabled Vault PKI Engine.\n" ; fi ;

	vault write pki/config/ca pem_bundle="@${CERT_INTER_BUNDLE}" ;
	if (($? == 0)) ; then printf "SUCCESSFULLY: Written PEM_BUNDLE.\n" ; fi ;

	vault write pki/config/urls issuing_certificates="${VAULT_ADDR}/v1/pki/ca" crl_distribution_points="${VAULT_ADDR}/v1/pki/crl" ocsp_servers="${VAULT_ADDR}/v1/pki/ocsp" 1>/dev/null ;
	if (($? == 0)) ; then printf "SUCCESSFULLY: Set CRL & OCSP to: ${VAULT_ADDR}.\n" ; fi ;

	if [[ ! ${TTL_PKI+x} ]]; then TTL_PKI='72h' ; fi ;
	if [[ ! ${FQDN+x} ]]; then FQDN='tld.com.local' ; fi ;
	if [[ ! ${FQDN_ALLOWED+x} ]]; then FQDN_ALLOWED="${FQDN}" ; fi ;

	vault write pki/roles/${FQDN} allowed_domains="${FQDN_ALLOWED}" allow_subdomains=true allow_localhost="true" allow_ip_sans="true" max_ttl="${TTL_PKI}" 1>/dev/null;
	if (($? == 0)) ; then printf "SUCCESSFULLY: Wrote PKI role for ${FQDN}.\n" ; fi ;
}

URL="${URL}${FILE}" ;
donwloadUnpack && if [[ ${SETUP,,} == *"server"* ]]; then sudoSetup && setupPKI ; fi ;
