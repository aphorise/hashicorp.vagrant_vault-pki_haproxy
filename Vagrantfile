# -*- mode: ruby -*-
# vi: set ft=ruby :
sVUSER='vagrant'  # // vagrant user
sHOME="/home/#{sVUSER}"  # // home path for vagrant user
#sNET='en0: Wi-Fi (Wireless)'  # // network adaptor to use for bridged mode
sNET='en7: USB 10/100/1000 LAN'
sIP_CLASS_D='192.168.178'  # // NETWORK CIDR for Consul configs.
sIP="#{sIP_CLASS_D}.200"
sIP_VAULT="#{sIP_CLASS_D}.201"
sCERT_BUNDLE='ca_intermediate.pem'

Vagrant.configure("2") do |config|

  config.vm.box = "debian/buster64"
  config.vm.provider "virtualbox" do |v|
    v.memory = 1024  # // RAM / Memory
    v.cpus = 1  # // CPU Cores / Threads
  end

  config.vm.provision "shell", path: "1.install_commons.sh"

  # // HAProxy 1st node & Vault Dev Server 2nd node.
  (1..2).each do |iX|
    if iX == 1 then
      config.vm.define vm_name="haproxy" do |haproxy_node|
        haproxy_node.vm.hostname = vm_name
        haproxy_node.vm.network "public_network", bridge: "#{sNET}", ip: "#{sIP}"
        haproxy_node.vm.provision "file", source: "2.install_haproxy.sh", destination: "#{sHOME}/install_haproxy.sh"
        haproxy_node.vm.provision "shell", inline: "/bin/bash -c 'echo \"export IP=(#{sIP_VAULT})\" >> ~/.profile ; #{sHOME}/install_haproxy.sh'"
        haproxy_node.vm.provision "file", source: "3.vault_certs.sh", destination: "#{sHOME}/install_certs.sh"
        haproxy_node.vm.provision "shell", inline: "/bin/bash -c '#{sHOME}/install_certs.sh'"
        # // allow for SSHD on all interfaces
        haproxy_node.vm.provision "shell", inline: 'sed -i "s/#ListenAddress/ListenAddress/g" /etc/ssh/sshd_config'
      end
    end

    if iX == 2 then
      config.vm.define vm_name="vault#{iX-1}" do |vault_node|
        vault_node.vm.hostname = vm_name
        vault_node.vm.network "public_network", bridge: "#{sNET}", ip: "#{sIP_VAULT}"
        # // ssh setup default identity files & copy file from haproxy host (bundle certificate).
        vault_node.vm.provision "file", source: ".vagrant/machines/haproxy/virtualbox/private_key", destination: "~/.ssh/id_rsa2"
        vault_node.vm.provision "shell", inline: 'sed -i "s/#.*IdentityFile ~\/\.ssh\/id_rsa/    IdentityFile ~\/\.ssh\/id_rsa/g" /etc/ssh/ssh_config'
        vault_node.vm.provision "shell", inline: 'sed -i "s/.*IdentityFile ~\/\.ssh\/id_rsa/    IdentityFile ~\/\.ssh\/id_rsa\n    IdentityFile ~\/\.ssh\/id_rsa2/g" /etc/ssh/ssh_config'

        vault_node.vm.provision "shell", inline: "mkdir ~/.ssh ; ssh-keyscan #{sIP} 2>/dev/null >> ~/.ssh/known_hosts ;"
        vault_node.vm.provision "shell", inline: "ssh-keyscan #{sIP} 2>/dev/null >> #{sHOME}/.ssh/known_hosts ; chown #{sVUSER}:#{sVUSER} -R #{sHOME}/.ssh ;"

#        puts  "rsync -qva --rsh='ssh -p2200  -i #{sHOME}/.ssh/id_rsa2' #{sVUSER}@#{sIP}:~/#{sCERT_BUNDLE} #{sHOME}/."
        vault_node.vm.provision "shell", inline: "rsync -qva --rsh='ssh -p22  -i #{sHOME}/.ssh/id_rsa2' #{sVUSER}@#{sIP}:~/#{sCERT_BUNDLE} #{sHOME}/."
        vault_node.vm.provision "file", source: "4.install_vault.sh", destination: "#{sHOME}/install_vault.sh"
        vault_node.vm.provision "shell", inline: "/bin/bash -c '#{sHOME}/install_vault.sh'"
        vault_node.vm.provision "file", source: "5.vcert.sh", destination: "#{sHOME}/vcert.sh"
      end
    end
  end

end
