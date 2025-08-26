Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.boot_timeout = 120

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
    vb.cpus = 2
  end

  config.vm.define "freeradius" do |frerad|
    frerad.vm.hostname = "freeradius"
    frerad.vm.network "forwarded_port", guest: 1812, host: 1812, protocol: "udp"
    frerad.vm.network "forwarded_port", guest: 1813, host: 1813, protocol: "udp"
    frerad.vm.network "forwarded_port", guest: 5000, host: 5000, protocol: "tcp"
    frerad.vm.synced_folder "./provision", "/vagrant_provision"
    frerad.vm.provision "shell", inline: <<-SHELL
        bash /vagrant_provision/install.sh
        bash /vagrant_provision/run.sh
    SHELL

  end

end
