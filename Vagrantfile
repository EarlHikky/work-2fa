Vagrant.configure("2") do |config|
  config.vm.box = "debian/bookworm64"
  config.vm.boot_timeout = 120

  config.vm.provider "virtualbox" do |vb|
    vb.gui = false
    vb.memory = "1024"
    vb.cpus = 2
  end

  config.vm.define "freeradius" do |mgr|
    mgr.vm.hostname = "freeradius"
    mgr.vm.network "private_network", ip: "192.168.56.10"
    mgr.vm.synced_folder "./freeradius", "/etc/freeradius"
  end

end
