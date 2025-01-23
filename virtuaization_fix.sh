sudo lsmod | grep -E 'kvm|vbox'
modprobe -r kvm
sudo rmmod kvm_amd
sudo rmmod kvm
sudo lsmod | grep -E 'kvm|vbox'
