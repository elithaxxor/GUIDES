lsusb
sudo airmon-ng check
sudo airmon-ng check kill
sudo airmon-ng start wlan1
sudo airmon-ng start wlan2
iwconfig 
sudo hciconfig -a
sudo hciconfig hci0 up
sudo hciconfig -a
systemctl restart NetworkManager
iwconfig

