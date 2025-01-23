function _broadcastInfo() {
	_broadcast = $(ifconfig | grep broadcast) > date + broadcast.txt && echo _broadcast
	_inet = $(ifconfig | grep inet)
	_mac = $(ifconfig | grep mac)
	_radio_name = $(iw dev | awk) '$1=="Interface"{print $2}'
	_usb = $(lsusb)
	_mac = $(ifconfig | grep mac)
	_DIRS=$(ls *.txt)
	_devInfo01 = $(powermetrics)
	_devInfo02 = $(Infix -Fxz)
	_sshMSG = "/var/log/syslog"
	_sshLogs =  "/var/log/syslog"
	_passDir = "/etc/passwd"
	_user_list = $(awk -F: '{ print $1}' /etc/passwd)
	_getDB_pass = $(getent passwd | awk -F: '{ print $1}')
	
broadcastInfo
