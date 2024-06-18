function monitorWIFI() {
	sudo iwevent # display wireless events
	sudo iwlist # scan savailable aps or essid
	sudo iwspy # monitors iw nodes and records strenght and quality of signal
	sudo iwgetid # reports current essid
}
monitorWIFI

