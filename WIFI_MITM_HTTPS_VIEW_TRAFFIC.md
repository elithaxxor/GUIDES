#######################################

# TO CAPTURE ANALYZE AND DEBUG HTTPS TRAFFIC 

# There will be two servers set up. 

	Server #1--> Establishes Proxy Server 

	Server #2--> The webserver that will be hosting the webcontent 


####---> START SERVER 1 

    #RUN PROGRAM —> initiates the proxy to receive traffic 

	—> mitmproxy 


    #Change OS Proxy to listen on 

	#--> This should force the connection to be http, which would disable most browser-based website connections 

		—> Web Proxy (HTTP) 

		—> Secure Web Proxy (HTTPS) 


   3. #INSTALL mitmproxy Certificate Authority 

	—> Visit mitm.it and download the proxy certificate 

	—> Click on downloaded certificate, and set TRUST parameters to  ALWAYS Trust 


####---> START SERVER 2

	1. #RUN PROGRAM: 

		—> mitmweb 
