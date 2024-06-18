# NET CAT CAN CREATE SERVERS AND CONNECT TO THEM 

#create server
nc -l 9999
# connect to server (from another device) 
nc 192.168.86.23

# use python to create server
python -m http.server 5432

