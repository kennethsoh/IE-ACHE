#!/user/bin/env/python3

import time
import hashlib
import random
import logging
import socket
import re, uuid
import base64
import os, random, struct
import subprocess
import asn1tools
from collections import namedtuple
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from optparse   import *
import sys
import select

asn1_file = asn1tools.compile_files("declaration.asn")

#Create tcp/ip socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#retrieve local hostname
local_hostname = socket.gethostname()

#get fully qualified hostname
local_fqdn = socket.getfqdn()

#get the according ip address
ip_address = "192.168.0.22"

#bind socket 
own_address = (ip_address, 4381)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print("Starting up on %s port %s" % own_address)
sock.bind(own_address)



def cipher():

    sock.listen(1)
    connection, cloud_address = sock.accept()
    with connection:
        print("Connecting from", cloud_address)
        
        # Run Adder_alice to get ciphertext
        print("Getting ciphertext...\n")
        subprocess.call("./alice")
        print("Printing ciphertext...\n")
        cloud_data = "cloud.data"
        print("This file ", cloud_data, "is our ciphertext\n")
        
        f = open(cloud_data, "rb")
        content = f.read(8192)
        print(content)

        # Send the file size of the data to the cloud server
        fsize = os.path.getsize(cloud_data)
        print("This is the fsize" ,fsize)

        # Send fsize in BER NOTE: COMPLETE
        fsize_encoded = asn1_file.encode('DataFsize',{'data':fsize})

#####
        while True:
            #Send file size to cloud
            connection.send(fsize_encoded)

            #Receive msg
            encode_msg = connection.recv(1024)
            msg = encode_msg.decode()

            print(fsize_encoded)

            #If success, break
            if (msg == "success"):
                break
            else:
                continue


        #set offset value
        offset_value = 0

        BUFFER_SIZE = 1024
        with open(cloud_data, 'rb') as f:
            while True:
                print("offset value", f.tell())

                #Before offset
                before_offset = f.tell()
                content = f.read(BUFFER_SIZE)

                #BER encode data and send
                data_encoded = asn1_file.encode('DataContent', {'data':content})
                connection.send(data_encoded)
                
                #After offset
                after_offset = f.tell()

                #Receive msg
                encode_msg = connection.recv(1024)
                msg = encode_msg.decode()
                print("msg", msg)

                if(msg == "success"):
                    if(int(after_offset == fsize)):
                        break
                    else:
                        continue
                else:
                    #offset differences
                    offset_differences = int(after_offset) - int(before_offset)

                    #offset values
                    offset_value = int(after_offset) - int(offset_differences)
                    f.seek(offset_value)
            

            f.close()

#####
        # Get the file size of sent data
        print("Original file size: ", os.path.getsize(cloud_data))
    
        #  Decode BER indication data received from cloud 
        print("The CLOUD will send the computed answer to OUTPUT.\n")
#####
        # buffer_size = 10
        while True:
            try:
                irecv = connection.recv(1024)
                indication = asn1_file.decode('DataIndicator', irecv)
                indication_decoded = indication.get('data')
                print(indication_decoded)

                msg = "success"
                connection.send(msg.encode())

                #break out of while loop
                break

            except:
                #print out err msg
                print("An error has occured", sys.exc_info()[0])

                #empty out data from socket
                read_con = [connection]
                while True:
                    r, w, e = select.select(read_con, [], [], 0.0)
                    if len(r) == 0:
                        break
                    else:
                        for data in r:
                            data.recv(1024)

                #testing phase
                # buffer_size = int(input("size of buffer?"))
                
                msg = "fail"
                connection.send(msg.encode())
                continue
#####
       
        sock.close()
    

if __name__ == '__main__':
    cipher()
                






