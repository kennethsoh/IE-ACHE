import time
import hashlib
import random
import logging
import socket
import re, uuid
import base64
import os, random, struct
import subprocess
import sys
import asn1tools
from collections import namedtuple
from Cryptodome.Cipher import AES
from Cryptodome import Random
from Cryptodome.Hash import SHA256
from optparse import *
import logging

# THE PURPOSE OF THIS FILE IS TO INITATE DRAGONFLY KEY EXHANGE AND VERIFY ITS COMPLETION 

def dragonfly():

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    output_address = ("192.168.0.4", 7000)
    

    print('Listening...')
    logging.info('STARTING dragonfly')

    # secretkey = os.path.isfile('secret.key.hacklab')
    # cloudkey = os.path.isfile('cloud.key.hacklab')

# if (secretkey and cloudkey): 
    # try:
    #     sock.connect(output_address)
    #     logging.info('Sending finished message')
    #     message = "finished"
    #     sock.sendall(message.encode())
    #     sock.close()
    # except:
    #     pass


    #Execute dragonfly private for output machine
    # print ('Executing dragonfly code for Output machine only.')
    # subprocess.run('./dragonfly_private_output.py')

    # time.sleep(5)

# else:
    #Execute dragonfly private for output machine
    print ('Executing dragonfly code for Output machine.')
    # subprocess.run('./dragonfly_private_output.py')
    subprocess.run('./dragonfly_private_output.py')
    
    #Execute dragonfly public for cloud machine
    logging.info("dragonfly cloud")
    print ('executing dragonfly code for CLOUD machine')
    # print ('execute cloud_dynamic.py on CLOUD')
    subprocess.run('./dragonfly_public_keygen.py')

    HOSTUP1 = True if os.system("ping -c 2 192.168.0.21 > /dev/null 2>&1") == 0 else False
    HOSTUP2 = True if os.system("ping -c 2 192.168.0.22 > /dev/null 2>&1") == 0 else False
    HOSTUP3 = True if os.system("ping -c 2 192.168.0.23 > /dev/null 2>&1") == 0 else False

    if (HOSTUP1):
        #execute dragonfly private for 192.168.0.21
        logging.info("dragonfly 192.168.0.21")
        print("")
        print ('executing dragonfly code for 192.168.0.21')
        # print ('execute client_dynamic.py on 192.168.0.21')
        subprocess.run('./dragonfly_private_keygen.py')
    
    if (HOSTUP2):
        #Execute dragonfly private for client machine 192.168.0.22
        logging.info("dragonfly 192.168.0.22")
        print("")
        print ('executing dragonfly code for 192.168.0.22')
        # print ('execute client_dynamic.py on 192.168.0.22')
        # subprocess.run('./dragonfly_private_keygen2.py')
        subprocess.run('./dragonfly_private_keygen2.py')
    
    if (HOSTUP3):
        #Execute dragonfly private for client machine 192.168.0.23
        logging.info("dragonfly 192.168.0.23")
        print("")
        print ('executing dragonfly code for CLIENT 192.168.0.23')
        # print ('execute client_dynamic.py on CLIENT 192.168.0.23')
        # subprocess.run('./dragonfly_private_keygen3.py')
        subprocess.run('./dragonfly_private_keygen3.py')

    print("Sending finish to output addr ")
    time.sleep(10)
    try:
        sock.connect(output_address)
        logging.info('Sending finished message')
        message = "finished"
        sock.sendall(message.encode())
        sock.close()
    except:
        pass


while True:
    dragonfly()
